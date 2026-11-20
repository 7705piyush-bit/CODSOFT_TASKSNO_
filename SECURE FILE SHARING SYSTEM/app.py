import hashlib
import io
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "secure_files.db"
UPLOAD_DIR = BASE_DIR / "uploads"

load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY")
FERNET_KEY = os.getenv("FILE_ENCRYPTION_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing. Copy .env.example to .env and configure it.")
if not FERNET_KEY:
    raise RuntimeError(
        "FILE_ENCRYPTION_KEY is missing. Copy .env.example to .env and configure it."
    )

try:
    cipher = Fernet(FERNET_KEY.encode("utf-8"))
except (TypeError, ValueError) as exc:
    raise RuntimeError(
        "FILE_ENCRYPTION_KEY is invalid. Generate a Fernet key as described in README.md."
    ) from exc

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"

csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "index"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "warning"

ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "jpg", "jpeg", "png", "zip"}
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


class User(UserMixin):
    def __init__(self, row):
        self.id = str(row["id"])
        self.username = row["username"]
        self.email = row["email"]
        self.role = row["role"]
        self.created_at = row["created_at"]


def get_db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def utc_now():
    return datetime.now(timezone.utc)


def utc_string(value=None):
    value = value or utc_now()
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_utc(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def initialize_database():
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                original_filename TEXT NOT NULL,
                encrypted_filename TEXT NOT NULL UNIQUE,
                file_size INTEGER NOT NULL CHECK(file_size >= 0),
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS share_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_revoked INTEGER NOT NULL DEFAULT 0 CHECK(is_revoked IN (0, 1)),
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
            );
            """
        )


initialize_database()


@login_manager.user_loader
def load_user(user_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
    return User(row) if row else None


def admin_required():
    if not current_user.is_authenticated or current_user.role != "admin":
        abort(403)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def format_size(size):
    size = int(size)
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def owner_or_admin(file_row):
    return current_user.role == "admin" or file_row["owner_id"] == int(current_user.id)


@app.context_processor
def utility_processor():
    return {"format_size": format_size}


@app.route("/", methods=["GET", "POST"])
def index():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard" if current_user.role == "admin" else "dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row), remember=False)
            flash("Login successful.", "success")
            return redirect(url_for("admin_dashboard" if row["role"] == "admin" else "dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(username) < 3 or len(username) > 50:
            flash("Username must contain 3 to 50 characters.", "danger")
        elif "@" not in email or len(email) > 120:
            flash("Enter a valid email address.", "danger")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
        elif password != confirm_password:
            flash("Passwords do not match.", "danger")
        else:
            with get_db() as db:
                count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                role = "admin" if count == 0 else "user"
                try:
                    db.execute(
                        """
                        INSERT INTO users (username, email, password_hash, role, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            username,
                            email,
                            generate_password_hash(password),
                            role,
                            utc_string(),
                        ),
                    )
                except sqlite3.IntegrityError:
                    flash("Username or email already exists.", "danger")
                else:
                    flash(
                        "Registration successful. The first account has administrator access."
                        if role == "admin"
                        else "Registration successful. Please log in.",
                        "success",
                    )
                    return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))

    with get_db() as db:
        files = db.execute(
            "SELECT * FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC",
            (int(current_user.id),),
        ).fetchall()
        share_links = db.execute(
            """
            SELECT sl.*, f.original_filename
            FROM share_links sl
            JOIN files f ON f.id = sl.file_id
            WHERE f.owner_id = ? AND sl.is_revoked = 0
            ORDER BY sl.created_at DESC
            """,
            (int(current_user.id),),
        ).fetchall()

    return render_template(
        "dashboard.html",
        files=files,
        share_links=share_links,
        now=utc_now(),
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Please choose a file.", "danger")
        return redirect(url_for("dashboard"))

    original_filename = secure_filename(uploaded.filename)
    if not original_filename:
        flash("The filename is invalid.", "danger")
        return redirect(url_for("dashboard"))
    if not allowed_file(original_filename):
        flash("Unsupported file type. Allowed: PDF, DOCX, TXT, JPG, PNG and ZIP.", "danger")
        return redirect(url_for("dashboard"))

    content = uploaded.read(app.config["MAX_CONTENT_LENGTH"] + 1)
    if len(content) > app.config["MAX_CONTENT_LENGTH"]:
        flash("File is too large. Maximum size is 25 MB.", "danger")
        return redirect(url_for("dashboard"))
    if not content:
        flash("Empty files cannot be uploaded.", "danger")
        return redirect(url_for("dashboard"))

    encrypted_filename = f"{uuid.uuid4().hex}.encrypted"
    encrypted_path = UPLOAD_DIR / encrypted_filename
    encrypted_path.write_bytes(cipher.encrypt(content))

    try:
        with get_db() as db:
            db.execute(
                """
                INSERT INTO files
                    (owner_id, original_filename, encrypted_filename, file_size, uploaded_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    int(current_user.id),
                    original_filename,
                    encrypted_filename,
                    len(content),
                    utc_string(),
                ),
            )
    except sqlite3.Error:
        encrypted_path.unlink(missing_ok=True)
        flash("The file could not be saved.", "danger")
    else:
        flash("File uploaded and encrypted successfully.", "success")

    return redirect(url_for("dashboard"))


@app.route("/download/<int:file_id>")
@login_required
def download_file(file_id):
    with get_db() as db:
        file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row:
        abort(404)
    if not owner_or_admin(file_row):
        abort(403)

    encrypted_path = UPLOAD_DIR / file_row["encrypted_filename"]
    if not encrypted_path.resolve().parent == UPLOAD_DIR.resolve():
        abort(403)
    if not encrypted_path.is_file():
        abort(404)

    try:
        plaintext = cipher.decrypt(encrypted_path.read_bytes())
    except (InvalidToken, OSError):
        app.logger.error("Encrypted file could not be decrypted: file id %s", file_id)
        abort(500)

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=file_row["original_filename"],
        mimetype="application/octet-stream",
    )


@app.route("/share/<int:file_id>", methods=["POST"])
@login_required
def create_share_link(file_id):
    with get_db() as db:
        file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row:
        abort(404)
    if not owner_or_admin(file_row):
        abort(403)

    duration_options = {"5": 5, "60": 60, "1440": 1440}
    selected = request.form.get("duration", "60")
    if selected not in duration_options:
        flash("Invalid link expiration period.", "danger")
        return redirect(url_for("dashboard"))

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = utc_now() + timedelta(minutes=duration_options[selected])

    with get_db() as db:
        db.execute(
            """
            INSERT INTO share_links (file_id, token_hash, expires_at, created_at, is_revoked)
            VALUES (?, ?, ?, ?, 0)
            """,
            (file_id, token_hash, utc_string(expires_at), utc_string()),
        )

    share_url = url_for("shared_download", token=raw_token, _external=True)
    flash(f"Temporary sharing link created: {share_url}", "success")
    return redirect(url_for("dashboard"))


@app.route("/s/<token>")
def shared_download(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with get_db() as db:
        row = db.execute(
            """
            SELECT sl.*, f.original_filename, f.encrypted_filename
            FROM share_links sl
            JOIN files f ON f.id = sl.file_id
            WHERE sl.token_hash = ? AND sl.is_revoked = 0
            """,
            (token_hash,),
        ).fetchone()

    if not row:
        abort(404)
    if parse_utc(row["expires_at"]) <= utc_now():
        abort(410)

    encrypted_path = UPLOAD_DIR / row["encrypted_filename"]
    if not encrypted_path.resolve().parent == UPLOAD_DIR.resolve() or not encrypted_path.is_file():
        abort(404)

    try:
        plaintext = cipher.decrypt(encrypted_path.read_bytes())
    except (InvalidToken, OSError):
        app.logger.error("Shared encrypted file could not be decrypted")
        abort(500)

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=row["original_filename"],
        mimetype="application/octet-stream",
    )


@app.route("/share/revoke/<int:link_id>", methods=["POST"])
@login_required
def revoke_share_link(link_id):
    with get_db() as db:
        row = db.execute(
            """
            SELECT sl.id, f.owner_id
            FROM share_links sl
            JOIN files f ON f.id = sl.file_id
            WHERE sl.id = ?
            """,
            (link_id,),
        ).fetchone()
        if not row:
            abort(404)
        if current_user.role != "admin" and row["owner_id"] != int(current_user.id):
            abort(403)
        db.execute(
            "UPDATE share_links SET is_revoked = 1 WHERE id = ?", (link_id,)
        )

    flash("Sharing link revoked.", "success")
    return redirect(url_for("admin_dashboard" if current_user.role == "admin" else "dashboard"))


@app.route("/file/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    with get_db() as db:
        file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if not file_row:
            abort(404)
        if not owner_or_admin(file_row):
            abort(403)

        encrypted_path = UPLOAD_DIR / file_row["encrypted_filename"]
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))

    if encrypted_path.resolve().parent == UPLOAD_DIR.resolve():
        encrypted_path.unlink(missing_ok=True)
    flash("File deleted.", "success")
    return redirect(url_for("admin_dashboard" if current_user.role == "admin" else "dashboard"))


@app.route("/admin")
@login_required
def admin_dashboard():
    admin_required()
    with get_db() as db:
        users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        files = db.execute(
            """
            SELECT f.*, u.username AS owner_name
            FROM files f
            JOIN users u ON u.id = f.owner_id
            ORDER BY f.uploaded_at DESC
            """
        ).fetchall()
        share_links = db.execute(
            """
            SELECT sl.*, f.original_filename, u.username AS owner_name
            FROM share_links sl
            JOIN files f ON f.id = sl.file_id
            JOIN users u ON u.id = f.owner_id
            WHERE sl.is_revoked = 0
            ORDER BY sl.created_at DESC
            """
        ).fetchall()

    return render_template(
        "admin.html",
        users=users,
        files=files,
        share_links=share_links,
        now=utc_now(),
    )


@app.route("/admin/user/role/<int:user_id>", methods=["POST"])
@login_required
def change_user_role(user_id):
    admin_required()
    role = request.form.get("role")
    if role not in {"admin", "user"}:
        flash("Invalid role.", "danger")
        return redirect(url_for("admin_dashboard"))

    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            abort(404)
        if row["id"] == int(current_user.id) and role != "admin":
            flash("You cannot remove your own administrator role.", "danger")
            return redirect(url_for("admin_dashboard"))
        db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))

    flash("User role updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    admin_required()
    if user_id == int(current_user.id):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_dashboard"))

    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            abort(404)
        files = db.execute(
            "SELECT encrypted_filename FROM files WHERE owner_id = ?", (user_id,)
        ).fetchall()
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))

    for file_row in files:
        encrypted_path = UPLOAD_DIR / file_row["encrypted_filename"]
        if encrypted_path.resolve().parent == UPLOAD_DIR.resolve():
            encrypted_path.unlink(missing_ok=True)

    flash("User and all owned files deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.errorhandler(403)
def forbidden(error):
    return render_template("base.html", error_code=403, error_message="Access denied."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("base.html", error_code=404, error_message="Page not found."), 404


@app.errorhandler(410)
def gone(error):
    return render_template("base.html", error_code=410, error_message="This sharing link has expired."), 410


@app.errorhandler(413)
def too_large(error):
    flash("File is too large. Maximum size is 25 MB.", "danger")
    return redirect(url_for("dashboard") if current_user.is_authenticated else url_for("index"))


if __name__ == "__main__":
    initialize_database()
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true", host="127.0.0.1", port=5000)
