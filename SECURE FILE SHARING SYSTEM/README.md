# Secure File Sharing System

A beginner-friendly Flask application that encrypts uploaded files with Fernet (AES-based authenticated encryption), stores metadata in SQLite, and supports login, roles and temporary sharing links.

## 1. Requirements

- Windows 10/11
- Python 3.10 or newer
- VS Code

## 2. Setup

Open PowerShell in this project folder:

```powershell
cd "C:\Users\7705p\.vscode-shared\my project 2\SECURE FILE SHARING SYSTEM"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 3. Configure environment variables

Copy `.env.example` to `.env`, then generate values:

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Place the first generated value after `SECRET_KEY=` and the second after `FILE_ENCRYPTION_KEY=`. Do not commit `.env`.

For local HTTP development keep `SESSION_COOKIE_SECURE=false`. If HTTPS is used, set it to `true`.

## 4. Start

```powershell
python app.py
```

Open `http://127.0.0.1:5000`.

## 5. Demonstration

1. Register the **first account**. It receives the administrator role.
2. Register another account to demonstrate normal-user access.
3. Log in as the normal user and upload a PDF, DOCX, TXT, JPG, PNG or ZIP file under 25 MB.
4. Download the file and verify that the original name and contents are retained.
5. Create a 5-minute, 1-hour or 24-hour sharing link. Copy the URL shown in the success notification.
6. Open the link in a private window to test temporary sharing. Revoke it from My Files, then verify that it no longer works.
7. Log in as the administrator to view users, all files and sharing links.
8. Test an unauthorized download by attempting to access another user's file URL.

The database `secure_files.db` is created automatically. Encrypted files are stored in `uploads/`. Do not add the database or `.env` to source control.
