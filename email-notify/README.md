# email-notify
Simple email notification service using FastAPI + smtplib.

## Features
- `/notify` endpoint: send a simple HTML email.
- Uses environment variables (see `.env.example`).
- Jinja2 email template.
- Pytest with SMTP mock.

## Run locally
```bash
python -m venv .venv
# activate the venv (Windows PowerShell)
.venv\Scripts\Activate.ps1
# or Linux/macOS: source .venv/bin/activate

pip install -r requirements.txt

# Copy .env.example -> .env and fill credentials (use Gmail App Password)

uvicorn app:app --reload
# then POST to http://127.0.0.1:8000/notify
```

## Example curl
```bash
curl -X POST http://127.0.0.1:8000/notify       -H "Content-Type: application/json"       -d '{"to":"TO_EMAIL@domain.com","subject":"Xin chào","message":"Đây là thông báo."}'
```

## Run tests
```bash
pytest -q
```

## Push to GitHub
```bash
git init
git branch -M main
git add .
git commit -m "feat: minimal email notifier (FastAPI + smtplib)"
git remote add origin https://github.com/<username>/email-notify.git
git push -u origin main
```
