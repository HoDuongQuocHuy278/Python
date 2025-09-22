import os, ssl, smtplib
from email.message import EmailMessage
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from dotenv import load_dotenv

# load .env if present
load_dotenv(override=False)

TEMPLATES_DIR = Path(__file__).parent / "templates"
env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER or "")

class EmailSendError(Exception):
    pass

def render_template(template_name: str, **context) -> str:
    template = env.get_template(template_name)
    return template.render(**context)

def send_email(to: str, subject: str, html: str, plain: str | None = None):
    if not (SMTP_USER and SMTP_PASS):
        raise EmailSendError("Missing SMTP_USER/SMTP_PASS in environment variables")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL or SMTP_USER
    msg["To"] = to
    msg.set_content(plain or " ")
    msg.add_alternative(html, subtype="html")

    ctx = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls(context=ctx)
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

def send_simple_template(to: str, subject: str, message: str):
    html = render_template("email_notification.html", subject=subject, message=message)
    send_email(to=to, subject=subject, html=html, plain=message)
