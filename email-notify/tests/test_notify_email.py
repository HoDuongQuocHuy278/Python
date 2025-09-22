import types
import notify_email as ne

class DummySMTP:
    def __init__(self, *a, **k): self.sent = []
    def starttls(self, *a, **k): pass
    def login(self, *a, **k): pass
    def send_message(self, msg): self.sent.append(msg)
    def __enter__(self): return self
    def __exit__(self, *a): pass

def test_send_simple_template(monkeypatch):
    # patch SMTP creds
    ne.SMTP_USER = "u@e.com"
    ne.SMTP_PASS = "x"
    ne.FROM_EMAIL = "u@e.com"

    dummy = DummySMTP()
    monkeypatch.setattr(ne.smtplib, "SMTP", lambda *a, **k: dummy)

    ne.send_simple_template("to@e.com", "Subject", "Body")
    assert len(dummy.sent) == 1
    msg = dummy.sent[0]
    assert msg["To"] == "to@e.com"
    assert msg["Subject"] == "Subject"
