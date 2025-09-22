from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel, EmailStr
from notify_email import send_simple_template, EmailSendError

app = FastAPI(title="Email Notify Service")

class NotifyPayload(BaseModel):
    to: EmailStr
    subject: str
    message: str

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/notify")
def notify(payload: NotifyPayload, bg: BackgroundTasks):
    try:
        bg.add_task(send_simple_template, payload.to, payload.subject, payload.message)
        return {"queued": True}
    except EmailSendError as e:
        # If env missing, raise immediately
        raise HTTPException(status_code=400, detail=str(e))
