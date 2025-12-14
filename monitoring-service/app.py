from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Monitoring Service")

logs = []

class LogRequest(BaseModel):
    event: str
    user: str

@app.post("/log_event")
def log_event(data: LogRequest):
    logs.append({"user": data.user, "event": data.event})
    return {"status": "ok", "total_logs": len(logs)}

@app.get("/logs")
def get_logs():
    return logs
