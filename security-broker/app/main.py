from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Security Broker")


class SecurityRequest(BaseModel):
    command: str
    card_id: str


@app.get("/health")
def health():
    return {"status": "security-broker alive"}


@app.post("/check")
def check_security(data: SecurityRequest):
    # ВРЕМЕННО: всегда разрешаем
    return {
        "decision": "ALLOW",
        "reason": "Temporary stub"
    }
