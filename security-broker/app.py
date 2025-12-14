from fastapi import FastAPI
from pydantic import BaseModel
import httpx

app = FastAPI(title="Security Broker")

class CheckRequest(BaseModel):
    token: str
    resource: str

@app.post("/check_access")
def check_access(data: CheckRequest):
    # Простейшая логика: токен содержит username
    if "TOKEN-" in data.token:
        username = data.token.replace("TOKEN-", "")
        return {"username": username, "access_granted": True}
    return {"access_granted": False}
