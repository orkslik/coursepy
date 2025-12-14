from fastapi import FastAPI
from pydantic import BaseModel
from enum import Enum
import httpx
from typing import Optional, Dict

app = FastAPI(title="API Gateway")

AUTH_SERVICE_URL = "http://auth-service:8000"
SECURITY_BROKER_URL = "http://security-broker:8000"

# --- МОДЕЛИ ДАННЫХ (ДОЛЖНЫ СОВПАДАТЬ С SECURITY-BROKER!) ---
class CommandType(str, Enum):
    """Типы APDU-команд (ISO 7816)."""
    VERIFY_PIN = "VERIFY_PIN"
    SIGN_DATA = "SIGN_DATA"
    GET_PUBLIC_KEY = "GET_PUBLIC_KEY"
    READ_DATA = "READ_DATA"
    WRITE_DATA = "WRITE_DATA"
    UPDATE_KEY = "UPDATE_KEY"

class SecurityRequest(BaseModel):
    """Модель запроса на проверку безопасности. ДОЛЖНА БЫТЬ ИДЕНТИЧНОЙ security-broker!"""
    card_id: str
    user_id: str
    command: CommandType
    command_data: Optional[Dict] = {}
    user_role: str = "user"

class LoginRequest(BaseModel):
    """Модель запроса на логин (отдельная, для auth-service)."""
    username: str
    password: str

# --- ENDPOINTS ---
@app.get("/health")
def health():
    return {"status": "api-gateway alive"}

@app.post("/auth/login")
async def login(data: LoginRequest):
    """Маршрут для аутентификации. Перенаправляет в auth-service."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{AUTH_SERVICE_URL}/login",
            json=data.dict()
        )
    return response.json()

@app.post("/security/check")
async def security_check(data: SecurityRequest):
    """Маршрут для проверки безопасности. Перенаправляет в security-broker."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{SECURITY_BROKER_URL}/check",
            json=data.dict()
        )
    return response.json()