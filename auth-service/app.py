from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import jwt
import datetime
import logging

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("auth-service")

app = FastAPI(title="Auth Service")

SECRET_KEY = "secret-key"  # Для JWT


# Модель запроса для Smart-карты
class CardLoginRequest(BaseModel):
    card_id: str


@app.post("/auth/login")
def login(request: CardLoginRequest):
    logger.info(f"Login attempt with card_id: {request.card_id}")
    
    # Имитация проверки Smart-карты
    if request.card_id == "card123":
        token = jwt.encode(
            {"sub": request.card_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            SECRET_KEY,
            algorithm="HS256"
        )
        logger.info(f"Login success for card_id: {request.card_id}")
        return {"access_token": token, "token_type": "bearer"}
    else:
        logger.warning(f"Unauthorized access attempt with card_id: {request.card_id}")
        raise HTTPException(status_code=401, detail="Invalid card")
