from fastapi import FastAPI, Request, HTTPException, Depends
import jwt
from fastapi.responses import JSONResponse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api-gateway")

app = FastAPI(title="API Gateway")

SECRET_KEY = "secret-key"  # Должен совпадать с Auth Service


# Проверка JWT
def verify_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        logger.warning("Missing Authorization header")
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    try:
        scheme, token = auth_header.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid auth scheme")
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        logger.info(f"Token verified for card_id: {payload['sub']}")
        return payload
    except Exception as e:
        logger.warning(f"Token verification failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/protected/data")
def protected_data(payload: dict = Depends(verify_token)):
    logger.info(f"Access to protected data by card_id: {payload['sub']}")
    return {"message": f"Hello {payload['sub']}, this is protected data."}
