from fastapi import FastAPI, HTTPException, Depends, Request
import httpx
import logging
from datetime import datetime
from typing import Optional

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="API Gateway", description="Gateway for microservices security pattern")

# URL-адреса других сервисов
AUTH_SERVICE_URL = "http://auth-service:8901"
SECURITY_BROKER_URL = "http://security-broker:8902"
THREAT_INTELLIGENCE_URL = "http://threat-intelligence:8903"
MONITORING_SERVICE_URL = "http://monitoring-service:8905"

@app.get("/")
async def gateway_info():
    """Информация о шлюзе API"""
    return {"message": "API Gateway for Microservices Security Pattern", "status": "running"}

@app.post("/check-access")
async def check_access(request: Request):
    """
    Проверяет доступ к защищенным ресурсам через брокер безопасности
    """
    try:
        # Получаем JSON-данные из запроса
        data = await request.json()
        
        # Отправляем проверку доступа в брокер безопасности
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{SECURITY_BROKER_URL}/check_access",
                json=data
            )
            
            if response.status_code == 200:
                access_result = response.json()
                
                # Отправляем информацию о запросе в сервис мониторинга
                monitoring_data = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source_ip": request.client.host,
                    "endpoint": "/check-access",
                    "status": "success",
                    "details": access_result
                }
                
                try:
                    await client.post(
                        f"{MONITORING_SERVICE_URL}/log_event",
                        json=monitoring_data
                    )
                except Exception as e:
                    logger.error(f"Failed to log event to monitoring service: {e}")
                
                return access_result
            else:
                raise HTTPException(status_code=response.status_code, detail="Access check failed")
    
    except httpx.RequestError as e:
        logger.error(f"Request error: {e}")
        raise HTTPException(status_code=500, detail=f"Request error: {e}")
    
    except Exception as e:
        logger.error(f"Error checking access: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/users")
async def get_users(token: str = Depends(lambda: None)):
    """
    Пример защищенного эндпоинта для получения списка пользователей
    """
    if not token:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
    
    # Проверяем токен через аутентификационный сервис
    async with httpx.AsyncClient() as client:
        try:
            auth_response = await client.post(
                f"{AUTH_SERVICE_URL}/validate_token",
                json={"token": token}
            )
            
            if auth_response.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid token")
            
            user_info = auth_response.json()
            
            # Проверяем права доступа через брокер безопасности
            access_check_data = {
                "user_id": user_info["user_id"],
                "resource": "/api/users",
                "action": "read",
                "role": user_info.get("role", "user")
            }
            
            access_response = await client.post(
                f"{SECURITY_BROKER_URL}/check_access",
                json=access_check_data
            )
            
            if access_response.status_code != 200 or not access_response.json().get("allowed"):
                raise HTTPException(status_code=403, detail="Access denied")
            
            # Логируем событие в мониторинг
            monitoring_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": user_info["user_id"],
                "endpoint": "/api/users",
                "action": "read",
                "status": "success"
            }
            
            try:
                await client.post(
                    f"{MONITORING_SERVICE_URL}/log_event",
                    json=monitoring_data
                )
            except Exception as e:
                logger.error(f"Failed to log event to monitoring service: {e}")
            
            # Возвращаем пример данных пользователей
            return {"users": [
                {"id": 1, "name": "Alice Johnson", "email": "alice@example.com"},
                {"id": 2, "name": "Bob Smith", "email": "bob@example.com"}
            ]}
        
        except httpx.RequestError as e:
            logger.error(f"Auth service request error: {e}")
            raise HTTPException(status_code=500, detail="Authentication service unavailable")
        
        except Exception as e:
            logger.error(f"Error getting users: {e}")
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin")
async def get_admin_data(token: str = Depends(lambda: None)):
    """
    Пример защищенного эндпоинта для административных данных
    """
    if not token:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
    
    # Проверяем токен через аутентификационный сервис
    async with httpx.AsyncClient() as client:
        try:
            auth_response = await client.post(
                f"{AUTH_SERVICE_URL}/validate_token",
                json={"token": token}
            )
            
            if auth_response.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid token")
            
            user_info = auth_response.json()
            
            # Проверяем права доступа через брокер безопасности
            access_check_data = {
                "user_id": user_info["user_id"],
                "resource": "/api/admin",
                "action": "read",
                "role": user_info.get("role", "user")
            }
            
            access_response = await client.post(
                f"{SECURITY_BROKER_URL}/check_access",
                json=access_check_data
            )
            
            if access_response.status_code != 200 or not access_response.json().get("allowed"):
                raise HTTPException(status_code=403, detail="Access denied")
            
            # Логируем событие в мониторинг
            monitoring_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": user_info["user_id"],
                "endpoint": "/api/admin",
                "action": "read",
                "status": "success"
            }
            
            try:
                await client.post(
                    f"{MONITORING_SERVICE_URL}/log_event",
                    json=monitoring_data
                )
            except Exception as e:
                logger.error(f"Failed to log event to monitoring service: {e}")
            
            # Возвращаем пример административных данных
            return {
                "admin_data": {
                    "system_status": "operational",
                    "active_users": 150,
                    "security_level": "high"
                }
            }
        
        except httpx.RequestError as e:
            logger.error(f"Auth service request error: {e}")
            raise HTTPException(status_code=500, detail="Authentication service unavailable")
        
        except Exception as e:
            logger.error(f"Error getting admin data: {e}")
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Проверка работоспособности сервиса"""
    return {"status": "healthy", "service": "api-gateway"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8900)