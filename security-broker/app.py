from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
import httpx
import asyncio

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Security Broker", description="Security broker for microservices pattern")

# URL-адреса других сервисов
THREAT_INTELLIGENCE_URL = "http://threat-intelligence:8903"
MONITORING_SERVICE_URL = "http://monitoring-service:8905"

# Правила безопасности (в реальной системе эти правила должны храниться в БД или конфигурационном файле)
security_policies = {
    "default_policy": {
        "allow_same_role_access": True,
        "require_mfa_for_admin_actions": True,
        "restrict_ip_access": False,
        "check_threat_intel": True
    },
    "admin_policy": {
        "allow_same_role_access": True,
        "require_mfa_for_admin_actions": True,
        "restrict_ip_access": True,
        "check_threat_intel": True,
        "require_justification": True
    }
}

class AccessRequest(BaseModel):
    user_id: str
    resource: str
    action: str
    role: str
    ip_address: Optional[str] = None
    mfa_verified: bool = False
    justification: Optional[str] = None

class RiskFactor(BaseModel):
    factor: str
    weight: float
    description: str

class RiskAssessment(BaseModel):
    user_id: str
    resource: str
    action: str
    risk_score: float
    factors: List[RiskFactor]
    recommendation: str

@app.get("/")
async def broker_info():
    """Информация о брокере безопасности"""
    return {"message": "Security Broker for Microservices Security Pattern", "status": "running"}

@app.post("/check_access")
async def check_access(request: AccessRequest, background_tasks: BackgroundTasks):
    """Проверяет доступ к ресурсу на основе политики безопасности"""
    try:
        # Определяем политику безопасности на основе роли пользователя
        policy_key = "admin_policy" if request.role == "admin" else "default_policy"
        policy = security_policies.get(policy_key, security_policies["default_policy"])
        
        # Выполняем оценку рисков
        risk_assessment = await assess_risk(request)
        
        # Проверяем соответствие политике безопасности
        allowed = True
        reason = "Access granted"
        
        # Проверка политики: требуется ли MFA для административных действий
        if policy["require_mfa_for_admin_actions"] and "admin" in request.resource and not request.mfa_verified:
            allowed = False
            reason = "MFA verification required for admin actions"
        
        # Проверка политики: ограничение доступа по IP
        if policy["restrict_ip_access"] and request.ip_address:
            # Здесь должна быть логика проверки доверенного IP-адреса
            trusted_ips = ["10.0.0.1", "192.168.1.100"]  # Пример доверенных IP
            if request.ip_address not in trusted_ips:
                allowed = False
                reason = f"Access restricted to trusted IPs only. Your IP: {request.ip_address}"
        
        # Проверка политики: необходимость обоснования
        if policy["require_justification"] and not request.justification:
            allowed = False
            reason = "Justification required for this action"
        
        # Если политики позволяют, проверяем через сервис интеллекта угроз
        if allowed and policy["check_threat_intel"] and request.ip_address:
            async with httpx.AsyncClient() as client:
                try:
                    threat_response = await client.post(
                        f"{THREAT_INTELLIGENCE_URL}/check_ip",
                        json={"ip_address": request.ip_address}
                    )
                    
                    if threat_response.status_code == 200:
                        threat_data = threat_response.json()
                        if threat_data.get("is_threat", False):
                            allowed = False
                            reason = f"IP address {request.ip_address} identified as threat: {threat_data.get('threat_type', 'Unknown')}"
                
                except httpx.RequestError as e:
                    logger.error(f"Threat intelligence service request error: {e}")
                    # В зависимости от политики, можно разрешить или запретить доступ при ошибке сервиса
                    allowed = False
                    reason = "Could not verify threat intelligence, access denied for safety"
        
        # Логируем запрос в мониторинг
        monitoring_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": request.user_id,
            "resource": request.resource,
            "action": request.action,
            "status": "granted" if allowed else "denied",
            "reason": reason,
            "risk_score": risk_assessment.risk_score
        }
        
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{MONITORING_SERVICE_URL}/log_event",
                    json=monitoring_data
                )
        except Exception as e:
            logger.error(f"Failed to log event to monitoring service: {e}")
        
        return {
            "allowed": allowed,
            "reason": reason,
            "user_id": request.user_id,
            "resource": request.resource,
            "action": request.action,
            "risk_score": risk_assessment.risk_score,
            "factors": [factor.dict() for factor in risk_assessment.factors],
            "recommendation": risk_assessment.recommendation
        }
    
    except Exception as e:
        logger.error(f"Error checking access: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def assess_risk(request: AccessRequest) -> RiskAssessment:
    """Оценивает риски, связанные с запросом доступа"""
    factors = []
    total_risk = 0.0
    
    # Фактор 1: Роль пользователя
    role_risk_map = {
        "guest": 0.1,
        "user": 0.2,
        "moderator": 0.5,
        "admin": 0.8,
        "super_admin": 1.0
    }
    
    role_risk = role_risk_map.get(request.role, 0.3)
    factors.append(RiskFactor(
        factor="user_role",
        weight=role_risk,
        description=f"Risk based on user role: {request.role}"
    ))
    total_risk += role_risk * 0.3  # Вклад в общий риск
    
    # Фактор 2: Тип ресурса
    sensitive_resources = ["/api/admin", "/api/users", "/api/config", "/api/secrets"]
    resource_risk = 0.7 if any(sensitive in request.resource for sensitive in sensitive_resources) else 0.1
    
    factors.append(RiskFactor(
        factor="resource_sensitivity",
        weight=resource_risk,
        description=f"Risk based on resource sensitivity: {request.resource}"
    ))
    total_risk += resource_risk * 0.3
    
    # Фактор 3: Тип действия
    sensitive_actions = ["delete", "modify", "create", "admin"]
    action_risk = 0.8 if any(sensitive in request.action.lower() for sensitive in sensitive_actions) else 0.1
    
    factors.append(RiskFactor(
        factor="action_sensitivity",
        weight=action_risk,
        description=f"Risk based on action type: {request.action}"
    ))
    total_risk += action_risk * 0.2
    
    # Фактор 4: Время суток (подозрительное время)
    current_hour = datetime.utcnow().hour
    suspicious_hours = list(range(0, 6)) + [23]  # С 23:00 до 06:00
    time_risk = 0.6 if current_hour in suspicious_hours else 0.1
    
    factors.append(RiskFactor(
        factor="time_suspicion",
        weight=time_risk,
        description=f"Risk based on access time: {current_hour}:00 UTC"
    ))
    total_risk += time_risk * 0.2
    
    # Нормализуем общий риск в диапазоне 0-1
    normalized_risk = min(total_risk, 1.0)
    
    # Формируем рекомендацию на основе риска
    if normalized_risk > 0.8:
        recommendation = "High risk - deny access or require additional verification"
    elif normalized_risk > 0.5:
        recommendation = "Medium risk - allow access with monitoring"
    elif normalized_risk > 0.3:
        recommendation = "Low risk - allow access with standard checks"
    else:
        recommendation = "Minimal risk - allow access"
    
    return RiskAssessment(
        user_id=request.user_id,
        resource=request.resource,
        action=request.action,
        risk_score=round(normalized_risk, 3),
        factors=factors,
        recommendation=recommendation
    )

@app.post("/update_policy")
async def update_policy(policy_name: str, policy_config: dict):
    """Обновляет политику безопасности"""
    if policy_name not in security_policies:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    # Валидируем конфигурацию политики
    required_keys = ["allow_same_role_access", "require_mfa_for_admin_actions", "restrict_ip_access", "check_threat_intel"]
    for key in required_keys:
        if key not in policy_config:
            raise HTTPException(status_code=400, detail=f"Missing required policy key: {key}")
    
    security_policies[policy_name] = policy_config
    logger.info(f"Updated security policy: {policy_name}")
    
    return {"message": f"Policy {policy_name} updated successfully", "policy": policy_config}

@app.get("/policies")
async def get_policies():
    """Возвращает все политики безопасности"""
    return {"policies": security_policies}

@app.get("/health")
async def health_check():
    """Проверка работоспособности сервиса"""
    return {"status": "healthy", "service": "security-broker"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8902)