--- monitoring-service/app/main.py (原始)
from fastapi import FastAPI

app = FastAPI(title="Monitoring Service")


@app.get("/health")
def health():
    return {"status": "monitoring-service alive"}


@app.post("/event")
def collect_event(event: dict):
    return {"status": "event received"}

+++ monitoring-service/app/main.py (修改后)
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List
import logging
from datetime import datetime
import json

app = FastAPI(title="Monitoring Service")

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- МОДЕЛИ ДАННЫХ ---
class MonitoringEvent(BaseModel):
    """Модель события для мониторинга."""
    event_type: str
    service_name: str
    timestamp: str
    user_id: str
    card_id: str
    command: str
    security_decision: str
    risk_score: float
    metadata: Dict = {}

class SecurityMetrics(BaseModel):
    """Модель метрик безопасности."""
    total_requests: int
    blocked_requests: int
    high_risk_requests: int
    avg_response_time: float
    security_alerts: int

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
# В реальной системе это будет база данных или Prometheus
security_metrics = {
    "total_requests": 0,
    "blocked_requests": 0,
    "high_risk_requests": 0,
    "avg_response_time": 0.0,
    "security_alerts": 0
}

event_log = []

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def update_security_metrics(event: MonitoringEvent):
    """Обновление метрик безопасности на основе события."""
    global security_metrics

    security_metrics["total_requests"] += 1

    if event.security_decision == "DENY":
        security_metrics["blocked_requests"] += 1
    elif event.risk_score > 0.7:
        security_metrics["high_risk_requests"] += 1

def generate_security_alert(event: MonitoringEvent) -> bool:
    """Генерация тревоги безопасности при определенных условиях."""
    alert_conditions = [
        event.security_decision == "DENY",
        event.risk_score > 0.8,
        event.command in ["SIGN_DATA", "UPDATE_KEY"] and event.security_decision != "ALLOW",
    ]

    return any(alert_conditions)

# --- ENDPOINTS ---
@app.get("/health")
def health():
    return {"status": "monitoring-service alive"}

@app.post("/event")
def collect_event(event: MonitoringEvent):
    """Сбор событий для мониторинга."""
    global security_metrics, event_log

    logger.info(f"Получено событие: {event.event_type} от {event.service_name}")

    # Обновление метрик
    update_security_metrics(event)

    # Добавление в лог событий
    event_log.append(event.dict())

    # Проверка необходимости генерации тревоги
    if generate_security_alert(event):
        security_metrics["security_alerts"] += 1
        logger.warning(f"Сгенерирована тревога безопасности для события: {event.command} от {event.user_id}")

    return {"status": "event received", "event_id": len(event_log)}

@app.get("/metrics")
def get_security_metrics():
    """Получение текущих метрик безопасности."""
    return security_metrics

@app.get("/events")
def get_events():
    """Получение лога событий (последние 100 записей)."""
    return {"events": event_log[-100:]}

@app.get("/alerts")
def get_security_alerts():
    """Получение информации о тревогах безопасности."""
    alerts = [event for event in event_log if generate_security_alert(MonitoringEvent(**event))]
    return {
        "total_alerts": len(alerts),
        "recent_alerts": alerts[-10:]
    }

@app.post("/reset-metrics")
def reset_metrics():
    """Сброс метрик (для тестирования)."""
    global security_metrics, event_log
    security_metrics = {
        "total_requests": 0,
        "blocked_requests": 0,
        "high_risk_requests": 0,
        "avg_response_time": 0.0,
        "security_alerts": 0
    }
    event_log = []
    return {"status": "Метрики сброшены"}