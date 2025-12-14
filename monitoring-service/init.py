"""
Monitoring Service module for microservices security pattern
"""from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging
import statistics

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Monitoring Service", description="Security monitoring for microservices pattern")

# In-memory storage for events and metrics (use a database in production)
security_events: List[Dict] = []
metrics_history: List[Dict] = []
alerts: List[Dict] = []

class SecurityEvent(BaseModel):
    timestamp: str
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    endpoint: str
    action: str
    status: str
    details: Optional[Dict] = None

class Alert(BaseModel):
    id: str
    timestamp: str
    severity: str
    description: str
    source: str
    resolved: bool = False

@app.get("/")
async def monitoring_info():
    """Информация о сервисе мониторинга"""
    return {"message": "Monitoring Service for Microservices Security Pattern", "status": "running"}

@app.post("/log_event")
async def log_event(event: SecurityEvent):
    """Логирует событие безопасности"""
    event_dict = event.dict()
    event_dict['timestamp'] = datetime.utcnow().isoformat()
    
    security_events.append(event_dict)
    
    # Проверяем, нужно ли создать тревогу
    await check_for_alerts(event_dict)
    
    logger.info(f"Logged security event: {event.action} at {event.endpoint}")
    return {"message": "Event logged successfully", "event_id": len(security_events)}

async def check_for_alerts(event: Dict):
    """Проверяет, нужно ли создать тревогу на основе события"""
    # Примеры правил для создания тревог
    if event.get('status') == 'failed' and 'authentication' in event.get('endpoint', ''):
        alert = {
            "id": f"alert_{len(alerts)+1}",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "high",
            "description": f"Failed authentication attempt from {event.get('source_ip', 'unknown')}",
            "source": "auth_service",
            "resolved": False
        }
        alerts.append(alert)
        logger.warning(f"Created high severity alert: {alert['description']}")
    
    # Проверяем количество неудачных попыток с одного IP за короткий период
    recent_failed_attempts = [
        e for e in security_events
        if e.get('source_ip') == event.get('source_ip') and
           e.get('status') == 'failed' and
           e.get('action') == 'login' and
           datetime.fromisoformat(e['timestamp']) > datetime.utcnow() - timedelta(minutes=5)
    ]
    
    if len(recent_failed_attempts) >= 5:
        alert = {
            "id": f"alert_{len(alerts)+1}",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "critical",
            "description": f"Multiple failed login attempts ({len(recent_failed_attempts)}) from {event.get('source_ip')}",
            "source": "auth_service",
            "resolved": False
        }
        alerts.append(alert)
        logger.critical(f"Created critical alert: {alert['description']}")

@app.get("/events")
async def get_events(limit: int = 100):
    """Возвращает последние события безопасности"""
    return {"events": security_events[-limit:]}

@app.get("/security_status")
async def get_security_status():
    """Возвращает общий статус безопасности системы"""
    total_events = len(security_events)
    failed_events = len([e for e in security_events if e.get('status') == 'failed'])
    recent_alerts = len([a for a in alerts if not a['resolved']])
    
    # Подсчитываем количество успешных и неудачных событий за последние 24 часа
    day_ago = datetime.utcnow() - timedelta(days=1)
    recent_events = [e for e in security_events if datetime.fromisoformat(e['timestamp']) > day_ago]
    
    success_count = len([e for e in recent_events if e.get('status') == 'success'])
    failed_count = len([e for e in recent_events if e.get('status') == 'failed'])
    
    # Вычисляем уровень безопасности
    if total_events > 0:
        failure_rate = failed_count / max(success_count + failed_count, 1)
        if failure_rate > 0.1:  # больше 10% неудачных событий
            security_level = "low"
        elif failure_rate > 0.05:  # больше 5% неудачных событий
            security_level = "medium"
        else:
            security_level = "high"
    else:
        security_level = "unknown"
    
    return {
        "total_events": total_events,
        "recent_events": len(recent_events),
        "failed_events": failed_events,
        "recent_alerts": recent_alerts,
        "success_count_24h": success_count,
        "failed_count_24h": failed_count,
        "failure_rate_24h": round(failure_rate, 3) if total_events > 0 else 0,
        "security_level": security_level,
        "last_updated": datetime.utcnow().isoformat()
    }

@app.get("/metrics")
async def get_metrics():
    """Возвращает метрики безопасности"""
    # Подсчитываем метрики за последние 24 часа
    day_ago = datetime.utcnow() - timedelta(days=1)
    recent_events = [e for e in security_events if datetime.fromisoformat(e['timestamp']) > day_ago]
    
    # Количество событий по типам
    event_types = {}
    for event in recent_events:
        endpoint = event.get('endpoint', 'unknown')
        event_types[endpoint] = event_types.get(endpoint, 0) + 1
    
    # Количество неудачных попыток по IP
    failed_by_ip = {}
    for event in recent_events:
        if event.get('status') == 'failed':
            ip = event.get('source_ip', 'unknown')
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1
    
    # Уровень активности по времени (часы суток)
    hourly_activity = [0] * 24
    for event in recent_events:
        hour = datetime.fromisoformat(event['timestamp']).hour
        hourly_activity[hour] += 1
    
    # Добавляем метрики в историю
    metrics_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_events": len(recent_events),
        "event_types": event_types,
        "failed_by_ip": failed_by_ip,
        "hourly_activity": hourly_activity,
        "alert_count": len([a for a in alerts if not a['resolved']])
    }
    metrics_history.append(metrics_entry)
    
    # Ограничиваем размер истории метрик
    if len(metrics_history) > 1000:
        metrics_history.pop(0)
    
    return {
        "current_metrics": metrics_entry,
        "trend_analysis": calculate_trends(recent_events)
    }

def calculate_trends(events):
    """Вычисляет тренды безопасности"""
    if not events:
        return {"message": "No recent events for trend analysis"}
    
    # Подсчитываем количество событий по дням
    daily_counts = {}
    for event in events:
        date = datetime.fromisoformat(event['timestamp']).date().isoformat()
        daily_counts[date] = daily_counts.get(date, 0) + 1
    
    # Преобразуем в список значений для анализа
    values = list(daily_counts.values())
    if len(values) < 2:
        return {"trend": "insufficient_data", "message": "Need at least 2 days of data for trend analysis"}
    
    # Простой анализ тренда
    avg_recent = sum(values[-3:]) / min(3, len(values)) if len(values) >= 3 else values[-1]
    avg_prev = sum(values[:-3]) / max(1, len(values) - 3) if len(values) > 3 else values[0]
    
    if avg_recent > avg_prev * 1.2:
        trend = "increasing"
    elif avg_recent < avg_prev * 0.8:
        trend = "decreasing"
    else:
        trend = "stable"
    
    return {
        "trend": trend,
        "average_recent": avg_recent,
        "average_previous": avg_prev,
        "daily_counts": daily_counts
    }

@app.get("/alerts")
async def get_alerts(resolved: bool = False):
    """Возвращает тревоги безопасности"""
    filtered_alerts = [a for a in alerts if a['resolved'] == resolved]
    return {"alerts": filtered_alerts}

@app.post("/resolve_alert/{alert_id}")
async def resolve_alert(alert_id: str):
    """Отмечает тревогу как решенную"""
    for alert in alerts:
        if alert['id'] == alert_id:
            alert['resolved'] = True
            logger.info(f"Alert {alert_id} marked as resolved")
            return {"message": f"Alert {alert_id} resolved"}
    
    raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

@app.get("/top_risk_ips")
async def get_top_risk_ips(limit: int = 10):
    """Возвращает топ IP-адресов по количеству неудачных попыток"""
    failed_events = [e for e in security_events if e.get('status') == 'failed']
    
    ip_counts = {}
    for event in failed_events:
        ip = event.get('source_ip', 'unknown')
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    return {
        "top_risk_ips": [{"ip": ip, "count": count} for ip, count in sorted_ips],
        "total_unique_ips": len(ip_counts)
    }

@app.get("/health")
async def health_check():
    """Проверка работоспособности сервиса"""
    return {"status": "healthy", "service": "monitoring-service", "events_logged": len(security_events)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8905)