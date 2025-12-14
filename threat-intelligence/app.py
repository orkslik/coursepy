from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
import re
import ipaddress

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Threat Intelligence", description="Threat intelligence for microservices pattern")

# База данных угроз (в реальной системе это будет БД)
threat_database = {
    "ips": {
        "192.168.1.100": {
            "type": "malware_c2_server",
            "first_seen": "2023-01-15T10:30:00Z",
            "last_seen": "2023-11-20T14:22:00Z",
            "confidence": 0.95,
            "description": "Known malware command and control server"
        },
        "10.0.0.50": {
            "type": "botnet_node",
            "first_seen": "2023-03-22T09:15:00Z",
            "last_seen": "2023-11-18T16:45:00Z",
            "confidence": 0.88,
            "description": "Part of known botnet network"
        },
        "203.0.113.45": {
            "type": "scanning_host",
            "first_seen": "2023-05-10T12:00:00Z",
            "last_seen": "2023-11-22T08:30:00Z",
            "confidence": 0.75,
            "description": "Host performing automated scanning"
        }
    },
    "id_cards": {
        "ID001234567": {
            "type": "stolen_identity",
            "first_seen": "2023-02-10T11:20:00Z",
            "last_seen": "2023-11-15T13:45:00Z",
            "confidence": 0.92,
            "description": "Reported stolen identity document"
        },
        "ID987654321": {
            "type": "fraudulent_document",
            "first_seen": "2023-04-05T14:30:00Z",
            "last_seen": "2023-10-28T10:15:00Z",
            "confidence": 0.85,
            "description": "Document identified as fraudulent"
        }
    }
}

class IPCheckRequest(BaseModel):
    ip_address: str

class IDCheckRequest(BaseModel):
    id_card: str

class ThreatResponse(BaseModel):
    is_threat: bool
    threat_type: Optional[str] = None
    confidence: Optional[float] = None
    description: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

@app.get("/")
async def threat_intel_info():
    """Информация о сервисе интеллекта угроз"""
    return {"message": "Threat Intelligence Service for Microservices Security Pattern", "status": "running"}

@app.post("/check_ip")
async def check_ip(request: IPCheckRequest):
    """Проверяет IP-адрес на наличие в базе угроз"""
    ip = request.ip_address
    
    # Валидация IP-адреса
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    
    # Проверяем IP в базе угроз
    threat_info = threat_database["ips"].get(ip)
    
    if threat_info:
        logger.warning(f"Threat detected for IP {ip}: {threat_info['type']}")
        return ThreatResponse(
            is_threat=True,
            threat_type=threat_info["type"],
            confidence=threat_info["confidence"],
            description=threat_info["description"],
            first_seen=threat_info["first_seen"],
            last_seen=threat_info["last_seen"]
        )
    else:
        return ThreatResponse(is_threat=False)

@app.post("/check_id")
async def check_id(request: IDCheckRequest):
    """Проверяет ID-карту на наличие в базе угроз"""
    id_card = request.id_card
    
    # Проверяем ID в базе угроз
    threat_info = threat_database["id_cards"].get(id_card)
    
    if threat_info:
        logger.warning(f"Threat detected for ID {id_card}: {threat_info['type']}")
        return ThreatResponse(
            is_threat=True,
            threat_type=threat_info["type"],
            confidence=threat_info["confidence"],
            description=threat_info["description"],
            first_seen=threat_info["first_seen"],
            last_seen=threat_info["last_seen"]
        )
    else:
        return ThreatResponse(is_threat=False)

@app.get("/threats/ip")
async def get_threat_ips():
    """Возвращает все известные угрозы IP-адресов"""
    return {"threat_ips": threat_database["ips"]}

@app.get("/threats/id")
async def get_threat_ids():
    """Возвращает все известные угрозы ID-карт"""
    return {"threat_ids": threat_database["id_cards"]}

@app.post("/add_threat_ip")
async def add_threat_ip(ip: str, threat_type: str, description: str, confidence: float = 0.5):
    """Добавляет новый IP-адрес в базу угроз"""
    # Валидация IP-адреса
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    
    # Валидация уровня достоверности
    if not 0 <= confidence <= 1:
        raise HTTPException(status_code=400, detail="Confidence must be between 0 and 1")
    
    threat_database["ips"][ip] = {
        "type": threat_type,
        "first_seen": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "confidence": confidence,
        "description": description
    }
    
    logger.info(f"Added new threat IP: {ip}")
    return {"message": f"IP {ip} added to threat database", "ip": ip}

@app.post("/add_threat_id")
async def add_threat_id(id_card: str, threat_type: str, description: str, confidence: float = 0.5):
    """Добавляет новую ID-карту в базу угроз"""
    # Валидация длины ID-карты (простая проверка)
    if len(id_card) < 5 or len(id_card) > 20:
        raise HTTPException(status_code=400, detail="Invalid ID card format")
    
    # Валидация уровня достоверности
    if not 0 <= confidence <= 1:
        raise HTTPException(status_code=400, detail="Confidence must be between 0 and 1")
    
    threat_database["id_cards"][id_card] = {
        "type": threat_type,
        "first_seen": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "confidence": confidence,
        "description": description
    }
    
    logger.info(f"Added new threat ID: {id_card}")
    return {"message": f"ID {id_card} added to threat database", "id_card": id_card}

@app.post("/update_threat_last_seen")
async def update_threat_last_seen(identifier: str, identifier_type: str):
    """Обновляет время последнего обнаружения угрозы"""
    if identifier_type == "ip":
        if identifier in threat_database["ips"]:
            threat_database["ips"][identifier]["last_seen"] = datetime.utcnow().isoformat()
            return {"message": f"Last seen updated for IP {identifier}"}
        else:
            raise HTTPException(status_code=404, detail=f"IP {identifier} not found in threat database")
    elif identifier_type == "id":
        if identifier in threat_database["id_cards"]:
            threat_database["id_cards"][identifier]["last_seen"] = datetime.utcnow().isoformat()
            return {"message": f"Last seen updated for ID {identifier}"}
        else:
            raise HTTPException(status_code=404, detail=f"ID {identifier} not found in threat database")
    else:
        raise HTTPException(status_code=400, detail="Invalid identifier type. Use 'ip' or 'id'")

@app.get("/analytics")
async def get_analytics():
    """Возвращает аналитику по угрозам"""
    total_ips = len(threat_database["ips"])
    total_ids = len(threat_database["id_cards"])
    
    # Подсчитываем типы угроз
    ip_threat_types = {}
    for ip, info in threat_database["ips"].items():
        threat_type = info["type"]
        ip_threat_types[threat_type] = ip_threat_types.get(threat_type, 0) + 1
    
    id_threat_types = {}
    for id_card, info in threat_database["id_cards"].items():
        threat_type = info["type"]
        id_threat_types[threat_type] = id_threat_types.get(threat_type, 0) + 1
    
    # Подсчитываем уровень достоверности
    avg_ip_confidence = sum(info["confidence"] for info in threat_database["ips"].values()) / max(1, total_ips)
    avg_id_confidence = sum(info["confidence"] for info in threat_database["id_cards"].values()) / max(1, total_ids)
    
    return {
        "summary": {
            "total_threat_ips": total_ips,
            "total_threat_ids": total_ids,
            "total_threats": total_ips + total_ids
        },
        "ip_threat_breakdown": ip_threat_types,
        "id_threat_breakdown": id_threat_types,
        "confidence_levels": {
            "avg_ip_confidence": round(avg_ip_confidence, 3),
            "avg_id_confidence": round(avg_id_confidence, 3)
        }
    }

@app.get("/health")
async def health_check():
    """Проверка работоспособности сервиса"""
    return {
        "status": "healthy", 
        "service": "threat-intelligence",
        "threat_db_stats": {
            "known_ips": len(threat_database["ips"]),
            "known_ids": len(threat_database["id_cards"])
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8903)from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Threat Intelligence")

threats = ["SC123456"]  # заблокированные smart-карты

class ThreatCheckRequest(BaseModel):
    smartcard_id: str

@app.post("/check_threat")
def check_threat(data: ThreatCheckRequest):
    if data.smartcard_id in threats:
        return {"threat_detected": True}
    return {"threat_detected": False}
