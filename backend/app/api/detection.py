"""
AI Attack Detection & Classification API Endpoints
"""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.session import get_db
from app.models.models import NetworkTraffic, AttackPrediction
from app.schemas.schemas import PacketPredictRequest, PredictionResponse, TrafficFlowOut
from app.services.ml_service import ml_service

router = APIRouter(prefix="/api/predict", tags=["Detection"])

@router.post("", response_model=PredictionResponse)
def predict_single_packet(
    req: PacketPredictRequest,
    db: Session = Depends(get_db)
):
    """Classifies network traffic parameters, computes anomaly score, and returns XAI feature attribution"""
    req_dict = req.model_dump()
    result = ml_service.predict_packet(req_dict)
    
    # Optionally persist prediction
    traffic = NetworkTraffic(
        source_ip=req.source_ip,
        destination_ip=req.destination_ip,
        source_port=req.source_port,
        destination_port=req.destination_port,
        protocol=req.protocol,
        packet_count=req.packet_count,
        packet_size=req.packet_size,
        flow_duration=req.flow_duration,
        bytes_per_second=req.bytes_per_second or (req.packet_count * req.packet_size / max(req.flow_duration, 0.1)),
        packets_per_second=req.packets_per_second or (req.packet_count / max(req.flow_duration, 0.1)),
        tcp_flags=req.tcp_flags,
        label=0 if result["attack_type"] == "Normal" else 1,
        attack_type=result["attack_type"],
        confidence=result["confidence"],
        risk_level=result["risk_level"],
        is_anomaly=result["is_anomaly"],
        anomaly_score=result["anomaly_score"],
        is_demo=False
    )
    db.add(traffic)
    db.commit()
    db.refresh(traffic)

    # Save prediction entity
    prediction = AttackPrediction(
        traffic_id=traffic.id,
        attack_type=result["attack_type"],
        confidence=result["confidence"],
        risk_level=result["risk_level"],
        contributing_features=result["explanation"]["contributions"]
    )
    db.add(prediction)
    db.commit()

    return result

@router.get("/recent-attacks", response_model=List[TrafficFlowOut])
def get_recent_detected_attacks(
    limit: int = 20,
    db: Session = Depends(get_db)
):
    """Fetches recently detected non-normal attack flows"""
    attacks = (
        db.query(NetworkTraffic)
        .filter(NetworkTraffic.attack_type != "Normal")
        .order_by(desc(NetworkTraffic.timestamp))
        .limit(limit)
        .all()
    )
    return attacks
