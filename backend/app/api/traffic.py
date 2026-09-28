"""
Real-Time & Historical Network Traffic API Endpoints
"""

import sys
import os
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.session import get_db
from app.models.models import NetworkTraffic, Alert
from app.schemas.schemas import TrafficFlowOut

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../ml")))
from demo_stream import generate_live_packet

router = APIRouter(prefix="/api/traffic", tags=["Traffic"])

@router.get("/live", response_model=List[TrafficFlowOut])
def get_live_traffic_feed(
    limit: int = Query(25, ge=5, le=100),
    db: Session = Depends(get_db)
):
    """Returns the most recent network traffic packets"""
    flows = db.query(NetworkTraffic).order_by(desc(NetworkTraffic.timestamp)).limit(limit).all()
    return flows

@router.get("/history", response_model=List[TrafficFlowOut])
def get_traffic_history(
    protocol: Optional[str] = None,
    attack_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = Query(100, ge=10, le=500),
    db: Session = Depends(get_db)
):
    """Filters network traffic history by protocol, attack type, or severity"""
    q = db.query(NetworkTraffic)
    if protocol and protocol != "ALL":
        q = q.filter(NetworkTraffic.protocol == protocol)
    if attack_type and attack_type != "ALL":
        q = q.filter(NetworkTraffic.attack_type == attack_type)
    if risk_level and risk_level != "ALL":
        q = q.filter(NetworkTraffic.risk_level == risk_level)
        
    return q.order_by(desc(NetworkTraffic.timestamp)).limit(limit).all()

@router.post("/simulate", response_model=TrafficFlowOut)
def inject_simulated_packet(
    forced_attack: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Injects a simulated live packet into the stream for SOC presentation"""
    pkt = generate_live_packet(forced_attack=forced_attack)
    
    traffic = NetworkTraffic(
        source_ip=pkt["source_ip"],
        destination_ip=pkt["destination_ip"],
        source_port=pkt["source_port"],
        destination_port=pkt["destination_port"],
        protocol=pkt["protocol"],
        packet_count=pkt["packet_count"],
        packet_size=pkt["packet_size"],
        flow_duration=pkt["flow_duration"],
        bytes_per_second=pkt["bytes_per_second"],
        packets_per_second=pkt["packets_per_second"],
        tcp_flags=pkt["tcp_flags"],
        label=pkt["label"],
        attack_type=pkt["attack_type"],
        confidence=pkt["confidence"],
        risk_level=pkt["risk_level"],
        is_anomaly=pkt["is_anomaly"],
        anomaly_score=pkt["anomaly_score"],
        is_demo=True
    )
    db.add(traffic)
    db.commit()
    db.refresh(traffic)

    # If severe attack, create real alert
    if pkt["risk_level"] in ["HIGH", "CRITICAL"]:
        alert = Alert(
            alert_code=f"ALT-{traffic.id:05d}",
            severity=pkt["risk_level"],
            attack_type=pkt["attack_type"],
            source_ip=pkt["source_ip"],
            destination_ip=pkt["destination_ip"],
            description=f"Automated AI Engine flagged hostile {pkt['attack_type']} traffic with {int(pkt['confidence']*100)}% confidence score.",
            status="Open"
        )
        db.add(alert)
        db.commit()

    return traffic
