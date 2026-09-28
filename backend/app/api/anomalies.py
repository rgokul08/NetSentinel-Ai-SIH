"""
Anomaly Detection & Isolation Forest API Endpoints
"""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.session import get_db
from app.models.models import NetworkTraffic
from app.services.ml_service import ml_service

router = APIRouter(prefix="/api/anomalies", tags=["Anomalies"])

@router.get("")
def get_detected_anomalies(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Retrieves high-anomaly traffic flows with root-cause attribution"""
    anomalous_flows = (
        db.query(NetworkTraffic)
        .filter(NetworkTraffic.is_anomaly == True)
        .order_by(desc(NetworkTraffic.anomaly_score))
        .limit(limit)
        .all()
    )

    results = []
    for flow in anomalous_flows:
        flow_dict = {
            "source_port": flow.source_port,
            "destination_port": flow.destination_port,
            "packet_count": flow.packet_count,
            "packet_size": flow.packet_size,
            "flow_duration": flow.flow_duration,
            "bytes_per_second": flow.bytes_per_second,
            "packets_per_second": flow.packets_per_second,
            "tcp_flags": flow.tcp_flags,
            "protocol": flow.protocol
        }
        analysis = ml_service.anomaly_detector.analyze_flow(flow_dict, flow.anomaly_score)
        
        results.append({
            "id": flow.id,
            "timestamp": flow.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "protocol": flow.protocol,
            "destination_port": flow.destination_port,
            "anomaly_score": round(flow.anomaly_score, 4),
            "attack_type": flow.attack_type,
            "risk_level": flow.risk_level,
            "reason": analysis["primary_reason"],
            "all_reasons": analysis["all_reasons"],
            "packets_per_second": flow.packets_per_second,
            "bytes_per_second": flow.bytes_per_second
        })

    # Summary statistics
    total_scanned = db.query(NetworkTraffic).count()
    anomaly_count = len(results)
    
    return {
        "total_anomalies_detected": anomaly_count,
        "anomaly_rate_percentage": round((anomaly_count / max(total_scanned, 1)) * 100, 2),
        "detector_algorithm": "Isolation Forest (100 Estimators, Contamination=0.12)",
        "anomalies": results
    }
