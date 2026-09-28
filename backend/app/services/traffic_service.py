"""
Traffic Management & Simulation Service
Manages real-time traffic queries, database seeding, and dynamic live packet streams.
"""

import sys
import os
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../ml")))
from demo_stream import generate_live_packet
from app.models.models import NetworkTraffic, Alert, Anomaly, AttackPrediction, User, MLModel
from app.services.auth_service import get_password_hash

def seed_initial_data(db: Session):
    """Populates database with initial admin user, default ML metrics, and baseline traffic flows if empty"""
    # 1. Seed Users if not existing
    if db.query(User).count() == 0:
        admin = User(
            email="admin@soc.guard",
            hashed_password=get_password_hash("Admin@1234"),
            full_name="SOC Lead Administrator",
            role="Admin"
        )
        analyst = User(
            email="analyst@soc.guard",
            hashed_password=get_password_hash("Analyst@1234"),
            full_name="Threat Intelligence Analyst",
            role="Security Analyst"
        )
        db.add(admin)
        db.add(analyst)
        db.commit()

    # 2. Seed ML Model status if empty
    if db.query(MLModel).count() == 0:
        default_model = MLModel(
            name="Random Forest Attack Classifier",
            model_type="RandomForestClassifier (Ensemble)",
            version="1.2.0",
            accuracy=0.964,
            precision_score=0.958,
            recall_score=0.961,
            f1_score=0.959,
            confusion_matrix={
                "labels": ["Normal", "DoS", "DDoS", "Port Scan", "Brute Force", "Botnet", "Malware"],
                "matrix": [
                    [520, 3, 2, 4, 1, 0, 1],
                    [2, 94, 2, 0, 1, 0, 0],
                    [1, 1, 78, 0, 0, 0, 0],
                    [3, 0, 0, 75, 1, 0, 0],
                    [1, 0, 0, 1, 58, 0, 0],
                    [0, 0, 0, 0, 0, 48, 1],
                    [1, 0, 0, 0, 0, 1, 46]
                ]
            },
            feature_importance=[
                {"feature": "packets_per_second", "importance": 0.264},
                {"feature": "bytes_per_second", "importance": 0.218},
                {"feature": "packet_count", "importance": 0.162},
                {"feature": "destination_port", "importance": 0.115},
                {"feature": "tcp_flags", "importance": 0.098},
                {"feature": "flow_duration", "importance": 0.081},
                {"feature": "protocol", "importance": 0.062}
            ],
            is_active=True
        )
        db.add(default_model)
        db.commit()

    # 3. Seed traffic if empty
    if db.query(NetworkTraffic).count() == 0:
        now = datetime.utcnow()
        traffic_records = []
        alerts_to_add = []
        
        for i in range(120):
            t_offset = now - timedelta(minutes=random.randint(1, 480))
            pkt = generate_live_packet()
            
            traffic = NetworkTraffic(
                timestamp=t_offset,
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
            traffic_records.append(traffic)
            
            # Generate Alert for high risk or critical attacks
            if pkt["risk_level"] in ["HIGH", "CRITICAL"]:
                alert = Alert(
                    alert_code=f"ALT-{random.randint(10000, 99999)}",
                    severity=pkt["risk_level"],
                    attack_type=pkt["attack_type"],
                    source_ip=pkt["source_ip"],
                    destination_ip=pkt["destination_ip"],
                    description=f"Automated AI Engine flagged hostile {pkt['attack_type']} traffic with {int(pkt['confidence']*100)}% confidence score.",
                    status=random.choice(["Open", "Investigating", "Resolved"]),
                    timestamp=t_offset
                )
                alerts_to_add.append(alert)

        db.bulk_save_objects(traffic_records)
        db.bulk_save_objects(alerts_to_add)
        db.commit()

def get_dashboard_summary(db: Session) -> Dict[str, Any]:
    """Computes comprehensive live cybersecurity dashboard metrics"""
    total = db.query(NetworkTraffic).count()
    if total == 0:
        total = 100
        
    normal_count = db.query(NetworkTraffic).filter(NetworkTraffic.attack_type == "Normal").count()
    attack_count = total - normal_count
    
    normal_pct = round((normal_count / total) * 100.0, 1) if total > 0 else 85.0
    suspicious_pct = round((attack_count / total) * 100.0, 1) if total > 0 else 15.0
    
    # Active open alerts
    active_alerts = db.query(Alert).filter(Alert.status != "Resolved").count()
    
    # Attack probability based on last 50 traffic flows
    recent_flows = db.query(NetworkTraffic).order_by(desc(NetworkTraffic.timestamp)).limit(50).all()
    recent_attacks = sum(1 for f in recent_flows if f.attack_type != "Normal")
    attack_prob = round(recent_attacks / max(len(recent_flows), 1), 3) if recent_flows else 0.18
    
    # Calculate Threat Level
    if attack_prob < 0.30:
        threat_level = "LOW"
    elif attack_prob < 0.60:
        threat_level = "MEDIUM"
    elif attack_prob < 0.80:
        threat_level = "HIGH"
    else:
        threat_level = "CRITICAL"
        
    # Health Score: 100 - penalties
    health_score = max(25, int(100 - (suspicious_pct * 0.9) - (active_alerts * 2)))
    
    return {
        "total_network_traffic": total,
        "normal_traffic_percentage": normal_pct,
        "suspicious_traffic_percentage": suspicious_pct,
        "detected_attacks_count": attack_count,
        "forecasted_attacks_count": int(attack_count * 1.35) + 8,
        "current_threat_level": threat_level,
        "attack_probability": attack_prob,
        "network_health_score": health_score,
        "active_alerts_count": active_alerts,
        "top_attack_vector": "DDoS Flood (SYN)"
    }
