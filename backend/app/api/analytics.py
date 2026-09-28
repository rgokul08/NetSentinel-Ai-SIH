"""
Network Traffic Analytics & SOC Visualizations API Endpoints
"""

from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.database.session import get_db
from app.models.models import NetworkTraffic

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])

@router.get("/summary")
def get_analytics_summary(db: Session = Depends(get_db)):
    # 1. Protocol Distribution
    proto_query = (
        db.query(NetworkTraffic.protocol, func.count(NetworkTraffic.id))
        .group_by(NetworkTraffic.protocol)
        .all()
    )
    protocols = [{"name": p[0], "count": p[1]} for p in proto_query]

    # 2. Attack Category Breakdown
    attack_query = (
        db.query(NetworkTraffic.attack_type, func.count(NetworkTraffic.id))
        .group_by(NetworkTraffic.attack_type)
        .all()
    )
    attacks = [{"name": a[0], "count": a[1]} for a in attack_query]

    # 3. Top Source IPs (Top Talkers / Attackers)
    top_sources_q = (
        db.query(NetworkTraffic.source_ip, func.count(NetworkTraffic.id), func.sum(NetworkTraffic.bytes_per_second))
        .group_by(NetworkTraffic.source_ip)
        .order_by(desc(func.count(NetworkTraffic.id)))
        .limit(8)
        .all()
    )
    top_sources = [
        {"ip": s[0], "packets": s[1], "bandwidth": round(float(s[2] or 0) / 1024, 1)}
        for s in top_sources_q
    ]

    # 4. Top Destination IPs (High Value Targets)
    top_dest_q = (
        db.query(NetworkTraffic.destination_ip, func.count(NetworkTraffic.id))
        .group_by(NetworkTraffic.destination_ip)
        .order_by(desc(func.count(NetworkTraffic.id)))
        .limit(8)
        .all()
    )
    top_destinations = [{"ip": d[0], "connections": d[1]} for d in top_dest_q]

    # 5. Bandwidth & Rate time-series (Simulated recent sample)
    recent = db.query(NetworkTraffic).order_by(desc(NetworkTraffic.timestamp)).limit(20).all()
    time_series = []
    for f in reversed(recent):
        time_series.append({
            "time": f.timestamp.strftime("%H:%M:%S"),
            "pps": round(f.packets_per_second, 1),
            "bps": round(f.bytes_per_second / 1024, 1),
            "attack": f.attack_type != "Normal"
        })

    return {
        "protocols": protocols,
        "attack_distribution": attacks,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
        "bandwidth_time_series": time_series
    }
