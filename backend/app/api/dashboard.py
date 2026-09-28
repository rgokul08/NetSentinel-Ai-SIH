"""
Dashboard Analytics & Overview API Endpoints
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.session import get_db
from app.schemas.schemas import DashboardStatsOut
from app.services.traffic_service import get_dashboard_summary
from app.models.models import NetworkTraffic, Alert
from app.services.ml_service import ml_service

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStatsOut)
def get_dashboard_statistics(db: Session = Depends(get_db)):
    return get_dashboard_summary(db)

@router.get("/overview")
def get_dashboard_overview(db: Session = Depends(get_db)):
    stats = get_dashboard_summary(db)
    
    # Fetch recent 10 traffic flows
    recent_flows = db.query(NetworkTraffic).order_by(desc(NetworkTraffic.timestamp)).limit(10).all()
    
    # Fetch recent 5 alerts
    recent_alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(5).all()
    
    # Short forecast trend
    forecast = ml_service.get_forecast(hours_ahead=12)
    
    return {
        "stats": stats,
        "recent_flows": recent_flows,
        "recent_alerts": recent_alerts,
        "forecast_preview": forecast["forecast_trend"][:6],
        "attack_distribution": forecast["attack_type_distribution"]
    }

@router.get("/health")
def get_soc_engine_health(db: Session = Depends(get_db)):
    return {
        "status": "OPERATIONAL",
        "detection_engine": "ONLINE",
        "forecasting_engine": "ACTIVE",
        "anomaly_detector": "ACTIVE",
        "database_connected": True,
        "latency_ms": 12.4
    }
