"""Dashboard + analytics aggregation endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query

from app.blockchain import ledger
from app.security.deps import require_capability
from app.services import (
    alert_service,
    analytics_service,
    forecast_service,
    health_service,
    model_service,
    traffic_service,
)
from app.services.simulation_service import engine as simulation_engine

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/overview")
def overview(window: str = Query("24h"), user: Dict[str, Any] = Depends(require_capability("analytics.view"))) -> Dict[str, Any]:
    return analytics_service.overview(window)


@router.get("/trends")
def trends(window: str = Query("24h"), bucket: Optional[str] = Query(None),
           user: Dict[str, Any] = Depends(require_capability("analytics.view"))) -> Dict[str, Any]:
    return analytics_service.trends(window, bucket=bucket)


@router.get("/top-entities")
def top_entities(window: str = Query("24h"), limit: int = Query(10, ge=3, le=50),
                 user: Dict[str, Any] = Depends(require_capability("analytics.view"))) -> Dict[str, Any]:
    return analytics_service.top_entities(window, limit=limit)


@router.get("/dashboard")
def dashboard(window: str = Query("24h"), user: Dict[str, Any] = Depends(require_capability("analytics.view"))) -> Dict[str, Any]:
    """Single call that feeds the whole SOC dashboard."""
    overview_payload = analytics_service.overview(window)
    try:
        forecast = forecast_service.latest_run()
    except Exception:
        forecast = None
    critical_alerts, _ = alert_service.list_alerts(limit=6, severity="critical", order_by="-timestamp")
    recent_alerts, _ = alert_service.list_alerts(limit=8, order_by="-timestamp")
    trends_payload = analytics_service.trends(window)

    return {
        "window": window,
        "overview": overview_payload,
        "kpis": overview_payload.get("kpis", {}),
        "threat_level": overview_payload.get("threat_level"),
        "traffic_summary": traffic_service.summary(window),
        "forecast": forecast,
        "trends": {
            "attacks_over_time": trends_payload.get("attacks_over_time", [])[-60:],
            "anomaly_trend": trends_payload.get("anomaly_trend", [])[-60:],
            "attack_by_category": trends_payload.get("attack_by_category", []),
            "severity_distribution": trends_payload.get("severity_distribution", []),
            "protocol_distribution": trends_payload.get("protocol_distribution", []),
            "forecast_trend": trends_payload.get("forecast_trend", [])[-40:],
            "correctness": trends_payload.get("correctness"),
        },
        "live_activity": traffic_service.recent_events(limit=12),
        "critical_alerts": critical_alerts,
        "latest_alerts": recent_alerts,
        "alert_stats": alert_service.stats(),
        "blockchain": ledger.stats(),
        "models": model_service.registry_status(),
        "simulation": simulation_engine.status(),
        "system_health": health_service.full_health(include_counts=False),
        "generated_at": overview_payload.get("generated_at"),
    }
