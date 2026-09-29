"""Attack forecast endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.common import service_error
from app.core.utils import iso, safe_float, utcnow
from app.ml.forecast import SUPPORTED_HORIZONS
from app.schemas.schemas import ForecastRequest
from app.security.deps import client_ip, get_current_user, require_capability
from app.security.ratelimit import limiter
from app.services import audit_service, forecast_service
from app.storage import get_store
from app.storage.schema import ATTACK_CLASSES, RECOMMENDATIONS

router = APIRouter(prefix="/forecast", tags=["Forecast"])


@router.post("")
@limiter.limit("30/minute")
def run_forecast(payload: ForecastRequest, request: Request,
                 user: Dict[str, Any] = Depends(require_capability("forecast.run"))) -> Dict[str, Any]:
    try:
        result = forecast_service.run_forecast(
            horizons=payload.horizons, dataset_id=payload.dataset_id, window=payload.window,
            persist=payload.persist, create_alerts=payload.create_alerts, user=user,
        )
    except Exception as exc:
        raise service_error(exc, default_status=500)
    audit_service.log("forecast.run", category="prediction", user=user, resource="forecast",
                      resource_id=result.get("run_id"),
                      metadata={"horizons": payload.horizons or SUPPORTED_HORIZONS,
                                "records_used": result.get("records_used"),
                                "overall": (result.get("overall") or {}).get("risk_level")},
                      ip_address=client_ip(request))
    return result


@router.get("/latest")
def latest(user: Dict[str, Any] = Depends(require_capability("forecast.view"))) -> Dict[str, Any]:
    payload = forecast_service.latest_run()
    if not payload:
        return {"available": False, "message": "No forecast run stored yet. Trigger POST /api/forecast.",
                "generated_at": iso(utcnow())}
    payload["available"] = True
    return payload


@router.get("/trend")
def trend(limit: int = Query(40, ge=5, le=200), user: Dict[str, Any] = Depends(require_capability("forecast.view"))) -> Dict[str, Any]:
    return {"items": forecast_service.trend(limit=limit), "generated_at": iso(utcnow())}


@router.get("/options")
def options(user: Dict[str, Any] = Depends(require_capability("forecast.view"))) -> Dict[str, Any]:
    return {
        "horizons": SUPPORTED_HORIZONS,
        "categories": [c for c in ATTACK_CLASSES if c != "Benign"],
        "recommendations": RECOMMENDATIONS,
        "method": "Ridge regression on lagged per-category event counts + traffic features, Poisson link for probabilities",
        "fallback_method": "EWMA baseline rate when history is too short",
        "disclaimer": "Probabilistic model estimate, not a certainty.",
    }


@router.get("/history")
def history(limit: int = Query(20, ge=1, le=100), user: Dict[str, Any] = Depends(require_capability("forecast.view"))) -> Dict[str, Any]:
    rows, total = get_store().list("forecasts", order_by="-created_at", limit=limit * 40)
    runs: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        run_id = row.get("run_id")
        entry = runs.setdefault(run_id, {"run_id": run_id, "created_at": row.get("created_at"),
                                         "horizons": {}, "based_on_records": row.get("based_on_records")})
        horizon = int(row.get("horizon_minutes") or 0)
        bucket = entry["horizons"].setdefault(horizon, [])
        bucket.append({
            "attack_type": row.get("attack_type"), "probability": row.get("probability"),
            "risk_level": row.get("risk_level"), "confidence": row.get("confidence"),
            "expected_events": row.get("expected_events"),
        })
    ordered = sorted(runs.values(), key=lambda item: item.get("created_at") or "", reverse=True)[:limit]
    for item in ordered:
        # rebuild the mapping instead of mutating it while iterating
        normalized: Dict[str, Any] = {}
        for horizon in sorted(item["horizons"]):
            categories = sorted(item["horizons"][horizon], key=lambda c: safe_float(c.get("probability")), reverse=True)
            top = categories[0] if categories else {}
            normalized[str(horizon)] = {
                "categories": categories,
                "top_attack": top.get("attack_type"),
                "overall_probability": max((safe_float(c.get("probability")) for c in categories), default=0.0),
                "risk_level": top.get("risk_level"),
                "confidence": top.get("confidence"),
                "expected_events": round(sum(safe_float(c.get("expected_events")) for c in categories), 2),
            }
        item["horizons"] = normalized
        item["horizon_minutes"] = sorted((int(key) for key in normalized), reverse=True)[:1]
        item["horizon_minutes"] = item["horizon_minutes"][0] if item["horizon_minutes"] else None
    return {
        "items": ordered,
        "total": total,
        "runs_returned": len(ordered),
        "rows_scanned": len(rows),
        "generated_at": iso(utcnow()),
    }
