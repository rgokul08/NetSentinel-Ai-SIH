"""Threat alert endpoints: query, triage and export."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from app.api.common import Paging, envelope, paging_params, service_error
from app.core.utils import window_start
from app.schemas.schemas import AlertUpdate
from app.security.deps import client_ip, get_current_user, require_capability
from app.services import alert_service, audit_service
from app.storage import get_store
from app.storage.schema import ALERT_STATUSES, SEVERITIES

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("")
def list_alerts(paging: Paging = Depends(paging_params),
                severity: Optional[str] = Query(None),
                status_filter: Optional[str] = Query(None, alias="status"),
                attack_type: Optional[str] = Query(None),
                origin: Optional[str] = Query(None),
                window: Optional[str] = Query("7d"),
                search: Optional[str] = Query(None),
                order_by: str = Query("-timestamp", pattern="^(-?)(timestamp|severity|risk_score|attack_type|status)$"),
                user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    rows, total = alert_service.list_alerts(
        limit=paging.limit, offset=paging.offset, severity=severity, status=status_filter,
        attack_type=attack_type, origin=origin, search=search,
        since=window_start(window), order_by=order_by,
    )
    return envelope(rows, total, paging, filters={"severity": severity, "status": status_filter,
                                                  "attack_type": attack_type, "origin": origin, "window": window},
                    options={"severities": SEVERITIES, "statuses": ALERT_STATUSES})


@router.get("/stats")
def alert_stats(window: str = Query("24h"), user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return alert_service.stats(since=window_start(window))


@router.get("/export")
def export_alerts(window: str = Query("7d"), severity: Optional[str] = Query(None),
                  status_filter: Optional[str] = Query(None, alias="status"),
                  limit: int = Query(2000, ge=1, le=5000),
                  user: Dict[str, Any] = Depends(require_capability("alerts.view"))) -> Response:
    rows, _ = alert_service.list_alerts(limit=limit, severity=severity, status=status_filter,
                                        since=window_start(window), order_by="-timestamp")
    content = alert_service.export_csv(rows)
    return Response(content=content, media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="cyberforecast-alerts.csv"'})


@router.get("/{alert_id}")
def get_alert(alert_id: str, user: Dict[str, Any] = Depends(require_capability("alerts.view"))) -> Dict[str, Any]:
    alert = alert_service.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    if alert.get("prediction_id"):
        alert["prediction"] = get_store().get("predictions", alert["prediction_id"])
    if alert.get("traffic_record_id"):
        alert["traffic_record"] = get_store().get("traffic_records", alert["traffic_record_id"])
    if alert.get("blockchain_event_id"):
        from app.blockchain import ledger

        alert["blockchain_event"] = ledger.get_event(alert["blockchain_event_id"])
    return alert


@router.patch("/{alert_id}")
def update_alert(alert_id: str, payload: AlertUpdate, request: Request,
                 user: Dict[str, Any] = Depends(require_capability("alerts.triage"))) -> Dict[str, Any]:
    try:
        updated = alert_service.update_alert(alert_id, payload.model_dump(exclude_none=True), user=user)
    except Exception as exc:
        raise service_error(exc)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found.")
    audit_service.log(f"alert.{payload.status or 'updated'}", category="alert", user=user, resource="alert",
                      resource_id=alert_id, metadata={"status": payload.status,
                                                      "severity": updated.get("severity"),
                                                      "attack_type": updated.get("attack_type"),
                                                      "assigned_to": payload.assigned_to,
                                                      "note_recorded": bool(payload.notes)},
                      ip_address=client_ip(request))
    return updated
