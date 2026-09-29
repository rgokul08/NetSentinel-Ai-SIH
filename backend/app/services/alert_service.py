"""
Threat alert engine.

Turns model verdicts and forecast results into triageable alerts, anchors each
one in the integrity ledger, and provides the query/triage/export operations the
Threat Alerts page needs.
"""

from __future__ import annotations

import csv
import io
import logging
import random
import threading
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.blockchain import ledger
from app.core.utils import iso, new_id, utcnow
from app.ml.features import BENIGN
from app.storage import get_store
from app.storage.schema import ALERT_STATUSES, RECOMMENDATIONS, SEVERITIES

logger = logging.getLogger("cyberforecast.alerts")

_throttle_lock = threading.Lock()
ALERT_SEVERITIES = ("medium", "high", "critical")


class AlertError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _alert_code() -> str:
    return f"CF-{utcnow().strftime('%y%m%d')}-{random.randint(1000, 9999)}"


def should_alert(severity: str, attack_type: str) -> bool:
    return severity in ALERT_SEVERITIES and attack_type != BENIGN


def throttle_minutes() -> int:
    from app.services import settings_service

    value = settings_service.get("alert_throttle_minutes", 5)
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 5


VOLUMETRIC_ATTACKS = {"DDoS", "DoS"}


def _recent_duplicate(attack_type: str, source_ip: Optional[str], origin: str,
                      destination_ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Deduplicate alerts inside the throttle window.

    Volumetric floods usually come from many (often spoofed) sources against one
    target, so they are grouped by target; targeted attacks are grouped by source.
    """
    minutes = throttle_minutes()
    if minutes <= 0:
        return None
    since = utcnow() - timedelta(minutes=minutes)
    filters: Dict[str, Any] = {"attack_type": attack_type, "origin": origin, "timestamp": {"$gte": since}}
    if attack_type in VOLUMETRIC_ATTACKS:
        if destination_ip:
            filters["destination_ip"] = destination_ip
    elif source_ip:
        filters["source_ip"] = source_ip
    return get_store().find_one("alerts", filters, order_by="-timestamp")


def raise_alert(
    attack_type: str,
    severity: str,
    risk_score: float,
    confidence: float,
    description: str,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: int = 0,
    destination_port: int = 0,
    origin: str = "detection",
    prediction_id: Optional[str] = None,
    traffic_record_id: Optional[str] = None,
    recommendation: Optional[str] = None,
    title: Optional[str] = None,
    is_simulated: bool = True,
    record_blockchain: bool = True,
    throttle: bool = True,
    user_email: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Create an alert. Returns (alert|None, suppressed)."""
    if throttle:
        with _throttle_lock:
            if _recent_duplicate(attack_type, source_ip, origin, destination_ip):
                return None, True

    severity = severity if severity in SEVERITIES else "medium"
    alert = get_store().create("alerts", {
        "id": new_id(),
        "alert_code": _alert_code(),
        "timestamp": utcnow(),
        "severity": severity,
        "attack_type": attack_type,
        "risk_score": round(float(risk_score), 4),
        "confidence": round(float(confidence), 4),
        "status": "open",
        "title": title or f"{attack_type} activity detected",
        "description": description,
        "recommendation": recommendation or RECOMMENDATIONS.get(attack_type, "Investigate the affected segment."),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": int(source_port or 0),
        "destination_port": int(destination_port or 0),
        "prediction_id": prediction_id,
        "traffic_record_id": traffic_record_id,
        "origin": origin,
        "blockchain_status": "pending",
        "is_simulated": bool(is_simulated),
    })

    if record_blockchain:
        try:
            event = ledger.record_event(
                event_type="alert",
                payload={
                    "alert_id": alert["id"],
                    "alert_code": alert["alert_code"],
                    "attack_type": attack_type,
                    "severity": severity,
                    "risk_score": alert["risk_score"],
                    "confidence": alert["confidence"],
                    "origin": origin,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "destination_port": alert["destination_port"],
                    "is_simulated": bool(is_simulated),
                },
                related_id=alert["id"],
                recorded_by=user_email or "detection-engine",
            )
            alert = get_store().update("alerts", alert["id"], {
                "blockchain_event_id": event["id"],
                "blockchain_status": event.get("verification_status", "pending"),
            }) or alert
        except Exception as exc:  # pragma: no cover - ledger must not break alerting
            logger.warning("Ledger write failed for alert %s: %s", alert["id"], exc)

    return alert, False


def list_alerts(
    limit: int = 25,
    offset: int = 0,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    attack_type: Optional[str] = None,
    origin: Optional[str] = None,
    search: Optional[str] = None,
    since: Optional[Any] = None,
    order_by: str = "-timestamp",
) -> Tuple[List[Dict[str, Any]], int]:
    filters: Dict[str, Any] = {}
    if severity:
        filters["severity"] = severity
    if status:
        filters["status"] = status
    if attack_type:
        filters["attack_type"] = attack_type
    if origin:
        filters["origin"] = origin
    if since:
        filters["timestamp"] = {"$gte": since}
    return get_store().list(
        "alerts", filters=filters or None, order_by=order_by, limit=limit, offset=offset,
        search=search, search_fields=["alert_code", "title", "description", "attack_type", "source_ip", "destination_ip"],
    )


def get_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    return get_store().get("alerts", alert_id)


def update_alert(alert_id: str, updates: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    alert = get_alert(alert_id)
    if not alert:
        return None
    patch: Dict[str, Any] = {}
    status = updates.get("status")
    if status:
        if status not in ALERT_STATUSES:
            raise AlertError(f"Invalid status '{status}'. Allowed: {', '.join(ALERT_STATUSES)}")
        patch["status"] = status
        if status == "reviewed":
            patch["reviewed_by"] = (user or {}).get("email")
            patch["reviewed_at"] = utcnow()
        if status == "resolved":
            patch["resolved_by"] = (user or {}).get("email")
            patch["resolved_at"] = utcnow()
    if "description" in updates and updates["description"]:
        patch["description"] = str(updates["description"])[:4000]
    if "recommendation" in updates and updates["recommendation"]:
        patch["recommendation"] = str(updates["recommendation"])[:4000]
    note = str(updates.get("notes") or "").strip()[:4000]
    if note:
        patch["notes"] = note
    assigned = str(updates.get("assigned_to") or "").strip()[:160]
    if assigned:
        patch["assigned_to"] = assigned

    actor = (user or {}).get("email") or "system"
    if status or note or assigned:
        history = list(alert.get("history") or [])
        history.append({
            "at": iso(utcnow()),
            "actor": actor,
            "action": status or "note",
            "from_status": alert.get("status"),
            "note": note or None,
            "assigned_to": assigned or None,
        })
        patch["history"] = history[-50:]

    if not patch:
        return alert
    updated = get_store().update("alerts", alert_id, patch)
    if updated and (status in ("resolved", "reviewed", "false_positive") or note):
        try:
            ledger.record_event(
                event_type="alert_update",
                payload={"alert_id": alert_id, "status": status or alert.get("status"), "actor": actor,
                         "previous_status": alert.get("status"), "note_present": bool(note),
                         "assigned_to": assigned or None},
                related_id=alert_id,
                recorded_by=actor,
            )
        except Exception:  # pragma: no cover
            pass
    return updated


def stats(since: Optional[Any] = None) -> Dict[str, Any]:
    store = get_store()
    filters: Dict[str, Any] = {"timestamp": {"$gte": since}} if since else {}
    total = store.count("alerts", filters or None)
    by_severity = {s: store.count("alerts", {**filters, "severity": s}) for s in SEVERITIES}
    by_status = {s: store.count("alerts", {**filters, "status": s}) for s in ALERT_STATUSES}
    by_type: Dict[str, int] = {}
    if hasattr(store, "group_count"):
        by_type = {r["key"]: r["count"] for r in store.group_count("alerts", "attack_type", filters=filters or None, limit=20)}
    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_attack_type": by_type,
        "critical_open": store.count("alerts", {**filters, "severity": "critical", "status": ["open", "reviewed"]}),
        "open": by_status.get("open", 0),
    }


def export_csv(rows: List[Dict[str, Any]]) -> str:
    buffer = io.StringIO()
    columns = ["alert_code", "timestamp", "severity", "attack_type", "risk_score", "confidence", "status",
               "title", "description", "recommendation", "source_ip", "destination_ip", "destination_port",
               "origin", "blockchain_event_id", "blockchain_status", "reviewed_by", "resolved_by", "is_simulated"]
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()
