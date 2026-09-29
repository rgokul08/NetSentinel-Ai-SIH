"""Real health checks for every subsystem the platform depends on."""

from __future__ import annotations

import socket
import time
from typing import Any, Dict

from app.blockchain.evm import anchor
from app.core.config import settings
from app.core.utils import iso, utcnow
from app.ml import inference
from app.services import model_service
from app.services.simulation_service import engine as simulation_engine
from app.storage import get_appwrite_store, get_store


def _timed(label: str, fn) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        detail = fn() or {}
        detail.update({"component": label, "ok": True, "latency_ms": round((time.perf_counter() - started) * 1000, 1)})
        return detail
    except Exception as exc:
        return {"component": label, "ok": False, "error": str(exc)[:220],
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)}


def api_health() -> Dict[str, Any]:
    return {"status": "online", "version": settings.version, "environment": settings.environment}


def ml_health() -> Dict[str, Any]:
    def check():
        record, bundle = inference.active_bundle("classification")
        anomaly_record, anomaly_bundle = inference.active_bundle("anomaly")
        if bundle is None:
            return {
                "status": "degraded",
                "engine": "heuristic-fallback",
                "detail": "No trained classifier is active; predictions use the transparent heuristic baseline.",
            }
        return {
            "status": "online",
            "engine": "ml",
            "model_id": record.get("id"),
            "model_name": record.get("name"),
            "model_version": record.get("version"),
            "algorithm": record.get("algorithm"),
            "accuracy": record.get("accuracy"),
            "classes": len(record.get("classes") or []),
            "features": len(bundle.get("feature_names") or []),
            "anomaly_detector": bool(anomaly_bundle),
            "anomaly_model_id": (anomaly_record or {}).get("id"),
        }

    return _timed("ml_engine", check)


def database_health() -> Dict[str, Any]:
    def check():
        store = get_store()
        result = store.healthcheck()
        result["status"] = "online" if result.get("ok") else "offline"
        result["counts"] = {
            "users": store.count("users"),
            "traffic_records": store.count("traffic_records"),
            "predictions": store.count("predictions"),
            "alerts": store.count("alerts"),
            "forecasts": store.count("forecasts"),
            "datasets": store.count("datasets"),
            "models": store.count("models"),
            "blockchain_events": store.count("blockchain_events"),
            "audit_logs": store.count("audit_logs"),
        }
        return result

    return _timed("database", check)


def appwrite_health() -> Dict[str, Any]:
    def check():
        if not settings.appwrite_enabled:
            return {"status": "not_configured", "detail": "APPWRITE_* environment variables are not set; using the SQL store."}
        store = get_appwrite_store()
        if store is None:
            return {"status": "fallback", "detail": "Appwrite configured but unreachable - SQL fallback is active."}
        result = store.healthcheck()
        result["status"] = "online" if result.get("ok") else "offline"
        return result

    return _timed("appwrite", check)


def blockchain_health() -> Dict[str, Any]:
    def check():
        status = anchor.status()
        rpc_ok = None
        if settings.blockchain_rpc_url:
            rpc_ok = _rpc_reachable(settings.blockchain_rpc_url)
        status.update({
            "status": "online" if status.get("connected") else ("not_configured" if not status.get("configured") else "offline"),
            "rpc_reachable": rpc_ok,
        })
        return status

    return _timed("blockchain", check)


def _rpc_reachable(url: str) -> bool:
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 8545)
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def simulation_health() -> Dict[str, Any]:
    state = simulation_engine.status()
    return {"component": "simulation", "ok": True, "status": state["status"], "state": state}


def full_health(include_counts: bool = True) -> Dict[str, Any]:
    components = {
        "api": api_health(),
        "ml_engine": ml_health(),
        "database": database_health(),
        "appwrite": appwrite_health(),
        "blockchain": blockchain_health(),
        "simulation": simulation_health(),
    }
    overall = all(
        c.get("ok", True) and c.get("status") not in ("offline", "degraded")
        for key, c in components.items() if key != "appwrite"
    )
    degraded = any(c.get("status") == "degraded" for c in components.values())
    return {
        "status": "online" if overall and not degraded else ("degraded" if overall else "partial"),
        "checked_at": iso(utcnow()),
        "config": settings.public_config(),
        "components": components,
        "registry": model_service.registry_status() if include_counts else None,
    }
