"""Health, configuration and platform metadata endpoints."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends

from app.core.config import settings
from app.security.deps import get_current_user
from app.core.utils import iso, utcnow
from app.services import health_service
from app.services.seed_service import seed_status
from app.services.simulation_service import engine as simulation_engine, scenarios

router = APIRouter(tags=["System"])


@router.get("/health")
def health() -> Dict[str, Any]:
    """Liveness + one-line subsystem status (used by uptime checks)."""
    detailed = health_service.full_health(include_counts=False)
    return {
        "status": detailed["status"],
        "app": settings.app_name,
        "version": settings.version,
        "environment": settings.environment,
        "checked_at": iso(utcnow()),
        "components": {
            key: {"ok": value.get("ok", True), "status": value.get("status")}
            for key, value in detailed["components"].items()
        },
    }


@router.get("/health/detailed")
def health_detailed(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Full component diagnostics.

    Authentication is required: this payload includes record counts, dialect and
    model details that should not be published to anonymous callers. Plain
    ``/health`` stays public for uptime probes and orchestrator healthchecks.
    """
    payload = health_service.full_health()
    payload["seed"] = seed_status()
    return payload


@router.get("/config")
def config() -> Dict[str, Any]:
    """Non-secret runtime configuration consumed by the frontend."""
    return {
        **settings.public_config(),
        "seed_status": seed_status(),
        "simulation": simulation_engine.status(),
        "simulation_scenarios": scenarios(),
        "limits": {
            "rate_limit": settings.rate_limit,
            "auth_rate_limit": settings.auth_rate_limit,
            "max_upload_mb": settings.max_upload_mb,
        },
    }


@router.get("/")
def root() -> Dict[str, Any]:
    return {
        "status": "ONLINE",
        "system": settings.app_name,
        "subtitle": settings.app_subtitle,
        "version": settings.version,
        "theme": "Blockchain & Cybersecurity (Smart India Hackathon)",
        "docs": "/api/docs",
        "health": "/api/health",
    }
