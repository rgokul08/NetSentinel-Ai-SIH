"""Admin console endpoints: users, system health, settings, seeding, demo reset."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.common import Paging, envelope, paging_params, service_error
from app.blockchain import ledger
from app.core.config import settings
from app.schemas.schemas import AdminUserUpdate, SeedRequest, SettingsUpdate
from app.security.deps import client_ip, get_current_user, require_capability, require_role
from app.security.ratelimit import limiter
from app.services import (
    alert_service,
    audit_service,
    auth_service,
    health_service,
    model_service,
    seed_service,
    settings_service,
)
from app.storage import get_store

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/users")
def list_users(paging: Paging = Depends(paging_params), search: Optional[str] = Query(None),
               role: Optional[str] = Query(None),
               user: Dict[str, Any] = Depends(require_capability("users.manage"))) -> Dict[str, Any]:
    rows, total = auth_service.list_users(limit=paging.limit, offset=paging.offset, search=search, role=role)
    return envelope(rows, total, paging, roles=__import__("app.storage.schema", fromlist=["ROLES"]).ROLES)


@router.post("/users", status_code=201)
def create_user(payload: RegisterAdminUser, request: Request,  # noqa: F821 - defined below
                user: Dict[str, Any] = Depends(require_capability("users.manage"))) -> Dict[str, Any]:
    try:
        created = auth_service.register(payload.name, payload.email, payload.password, payload.role)
        if payload.role == "admin":
            created = auth_service.update_user(created["id"], {"role": "admin"}) or created
    except Exception as exc:
        raise service_error(exc)
    audit_service.log("admin.user_created", category="admin", user=user, resource="user",
                      resource_id=created["id"], metadata={"email": created.get("email"), "role": created.get("role")},
                      ip_address=client_ip(request))
    return created


@router.patch("/users/{user_id}")
def update_user(user_id: str, payload: AdminUserUpdate, request: Request,
                actor: Dict[str, Any] = Depends(require_capability("users.manage"))) -> Dict[str, Any]:
    if user_id == actor["id"] and payload.is_active is False:
        raise HTTPException(status_code=409, detail="You cannot disable your own account.")
    if user_id == actor["id"] and payload.role and payload.role != actor.get("role"):
        raise HTTPException(status_code=409, detail="You cannot change your own role.")
    updated = auth_service.update_user(user_id, payload.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail="User not found.")
    audit_service.log("admin.user_updated", category="admin", user=actor, resource="user", resource_id=user_id,
                      metadata=payload.model_dump(exclude_none=True), ip_address=client_ip(request))
    return updated


@router.delete("/users/{user_id}")
def delete_user(user_id: str, request: Request,
                actor: Dict[str, Any] = Depends(require_capability("users.manage"))) -> Dict[str, Any]:
    if user_id == actor["id"]:
        raise HTTPException(status_code=409, detail="You cannot delete your own account.")
    if not auth_service.delete_user(user_id):
        raise HTTPException(status_code=404, detail="User not found.")
    audit_service.log("admin.user_deleted", category="admin", user=actor, resource="user", resource_id=user_id,
                      ip_address=client_ip(request))
    return {"ok": True, "deleted": user_id}


@router.get("/health")
def system_health(user: Dict[str, Any] = Depends(require_role("admin"))) -> Dict[str, Any]:
    return health_service.full_health()


@router.get("/stats")
def system_stats(user: Dict[str, Any] = Depends(require_role("admin"))) -> Dict[str, Any]:
    store = get_store()
    return {
        "counts": {
            "users": store.count("users"),
            "datasets": store.count("datasets"),
            "traffic_records": store.count("traffic_records"),
            "predictions": store.count("predictions"),
            "forecasts": store.count("forecasts"),
            "alerts": store.count("alerts"),
            "models": store.count("models"),
            "reports": store.count("reports"),
            "blockchain_events": store.count("blockchain_events"),
            "audit_logs": store.count("audit_logs"),
            "password_resets": store.count("password_resets"),
        },
        "alerts": alert_service.stats(),
        "blockchain": ledger.stats(),
        "audit": audit_service.stats(),
        "models": model_service.registry_status(),
        "seed": seed_service.seed_status(),
    }


@router.get("/settings")
def get_settings(user: Dict[str, Any] = Depends(require_role("admin"))) -> Dict[str, Any]:
    return {
        "runtime": settings_service.get_all(),
        "defaults": settings_service.DEFAULTS,
        "environment": settings.public_config(),
        "security": {
            "jwt_algorithm": settings.jwt_algorithm,
            "access_token_minutes": settings.access_token_minutes,
            "reset_token_minutes": settings.reset_token_minutes,
            "max_upload_mb": settings.max_upload_mb,
            "allowed_upload_extensions": settings.allowed_upload_extensions,
            "cors_origins": settings.cors_origins,
            "cors_allow_all": settings.cors_allow_all,
            "rate_limit": settings.rate_limit,
            "auth_rate_limit": settings.auth_rate_limit,
        },
    }


@router.patch("/settings")
def update_settings(payload: SettingsUpdate, request: Request,
                    user: Dict[str, Any] = Depends(require_role("admin"))) -> Dict[str, Any]:
    changed = settings_service.update(payload.model_dump(exclude_none=True))
    audit_service.log("admin.settings_updated", category="admin", user=user, resource="settings",
                      metadata={"changed": changed}, ip_address=client_ip(request))
    return {"changed": changed, "runtime": settings_service.get_all()}


@router.post("/seed")
@limiter.limit("6/minute")
def seed(payload: SeedRequest, request: Request,
         user: Dict[str, Any] = Depends(require_role("admin"))) -> Dict[str, Any]:
    if payload.traffic_records:
        settings_service.update({"seed_traffic_records": payload.traffic_records})
    result = seed_service.seed_all(force=payload.force)
    audit_service.log("admin.seed", category="admin", user=user, resource="platform",
                      metadata={"force": payload.force, "status": result.get("status")},
                      ip_address=client_ip(request))
    return result


@router.get("/seed/status")
def seed_status(user: Dict[str, Any] = Depends(require_role("admin"))) -> Dict[str, Any]:
    return seed_service.seed_status()


@router.post("/reset-demo")
@limiter.limit("2/minute")
def reset_demo(request: Request, user: Dict[str, Any] = Depends(require_role("admin"))) -> Dict[str, Any]:
    """Clear operational data and rebuild the demo dataset from scratch."""
    store = get_store()
    cleared = {}
    for collection in ("traffic_records", "predictions", "forecasts", "alerts"):
        rows, total = store.list(collection, limit=1000)
        removed = 0
        for row in rows:
            if store.delete(collection, row["id"]):
                removed += 1
        cleared[collection] = removed
    audit_service.log("admin.demo_reset", category="admin", user=user, resource="platform",
                      metadata={"cleared": cleared}, ip_address=client_ip(request))
    result = seed_service.seed_all(force=True)
    return {"cleared": cleared, "seed": result}


from app.schemas.schemas import RegisterRequest as RegisterAdminUser  # noqa: E402
