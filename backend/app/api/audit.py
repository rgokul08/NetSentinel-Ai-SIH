"""Security audit log endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from app.api.common import Paging, envelope, paging_params
from app.core.utils import window_start
from app.security.deps import get_current_user, require_capability
from app.services import audit_service

router = APIRouter(prefix="/audit-logs", tags=["Audit"])


@router.get("")
def list_audit_logs(paging: Paging = Depends(paging_params),
                    category: Optional[str] = Query(None),
                    action: Optional[str] = Query(None),
                    user_id: Optional[str] = Query(None),
                    outcome: Optional[str] = Query(None),
                    window: Optional[str] = Query("7d"),
                    search: Optional[str] = Query(None),
                    user: Dict[str, Any] = Depends(require_capability("audit.view"))) -> Dict[str, Any]:
    rows, total = audit_service.list_logs(
        limit=paging.limit, offset=paging.offset, category=category, action=action,
        user_id=user_id, outcome=outcome, search=search, since=window_start(window),
    )
    return envelope(rows, total, paging, stats=audit_service.stats())


@router.get("/categories")
def categories(user: Dict[str, Any] = Depends(require_capability("audit.view"))) -> Dict[str, Any]:
    return {"items": list(audit_service.CATEGORIES), "stats": audit_service.stats()}


@router.post("/verify")
def verify(limit: int = Query(300, ge=10, le=1000),
           user: Dict[str, Any] = Depends(require_capability("audit.view"))) -> Dict[str, Any]:
    return audit_service.verify_chain(limit=limit)


@router.get("/export")
def export(window: str = Query("7d"), category: Optional[str] = Query(None),
           limit: int = Query(5000, ge=10, le=20000),
           user: Dict[str, Any] = Depends(require_capability("audit.export"))) -> Response:
    rows, _ = audit_service.list_logs(limit=limit, category=category, since=window_start(window))
    return Response(content=audit_service.export_csv(rows), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="cyberforecast-audit-log.csv"'})
