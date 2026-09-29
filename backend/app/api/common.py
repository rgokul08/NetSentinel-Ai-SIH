"""Shared API helpers: error mapping, pagination, structured JSON errors."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import logging

from fastapi import HTTPException, Query

from app.core.utils import iso, paginate, utcnow

logger = logging.getLogger("cyberforecast.api")


def service_error(exc: Exception, default_status: int = 400) -> HTTPException:
    """Convert service-layer exceptions into structured HTTP errors.

    4xx errors carry their message (they are validation/state problems the user
    can act on). 5xx errors are logged server-side and returned with a generic,
    safe message so internals are never disclosed to clients.
    """
    status = getattr(exc, "status_code", default_status)
    message = getattr(exc, "message", None) or str(exc)
    if status >= 500:
        logger.error("service error (%s): %s", type(exc).__name__, message)
        return HTTPException(
            status_code=status,
            detail="The request could not be completed due to an internal error. The event has been logged.",
        )
    return HTTPException(status_code=status, detail=message)


class Paging:
    def __init__(self, limit: int = 25, offset: int = 0) -> None:
        self.limit = max(1, min(int(limit), 500))
        self.offset = max(0, int(offset))


def paging_params(
    limit: int = Query(25, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Rows to skip"),
) -> Paging:
    return Paging(limit=limit, offset=offset)


def envelope(items: Any, total: int, paging: Paging, **extra: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "items": items,
        "pagination": paginate(total, paging.limit, paging.offset),
        "generated_at": iso(utcnow()),
    }
    payload.update(extra)
    return payload


def window_param(default: str = "24h") -> str:
    return default
