"""Request rate limiting (slowapi). Limits are configurable via environment."""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings


def _key_func(request) -> str:
    """Use the authenticated user when available, otherwise the client IP."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    identity = getattr(request.state, "user_id", None)
    if identity:
        return f"user:{identity}"
    return get_remote_address(request) or "unknown"


limiter = Limiter(key_func=_key_func, default_limits=[settings.rate_limit], storage_uri="memory://")
