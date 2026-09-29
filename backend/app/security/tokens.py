"""JWT issuing and validation for the local authentication provider."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, Optional

from jose import JWTError, jwt

from app.core.config import settings
from app.core.utils import new_id, utcnow


def create_access_token(user: Dict[str, Any], expires_minutes: Optional[int] = None) -> Dict[str, Any]:
    now = utcnow()
    minutes = expires_minutes or settings.access_token_minutes
    expires = now + timedelta(minutes=minutes)
    payload = {
        "sub": user["id"],
        "email": user.get("email"),
        "name": user.get("name"),
        "role": user.get("role", "viewer"),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": new_id(length=16),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return {"access_token": token, "token_type": "bearer", "expires_at": expires.isoformat().replace("+00:00", "Z")}


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None
    if payload.get("type") != "access" or not payload.get("sub"):
        return None
    return payload
