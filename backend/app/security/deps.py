"""
FastAPI dependencies for authentication and authorization.

Every protected route declares the capability it needs; the dependency resolves
the caller (local JWT or Appwrite session), loads the user record, checks that
the account is active and that its role grants the capability.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.security.rbac import capabilities_for_role, normalize_role, role_can
from app.security.tokens import decode_access_token
from app.services import auth_service
from app.storage import get_store

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")


def _extract_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[str]:
    if credentials and credentials.credentials:
        return credentials.credentials
    header = request.headers.get("Authorization") or request.headers.get("authorization")
    if header and header.lower().startswith("bearer "):
        return header.split(" ", 1)[1].strip()
    return request.query_params.get("token")  # used by WebSocket connections


def get_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> Optional[str]:
    return _extract_token(request, credentials)


def get_optional_user(token: Optional[str] = Depends(get_token)) -> Optional[Dict[str, Any]]:
    """Resolve the caller when a token is present; never raises."""
    if not token:
        return None
    payload = decode_access_token(token)
    if payload:
        user = auth_service.get_user(payload["sub"])
        if user and user.get("is_active", True):
            return user
        return None
    # Not a local JWT: if Appwrite is enabled it may be an Appwrite session JWT.
    if settings.appwrite_enabled:
        store = get_store()
        verifier = getattr(store, "verify_session_jwt", None)
        if verifier:
            identity = verifier(token)
            if identity and identity.get("email"):
                return auth_service.get_user_by_email(identity["email"])
    return None


def default_user() -> Dict[str, Any]:
    """
    Synthetic full-access operator used when the platform runs without login.

    The whole SOC workspace is intentionally usable anonymously, so any request
    that carries no bearer token is treated as this operator. It holds the
    ``admin`` role (hence every capability) purely so the existing permission
    matrix keeps working unchanged; it is not a real account and never touches
    the user store.
    """
    return {
        "id": "operator",
        "email": "operator@cyberforecast.local",
        "name": "Operator",
        "role": "admin",
        "capabilities": capabilities_for_role("admin"),
        "is_active": True,
        "mfa_enabled": False,
    }


def get_current_user(
    token: Optional[str] = Depends(get_token),
    user: Optional[Dict[str, Any]] = Depends(get_optional_user),
) -> Dict[str, Any]:
    """
    Resolve the caller for a protected route.

    No-login mode: a request with **no** bearer token resolves to the synthetic
    full-access operator, so the entire platform is usable without signing in. A
    token that *is* supplied but cannot be resolved (expired, malformed,
    revoked) is still rejected with 401 - we open the door only to truly
    anonymous visitors, never to callers presenting bad credentials.
    """
    if token and not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user or default_user()


def require_role(*roles: str):
    """Dependency factory enforcing that the caller holds one of `roles`."""
    allowed = {normalize_role(r) for r in roles}

    def dependency(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        if normalize_role(user.get("role")) not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of the following roles: {', '.join(sorted(allowed))}.",
            )
        return user

    return dependency


def require_capability(capability: str):
    """Dependency factory enforcing a named capability from the permission matrix."""

    def dependency(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        if not role_can(normalize_role(user.get("role")), capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Your role ('{user.get('role')}') is not permitted to perform '{capability}'.",
            )
        return user

    return dependency


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"
