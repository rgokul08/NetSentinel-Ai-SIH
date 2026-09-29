"""Authentication and profile endpoints."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.common import service_error
from app.core.config import settings
from app.core.utils import iso, utcnow
from app.schemas.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MFAVerifyRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UpdateProfileRequest,
    UserOut,
)
from app.security.deps import client_ip, get_current_user
from app.security.ratelimit import limiter
from app.security.rbac import ROLE_DESCRIPTIONS, ROLE_LABELS, capabilities_for_role
from app.security.tokens import create_access_token
from app.services import audit_service, auth_service
from app.storage.schema import ROLES

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.auth_rate_limit)
def register(payload: RegisterRequest, request: Request) -> TokenResponse:
    try:
        user = auth_service.register(payload.name, payload.email, payload.password, payload.role or "viewer")
    except Exception as exc:
        audit_service.log("auth.register_failed", category="auth", outcome="failure",
                          metadata={"email": payload.email, "reason": str(exc)[:200]},
                          ip_address=client_ip(request))
        raise service_error(exc)
    token = create_access_token(user)
    audit_service.log("auth.register", category="auth", user=user, resource="user", resource_id=user["id"],
                      metadata={"role": user["role"]}, ip_address=client_ip(request))
    return TokenResponse(**token, user=UserOut(**user))


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.auth_rate_limit)
def login(payload: LoginRequest, request: Request) -> TokenResponse:
    """Email/password login. Accounts with MFA enrolled receive a challenge instead of tokens."""
    try:
        user = auth_service.authenticate(payload.email, payload.password, mfa_code=payload.mfa_code)
    except Exception as exc:
        code = getattr(exc, "code", None)
        if code in {"mfa_required", "mfa_invalid"}:
            audit_service.log("auth.mfa_challenge", category="auth", outcome="failure",
                              metadata={"email": payload.email, "reason": code}, ip_address=client_ip(request))
            return TokenResponse(access_token=None, require_mfa=True, mfa_message=str(getattr(exc, "message", exc)))
        audit_service.log("auth.login_failed", category="auth", outcome="failure",
                          metadata={"email": payload.email, "reason": str(exc)[:200]},
                          ip_address=client_ip(request))
        raise service_error(exc, default_status=401)
    if not user:
        audit_service.log("auth.login_failed", category="auth", outcome="failure",
                          metadata={"email": payload.email, "reason": "invalid credentials"},
                          ip_address=client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    token = create_access_token(user)
    audit_service.log("auth.login", category="auth", user=user, resource="session",
                      metadata={"role": user["role"], "provider": user.get("auth_provider"),
                                "mfa_used": bool(user.get("mfa_enabled"))},
                      ip_address=client_ip(request))
    return TokenResponse(**token, user=UserOut(**user))


@router.get("/mfa/status")
def mfa_status(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Current multi-factor enrolment state for the signed-in user."""
    return auth_service.mfa_status(user["id"])


@router.post("/mfa/enable")
@limiter.limit("6/hour")
def mfa_enable(request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Create a TOTP secret and return provisioning data (QR code + manual key)."""
    result = auth_service.mfa_enroll(user["id"], issuer=settings.app_name)
    audit_service.log("auth.mfa_enrolled", category="auth", user=user, resource="user", resource_id=user["id"],
                      metadata={"algorithm": result["algorithm"], "digits": result["digits"]},
                      ip_address=client_ip(request))
    return result


@router.post("/mfa/confirm")
@limiter.limit("12/hour")
def mfa_confirm(payload: MFAVerifyRequest, request: Request,
                user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Verify a code from the authenticator app and activate multi-factor authentication."""
    try:
        result = auth_service.mfa_confirm(user["id"], payload.code)
    except Exception as exc:
        audit_service.log("auth.mfa_confirm_failed", category="auth", user=user, outcome="failure",
                          metadata={"reason": str(exc)[:200]}, ip_address=client_ip(request))
        raise service_error(exc)
    audit_service.log("auth.mfa_enabled", category="auth", user=user, resource="user", resource_id=user["id"],
                      ip_address=client_ip(request))
    return result


@router.post("/mfa/disable")
@limiter.limit("6/hour")
def mfa_disable(payload: MFAVerifyRequest, request: Request,
                user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Disable multi-factor authentication after verifying a current code."""
    try:
        result = auth_service.mfa_disable(user["id"], payload.code)
    except Exception as exc:
        audit_service.log("auth.mfa_disable_failed", category="auth", user=user, outcome="failure",
                          metadata={"reason": str(exc)[:200]}, ip_address=client_ip(request))
        raise service_error(exc)
    audit_service.log("auth.mfa_disabled", category="auth", user=user, resource="user", resource_id=user["id"],
                      ip_address=client_ip(request))
    return result


@router.post("/logout")
def logout(request: Request, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """JWTs are stateless: the client discards the token and the event is audited."""
    audit_service.log("auth.logout", category="auth", user=user, resource="session",
                      ip_address=client_ip(request))
    return {"ok": True, "message": "Session ended. Discard the access token on the client.", "logged_out_at": iso(utcnow())}


@router.get("/me", response_model=UserOut)
def me(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return auth_service.public_user(user)


@router.patch("/profile", response_model=UserOut)
def update_profile(payload: UpdateProfileRequest, request: Request,
                   user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    updates = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    updated = auth_service.update_user(user["id"], updates)
    audit_service.log("profile.updated", category="auth", user=user, resource="user", resource_id=user["id"],
                      metadata={"fields": list(updates.keys())}, ip_address=client_ip(request))
    return updated or auth_service.public_user(user)


@router.post("/change-password")
def change_password(payload: ChangePasswordRequest, request: Request,
                    user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    try:
        auth_service.change_password(user["id"], payload.current_password, payload.new_password)
    except Exception as exc:
        audit_service.log("auth.password_change_failed", category="auth", user=user, outcome="failure",
                          metadata={"reason": str(exc)[:200]}, ip_address=client_ip(request))
        raise service_error(exc, default_status=400)
    audit_service.log("auth.password_changed", category="auth", user=user, resource="user",
                      resource_id=user["id"], ip_address=client_ip(request))
    return {"ok": True, "message": "Password updated."}


@router.post("/forgot-password")
@limiter.limit("10/minute")
def forgot_password(payload: ForgotPasswordRequest, request: Request) -> Dict[str, Any]:
    result = auth_service.request_password_reset(payload.email)
    audit_service.log("auth.password_reset_requested", category="auth", resource="user",
                      metadata={"email": payload.email, "issued": bool(result.get("dev_token"))},
                      ip_address=client_ip(request))
    return result


@router.post("/reset-password")
@limiter.limit("10/minute")
def reset_password(payload: ResetPasswordRequest, request: Request) -> Dict[str, Any]:
    try:
        auth_service.reset_password(payload.token, payload.password)
    except Exception as exc:
        audit_service.log("auth.password_reset_failed", category="auth", outcome="failure",
                          metadata={"reason": str(exc)[:200]}, ip_address=client_ip(request))
        raise service_error(exc)
    audit_service.log("auth.password_reset", category="auth", resource="user", ip_address=client_ip(request))
    return {"ok": True, "message": "Password reset. You can sign in with the new password."}


@router.get("/roles")
def roles() -> Dict[str, Any]:
    return {
        "roles": [
            {"key": role, "label": ROLE_LABELS[role], "description": ROLE_DESCRIPTIONS[role],
             "capabilities": capabilities_for_role(role)}
            for role in ROLES
        ],
        "permission_matrix": __import__("app.security.rbac", fromlist=["PERMISSIONS"]).PERMISSIONS,
    }
