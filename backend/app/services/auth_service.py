"""
Authentication & user management.

Local mode (default): bcrypt password hashing + JWT access tokens stored against
the `users` collection.
Appwrite mode: users are mirrored into Appwrite Auth (bcrypt) so password
handling, sessions and recovery emails are delegated to Appwrite; the mirror
record keeps the role, which Appwrite does not model for us.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.core.utils import iso, new_id, utcnow
from app.security.hashing import (
    generate_reset_token,
    hash_password,
    hash_token,
    password_policy_violation,
    verify_password,
)
from app.security.rbac import capabilities_for_role, normalize_role
from app.security.totp import (
    generate_secret as generate_totp_secret,
    provisioning_uri as totp_provisioning_uri,
    qr_png_base64 as totp_qr_png,
    seconds_remaining as totp_seconds_remaining,
    verify_code as verify_totp,
)
from app.storage import get_appwrite_store, get_store

logger = logging.getLogger("cyberforecast.auth")

PUBLIC_USER_FIELDS = ("id", "name", "email", "role", "is_active", "avatar_color", "created_at", "last_login",
                      "mfa_enabled", "mfa_confirmed_at")

AVATAR_COLORS = ["#22d3ee", "#818cf8", "#34d399", "#f472b6", "#fbbf24", "#60a5fa"]


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 400, code: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


def public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    data = {key: user.get(key) for key in PUBLIC_USER_FIELDS}
    data["role"] = normalize_role(user.get("role"))
    data["capabilities"] = capabilities_for_role(data["role"])
    data["auth_provider"] = "appwrite" if user.get("appwrite_user_id") else "local"
    data["mfa_enabled"] = bool(user.get("mfa_enabled"))
    return data


def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    if not user_id:
        return None
    return get_store().get("users", user_id)


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    if not email:
        return None
    store = get_store()
    user = store.find_one("users", {"email": email.strip().lower()})
    if user:
        return user
    rows, _ = store.list("users", limit=1, search=email.strip().lower(), search_fields=["email"])
    return rows[0] if rows else None


def register(name: str, email: str, password: str, role: str = "viewer") -> Dict[str, Any]:
    email = (email or "").strip().lower()
    if not name or not name.strip():
        raise AuthError("Full name is required.")
    if "@" not in email:
        raise AuthError("A valid email address is required.")
    violation = password_policy_violation(password)
    if violation:
        raise AuthError(violation)
    if get_user_by_email(email):
        raise AuthError("An account with this email already exists.", status_code=409)

    role = normalize_role(role)
    if role == "admin":
        # Self-service sign-up never grants admin; an existing admin promotes users.
        role = "analyst"

    appwrite_user_id = None
    appwrite_store = get_appwrite_store()
    if appwrite_store:
        appwrite_user_id = appwrite_store.auth_create_user(email, password, name.strip())

    user = get_store().create("users", {
        "id": new_id(),
        "name": name.strip()[:120],
        "email": email,
        "role": role,
        "password_hash": "" if appwrite_user_id else hash_password(password),
        "appwrite_user_id": appwrite_user_id,
        "is_active": True,
        "avatar_color": AVATAR_COLORS[abs(hash(email)) % len(AVATAR_COLORS)],
        "created_at": utcnow(),
    })
    return public_user(user)


def authenticate(email: str, password: str, mfa_code: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Verify credentials and, when enrolled, the TOTP second factor."""
    user = get_user_by_email(email)
    if not user:
        return None
    if not user.get("is_active", True):
        raise AuthError("This account is disabled. Contact an administrator.", status_code=403)

    if user.get("appwrite_user_id") and not user.get("password_hash"):
        # Appwrite owns the password: verify by creating a session with the SDK.
        appwrite_store = get_appwrite_store()
        verified = False
        if appwrite_store:
            verified = bool(appwrite_store.auth_verify_password(email, password)) if hasattr(appwrite_store, "auth_verify_password") else False
        if not verified:
            return None
    else:
        if not verify_password(password, user.get("password_hash") or ""):
            return None

    if user.get("mfa_enabled") and user.get("mfa_secret"):
        if not mfa_code:
            raise AuthError("Multi-factor authentication is enabled. Enter the code from your authenticator app.",
                            status_code=401, code="mfa_required")
        if not verify_totp(user["mfa_secret"], mfa_code):
            raise AuthError("Invalid multi-factor code. Check your authenticator clock and try again.",
                            status_code=401, code="mfa_invalid")

    updated = get_store().update("users", user["id"], {"last_login": utcnow()}) or user
    return public_user(updated)


def mfa_status(user_id: str) -> Dict[str, Any]:
    user = get_user(user_id) or {}
    enrolled = bool(user.get("mfa_enabled") and user.get("mfa_secret"))
    return {
        "enabled": enrolled,
        "pending_enrolment": bool(user.get("mfa_secret")) and not enrolled,
        "confirmed_at": iso(user.get("mfa_confirmed_at")) if user.get("mfa_confirmed_at") else None,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    }


def mfa_enroll(user_id: str, issuer: Optional[str] = None) -> Dict[str, Any]:
    """Create (or rotate) a TOTP secret for the account and return provisioning data."""
    user = get_user(user_id)
    if not user:
        raise AuthError("User not found.", status_code=404)
    secret = generate_totp_secret()
    get_store().update("users", user_id, {"mfa_secret": secret, "mfa_enabled": False, "mfa_confirmed_at": None})
    account = user.get("email") or user_id
    label = issuer or settings.app_name
    uri = totp_provisioning_uri(secret, account, label)
    return {
        "secret": secret,
        "secret_formatted": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
        "otpauth_uri": uri,
        "qr_png_base64": totp_qr_png(uri),
        "account": account,
        "issuer": label,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
        "seconds_remaining": totp_seconds_remaining(),
        "status": "pending_confirmation",
        "instructions": "Add the account to any TOTP authenticator (Google Authenticator, Authy, 1Password, FreeOTP), "
                        "then confirm with the six digit code to activate MFA.",
    }


def mfa_confirm(user_id: str, code: str) -> Dict[str, Any]:
    user = get_user(user_id)
    if not user:
        raise AuthError("User not found.", status_code=404)
    secret = user.get("mfa_secret")
    if not secret:
        raise AuthError("No MFA enrolment in progress. Start enrolment first.", status_code=400, code="mfa_not_enrolled")
    if not verify_totp(secret, code):
        raise AuthError("That code did not match. Wait for the next code and try again.", status_code=400, code="mfa_invalid")
    now = utcnow()
    get_store().update("users", user_id, {"mfa_enabled": True, "mfa_confirmed_at": now})
    return {"enabled": True, "confirmed_at": iso(now), "message": "Multi-factor authentication is now active."}


def mfa_disable(user_id: str, code: str) -> Dict[str, Any]:
    user = get_user(user_id)
    if not user:
        raise AuthError("User not found.", status_code=404)
    if not user.get("mfa_enabled"):
        raise AuthError("Multi-factor authentication is not enabled for this account.", status_code=400)
    if not verify_totp(user.get("mfa_secret") or "", code):
        raise AuthError("Confirm with a valid authenticator code to disable MFA.", status_code=400, code="mfa_invalid")
    get_store().update("users", user_id, {"mfa_enabled": False, "mfa_secret": None, "mfa_confirmed_at": None})
    return {"enabled": False, "disabled_at": iso(utcnow()), "message": "Multi-factor authentication was disabled."}


def list_users(limit: int = 50, offset: int = 0, search: Optional[str] = None,
               role: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
    filters = {"role": normalize_role(role)} if role else None
    rows, total = get_store().list("users", filters=filters, order_by="-created_at", limit=limit,
                                   offset=offset, search=search, search_fields=["name", "email"])
    return [public_user(row) for row in rows], total


def update_user(user_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    allowed: Dict[str, Any] = {}
    if "name" in updates and updates["name"]:
        allowed["name"] = str(updates["name"])[:120]
    if "role" in updates and updates["role"]:
        allowed["role"] = normalize_role(updates["role"])
    if "is_active" in updates:
        allowed["is_active"] = bool(updates["is_active"])
    if "avatar_color" in updates and updates["avatar_color"]:
        allowed["avatar_color"] = str(updates["avatar_color"])[:16]
    if not allowed:
        return get_user(user_id)
    updated = get_store().update("users", user_id, allowed)
    return public_user(updated) if updated else None


def change_password(user_id: str, current_password: str, new_password: str) -> bool:
    user = get_user(user_id)
    if not user:
        raise AuthError("User not found.", status_code=404)
    if user.get("password_hash") and not verify_password(current_password, user["password_hash"]):
        raise AuthError("Current password is incorrect.", status_code=403)
    violation = password_policy_violation(new_password)
    if violation:
        raise AuthError(violation)
    hashed = hash_password(new_password)
    get_store().update("users", user_id, {"password_hash": hashed})
    if user.get("appwrite_user_id"):
        appwrite_store = get_appwrite_store()
        if appwrite_store:
            appwrite_store.auth_update_password(user["appwrite_user_id"], new_password)
    return True


def request_password_reset(email: str) -> Dict[str, Any]:
    """Create a single-use reset token. Returns it in demo mode (no mail service)."""
    user = get_user_by_email(email)
    response: Dict[str, Any] = {"requested": True, "expires_in_minutes": settings.reset_token_minutes}
    if not user:
        # Do not reveal whether the account exists.
        response["message"] = "If that email is registered, a reset link has been issued."
        return response

    token = generate_reset_token()
    get_store().create("password_resets", {
        "id": new_id(),
        "user_id": user["id"],
        "token_hash": hash_token(token),
        "expires_at": utcnow() + timedelta(minutes=settings.reset_token_minutes),
        "created_at": utcnow(),
    })
    response["message"] = "If that email is registered, a reset link has been issued."
    if settings.environment in ("development", "demo", "test") or settings.debug:
        response["dev_token"] = token
        response["dev_note"] = "No mail provider is configured; the token is returned directly in non-production environments."
    return response


def reset_password(token: str, new_password: str) -> bool:
    record = get_store().find_one("password_resets", {"token_hash": hash_token(token or "")}, order_by="-created_at")
    if not record:
        raise AuthError("This reset link is invalid.", status_code=400)
    if record.get("used_at"):
        raise AuthError("This reset link has already been used.", status_code=400)
    from app.core.utils import to_utc

    expires = to_utc(record.get("expires_at"))
    if expires and expires < utcnow():
        raise AuthError("This reset link has expired.", status_code=400)
    violation = password_policy_violation(new_password)
    if violation:
        raise AuthError(violation)

    user_id = record.get("user_id")
    hashed = hash_password(new_password)
    get_store().update("users", user_id, {"password_hash": hashed})
    get_store().update("password_resets", record["id"], {"used_at": utcnow()})
    user = get_user(user_id)
    if user and user.get("appwrite_user_id"):
        appwrite_store = get_appwrite_store()
        if appwrite_store:
            appwrite_store.auth_update_password(user["appwrite_user_id"], new_password)
    return True


def delete_user(user_id: str) -> bool:
    return get_store().delete("users", user_id)
