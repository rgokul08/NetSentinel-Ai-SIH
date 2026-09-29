"""Password hashing and token hashing primitives (bcrypt + SHA-256)."""

from __future__ import annotations

import hashlib
import secrets

import bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def hash_token(token: str) -> str:
    """One-way hash used for password-reset tokens (never store the raw token)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)


def password_policy_violation(password: str) -> str | None:
    """Return a human-readable violation, or None when the password is acceptable."""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit."
    return None
