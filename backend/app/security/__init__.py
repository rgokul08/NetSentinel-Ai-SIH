"""Security primitives: password hashing, JWTs, RBAC and FastAPI dependencies."""

from app.security.deps import (
    client_ip,
    get_current_user,
    get_optional_user,
    require_capability,
    require_role,
)
from app.security.hashing import (
    generate_reset_token,
    hash_password,
    hash_token,
    password_policy_violation,
    verify_password,
)
from app.security.rbac import ROLE_DESCRIPTIONS, ROLE_LABELS, capabilities_for_role, normalize_role, role_can

__all__ = [
    "client_ip",
    "get_current_user",
    "get_optional_user",
    "require_capability",
    "require_role",
    "hash_password",
    "verify_password",
    "hash_token",
    "generate_reset_token",
    "password_policy_violation",
    "normalize_role",
    "role_can",
    "capabilities_for_role",
    "ROLE_LABELS",
    "ROLE_DESCRIPTIONS",
]
