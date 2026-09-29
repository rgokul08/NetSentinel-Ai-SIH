"""
Role definitions and the permission matrix.

Authorization is enforced server-side through FastAPI dependencies; the
frontend only mirrors these rules for navigation convenience.
"""

from __future__ import annotations

from typing import Dict, List, Set

from app.storage.schema import ROLES

ROLE_LABELS: Dict[str, str] = {
    "admin": "Administrator",
    "analyst": "Security Analyst",
    "viewer": "Viewer",
}

ROLE_DESCRIPTIONS: Dict[str, str] = {
    "admin": "Full control: users, models, datasets, alerts, blockchain records, system settings and audit logs.",
    "analyst": "Operational: upload datasets, train/evaluate models, run predictions and forecasts, triage alerts, verify blockchain records, generate reports.",
    "viewer": "Read-only: dashboards, analytics, alerts and reports.",
}

# capability -> roles allowed to perform it
PERMISSIONS: Dict[str, List[str]] = {
    # read-only capabilities (everyone authenticated)
    "dashboard.view": ROLES,
    "traffic.view": ROLES,
    "alerts.view": ROLES,
    "analytics.view": ROLES,
    "forecast.view": ROLES,
    "blockchain.view": ROLES,
    "reports.view": ROLES,
    "models.view": ROLES,
    "profile.manage": ROLES,
    # analyst + admin
    "datasets.upload": ["admin", "analyst"],
    "datasets.manage": ["admin", "analyst"],
    "traffic.ingest": ["admin", "analyst"],
    "predict.run": ["admin", "analyst"],
    "forecast.run": ["admin", "analyst"],
    "models.train": ["admin", "analyst"],
    "models.activate": ["admin"],
    "models.upload": ["admin"],
    "alerts.triage": ["admin", "analyst"],
    "reports.generate": ["admin", "analyst"],
    "blockchain.record": ["admin", "analyst"],
    "blockchain.verify": ROLES,
    "simulation.control": ["admin", "analyst"],
    # admin only
    "users.manage": ["admin"],
    "system.configure": ["admin"],
    "audit.view": ["admin"],
    "audit.export": ["admin"],
}

_PERMISSION_CACHE: Dict[str, Set[str]] = {k: set(v) for k, v in PERMISSIONS.items()}


def role_can(role: str, capability: str) -> bool:
    allowed = _PERMISSION_CACHE.get(capability)
    if allowed is None:  # unknown capability -> deny by default
        return False
    return (role or "viewer") in allowed


def capabilities_for_role(role: str) -> List[str]:
    return sorted(name for name, allowed in _PERMISSION_CACHE.items() if (role or "viewer") in allowed)


def normalize_role(role: str | None) -> str:
    text = (role or "").strip().lower()
    aliases = {
        "admin": "admin",
        "administrator": "admin",
        "security analyst": "analyst",
        "analyst": "analyst",
        "viewer": "viewer",
        "read-only": "viewer",
        "readonly": "viewer",
    }
    return aliases.get(text, "viewer")
