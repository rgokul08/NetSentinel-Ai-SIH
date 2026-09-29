"""Role-based access control matrix (the rules the API enforces server-side)."""

from __future__ import annotations

import pytest

from app.security.rbac import PERMISSIONS, capabilities_for_role, normalize_role, role_can

ADMIN_ONLY = ["users.manage", "system.configure", "audit.view", "audit.export", "models.activate", "models.upload"]
ANALYST_OPERATIONS = ["predict.run", "forecast.run", "models.train", "alerts.triage", "reports.generate",
                      "blockchain.record", "simulation.control", "datasets.upload"]
READ_ONLY = ["dashboard.view", "traffic.view", "alerts.view", "analytics.view", "forecast.view",
             "blockchain.view", "reports.view", "models.view", "profile.manage"]


@pytest.mark.parametrize("capability", READ_ONLY)
def test_every_authenticated_role_can_read(capability):
    for role in ("admin", "analyst", "viewer"):
        assert role_can(role, capability), f"{role} should be able to {capability}"


@pytest.mark.parametrize("capability", ANALYST_OPERATIONS)
def test_analysts_can_operate(capability):
    assert role_can("analyst", capability)
    assert role_can("admin", capability)


@pytest.mark.parametrize("capability", ANALYST_OPERATIONS + ADMIN_ONLY)
def test_viewers_are_read_only(capability):
    assert not role_can("viewer", capability)


@pytest.mark.parametrize("capability", ADMIN_ONLY)
def test_admin_only_capabilities_exclude_analysts(capability):
    assert role_can("admin", capability)
    assert not role_can("analyst", capability)


def test_blockchain_verification_is_open_but_writing_is_not():
    """Anyone can *check* integrity; only operators can add entries."""
    assert role_can("viewer", "blockchain.verify")
    assert not role_can("viewer", "blockchain.record")


@pytest.mark.parametrize("capability", ["users.delete", "sudo", "", "blockchain.mint"])
def test_unknown_capabilities_are_denied(capability):
    for role in ("admin", "analyst", "viewer"):
        assert not role_can(role, capability)


def test_missing_role_denies_everything_except_anonymous_reads():
    assert not role_can("", "users.manage")
    assert role_can("", "dashboard.view")


@pytest.mark.parametrize("raw,expected", [
    ("admin", "admin"), ("Administrator", "admin"), (" ADMIN ", "admin"),
    ("analyst", "analyst"), ("Security Analyst", "analyst"),
    ("viewer", "viewer"), ("read-only", "viewer"), ("ReadOnly", "viewer"),
    ("superuser", "viewer"), ("", "viewer"), (None, "viewer"),
])
def test_normalize_role_downgrades_unknown_values(raw, expected):
    """Privilege escalation via a crafted role string must not be possible."""
    assert normalize_role(raw) == expected


def test_capabilities_for_role_is_monotonic():
    admin = set(capabilities_for_role("admin"))
    analyst = set(capabilities_for_role("analyst"))
    viewer = set(capabilities_for_role("viewer"))
    assert viewer < analyst < admin
    assert viewer == set(READ_ONLY) | {"blockchain.verify"}
    assert admin == set(PERMISSIONS)
