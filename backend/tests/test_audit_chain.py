"""The audit trail: hash chaining, secret stripping and CSV export."""

from __future__ import annotations

from app.blockchain.hashing import GENESIS_HASH
from app.services import audit_service

USER = {"id": "u-admin", "email": "admin@cyberforecast.ai", "role": "admin"}


def _log(action: str, **kwargs) -> dict:
    return audit_service.log(action, user=USER, ip_address="203.0.113.9", **kwargs)


def test_entries_chain_to_their_predecessor(store):
    first = _log("auth.login", category="auth")
    second = _log("model.trained", category="model", resource="model", resource_id="m1")
    third = _log("alert.triaged", category="alert", resource="alert", resource_id="a1")

    assert first["prev_hash"] == GENESIS_HASH
    assert second["prev_hash"] == first["integrity_hash"]
    assert third["prev_hash"] == second["integrity_hash"]
    assert audit_service.verify_chain()["intact"] is True


def test_actor_context_is_captured(store):
    entry = _log("admin.settings_updated", category="admin", resource="settings",
                 metadata={"alert_throttle_minutes": {"from": 5, "to": 10}})
    assert entry["user_email"] == "admin@cyberforecast.ai"
    assert entry["user_role"] == "admin"
    assert entry["ip_address"] == "203.0.113.9"
    assert entry["outcome"] == "success"
    assert entry["metadata"]["alert_throttle_minutes"] == {"from": 5, "to": 10}


def test_credentials_are_stripped_from_the_audit_trail(store):
    entry = _log("auth.login_failed", category="auth",
                 metadata={"email": "admin@cyberforecast.ai", "password": "hunter2",
                           "access_token": "jwt-value", "raw_packet": "AAAA"})
    assert entry["metadata"] == {"email": "admin@cyberforecast.ai"}
    assert "hunter2" not in str(entry)
    assert audit_service.verify_chain()["intact"] is True


def test_silent_edits_are_detected(store):
    entry = _log("alert.resolved", category="alert", metadata={"status": "resolved"})
    store.update("audit_logs", entry["id"], {"metadata": {"status": "ignored"}})

    result = audit_service.verify_chain()
    assert result["intact"] is False
    assert result["broken_entries"][0]["log_id"] == entry["id"]
    assert result["broken_entries"][0]["hash_ok"] is False


def test_failure_outcomes_can_be_filtered(store):
    _log("auth.login", category="auth")
    _log("auth.login", category="auth", outcome="failure")
    rows, total = audit_service.list_logs(outcome="failure")
    assert total == 1 and rows[0]["outcome"] == "failure"

    rows, total = audit_service.list_logs(category="auth")
    assert total == 2
    assert all(row["category"] == "auth" for row in rows)


def test_export_csv_has_a_header_and_one_row_per_entry(store):
    _log("auth.login", category="auth")
    _log("report.generated", category="report", resource="report", resource_id="r1")
    rows, _ = audit_service.list_logs(limit=10)
    exported = audit_service.export_csv(rows)
    header, *body = exported.strip().splitlines()
    assert header.startswith("timestamp,")
    assert "integrity_hash" in header
    assert len(body) == 2


def test_stats_group_by_category(store):
    _log("auth.login", category="auth")
    _log("auth.logout", category="auth")
    _log("model.trained", category="model")
    stats = audit_service.stats()
    assert stats["total"] == 3
    assert stats["by_category"]["auth"] == 2
    assert stats["by_category"]["model"] == 1
