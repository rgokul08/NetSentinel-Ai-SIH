"""Tamper-evidence of the local hash chain (EVM anchoring disabled in tests)."""

from __future__ import annotations

import pytest

from app.blockchain import ledger
from app.blockchain.hashing import GENESIS_HASH, compute_event_hash


def _record(event_type: str, payload: dict, **kwargs) -> dict:
    return ledger.record_event(event_type=event_type, payload=payload, do_anchor=False, **kwargs)


def test_first_entry_links_to_genesis(store):
    event = _record("alert_created", {"alert_id": "a1", "attack_type": "DDoS"})
    assert event["chain_position"] == 1
    assert event["prev_hash"] == GENESIS_HASH
    assert event["verification_status"] == "verified"
    assert event["anchor_mode"] == "local"


def test_chain_links_each_entry_to_its_predecessor(store):
    events = [_record("alert_created", {"alert_id": f"a{i}"}) for i in range(3)]
    assert [e["chain_position"] for e in events] == [1, 2, 3]
    assert events[1]["prev_hash"] == events[0]["event_hash"]
    assert events[2]["prev_hash"] == events[1]["event_hash"]
    assert ledger.verify_chain()["intact"] is True


def test_stored_hash_matches_an_independent_recomputation(store):
    event = _record("alert_created", {"alert_id": "a1", "risk_score": 0.7})
    recomputed = compute_event_hash(event["id"], event["event_type"], event["created_at"],
                                    event["payload"], event["prev_hash"])
    assert recomputed == event["event_hash"]


def test_verification_passes_for_an_untouched_entry(store):
    event = _record("alert_created", {"alert_id": "a1"})
    result = ledger.verify_event(event["id"])
    assert result["match"] is True
    assert result["status"] == "verified"
    assert all(check["passed"] for check in result["checks"])
    assert [check["name"] for check in result["checks"]] == ["Payload hash recomputation", "Hash-chain linkage"]


def test_tampering_with_a_stored_payload_is_detected(store):
    event = _record("alert_created", {"alert_id": "a1", "severity": "critical"})
    store.update("blockchain_events", event["id"], {"payload": {"alert_id": "a1", "severity": "informational"}})

    result = ledger.verify_event(event["id"])
    assert result["match"] is False
    assert result["status"] == "failed"
    assert result["checks"][0]["passed"] is False

    chain = ledger.verify_chain()
    assert chain["intact"] is False
    assert chain["broken_count"] == 1
    assert chain["hash_failures"] == 1


def test_breaking_the_chain_link_is_detected(store):
    events = [_record("alert_created", {"alert_id": f"a{i}"}) for i in range(2)]
    store.update("blockchain_events", events[1]["id"], {"prev_hash": "f" * 64})

    chain = ledger.verify_chain()
    assert chain["intact"] is False
    assert chain["link_failures"] == 1
    assert ledger.verify_event(events[1]["id"])["match"] is False


def test_tamper_demo_entries_are_flagged_and_fail_verification(store):
    event = ledger.record_event("alert_created", {"alert_id": "demo", "severity": "critical", "risk_score": 0.9},
                                do_anchor=False, is_tamper_demo=True)
    assert event["is_tamper_demo"] is True
    result = ledger.verify_event(event["id"])
    assert result["status"] == "failed"
    assert result["match"] is False


def test_a_forged_submitted_hash_never_changes_the_verdict(store):
    event = _record("alert_created", {"alert_id": "a1"})

    forged = ledger.verify_event(event["id"], submitted_hash="f" * 64)
    assert forged["match"] is True                      # server recomputation still wins
    assert forged["submitted_hash_match"] is False      # ... but the lie is reported
    assert any(check["name"] == "Submitted hash comparison" and not check["passed"] for check in forged["checks"])

    honest = ledger.verify_event(event["id"], submitted_hash=event["event_hash"])
    assert honest["submitted_hash_match"] is True
    assert all(check["passed"] for check in honest["checks"])


def test_verifying_an_unknown_event_is_reported_not_crashing(store):
    result = ledger.verify_event("does-not-exist")
    assert result == {"event_id": "does-not-exist", "exists": False, "match": False,
                      "status": "failed", "message": "No ledger entry with this event id."}


def test_credentials_in_a_payload_are_stripped_before_hashing(store):
    event = _record("manual_event", {"note": "ok", "password": "hunter2", "access_token": "jwt"})
    stored = event["payload"]
    assert "password" not in stored and "access_token" not in stored
    assert compute_event_hash(event["id"], event["event_type"], event["created_at"],
                              {"note": "ok"}, event["prev_hash"]) == event["event_hash"]


def test_stats_reflect_the_chain(store):
    _record("alert_created", {"alert_id": "a1"})
    _record("alert_created", {"alert_id": "a2"})
    demo = ledger.record_event("alert_created", {"alert_id": "a3"}, do_anchor=False, is_tamper_demo=True)

    stats = ledger.stats()
    assert stats["total_events"] == 3
    assert stats["verified"] == 2
    assert stats["pending"] == 1                      # the demo has not been verified yet
    assert stats["verified_percentage"] == pytest.approx(66.7, abs=0.5)
    assert stats["tamper_demo_events"] == 1
    assert stats["anchor_mode"] == "local-hash-chain"  # EVM anchoring is off in tests

    # Running verification flips the deliberately broken entry to "failed".
    ledger.verify_event(demo["id"])
    assert ledger.stats()["failed"] == 1
