"""Hashing and sanitization guarantees for the integrity ledger."""

from __future__ import annotations

import pytest

from app.blockchain.hashing import (
    GENESIS_HASH,
    bytes32_to_hash,
    compute_event_hash,
    event_hash_payload,
    event_id_to_bytes32,
    hash_to_bytes32,
    sanitize,
)

PAYLOAD = {"alert_id": "a1", "attack_type": "DDoS", "risk_score": 0.91, "severity": "critical"}


def test_hash_is_deterministic():
    first = compute_event_hash("evt-1", "alert_created", "2026-09-29T00:00:00Z", PAYLOAD)
    second = compute_event_hash("evt-1", "alert_created", "2026-09-29T00:00:00Z", PAYLOAD)
    assert first == second
    assert len(first) == 64
    assert all(c in "0123456789abcdef" for c in first)


def test_key_order_does_not_change_the_hash():
    """Canonical JSON means an identical structure always hashes identically."""
    reordered = {"severity": "critical", "risk_score": 0.91, "attack_type": "DDoS", "alert_id": "a1"}
    assert compute_event_hash("evt-1", "alert_created", "2026-09-29T00:00:00Z", reordered) == compute_event_hash(
        "evt-1", "alert_created", "2026-09-29T00:00:00Z", PAYLOAD
    )


@pytest.mark.parametrize(
    "changed",
    [
        {"event_id": "evt-2"},
        {"event_type": "alert_updated"},
        {"timestamp": "2026-09-29T00:00:01Z"},
        {"payload": {**PAYLOAD, "risk_score": 0.10}},
        {"prev_hash": "1" * 64},
    ],
)
def test_every_hashed_field_is_covered(changed):
    base = dict(event_id="evt-1", event_type="alert_created", timestamp="2026-09-29T00:00:00Z",
                payload=PAYLOAD, prev_hash=GENESIS_HASH)
    base.update(changed)
    assert compute_event_hash(**base) != compute_event_hash(
        "evt-1", "alert_created", "2026-09-29T00:00:00Z", PAYLOAD, GENESIS_HASH
    )


def test_hashed_structure_is_versioned():
    structure = event_hash_payload("evt-1", "alert_created", "2026-09-29T00:00:00Z", PAYLOAD)
    assert structure["hash_version"] == "v2"
    assert set(structure) == {"event_id", "event_type", "timestamp", "prev_hash", "payload", "hash_version"}


def test_secrets_are_never_hashed():
    """A payload that only differs by credential material must hash identically."""
    with_secret = {**PAYLOAD, "password": "hunter2", "access_token": "jwt", "private_key": "0xabc",
                   "raw_packet": "AAABBB", "authorization": "Bearer xyz"}
    assert sanitize(with_secret) == sanitize(PAYLOAD)
    assert compute_event_hash("evt-1", "alert_created", "2026-09-29T00:00:00Z", with_secret) == compute_event_hash(
        "evt-1", "alert_created", "2026-09-29T00:00:00Z", PAYLOAD
    )


def test_sanitize_truncates_and_bounds_nesting():
    assert len(sanitize("x" * 5000)) <= 2001
    assert len(sanitize(list(range(500)))) == 64
    deep = current = {}
    for _ in range(10):
        current["next"] = {}
        current = current["next"]
    assert "nested" in str(sanitize(deep))


@pytest.mark.parametrize("digest", [
    "0" * 64,                                   # all zeros
    "05ff2e648b854828cc5ef3624ec55a75fe274b7c8d45c249adc3e6edeafe9ca5",  # leading zero (regression)
    "0000abcd" + "f" * 56,                      # multiple leading zeros
    "0x" + "ab" * 32,                           # 0x prefixed
    "AB" * 32,                                  # upper case
])
def test_hash_to_bytes32_round_trips(digest):
    raw = hash_to_bytes32(digest)
    assert len(raw) == 32
    assert bytes32_to_hash(raw) == digest.lower().removeprefix("0x")


@pytest.mark.parametrize("digest", ["", "abc", "0x12", "z" * 64, None])
def test_hash_to_bytes32_rejects_malformed_input(digest):
    with pytest.raises(ValueError):
        hash_to_bytes32(digest)


def test_event_id_to_bytes32_is_stable_and_sized():
    first = event_id_to_bytes32("evt-1")
    assert first == event_id_to_bytes32("evt-1")
    assert len(first) == 32
    assert first != event_id_to_bytes32("evt-2")
