"""
Cryptographic hashing for security events.

Only non-sensitive, already-abstracted metadata is hashed: identifiers,
timestamps, verdicts and scores. Raw packet payloads, credentials and private
network details are never included (see BLOCKCHAIN_SETUP.md).
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from app.core.utils import canonical_json, iso, to_utc

GENESIS_HASH = "0" * 64

# Fields that must never reach a hash (defense in depth on top of sanitization).
FORBIDDEN_KEYS = {
    "password",
    "password_hash",
    "hashed_password",
    "secret",
    "api_key",
    "token",
    "access_token",
    "refresh_token",
    "private_key",
    "authorization",
    "payload_raw",
    "raw_packet",
    "pcap",
}


def sanitize(payload: Any, depth: int = 0) -> Any:
    """Recursively strip secrets and truncate long free-text values."""
    if depth > 6:
        return "…nested"
    if isinstance(payload, dict):
        clean: Dict[str, Any] = {}
        for key, value in payload.items():
            if str(key).lower() in FORBIDDEN_KEYS:
                continue
            clean[str(key)] = sanitize(value, depth + 1)
        return clean
    if isinstance(payload, (list, tuple)):
        return [sanitize(item, depth + 1) for item in list(payload)[:64]]
    if isinstance(payload, str):
        return payload if len(payload) <= 2000 else payload[:2000] + "…"
    if isinstance(payload, (int, float, bool)) or payload is None:
        return payload
    return str(payload)


def event_hash_payload(
    event_id: str,
    event_type: str,
    timestamp: Any,
    payload: Dict[str, Any],
    prev_hash: str = GENESIS_HASH,
) -> Dict[str, Any]:
    """Canonical structure that gets hashed. Any change to it changes the hash."""
    return {
        "event_id": str(event_id),
        "event_type": str(event_type),
        "timestamp": iso(timestamp),
        "prev_hash": prev_hash or GENESIS_HASH,
        "payload": sanitize(payload or {}),
        "hash_version": "v2",
    }


def compute_event_hash(
    event_id: str,
    event_type: str,
    timestamp: Any,
    payload: Dict[str, Any],
    prev_hash: str = GENESIS_HASH,
) -> str:
    structure = event_hash_payload(event_id, event_type, timestamp, payload, prev_hash)
    return hashlib.sha256(canonical_json(structure).encode("utf-8")).hexdigest()


def compute_audit_hash(entry: Dict[str, Any], prev_hash: str = GENESIS_HASH) -> str:
    """Hash-chained audit entry (independent of the blockchain ledger)."""
    structure = {
        "id": entry.get("id"),
        "timestamp": iso(entry.get("timestamp")),
        "user_id": entry.get("user_id"),
        "user_email": entry.get("user_email"),
        "action": entry.get("action"),
        "category": entry.get("category"),
        "resource": entry.get("resource"),
        "resource_id": entry.get("resource_id"),
        "outcome": entry.get("outcome"),
        "metadata": sanitize(entry.get("metadata") or {}),
        "prev_hash": prev_hash or GENESIS_HASH,
        "hash_version": "v2",
    }
    return hashlib.sha256(canonical_json(structure).encode("utf-8")).hexdigest()


def event_id_to_bytes32(event_id: str) -> bytes:
    """Map an arbitrary event id to the bytes32 key used by the smart contract."""
    return hashlib.sha256(str(event_id).encode("utf-8")).digest()


def hash_to_bytes32(event_hash: str) -> bytes:
    """Convert a 64-char hex digest to bytes32.

    ``str.lstrip("0x")`` must NOT be used here: it strips every leading ``0`` and
    ``x`` character, which corrupts (and shortens) digests that begin with zero.
    """
    cleaned = (event_hash or "").strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("event_hash must be a 64-character SHA-256 hex digest")
    return bytes.fromhex(cleaned)


def bytes32_to_hash(raw: bytes) -> str:
    return bytes(raw).hex()
