"""
Security-event integrity ledger.

Flow:  Network event -> AI analysis -> event hash -> ledger (local hash chain)
       -> optional EVM anchoring -> verification.

The local hash chain always works; the EVM anchor is additive. Raw traffic is
never stored on-chain - only hashes and non-sensitive metadata.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional, Tuple

from app.blockchain.evm import anchor
from app.blockchain.hashing import GENESIS_HASH, compute_event_hash, sanitize
from app.core.utils import iso, new_id, utcnow
from app.storage import get_store

logger = logging.getLogger("cyberforecast.blockchain")

_chain_lock = threading.Lock()


def _last_position() -> Tuple[int, str]:
    store = get_store()
    rows, _ = store.list("blockchain_events", order_by="-chain_position", limit=1)
    if not rows:
        return 0, GENESIS_HASH
    return int(rows[0].get("chain_position") or 0), rows[0].get("event_hash") or GENESIS_HASH


def record_event(
    event_type: str,
    payload: Dict[str, Any],
    related_id: Optional[str] = None,
    recorded_by: Optional[str] = None,
    do_anchor: bool = True,
    is_tamper_demo: bool = False,
    event_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Hash a security event, append it to the chain and optionally anchor it."""
    event_id = event_id or new_id()
    now = utcnow()

    with _chain_lock:
        position, prev_hash = _last_position()
        position += 1
        event_hash = compute_event_hash(event_id, event_type, now, payload, prev_hash)
        # Store exactly what was hashed: sanitized (secrets stripped, long text
        # bounded). This keeps verification reproducible and guarantees that
        # credentials can never linger in the ledger, on- or off-chain.
        stored_payload = sanitize(payload or {})

        record = {
            "id": event_id,
            "event_type": event_type,
            "event_hash": event_hash,
            "prev_hash": prev_hash,
            "chain_position": position,
            "payload": stored_payload,
            "related_id": related_id,
            "anchor_mode": "evm" if (do_anchor and anchor.configured and not is_tamper_demo) else "local",
            "verification_status": "verified",
            "recorded_by": recorded_by,
            "created_at": now,
            "is_tamper_demo": bool(is_tamper_demo),
        }

        # A deliberately broken tamper-demo entry must never be blessed on-chain:
        # the whole point of the demonstration is that its stored payload no
        # longer reproduces the recorded hash.
        if do_anchor and anchor.configured and not is_tamper_demo:
            result = anchor.record(event_id, event_hash, event_type)
            if result.get("anchored"):
                record.update({
                    "tx_hash": result.get("tx_hash"),
                    "block_number": result.get("block_number"),
                    "chain_id": result.get("chain_id"),
                    "contract_address": result.get("contract_address"),
                    "recorder_address": result.get("recorder_address"),
                    "verification_status": "verified",
                })
            else:
                # Local chain stays authoritative; on-chain anchoring is retried later.
                record["verification_status"] = "pending"
                record["anchor_mode"] = "local"
                logger.warning("Event %s could not be anchored: %s", event_id, result.get("reason"))

        created = get_store().create("blockchain_events", record)

    if is_tamper_demo:
        # Deliberately mutate the stored payload WITHOUT recomputing the hash so
        # the verification page can demonstrate tamper evidence. Clearly flagged.
        tampered = dict(stored_payload)
        tampered["tamper_note"] = "DEMO: payload altered after hashing to demonstrate tamper detection"
        if isinstance(tampered.get("risk_score"), (int, float)):
            tampered["risk_score"] = round(float(tampered["risk_score"]) * 0.5, 3)
        tampered["severity"] = "informational"
        # A tampered entry has NOT been verified, so it is stored as pending and
        # flips to "failed" the first time verification is run against it.
        created = get_store().update(
            "blockchain_events", event_id,
            {"payload": tampered, "verification_status": "pending", "verified_at": None},
        ) or created

    return created


def get_event(event_id: str) -> Optional[Dict[str, Any]]:
    return get_store().get("blockchain_events", event_id)


def list_events(
    limit: int = 20,
    offset: int = 0,
    event_type: Optional[str] = None,
    verification_status: Optional[str] = None,
    search: Optional[str] = None,
    order_by: str = "-created_at",
) -> Tuple[List[Dict[str, Any]], int]:
    filters: Dict[str, Any] = {}
    if event_type:
        filters["event_type"] = event_type
    if verification_status:
        filters["verification_status"] = verification_status
    return get_store().list(
        "blockchain_events", filters=filters or None, order_by=order_by,
        limit=limit, offset=offset, search=search, search_fields=["id", "event_type", "tx_hash", "related_id"],
    )


def verify_event(event_id: str, submitted_hash: Optional[str] = None) -> Dict[str, Any]:
    """Recompute the hash from the stored event and compare it with the record.

    `submitted_hash` is the value a client claims the event should have. It never
    influences the verdict (the server recomputes from stored data), but a
    mismatch is reported explicitly so a caller cannot silently submit a forged
    hash and receive a passing result.
    """
    event = get_event(event_id)
    if not event:
        return {"event_id": event_id, "exists": False, "match": False, "status": "failed",
                "message": "No ledger entry with this event id."}

    stored_hash = (event.get("event_hash") or "").lower()
    recomputed = compute_event_hash(
        event.get("id"),
        event.get("event_type"),
        event.get("created_at"),
        event.get("payload") or {},
        event.get("prev_hash") or GENESIS_HASH,
    ).lower()

    submitted = (submitted_hash or "").strip().lower() or None
    submitted_match = None if submitted is None else submitted == stored_hash

    checks: List[Dict[str, Any]] = [
        {
            "name": "Payload hash recomputation",
            "passed": recomputed == stored_hash,
            "detail": "Recomputed SHA-256 from the stored (sanitized) event payload.",
        }
    ]
    if submitted is not None:
        checks.append({
            "name": "Submitted hash comparison",
            "passed": bool(submitted_match),
            "detail": ("The hash submitted with this request matches the stored record."
                       if submitted_match else
                       "The hash submitted with this request does NOT match the stored record; "
                       "the server verdict below is based on its own recomputation."),
        })

    # Chain linkage check
    prev_hash = event.get("prev_hash") or GENESIS_HASH
    position = int(event.get("chain_position") or 0)
    chain_ok = True
    chain_detail = "Genesis link - nothing precedes this entry."
    if prev_hash != GENESIS_HASH:
        store = get_store()
        rows, _ = store.list("blockchain_events", filters={"chain_position": position - 1}, limit=1)
        if rows:
            chain_ok = (rows[0].get("event_hash") or "").lower() == prev_hash.lower()
            chain_detail = f"Entry #{position - 1} hash {'matches' if chain_ok else 'does NOT match'} the stored prev_hash."
        else:
            chain_ok = False
            chain_detail = f"Predecessor entry #{position - 1} is missing from the ledger."
    checks.append({
        "name": "Hash-chain linkage",
        "passed": chain_ok,
        "detail": chain_detail,
    })

    # Optional on-chain check
    onchain: Dict[str, Any] = {"available": False, "reason": "EVM anchoring is not configured"}
    if anchor.configured:
        onchain = anchor.read_record(event.get("id"))
        if onchain.get("available") and onchain.get("exists"):
            matches_chain = (onchain.get("event_hash") or "").lower() == stored_hash
            checks.append({
                "name": "On-chain record",
                "passed": matches_chain,
                "detail": f"Contract returned {onchain.get('event_hash')} "
                          f"(block {onchain.get('chain_id')} chain, recorder {onchain.get('recorder')}).",
            })
            onchain["matches"] = matches_chain
        elif onchain.get("available"):
            checks.append({
                "name": "On-chain record",
                "passed": False,
                "detail": "The event id is not present in the smart contract registry.",
            })
            onchain["matches"] = False
        else:
            checks.append({
                "name": "On-chain record",
                "passed": True,
                "detail": f"Skipped - RPC unavailable ({onchain.get('reason')}). Local chain remains authoritative.",
            })

    match = recomputed == stored_hash and chain_ok
    status = "verified" if match else "failed"

    if event.get("verification_status") != status:
        get_store().update("blockchain_events", event.get("id"), {
            "verification_status": status,
            "verified_at": utcnow() if match else None,
        })

    return {
        "event_id": event.get("id"),
        "exists": True,
        "match": match,
        "status": status,
        "message": (
            "Integrity verified - the recorded hash still matches the original event."
            if match else
            "Integrity check FAILED - the stored event no longer reproduces its recorded hash."
        ) + (
            "" if submitted_match is None or submitted_match else
            " Note: the hash submitted with this request did not match the stored record."
        ),
        "event_type": event.get("event_type"),
        "recorded_at": iso(event.get("created_at")),
        "original_hash": recomputed,
        "recorded_hash": stored_hash,
        "submitted_hash": submitted,
        "submitted_hash_match": submitted_match,
        "prev_hash": prev_hash,
        "chain_position": position,
        "anchor_mode": event.get("anchor_mode"),
        "tx_hash": event.get("tx_hash"),
        "block_number": event.get("block_number"),
        "contract_address": event.get("contract_address"),
        "chain_id": event.get("chain_id"),
        "recorder_address": event.get("recorder_address"),
        "is_tamper_demo": bool(event.get("is_tamper_demo")),
        "checks": checks,
        "onchain": onchain,
        "verified_at": iso(utcnow()) if match else None,
    }


def verify_chain(max_entries: int = 500) -> Dict[str, Any]:
    """Walk the whole chain and report the first broken link (if any)."""
    store = get_store()
    rows, total = store.list("blockchain_events", order_by="chain_position", limit=min(max_entries, total_hint(store)))
    previous = GENESIS_HASH
    broken: List[Dict[str, Any]] = []
    checked = 0
    for row in rows:
        recomputed = compute_event_hash(
            row.get("id"), row.get("event_type"), row.get("created_at"),
            row.get("payload") or {}, row.get("prev_hash") or GENESIS_HASH,
        ).lower()
        stored = (row.get("event_hash") or "").lower()
        link_ok = (row.get("prev_hash") or GENESIS_HASH).lower() == previous.lower()
        if recomputed != stored or not link_ok:
            broken.append({
                "event_id": row.get("id"),
                "chain_position": row.get("chain_position"),
                "event_type": row.get("event_type"),
                "is_tamper_demo": bool(row.get("is_tamper_demo")),
                "hash_ok": recomputed == stored,
                "link_ok": link_ok,
                "stored_hash": stored,
                "recomputed_hash": recomputed,
            })
            # persist the verdict so ledger statistics reflect reality
            if row.get("verification_status") != "failed":
                store.update("blockchain_events", row.get("id"),
                             {"verification_status": "failed", "verified_at": None})
        elif row.get("verification_status") == "pending" and not anchor.configured:
            # local hash chain verified this entry; nothing left to anchor
            store.update("blockchain_events", row.get("id"),
                         {"verification_status": "verified", "verified_at": utcnow()})
        previous = stored
        checked += 1
    return {
        "checked": checked,
        "total_entries": total,
        "intact": not broken,
        "broken_count": len(broken),
        "hash_failures": sum(1 for item in broken if not item["hash_ok"]),
        "link_failures": sum(1 for item in broken if not item["link_ok"]),
        "broken_entries": broken[:20],
        "verified_at": iso(utcnow()),
    }


def total_hint(store) -> int:
    try:
        return max(1, store.count("blockchain_events"))
    except Exception:
        return 500


def retry_pending(limit: int = 10) -> Dict[str, Any]:
    """Attempt to anchor events whose on-chain write previously failed."""
    if not anchor.configured:
        return {"attempted": 0, "anchored": 0, "message": "EVM anchoring is not configured."}
    store = get_store()
    rows, _ = store.list("blockchain_events", filters={"verification_status": "pending"},
                         order_by="chain_position", limit=limit * 2)
    rows = [row for row in rows if not row.get("is_tamper_demo")][:limit]
    anchored = 0
    for row in rows:
        result = anchor.record(row.get("id"), row.get("event_hash") or "", row.get("event_type") or "security_event")
        if result.get("anchored"):
            store.update("blockchain_events", row.get("id"), {
                "verification_status": "verified",
                "anchor_mode": "evm",
                "tx_hash": result.get("tx_hash"),
                "block_number": result.get("block_number"),
                "chain_id": result.get("chain_id"),
                "contract_address": result.get("contract_address"),
                "recorder_address": result.get("recorder_address"),
                "verified_at": utcnow(),
            })
            anchored += 1
    return {"attempted": len(rows), "anchored": anchored}


def stats() -> Dict[str, Any]:
    """Aggregated integrity statistics (never hard-coded)."""
    store = get_store()
    total = store.count("blockchain_events")
    by_status: Dict[str, int] = {}
    for status_name in ("verified", "pending", "failed"):
        by_status[status_name] = store.count("blockchain_events", {"verification_status": status_name})
    by_type = {}
    if hasattr(store, "group_count"):
        by_type = {r["key"]: r["count"] for r in store.group_count("blockchain_events", "event_type", limit=20)}
    verified_pct = round((by_status.get("verified", 0) / total) * 100, 1) if total else 0.0
    return {
        "total_events": total,
        "verified": by_status.get("verified", 0),
        "pending": by_status.get("pending", 0),
        "failed": by_status.get("failed", 0),
        "verified_percentage": verified_pct,
        "by_event_type": by_type,
        "anchor_mode": "evm" if anchor.configured else "local-hash-chain",
        "tamper_demo_events": store.count("blockchain_events", {"is_tamper_demo": True}),
    }
