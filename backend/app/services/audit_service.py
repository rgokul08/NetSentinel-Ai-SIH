"""
Security audit log with a hash chain.

Every security-relevant action (auth, uploads, training, predictions, alert
triage, blockchain operations, admin changes) is appended with an integrity hash
that covers the entry plus the previous hash, so silent edits are detectable.
"""

from __future__ import annotations

import csv
import io
import threading
from typing import Any, Dict, List, Optional, Tuple

from app.blockchain.hashing import GENESIS_HASH, compute_audit_hash, sanitize
from app.core.utils import iso, new_id, utcnow
from app.storage import get_store

_lock = threading.Lock()

CATEGORIES = ("auth", "dataset", "model", "prediction", "alert", "blockchain", "admin", "simulation", "report", "system")


def _previous_hash() -> str:
    rows, _ = get_store().list("audit_logs", order_by="-timestamp", limit=1)
    return (rows[0].get("integrity_hash") if rows else None) or GENESIS_HASH


def log(
    action: str,
    category: str = "system",
    user: Optional[Dict[str, Any]] = None,
    resource: Optional[str] = None,
    resource_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    outcome: str = "success",
    ip_address: str = "127.0.0.1",
) -> Dict[str, Any]:
    """Append an audit entry and return it (never raises into the caller path)."""
    entry = {
        "id": new_id(),
        "timestamp": utcnow(),
        "user_id": (user or {}).get("id"),
        "user_email": (user or {}).get("email") or "system",
        "user_role": (user or {}).get("role"),
        "action": action,
        "category": category,
        "resource": resource,
        "resource_id": resource_id,
        "outcome": outcome,
        # Sanitized before storage so the audit trail can never become a place
        # where credentials or raw packet data are persisted.
        "metadata": sanitize(metadata or {}),
        "ip_address": ip_address or "127.0.0.1",
    }
    try:
        with _lock:
            entry["prev_hash"] = _previous_hash()
            entry["integrity_hash"] = compute_audit_hash(entry, entry["prev_hash"])
            return get_store().create("audit_logs", entry)
    except Exception:  # pragma: no cover - audit must never break a request
        return entry


def list_logs(
    limit: int = 50,
    offset: int = 0,
    category: Optional[str] = None,
    action: Optional[str] = None,
    user_id: Optional[str] = None,
    outcome: Optional[str] = None,
    search: Optional[str] = None,
    since: Optional[Any] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    filters: Dict[str, Any] = {}
    if category:
        filters["category"] = category
    if action:
        filters["action"] = {"$like": f"%{action}%"}
    if user_id:
        filters["user_id"] = user_id
    if outcome:
        filters["outcome"] = outcome
    if since:
        filters["timestamp"] = {"$gte": since}
    return get_store().list(
        "audit_logs", filters=filters or None, order_by="-timestamp", limit=limit, offset=offset,
        search=search, search_fields=["action", "user_email", "resource", "category"],
    )


def verify_chain(limit: int = 300) -> Dict[str, Any]:
    """Recompute hashes over the most recent entries and report breaks."""
    store = get_store()
    rows, total = store.list("audit_logs", order_by="-timestamp", limit=min(limit, 1000))
    rows = list(reversed(rows))
    broken: List[Dict[str, Any]] = []
    previous = rows[0].get("prev_hash") if rows else GENESIS_HASH
    for row in rows:
        recomputed = compute_audit_hash(row, row.get("prev_hash") or GENESIS_HASH)
        hash_ok = recomputed.lower() == (row.get("integrity_hash") or "").lower()
        link_ok = (row.get("prev_hash") or GENESIS_HASH).lower() == (previous or GENESIS_HASH).lower()
        if not (hash_ok and link_ok):
            broken.append({"log_id": row.get("id"), "action": row.get("action"), "hash_ok": hash_ok, "link_ok": link_ok})
        previous = row.get("integrity_hash") or GENESIS_HASH
    return {"checked": len(rows), "total_entries": total, "intact": not broken, "broken_entries": broken[:20],
            "verified_at": iso(utcnow())}


def export_csv(rows: List[Dict[str, Any]]) -> str:
    buffer = io.StringIO()
    columns = ["timestamp", "user_email", "user_role", "category", "action", "resource", "resource_id",
               "outcome", "ip_address", "integrity_hash", "metadata"]
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        item = dict(row)
        item["metadata"] = str(row.get("metadata") or "")
        writer.writerow(item)
    return buffer.getvalue()


def stats() -> Dict[str, Any]:
    store = get_store()
    total = store.count("audit_logs")
    by_category = {}
    if hasattr(store, "group_count"):
        by_category = {r["key"]: r["count"] for r in store.group_count("audit_logs", "category", limit=20)}
    return {"total": total, "by_category": by_category}
