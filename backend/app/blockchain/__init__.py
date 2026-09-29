"""Blockchain / integrity layer: hashing, local hash chain and EVM anchoring."""

from app.blockchain.evm import anchor
from app.blockchain.hashing import GENESIS_HASH, compute_audit_hash, compute_event_hash
from app.blockchain.ledger import (
    get_event,
    list_events,
    record_event,
    retry_pending,
    stats,
    verify_chain,
    verify_event,
)

__all__ = [
    "anchor",
    "compute_event_hash",
    "compute_audit_hash",
    "GENESIS_HASH",
    "record_event",
    "get_event",
    "list_events",
    "verify_event",
    "verify_chain",
    "retry_pending",
    "stats",
]
