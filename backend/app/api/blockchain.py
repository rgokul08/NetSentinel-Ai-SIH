"""Blockchain / integrity ledger endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.common import Paging, envelope, paging_params, service_error
from app.blockchain import ledger
from app.blockchain.evm import anchor
from app.blockchain.hashing import GENESIS_HASH, compute_event_hash, event_hash_payload
from app.schemas.schemas import BlockchainRecordRequest, BlockchainVerifyRequest
from app.security.deps import client_ip, get_current_user, require_capability
from app.security.ratelimit import limiter
from app.services import audit_service

router = APIRouter(prefix="/blockchain", tags=["Blockchain"])

LEDGER_NOTE = (
    "The blockchain layer provides tamper-evident integrity for selected security events. "
    "Only event hashes and non-sensitive metadata are anchored; raw traffic remains off-chain."
)


@router.get("/status")
def status(user: Dict[str, Any] = Depends(require_capability("blockchain.view"))) -> Dict[str, Any]:
    return {"anchor": anchor.status(), "ledger": ledger.stats(), "note": LEDGER_NOTE}


@router.get("/events")
def list_events(paging: Paging = Depends(paging_params),
                event_type: Optional[str] = Query(None),
                verification_status: Optional[str] = Query(None),
                search: Optional[str] = Query(None),
                user: Dict[str, Any] = Depends(require_capability("blockchain.view"))) -> Dict[str, Any]:
    rows, total = ledger.list_events(limit=paging.limit, offset=paging.offset, event_type=event_type,
                                     verification_status=verification_status, search=search)
    for row in rows:
        row["hash_preview"] = (row.get("event_hash") or "")[:18] + "…"
    return envelope(rows, total, paging, stats=ledger.stats(), note=LEDGER_NOTE)


@router.get("/stats")
def stats(user: Dict[str, Any] = Depends(require_capability("blockchain.view"))) -> Dict[str, Any]:
    return ledger.stats()


@router.post("/record")
@limiter.limit("60/minute")
def record_event(payload: BlockchainRecordRequest, request: Request,
                 user: Dict[str, Any] = Depends(require_capability("blockchain.record"))) -> Dict[str, Any]:
    event = ledger.record_event(
        event_type=payload.event_type, payload=payload.payload, related_id=payload.related_id,
        recorded_by=user.get("email"), do_anchor=payload.anchor, is_tamper_demo=payload.is_tamper_demo,
    )
    audit_service.log("blockchain.recorded", category="blockchain", user=user, resource="blockchain_event",
                      resource_id=event["id"], metadata={"event_type": payload.event_type,
                                                         "anchor_mode": event.get("anchor_mode"),
                                                         "is_tamper_demo": payload.is_tamper_demo},
                      ip_address=client_ip(request))
    return event


@router.post("/verify")
def verify(payload: BlockchainVerifyRequest, request: Request,
           user: Dict[str, Any] = Depends(require_capability("blockchain.verify"))) -> Dict[str, Any]:
    """Verify by stored event id, or recompute a hash from supplied fields."""
    if payload.event_hash and payload.event_type:
        # Stateless verification: recompute purely from the supplied fields. The
        # hashed structure is event_id + event_type + ISO timestamp + prev_hash +
        # sanitized payload (see app.blockchain.hashing.event_hash_payload).
        prev_hash = payload.prev_hash or GENESIS_HASH
        recomputed = compute_event_hash(
            payload.event_id or "", payload.event_type, payload.timestamp, payload.payload or {}, prev_hash,
        )
        match = recomputed.lower() == payload.event_hash.lower()
        checks = [{"name": "Hash recomputation", "passed": match,
                   "detail": "Recomputed SHA-256 over the canonical (sorted, compact) event structure."}]
        if not match and not payload.event_id:
            checks.append({
                "name": "Completeness",
                "passed": False,
                "detail": "event_id and prev_hash are part of the hashed structure; "
                          "supply them (or verify by event_id) for a meaningful comparison.",
            })
        result = {
            "event_id": payload.event_id,
            "exists": False,
            "mode": "recomputation",
            "match": match,
            "status": "verified" if match else "failed",
            "message": "Supplied hash matches the recomputed hash." if match
            else "Supplied hash does NOT match the recomputed hash - the event was altered "
                 "or the supplied fields are incomplete.",
            "original_hash": recomputed,
            "recorded_hash": payload.event_hash,
            "hash_inputs": event_hash_payload(payload.event_id or "", payload.event_type,
                                              payload.timestamp, payload.payload or {}, prev_hash),
            "checks": checks,
        }
    elif payload.event_id:
        result = ledger.verify_event(payload.event_id, submitted_hash=payload.event_hash)
    else:
        raise HTTPException(status_code=422, detail="Provide either event_id, or event_type + event_hash (+ payload/timestamp/prev_hash).")

    audit_service.log("blockchain.verified", category="blockchain", user=user, resource="blockchain_event",
                      resource_id=payload.event_id, metadata={"match": result.get("match"),
                                                              "status": result.get("status")},
                      ip_address=client_ip(request))
    return result


@router.post("/verify-chain")
def verify_chain(limit: int = Query(500, ge=10, le=2000),
                 user: Dict[str, Any] = Depends(require_capability("blockchain.verify"))) -> Dict[str, Any]:
    return ledger.verify_chain(max_entries=limit)


@router.post("/retry-pending")
def retry_pending(limit: int = Query(10, ge=1, le=100), request: Request = None,
                  user: Dict[str, Any] = Depends(require_capability("blockchain.record"))) -> Dict[str, Any]:
    result = ledger.retry_pending(limit=limit)
    audit_service.log("blockchain.retry_pending", category="blockchain", user=user, resource="blockchain",
                      metadata=result, ip_address=client_ip(request) if request else "127.0.0.1")
    return result


@router.get("/contract")
def contract_info(user: Dict[str, Any] = Depends(require_capability("blockchain.view"))) -> Dict[str, Any]:
    from app.blockchain.contract import abi_source, load_abi

    abi = load_abi()
    functions = [item["name"] for item in abi if item.get("type") == "function"]
    events = [item["name"] for item in abi if item.get("type") == "event"]
    status_payload = anchor.status()
    return {
        "abi_source": abi_source(),
        "functions": functions,
        "events": events,
        "abi_size": len(abi),
        "contract_address": status_payload.get("contract_address"),
        "chain_id": status_payload.get("chain_id"),
        "connected": status_payload.get("connected", False),
        "mode": status_payload.get("mode"),
        "recorder_address": status_payload.get("recorder_address"),
        "onchain_event_count": status_payload.get("onchain_event_count"),
        "source_path": "blockchain/contracts/SecurityEventRegistry.sol",
    }


@router.get("/{event_id}")
def get_event(event_id: str, user: Dict[str, Any] = Depends(require_capability("blockchain.view"))) -> Dict[str, Any]:
    event = ledger.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Ledger entry not found.")
    event["verification"] = ledger.verify_event(event_id)
    event["hash_preview"] = (event.get("event_hash") or "")[:18] + "…"
    # Everything an independent verifier needs to reproduce the hash offline.
    event["hash_inputs"] = event_hash_payload(
        event.get("id"), event.get("event_type"), event.get("created_at"),
        event.get("payload") or {}, event.get("prev_hash") or GENESIS_HASH,
    )
    return event
