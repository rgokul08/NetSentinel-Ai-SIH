"""Traffic ingestion, live monitor, timeline and threat map endpoints."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import APIRouter, Depends, Query, Request, WebSocket, WebSocketDisconnect

from app.api.common import Paging, envelope, paging_params, service_error
from app.ml.features import detect_columns, normalize_frame
from app.security.deps import client_ip, get_current_user, get_optional_user, require_capability
from app.security.ratelimit import limiter
from app.security.tokens import decode_access_token
from app.schemas.schemas import AnalyzeRequest
from app.services import audit_service, pipeline_service, traffic_service
from app.services.realtime import hub
from app.services.simulation_service import engine as simulation_engine

logger = logging.getLogger("cyberforecast.api.traffic")
router = APIRouter(prefix="/traffic", tags=["Traffic"])


@router.post("/analyze")
@limiter.limit("60/minute")
def analyze(payload: AnalyzeRequest, request: Request,
            user: Dict[str, Any] = Depends(require_capability("traffic.ingest"))) -> Dict[str, Any]:
    """Run uploaded/manual flows through the full analysis pipeline."""
    records = [flow.model_dump(exclude_none=True) for flow in payload.flows]
    try:
        result = pipeline_service.analyze_records(
            records,
            source=payload.source or "manual",
            persist=payload.persist,
            create_alerts=payload.create_alerts,
            user=user,
        )
    except Exception as exc:
        raise service_error(exc, default_status=500)
    audit_service.log("traffic.analyzed", category="prediction", user=user, resource="traffic",
                      metadata={"rows": len(records), "persist": payload.persist,
                                "attacks": (result.get("summary") or {}).get("attacks_detected")},
                      ip_address=client_ip(request))
    return result


@router.get("/live")
def live(window: str = Query("5m", description="1m | 5m | 15m | 1h | 24h"),
         source: Optional[str] = Query(None, description="simulation | dataset | live"),
         user: Dict[str, Any] = Depends(require_capability("traffic.view"))) -> Dict[str, Any]:
    snapshot = traffic_service.live_snapshot(window=window, source=source)
    snapshot["simulation"] = simulation_engine.status()
    snapshot["subscribers"] = hub.subscriber_count
    return snapshot


@router.get("/summary")
def summary(window: str = Query("24h"), source: Optional[str] = Query(None),
            user: Dict[str, Any] = Depends(require_capability("traffic.view"))) -> Dict[str, Any]:
    return traffic_service.summary(window=window, source=source)


@router.get("/records")
def records(paging: Paging = Depends(paging_params), window: Optional[str] = Query("24h"),
            attack_type: Optional[str] = Query(None), risk_level: Optional[str] = Query(None),
            anomalies_only: bool = Query(False), source: Optional[str] = Query(None),
            search: Optional[str] = Query(None),
            user: Dict[str, Any] = Depends(require_capability("traffic.view"))) -> Dict[str, Any]:
    rows, total = traffic_service.list_records(
        limit=paging.limit, offset=paging.offset, window=window, attack_type=attack_type,
        risk_level=risk_level, anomalies_only=anomalies_only, source=source, search=search,
    )
    return envelope(rows, total, paging)


@router.get("/recent")
def recent(limit: int = Query(25, ge=1, le=200), source: Optional[str] = Query(None),
           user: Dict[str, Any] = Depends(require_capability("traffic.view"))) -> Dict[str, Any]:
    return {"items": traffic_service.recent_events(limit=limit, source=source)}


@router.get("/timeline")
def timeline(window: str = Query("24h"), limit: int = Query(120, ge=10, le=500),
             user: Dict[str, Any] = Depends(require_capability("traffic.view"))) -> Dict[str, Any]:
    return traffic_service.timeline(window=window, limit=limit)


@router.get("/threat-map")
def threat_map(window: str = Query("24h"), limit: int = Query(40, ge=5, le=200),
               user: Dict[str, Any] = Depends(require_capability("traffic.view"))) -> Dict[str, Any]:
    payload = traffic_service.threat_map(window=window, limit=limit)
    if user.get("role") == "viewer":
        # Viewers only get the abstracted representation.
        for node in payload["nodes"]:
            node["ip"] = node["masked"]
        for link in payload["links"]:
            link["source"], link["target"] = link["source"][:6] + ".x.x", link["target"][:6] + ".x.x"
    return payload


@router.get("/stream-events")
def stream_events(limit: int = Query(50, ge=1, le=300),
                  user: Dict[str, Any] = Depends(require_capability("traffic.view"))) -> Dict[str, Any]:
    """Polling fallback for clients without WebSocket support."""
    return {"items": hub.recent_events(limit), "subscribers": hub.subscriber_count,
            "published_total": hub.published_total}


@router.websocket("/ws")
async def websocket_traffic(websocket: WebSocket) -> None:
    """Live pipeline events + periodic metrics snapshots."""
    token = websocket.query_params.get("token")
    user = None
    if token:
        payload = decode_access_token(token)
        if payload:
            from app.services import auth_service

            user = auth_service.get_user(payload.get("sub"))
    await websocket.accept()
    queue = hub.subscribe()
    snapshot_task: Optional[asyncio.Task] = None

    async def snapshot_loop() -> None:
        while True:
            await asyncio.sleep(4)
            try:
                snapshot = traffic_service.live_snapshot(window="5m")
                snapshot["simulation"] = simulation_engine.status()
                await websocket.send_json({"type": "metrics", "timestamp": snapshot["generated_at"], "data": snapshot})
            except Exception:  # pragma: no cover - client may have vanished
                return

    try:
        await websocket.send_json({
            "type": "hello",
            "authenticated": bool(user),
            "role": (user or {}).get("role"),
            "simulation": simulation_engine.status(),
            "label": "Simulation Mode" if simulation_engine.status()["status"] == "running" else "Idle",
        })
        snapshot_task = asyncio.create_task(snapshot_loop())
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # pragma: no cover
        logger.debug("websocket closed: %s", exc)
    finally:
        hub.unsubscribe(queue)
        if snapshot_task:
            snapshot_task.cancel()

