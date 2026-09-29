"""Simulation controls (clearly labelled synthetic traffic)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.security.deps import client_ip, get_current_user, require_capability
from app.security.ratelimit import limiter
from app.services import audit_service, pipeline_service
from app.services.simulation_service import SCENARIOS, engine, scenarios

router = APIRouter(prefix="/simulation", tags=["Simulation"])

LABEL = "Simulation Mode - synthetic traffic generated for demonstration and defensive training."


@router.get("/scenarios")
def list_scenarios(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return {"items": scenarios(), "label": LABEL}


@router.get("/status")
def status(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    payload = engine.status()
    payload["label"] = LABEL
    return payload


@router.post("/start")
@limiter.limit("20/minute")
def start(request: Request, scenario: str = Query("mixed"), intensity: int = Query(5, ge=1, le=10),
          duration_seconds: int = Query(600, ge=30, le=7200), tick_seconds: float = Query(1.0, ge=0.25, le=5.0),
          user: Dict[str, Any] = Depends(require_capability("simulation.control"))) -> Dict[str, Any]:
    state = engine.start(scenario=scenario, intensity=intensity, duration_seconds=duration_seconds,
                         tick_seconds=tick_seconds)
    audit_service.log("simulation.started", category="simulation", user=user, resource="simulation",
                      metadata={"scenario": scenario, "intensity": intensity, "duration_seconds": duration_seconds},
                      ip_address=client_ip(request))
    state["label"] = LABEL
    return state


@router.post("/pause")
def pause(request: Request, user: Dict[str, Any] = Depends(require_capability("simulation.control"))) -> Dict[str, Any]:
    state = engine.pause()
    audit_service.log("simulation.paused", category="simulation", user=user, resource="simulation",
                      ip_address=client_ip(request))
    return state


@router.post("/resume")
def resume(request: Request, user: Dict[str, Any] = Depends(require_capability("simulation.control"))) -> Dict[str, Any]:
    state = engine.resume()
    audit_service.log("simulation.resumed", category="simulation", user=user, resource="simulation",
                      ip_address=client_ip(request))
    return state


@router.post("/stop")
def stop(request: Request, user: Dict[str, Any] = Depends(require_capability("simulation.control"))) -> Dict[str, Any]:
    state = engine.stop()
    audit_service.log("simulation.stopped", category="simulation", user=user, resource="simulation",
                      metadata={"generated_flows": state.get("generated_flows")}, ip_address=client_ip(request))
    return state


@router.patch("")
def update(request: Request, scenario: Optional[str] = Query(None), intensity: Optional[int] = Query(None, ge=1, le=10),
           duration_seconds: Optional[int] = Query(None, ge=30, le=7200),
           user: Dict[str, Any] = Depends(require_capability("simulation.control"))) -> Dict[str, Any]:
    state = engine.update(intensity=intensity, scenario=scenario, duration_seconds=duration_seconds)
    audit_service.log("simulation.updated", category="simulation", user=user, resource="simulation",
                      metadata={"scenario": scenario, "intensity": intensity}, ip_address=client_ip(request))
    return state


@router.post("/inject")
@limiter.limit("60/minute")
def inject(request: Request, attack_type: str = Query("DDoS"), count: int = Query(12, ge=1, le=200),
           create_alerts: bool = Query(True),
           user: Dict[str, Any] = Depends(require_capability("simulation.control"))) -> Dict[str, Any]:
    """Immediately push a burst of a chosen attack pattern through the pipeline."""
    valid = {"Benign", "DDoS", "DoS", "Port Scan", "Brute Force", "Bot Activity", "Intrusion", "Network Anomaly"}
    if attack_type not in valid:
        raise HTTPException(status_code=422, detail=f"attack_type must be one of: {', '.join(sorted(valid))}")
    import pandas as pd

    from app.ml.features import detect_columns, normalize_frame

    now = datetime.now(timezone.utc)
    flows = [engine.generate_flow(attack_type, now) for _ in range(count)]
    frame = normalize_frame(pd.DataFrame(flows), detect_columns(pd.DataFrame(flows)))
    result = pipeline_service.analyze_frame(frame, source="simulation", persist=True,
                                            create_alerts=create_alerts, explain=False, user=user)
    audit_service.log("simulation.injected", category="simulation", user=user, resource="simulation",
                      metadata={"attack_type": attack_type, "count": count,
                                "attacks": (result.get("summary") or {}).get("attacks_detected")},
                      ip_address=client_ip(request))
    result["injected"] = {"attack_type": attack_type, "count": count, "label": LABEL}
    return result
