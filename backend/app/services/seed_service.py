"""
Demo bootstrap / seeding.

Makes the platform immediately usable after `pip install && uvicorn`:

1. create the three role accounts (admin / analyst / viewer)
2. train + activate a real classifier and anomaly detector on the bundled sample dataset
3. generate 24h of labelled simulated traffic through the normal analysis pipeline
4. run a forecast so the Forecast Center has data on first load
5. write the ledger genesis entry plus one clearly-marked tamper demonstration

Every step is idempotent and skipped when data already exists.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from app.blockchain import ledger
from app.core.config import settings
from app.core.utils import iso, utcnow
from app.ml.features import detect_columns, normalize_frame
from app.services.dataset_service import profile_frame
from app.security.hashing import hash_password
from app.services import alert_service, forecast_service, model_service, pipeline_service
from app.services.simulation_service import engine as simulation_engine
from app.storage import get_store

logger = logging.getLogger("cyberforecast.seed")

_state: Dict[str, Any] = {
    "status": "idle",
    "steps": [],
    "started_at": None,
    "finished_at": None,
    "error": None,
}
_lock = threading.Lock()


def seed_status() -> Dict[str, Any]:
    with _lock:
        return dict(_state)


def _step(name: str, ok: bool, detail: str, seconds: float) -> None:
    with _lock:
        _state["steps"].append({"step": name, "ok": ok, "detail": detail, "seconds": round(seconds, 2),
                                "at": iso(utcnow())})
    logger.info("seed[%s] %s - %s (%.1fs)", "ok" if ok else "skip/fail", name, detail, seconds)


def ensure_users() -> Dict[str, Any]:
    started = time.time()
    store = get_store()
    created: List[str] = []
    demo_accounts = [
        (settings.demo_admin_email, settings.demo_admin_password, "Aarav Menon", "admin", "#22d3ee"),
        (settings.demo_analyst_email, settings.demo_analyst_password, "Isha Kulkarni", "analyst", "#818cf8"),
        (settings.demo_viewer_email, settings.demo_viewer_password, "Rohan Verma", "viewer", "#34d399"),
    ]
    for email, password, name, role, color in demo_accounts:
        if store.find_one("users", {"email": email}):
            continue
        store.create("users", {
            "name": name, "email": email, "role": role,
            "password_hash": hash_password(password), "is_active": True,
            "avatar_color": color, "created_at": utcnow(),
        })
        created.append(email)
    _step("users", True, f"created {len(created)} demo account(s)" if created else "demo accounts already present",
          time.time() - started)
    return {"created": created}


def ensure_models(force: bool = False) -> Optional[Dict[str, Any]]:
    started = time.time()
    store = get_store()
    if not force and model_service.active_model("classification") and model_service.active_model("anomaly"):
        _step("models", True, "active classifier and anomaly detector already registered", time.time() - started)
        return None

    dataset_path = settings.seed_dataset
    dataset_id: Optional[str] = None
    if os.path.isfile(dataset_path):
        with open(dataset_path, "rb") as handle:
            content = handle.read()
        raw = pd.read_csv(dataset_path)
        detection = detect_columns(raw)
        normalized = normalize_frame(raw, detection).drop_duplicates()
        bundled_profile = profile_frame(raw, normalized, detection)
        bundled_profile["note"] = "Bundled sample dataset shipped with the platform"
        record = store.create("datasets", {
            "user_id": None,
            "filename": os.path.basename(dataset_path),
            "original_filename": os.path.basename(dataset_path),
            "file_format": "csv",
            "size_bytes": len(content),
            "rows": int(len(normalized)),
            "columns": int(len(raw.columns)),
            "column_names": [str(c) for c in raw.columns],
            "profile": bundled_profile,
            "storage_backend": "bundled",
            "status": "processed",
            "uploaded_at": utcnow(),
        })
        dataset_id = record["id"]
        # Point the record at the on-disk sample so retraining works later.
        store.update("datasets", dataset_id, {"filename": os.path.abspath(dataset_path), "storage_backend": "bundled-path"})

    try:
        result = model_service.train(
            algorithm=settings.default_classifier, dataset_id=dataset_id,
            user={"email": "system-seed"}, train_anomaly=True,
        )
    except Exception as exc:
        _step("models", False, f"training failed: {exc}", time.time() - started)
        return None

    activated = []
    for record in result.get("trained", []):
        try:
            model_service.activate(record["id"], user={"email": "system-seed"}, dataset_id=dataset_id)
            activated.append(record["id"])
        except Exception as exc:
            logger.warning("could not activate seeded model %s: %s", record.get("id"), exc)

    _step("models", bool(activated),
          f"trained and activated {len(activated)} model(s) on {result.get('training_rows')} labeled rows",
          time.time() - started)
    return result


def _historical_flows(count: int) -> pd.DataFrame:
    """Build `count` hours-worth of synthetic flows ending now."""
    from app.services.simulation_service import SCENARIOS

    rng_engine = simulation_engine
    previous_scenario = rng_engine.state.scenario
    rng_engine.state.scenario = "mixed"
    now = datetime.now(timezone.utc)
    rows: List[Dict[str, Any]] = []
    try:
        for index in range(count):
            progress = index / max(count - 1, 1)
            when = now - timedelta(seconds=int((1 - progress) * 24 * 3600)) + timedelta(
                seconds=simulation_engine._rng.uniform(0, 20))
            attack = rng_engine._pick_attack(progress)
            # Realistic networks are mostly benign: damp the attack share so the
            # seeded 24h history looks like production traffic rather than a lab.
            if attack != "Benign" and simulation_engine._rng.random() < 0.6:
                attack = "Benign"
            rows.append(rng_engine.generate_flow(attack, when))
    finally:
        rng_engine.state.scenario = previous_scenario
    frame = pd.DataFrame(rows)
    return normalize_frame(frame, detect_columns(frame)).sort_values("timestamp").reset_index(drop=True)


def ensure_traffic(count: Optional[int] = None, force: bool = False) -> int:
    started = time.time()
    store = get_store()
    if not force and store.count("traffic_records") >= 200:
        _step("traffic", True, f"{store.count('traffic_records')} traffic records already present", time.time() - started)
        return store.count("traffic_records")

    total = count or settings.seed_traffic_records
    frame = _historical_flows(total)
    result = pipeline_service.analyze_frame(
        frame, source="simulation", persist=True, create_alerts=True, explain=False, user={"email": "system-seed"}
    )
    summary = result.get("summary") or {}
    _step("traffic", True,
          f"analyzed and persisted {summary.get('rows', 0)} simulated flows -> {summary.get('attacks_detected', 0)} attack verdicts, "
          f"{summary.get('alerts_created', 0)} alerts", time.time() - started)
    return int(summary.get("rows") or 0)


def ensure_forecast(force: bool = False) -> Optional[Dict[str, Any]]:
    started = time.time()
    store = get_store()
    if not force and store.count("forecasts") > 0:
        _step("forecast", True, "forecast run already available", time.time() - started)
        return None
    try:
        payload = forecast_service.run_forecast(user={"email": "system-seed"}, create_alerts=True)
        overall = payload.get("overall") or {}
        _step("forecast", True,
              f"forecast run {payload.get('run_id')} -> {overall.get('risk_level')} "
              f"({round(float(overall.get('probability') or 0) * 100, 1)}% over {overall.get('horizon_minutes')} min)",
              time.time() - started)
        return payload
    except Exception as exc:
        _step("forecast", False, f"forecast failed: {exc}", time.time() - started)
        return None


def ensure_ledger() -> None:
    started = time.time()
    store = get_store()
    created: List[str] = []
    has_genesis = bool(store.find_one("blockchain_events", {"event_type": "ledger_genesis"}))
    has_tamper = store.count("blockchain_events", {"is_tamper_demo": True}) > 0

    if not has_genesis:
        ledger.record_event(
            event_type="ledger_genesis",
            payload={"platform": settings.app_name, "version": settings.version,
                     "purpose": "Integrity chain genesis entry", "storage_backend": settings.storage_backend},
            recorded_by="system-seed",
        )
        created.append("genesis")

    if not has_tamper:
        ledger.record_event(
            event_type="alert",
            payload={
                "alert_id": "tamper-demo", "alert_code": "CF-DEMO-TAMPER", "attack_type": "DDoS",
                "severity": "critical", "risk_score": 0.91, "confidence": 0.88,
                "note": "TAMPER DEMONSTRATION EVENT - the stored payload is deliberately altered after hashing "
                        "so the verification page can show a failed integrity check.",
            },
            related_id="tamper-demo",
            recorded_by="system-seed",
            is_tamper_demo=True,
        )
        created.append("tamper-demo")

    _step("ledger", True,
          (f"created {', '.join(created)}" if created else "genesis + tamper demo already present")
          + f" ({store.count('blockchain_events')} entries total)", time.time() - started)


def ensure_audit() -> None:
    from app.services import audit_service

    store = get_store()
    if store.count("audit_logs") > 0:
        return
    audit_service.log("platform.seeded", category="system", resource="platform",
                      metadata={"storage_backend": settings.storage_backend,
                                "blockchain_mode": "evm" if settings.blockchain_anchor else "local-hash-chain"})


def seed_all(force: bool = False) -> Dict[str, Any]:
    """Run the full bootstrap. Safe to call repeatedly."""
    with _lock:
        if _state["status"] == "running":
            return dict(_state)
        _state.update({"status": "running", "steps": [], "started_at": iso(utcnow()),
                       "finished_at": None, "error": None})
    started = time.time()
    try:
        from app.storage.orm import init_db

        init_db()
        ensure_users()
        ensure_models(force=force)
        ensure_traffic(force=force)
        ensure_forecast(force=force)
        ensure_ledger()
        ensure_audit()
        with _lock:
            _state.update({"status": "complete", "finished_at": iso(utcnow()),
                           "seconds": round(time.time() - started, 2)})
    except Exception as exc:  # pragma: no cover - seeding must never crash boot
        logger.exception("seeding failed")
        with _lock:
            _state.update({"status": "failed", "error": str(exc)[:300], "finished_at": iso(utcnow()),
                           "seconds": round(time.time() - started, 2)})
    return seed_status()


def seed_in_background(force: bool = False) -> None:
    thread = threading.Thread(target=seed_all, args=(force,), name="cyberforecast-seed", daemon=True)
    thread.start()
