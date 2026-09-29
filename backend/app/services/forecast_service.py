"""
Forecast orchestration: builds the history frame from persisted data, runs the
forecasting engine, stores the run and raises forecast-origin alerts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import pandas as pd

from app.blockchain import ledger
from app.core.utils import iso, new_id, safe_float, utcnow
from app.ml.features import BENIGN
from app.ml.forecast import SUPPORTED_HORIZONS, forecast_frame
from app.services import alert_service
from app.storage import get_store

logger = logging.getLogger("cyberforecast.forecast")

MAX_HISTORY_ROWS = 20000


class ForecastError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def history_frame(dataset_id: Optional[str] = None, window: str = "24h", limit: int = MAX_HISTORY_ROWS) -> pd.DataFrame:
    """Traffic + verdict history used as forecast input."""
    store = get_store()
    filters: Dict[str, Any] = {}
    if dataset_id:
        filters["dataset_id"] = dataset_id
    else:
        from app.core.utils import window_start

        start = window_start(window)
        if start:
            filters["timestamp"] = {"$gte": start}
    rows, total = store.list("traffic_records", filters=filters or None, order_by="-timestamp", limit=limit)
    if not rows:
        return pd.DataFrame()
    frame = pd.DataFrame(rows)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    # Prefer the model verdict; fall back to the dataset label when present.
    frame["attack_type"] = frame["predicted_attack_type"].fillna(frame.get("attack_type", BENIGN)).replace({"Unknown": BENIGN})
    frame = frame.dropna(subset=["timestamp"]).sort_values("timestamp")
    return frame.reset_index(drop=True)


def run_forecast(
    horizons: Optional[List[int]] = None,
    dataset_id: Optional[str] = None,
    window: str = "24h",
    persist: bool = True,
    create_alerts: bool = True,
    user: Optional[Dict[str, Any]] = None,
    limit: int = MAX_HISTORY_ROWS,
) -> Dict[str, Any]:
    horizons = [int(h) for h in (horizons or SUPPORTED_HORIZONS) if int(h) > 0]
    frame = history_frame(dataset_id=dataset_id, window=window, limit=limit)
    if frame.empty:
        raise ForecastError(
            "No traffic history available to forecast. Start the simulation or analyze a dataset first.",
            status_code=409,
        )

    payload = forecast_frame(
        frame,
        horizons=horizons,
        source_label="dataset" if dataset_id else "database",
        model_version="ridge-lag-v2",
    )
    payload["dataset_id"] = dataset_id
    payload["window"] = window
    payload["requested_by"] = (user or {}).get("email")

    if persist:
        store = get_store()
        rows: List[Dict[str, Any]] = []
        for horizon in payload.get("horizons", []):
            for category in horizon.get("categories", []):
                steps = category.get("trend") or []
                rows.append({
                    "id": new_id(),
                    "run_id": payload["run_id"],
                    "created_at": utcnow(),
                    "horizon_minutes": int(horizon["horizon_minutes"]),
                    "forecast_time": steps[-1]["bucket"] if steps else iso(utcnow()),
                    "attack_type": category["attack_type"],
                    "probability": safe_float(category["probability"]),
                    "per_bucket_probability": safe_float(category.get("per_bucket_probability")),
                    "peak_bucket_probability": safe_float(category.get("peak_bucket_probability")),
                    "confidence": safe_float(category["confidence"]),
                    "expected_events": safe_float(category["expected_events"]),
                    "lower_bound": safe_float(category["lower_bound"]),
                    "upper_bound": safe_float(category["upper_bound"]),
                    "risk_level": (category.get("risk_level") or "informational").upper(),
                    "contributing_features": category.get("contributing_features") or [],
                    "method": category.get("method"),
                    "residual_rmse": safe_float(category.get("residual_rmse")),
                    "historical_events": int(safe_float(category.get("historical_events"))),
                    "recommendation": category.get("recommendation"),
                    "model_version": payload.get("model_version", "ridge-lag-v2"),
                    "based_on_records": int(payload.get("records_used") or 0),
                    "is_simulated": bool(frame["is_simulated"].mean() > 0.5) if "is_simulated" in frame else True,
                })
        if rows:
            store.create_many("forecasts", rows)

        if create_alerts:
            for horizon in payload.get("horizons", []):
                for category in horizon.get("categories", []):
                    probability = safe_float(category["probability"])
                    if probability < 0.5:
                        continue
                    severity = "critical" if probability >= 0.8 else "high"
                    drivers = ", ".join(f"{c['label']} {c.get('impact','')}".strip()
                                        for c in (category.get("contributing_features") or [])[:3]) or "lagged attack frequency"
                    alert_service.raise_alert(
                        attack_type=category["attack_type"],
                        severity=severity,
                        risk_score=probability,
                        confidence=safe_float(category["confidence"]),
                        description=(
                            f"Forecast for the next {horizon['horizon_minutes']} minute(s) estimates a "
                            f"{round(probability * 100, 1)}% probability of {category['attack_type']} activity "
                            f"(expected {category['expected_events']} events, confidence {category['confidence']}). "
                            f"Main drivers: {drivers}. This is a probabilistic model estimate, not a certainty."
                        ),
                        origin="forecast",
                        title=f"Forecast: {category['attack_type']} risk in next {horizon['horizon_minutes']}m",
                        recommendation=category.get("recommendation"),
                        is_simulated=bool(payload.get("is_simulated", True)),
                        throttle=True,
                        user_email=(user or {}).get("email"),
                    )

        try:
            ledger.record_event(
                event_type="forecast_run",
                payload={
                    "run_id": payload["run_id"],
                    "horizons": horizons,
                    "records_used": payload.get("records_used"),
                    "overall": payload.get("overall"),
                    "top_threats": [
                        {"attack_type": c["attack_type"], "probability": c["probability"], "risk_level": c["risk_level"]}
                        for c in (payload.get("categories") or [])[:4]
                    ],
                    "model_version": payload.get("model_version"),
                },
                related_id=payload["run_id"],
                recorded_by=(user or {}).get("email", "forecast-engine"),
            )
        except Exception:  # pragma: no cover
            logger.warning("ledger write failed for forecast run")

    return payload


def latest_run() -> Optional[Dict[str, Any]]:
    """Reconstruct the most recent persisted forecast run."""
    store = get_store()
    rows, _ = store.list("forecasts", order_by="-created_at", limit=1)
    if not rows:
        return None
    run_id = rows[0].get("run_id")
    records, total = store.list("forecasts", filters={"run_id": run_id}, order_by="horizon_minutes", limit=500)
    if not records:
        return None

    by_horizon: Dict[int, List[Dict[str, Any]]] = {}
    for record in records:
        by_horizon.setdefault(int(record.get("horizon_minutes") or 0), []).append(record)

    horizons = []
    for horizon_minutes in sorted(by_horizon):
        categories = sorted(by_horizon[horizon_minutes], key=lambda r: safe_float(r.get("probability")), reverse=True)
        overall = 1.0
        for category in categories:
            overall *= (1.0 - safe_float(category.get("probability")))
        overall_probability = round(1.0 - overall, 4)
        top = categories[0] if categories else None
        horizons.append({
            "horizon_minutes": horizon_minutes,
            "created_at": categories[0].get("created_at") if categories else None,
            "overall_probability": overall_probability,
            "overall_risk_level": (top or {}).get("risk_level", "INFORMATIONAL").lower(),
            "overall_confidence": round(float(sum(safe_float(c.get("confidence")) for c in categories) / max(len(categories), 1)), 3),
            "expected_attack_events": round(sum(safe_float(c.get("expected_events")) for c in categories), 2),
            "method": top.get("method") if top else None,
            "buckets_available": None,
            "top_threat": {
                "attack_type": top.get("attack_type"),
                "probability": top.get("probability"),
                "per_bucket_probability": top.get("per_bucket_probability"),
                "peak_bucket_probability": top.get("peak_bucket_probability"),
                "risk_level": (top.get("risk_level") or "").lower(),
                "confidence": top.get("confidence"),
                "expected_events": top.get("expected_events"),
                "recommendation": top.get("recommendation"),
                "contributing_features": top.get("contributing_features"),
            } if top else None,
            "categories": categories,
        })

    longest = horizons[-1]
    return {
        "run_id": run_id,
        "generated_at": longest["created_at"],
        "source": "database",
        "method": "ridge-lag-regression",
        "records_used": longest["categories"][0].get("based_on_records") if longest["categories"] else 0,
        "horizons": horizons,
        "categories": longest["categories"],
        "overall": {
            "horizon_minutes": longest["horizon_minutes"],
            "probability": longest["overall_probability"],
            "risk_level": longest["overall_risk_level"],
            "confidence": longest["overall_confidence"],
            "top_threat": longest["top_threat"],
        },
        "model_version": longest["categories"][0].get("model_version") if longest["categories"] else None,
        "disclaimer": ("Forecasts are probabilistic model estimates derived from recent traffic history. "
                       "They indicate elevated risk, not certainty that an attack will occur."),
        "loaded_from": "database",
    }


def trend(limit: int = 40) -> List[Dict[str, Any]]:
    """Forecast probability over time (one point per run, longest horizon)."""
    store = get_store()
    rows, _ = store.list("forecasts", order_by="-created_at", limit=limit * 12)
    if not rows:
        return []
    frame = pd.DataFrame(rows)
    frame["created_at"] = pd.to_datetime(frame["created_at"], errors="coerce", utc=True)
    frame = frame.dropna(subset=["created_at"])
    grouped = frame.groupby(["created_at", "horizon_minutes"])
    points = []
    for (created_at, horizon), group in grouped:
        overall = 1.0 - float((1.0 - group["probability"].astype(float)).prod())
        top = group.loc[group["probability"].astype(float).idxmax()]
        points.append({
            "created_at": iso(created_at),
            "horizon_minutes": int(horizon),
            "overall_probability": round(overall, 4),
            "top_attack": str(top["attack_type"]),
            "top_probability": round(float(top["probability"]), 4),
            "risk_level": str(top["risk_level"]).lower(),
        })
    points.sort(key=lambda item: (item["created_at"], item["horizon_minutes"]))
    return points[-limit * 4:]
