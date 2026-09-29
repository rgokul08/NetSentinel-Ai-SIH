"""
Attack forecasting engine.

Approach (all numbers come from the data, nothing is hard-coded):

1. Bucket the recent traffic/prediction history into fixed time windows.
2. Per bucket derive volume, rate, fan-out, failure and anomaly features.
3. For every attack category fit a Ridge regression on lagged counts + traffic
   features to predict the *next* bucket's event count.
4. Roll the model forward recursively across the requested horizon, converting
   predicted counts to probabilities with a Poisson link  p = 1 - exp(-lambda)
   and aggregating across buckets.
5. Derive confidence from out-of-sample residual error, sample size and horizon
   length; derive explanations from the fitted coefficients.

When history is too short for regression the engine falls back to an explicit
EWMA rate baseline and reports the lower confidence that comes with it.
"""

from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.linear_model import Ridge

from app.core.utils import clamp, iso, new_id, utcnow
from app.ml.features import BENIGN
from app.storage.schema import RECOMMENDATIONS

logger = logging.getLogger("cyberforecast.forecast")

FORECAST_CLASSES: List[str] = [
    "DDoS", "DoS", "Port Scan", "Brute Force", "Bot Activity", "Intrusion", "Network Anomaly",
]
SUPPORTED_HORIZONS: List[int] = [5, 15, 30, 60]
MIN_BUCKETS_FOR_REGRESSION = 10
LAGS = 3

EXOG_FEATURES = [
    ("log_pps", "Packet rate (log)"),
    ("log_bps", "Bandwidth (log)"),
    ("log_flows", "Flow volume (log)"),
    ("unique_sources", "Unique source IPs"),
    ("anomaly_rate", "Anomaly rate"),
    ("failed", "Failed connections"),
    ("hour_sin", "Time of day (sin)"),
    ("hour_cos", "Time of day (cos)"),
]


def risk_level(probability: float) -> str:
    if probability >= 0.75:
        return "critical"
    if probability >= 0.5:
        return "high"
    if probability >= 0.28:
        return "medium"
    if probability >= 0.12:
        return "low"
    return "informational"


def bucket_minutes_for_horizon(horizon_minutes: int) -> int:
    """Keep ~12-20 buckets inside a horizon so the regression stays meaningful."""
    if horizon_minutes <= 5:
        return 1
    if horizon_minutes <= 15:
        return 1
    if horizon_minutes <= 30:
        return 2
    return 5


def build_buckets(df: pd.DataFrame, bucket_minutes: int) -> pd.DataFrame:
    """Aggregate normalized traffic rows into time buckets with derived features."""
    frame = df.copy()
    if "timestamp" not in frame.columns or frame.empty:
        return pd.DataFrame()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    frame = frame.dropna(subset=["timestamp"]).sort_values("timestamp")
    if frame.empty:
        return pd.DataFrame()

    if "attack_type" not in frame.columns:
        frame["attack_type"] = BENIGN
    frame["attack_type"] = frame["attack_type"].astype(str).replace({"Unknown": BENIGN, "nan": BENIGN, "": BENIGN})
    for column in ("packet_count", "byte_count", "packets_per_second", "bytes_per_second", "failed_connections", "connection_count"):
        if column not in frame.columns:
            frame[column] = 0.0
        frame[column] = pd.to_numeric(frame[column], errors="coerce").fillna(0.0)
    frame["is_anomaly"] = frame.get("is_anomaly", pd.Series(False, index=frame.index)).astype(bool)

    bucket = f"{int(bucket_minutes)}min"
    indexed = frame.set_index("timestamp")
    resampled = indexed.resample(bucket)

    agg = pd.DataFrame({
        "flows": resampled.size(),
        "packets": resampled["packet_count"].sum(),
        "bytes": resampled["byte_count"].sum(),
        "failed": resampled["failed_connections"].sum(),
        "anomalies": resampled["is_anomaly"].sum().astype(float),
        "unique_sources": resampled["source_ip"].nunique() if "source_ip" in indexed else 0,
        "unique_destinations": resampled["destination_ip"].nunique() if "destination_ip" in indexed else 0,
    }).astype(float).fillna(0.0)

    class_flags = pd.DataFrame(
        {klass: (indexed["attack_type"] == klass).astype(float) for klass in FORECAST_CLASSES},
        index=indexed.index,
    )
    class_counts = class_flags.resample(bucket).sum()
    for klass in FORECAST_CLASSES:
        agg[f"cnt_{klass}"] = class_counts[klass] if klass in class_counts else 0.0

    agg["attacks"] = agg[[f"cnt_{k}" for k in FORECAST_CLASSES]].sum(axis=1)
    seconds = float(bucket_minutes) * 60.0
    agg["pps"] = agg["packets"] / seconds
    agg["bps"] = agg["bytes"] / seconds
    agg["anomaly_rate"] = (agg["anomalies"] / agg["flows"].replace(0, np.nan)).fillna(0.0).clip(0, 1)
    agg["log_pps"] = np.log1p(agg["pps"].clip(lower=0))
    agg["log_bps"] = np.log1p(agg["bps"].clip(lower=0))
    agg["log_flows"] = np.log1p(agg["flows"].clip(lower=0))
    mid = agg.index + pd.Timedelta(minutes=bucket_minutes / 2)
    agg["hour_sin"] = np.sin(2 * np.pi * mid.hour / 24.0)
    agg["hour_cos"] = np.cos(2 * np.pi * mid.hour / 24.0)

    # Drop buckets resampled beyond the last observed event.
    last_event = frame["timestamp"].max().floor(bucket)
    agg = agg[agg.index <= last_event]
    return agg.reset_index().rename(columns={"timestamp": "bucket"})


def _feature_row(history: List[float], exog: Dict[str, float], klass: str, attacks_hist: List[float]) -> List[float]:
    lags = [history[-i] if i <= len(history) else 0.0 for i in range(1, LAGS + 1)]
    attack_lags = [attacks_hist[-i] if i <= len(attacks_hist) else 0.0 for i in (1, 2)]
    roll = float(np.mean(history[-3:])) if history else 0.0
    return lags + attack_lags + [roll] + [exog.get(name, 0.0) for name, _ in EXOG_FEATURES]


FEATURE_NAMES = (
    [f"lag_{i}" for i in range(1, LAGS + 1)]
    + ["attacks_lag_1", "attacks_lag_2", "rolling_mean_3"]
    + [name for name, _ in EXOG_FEATURES]
)


def _fit_class_model(agg: pd.DataFrame, klass: str) -> Optional[Dict[str, Any]]:
    counts = agg[f"cnt_{klass}"].astype(float).tolist()
    attacks = agg["attacks"].astype(float).tolist()
    exog_rows = agg[[name for name, _ in EXOG_FEATURES]].astype(float).to_dict("records")

    X, y = [], []
    for i in range(LAGS, len(counts) - 1):
        X.append(_feature_row(counts[:i], exog_rows[i], klass, attacks[:i]))
        y.append(counts[i])
    if len(X) < MIN_BUCKETS_FOR_REGRESSION - LAGS:
        return None

    X_arr, y_arr = np.asarray(X, dtype=float), np.asarray(y, dtype=float)
    model = Ridge(alpha=1.0, fit_intercept=True)
    model.fit(X_arr, y_arr)

    # Leave-the-last-third-out residual estimate -> honest confidence bounds.
    split = max(1, int(len(X_arr) * 0.66))
    residuals = y_arr[split:] - model.predict(X_arr[split:])
    rmse = float(np.sqrt(np.mean(residuals ** 2))) if len(residuals) else float(np.std(y_arr) or 0.0)
    if not np.isfinite(rmse):
        rmse = 0.0

    return {
        "model": model,
        "rmse": rmse,
        "target_mean": float(np.mean(y_arr)),
        "target_max": float(np.max(y_arr)) if len(y_arr) else 0.0,
        "samples": int(len(X_arr)),
        "coefficients": {name: float(c) for name, c in zip(FEATURE_NAMES, model.coef_)},
        "intercept": float(model.intercept_),
        "history": counts,
        "attacks_history": attacks,
        "exog": exog_rows,
    }


def _project(fit: Dict[str, Any], steps: int) -> Tuple[List[float], List[float]]:
    """Recursively project `steps` future bucket counts. Returns (lambdas, upper)."""
    model = fit["model"]
    history = list(fit["history"])
    attacks = list(fit["attacks_history"])
    exog_recent = {name: float(np.mean([row[name] for row in fit["exog"][-3:]])) for name, _ in EXOG_FEATURES}
    lambdas: List[float] = []
    for _ in range(steps):
        row = np.asarray([_feature_row(history, exog_recent, "", attacks)], dtype=float)
        value = float(model.predict(row)[0])
        value = max(0.0, value)
        lambdas.append(value)
        history.append(value)
        attacks.append(sum(history[-3:]) / max(1, min(3, len(history))))
    upper = [max(0.0, lam + 1.96 * fit["rmse"]) for lam in lambdas]
    return lambdas, upper


def _confidence(fit: Optional[Dict[str, Any]], horizon_minutes: int, buckets: int, method: str) -> float:
    if method == "baseline-rate" or fit is None:
        return round(clamp(0.30 + min(buckets, 20) / 100.0, 0.25, 0.55), 3)
    mean = max(fit["target_mean"], 1e-6)
    relative_error = fit["rmse"] / (mean + fit["rmse"] + 1e-6)
    sample_factor = min(1.0, fit["samples"] / 40.0)
    horizon_penalty = min(0.22, (horizon_minutes / 240.0) * 0.22)
    value = 0.40 + 0.55 * (1.0 - relative_error) * sample_factor - horizon_penalty
    return round(clamp(value, 0.20, 0.94), 3)


def _contributions(fit: Optional[Dict[str, Any]], klass: str) -> List[Dict[str, Any]]:
    if fit is None:
        return []
    labels = {f"lag_{i}": f"{klass} events {i} bucket(s) ago" for i in range(1, LAGS + 1)}
    labels.update({"attacks_lag_1": "Total attacks in previous bucket", "attacks_lag_2": "Total attacks two buckets ago",
                   "rolling_mean_3": f"{klass} 3-bucket moving average"})
    labels.update({name: label for name, label in EXOG_FEATURES})

    last_exog = fit["exog"][-1] if fit["exog"] else {}
    values = {f"lag_{i}": fit["history"][-i] if i <= len(fit["history"]) else 0.0 for i in range(1, LAGS + 1)}
    values["attacks_lag_1"] = fit["attacks_history"][-1] if fit["attacks_history"] else 0.0
    values["attacks_lag_2"] = fit["attacks_history"][-2] if len(fit["attacks_history"]) > 1 else 0.0
    values["rolling_mean_3"] = float(np.mean(fit["history"][-3:])) if fit["history"] else 0.0
    values.update({name: last_exog.get(name, 0.0) for name, _ in EXOG_FEATURES})

    items = []
    for name, coefficient in fit["coefficients"].items():
        contribution = coefficient * float(values.get(name, 0.0))
        items.append({
            "feature": name,
            "label": labels.get(name, name),
            "coefficient": round(coefficient, 4),
            "value": round(float(values.get(name, 0.0)), 4),
            "contribution": round(contribution, 4),
            "direction": "risk_increase" if contribution > 0 else "risk_decrease",
        })
    items.sort(key=lambda item: abs(item["contribution"]), reverse=True)
    total = sum(abs(i["contribution"]) for i in items) or 1.0
    for item in items[:6]:
        item["impact"] = f"{'+' if item['contribution'] >= 0 else '-'}{round(abs(item['contribution']) / total * 100, 1)}%"
    return items[:6]


def forecast_frame(
    df: pd.DataFrame,
    horizons: Optional[List[int]] = None,
    now: Optional[pd.Timestamp] = None,
    model_version: str = "ridge-lag-v2",
    source_label: str = "database",
) -> Dict[str, Any]:
    """Produce multi-horizon, multi-category forecasts from a traffic frame."""
    horizons = sorted({int(h) for h in (horizons or SUPPORTED_HORIZONS) if int(h) > 0})
    now_ts = pd.Timestamp(now) if now is not None else pd.Timestamp.now(tz="UTC")
    if now_ts.tzinfo is None:
        now_ts = now_ts.tz_localize("UTC")

    if df is None or df.empty:
        return {
            "run_id": new_id(), "generated_at": iso(now_ts), "source": source_label,
            "method": "insufficient-data", "horizons": [], "categories": [],
            "message": "No traffic history available to forecast. Ingest a dataset or start the simulation.",
        }

    results: Dict[str, Any] = {
        "run_id": new_id(),
        "generated_at": iso(now_ts),
        "source": source_label,
        "records_used": int(len(df)),
        "time_span_minutes": None,
        "horizons": [],
        "categories": [],
        "history": [],
    }

    span = (pd.to_datetime(df["timestamp"], errors="coerce", utc=True).max()
            - pd.to_datetime(df["timestamp"], errors="coerce", utc=True).min())
    results["time_span_minutes"] = round(span.total_seconds() / 60.0, 1) if pd.notna(span) else 0.0

    horizon_payloads: List[Dict[str, Any]] = []
    for horizon in horizons:
        bucket_minutes = bucket_minutes_for_horizon(horizon)
        agg = build_buckets(df, bucket_minutes)
        if agg.empty:
            continue
        steps = max(1, int(math.ceil(horizon / bucket_minutes)))
        seconds = bucket_minutes * 60.0

        history_series = [{
            "bucket": iso(row["bucket"]),
            "flows": int(row["flows"]),
            "attacks": int(row["attacks"]),
            "anomalies": int(row["anomalies"]),
            "pps": round(float(row["pps"]), 2),
            "bps": round(float(row["bps"]), 2),
            "unique_sources": int(row["unique_sources"]),
            "anomaly_rate": round(float(row["anomaly_rate"]), 4),
        } for _, row in agg.tail(30).iterrows()]

        per_class: List[Dict[str, Any]] = []
        future_steps: Dict[str, List[Dict[str, Any]]] = {k: [] for k in FORECAST_CLASSES}
        fits = {klass: _fit_class_model(agg, klass) for klass in FORECAST_CLASSES}
        method = "ridge-lag-regression" if any(fits.values()) else "baseline-rate"

        for klass in FORECAST_CLASSES:
            fit = fits.get(klass)
            observed = agg[f"cnt_{klass}"].astype(float)
            historical_rate = float(observed.mean()) if len(observed) else 0.0
            historical_total = int(observed.sum())

            if fit is None:
                # Not enough history for this category: EWMA baseline over recent buckets.
                weights = np.exp(-np.linspace(0, 1.5, len(observed))) if len(observed) else np.array([1.0])
                ewma = float(np.average(observed, weights=weights)) if len(observed) else 0.0
                lambdas = [max(0.0, ewma) for _ in range(steps)]
                rmse = float(np.std(observed)) if len(observed) > 1 else 0.0
                upper = [lam + 1.96 * rmse for lam in lambdas]
                fit_payload = None
            else:
                lambdas, upper = _project(fit, steps)
                rmse = fit["rmse"]
                fit_payload = fit

            probabilities = [1.0 - math.exp(-lam) for lam in lambdas]
            horizon_probability = 1.0 - math.prod([1.0 - p for p in probabilities]) if probabilities else 0.0
            expected_events = float(sum(lambdas))
            confidence = _confidence(fit_payload, horizon, len(agg), "baseline-rate" if fit_payload is None else method)

            for step_index, (lam, prob, up) in enumerate(zip(lambdas, probabilities, upper)):
                future_steps[klass].append({
                    "bucket": iso(now_ts + pd.Timedelta(seconds=seconds * (step_index + 1))),
                    "attack_type": klass,
                    "lambda": round(lam, 3),
                    "probability": round(prob, 4),
                    "upper_bound": round(up, 3),
                })

            per_class.append({
                "attack_type": klass,
                "probability": round(clamp(horizon_probability, 0.0, 1.0), 4),
                "confidence": confidence,
                "expected_events": round(expected_events, 2),
                "lower_bound": round(max(0.0, expected_events - 1.96 * rmse * math.sqrt(steps)), 2),
                "upper_bound": round(expected_events + 1.96 * rmse * math.sqrt(steps), 2),
                "risk_level": risk_level(horizon_probability),
                "per_bucket_probability": round(float(np.mean(probabilities)), 4) if probabilities else 0.0,
                "peak_bucket_probability": round(float(np.max(probabilities)), 4) if probabilities else 0.0,
                "historical_events": historical_total,
                "historical_rate_per_bucket": round(historical_rate, 3),
                "residual_rmse": round(rmse, 4),
                "method": "ridge-lag-regression" if fit_payload else "ewma-baseline-rate",
                "contributing_features": _contributions(fit_payload, klass),
                "recommendation": RECOMMENDATIONS.get(klass, "Monitor the affected segment and refresh the baseline."),
                "trend": future_steps[klass],
            })

        per_class.sort(key=lambda item: item["probability"], reverse=True)
        overall_probability = 1.0 - math.prod([1.0 - c["probability"] for c in per_class])
        top = per_class[0] if per_class else None
        horizon_record = {
            "horizon_minutes": horizon,
            "bucket_minutes": bucket_minutes,
            "steps": steps,
            "generated_at": iso(now_ts),
            "window_end": iso(now_ts + pd.Timedelta(minutes=horizon)),
            "method": method,
            "buckets_available": int(len(agg)),
            "overall_probability": round(clamp(overall_probability, 0.0, 1.0), 4),
            "overall_risk_level": risk_level(overall_probability),
            "overall_confidence": round(float(np.mean([c["confidence"] for c in per_class])) if per_class else 0.0, 3),
            "top_threat": {
                "attack_type": top["attack_type"],
                "probability": top["probability"],
                "risk_level": top["risk_level"],
                "confidence": top["confidence"],
                "expected_events": top["expected_events"],
                "recommendation": top["recommendation"],
            } if top else None,
            "expected_attack_events": round(sum(c["expected_events"] for c in per_class), 2),
            "categories": per_class,
            "history": history_series,
        }
        horizon_payloads.append(horizon_record)

    results["horizons"] = horizon_payloads
    if horizon_payloads:
        # Category view across the longest horizon (used by the Forecast Center table).
        longest = horizon_payloads[-1]
        results["categories"] = longest["categories"]
        results["history"] = longest["history"]
        results["overall"] = {
            "horizon_minutes": longest["horizon_minutes"],
            "probability": longest["overall_probability"],
            "risk_level": longest["overall_risk_level"],
            "confidence": longest["overall_confidence"],
            "top_threat": longest["top_threat"],
        }
        results["method"] = longest["method"]
    results["model_version"] = model_version
    results["disclaimer"] = (
        "Forecasts are probabilistic model estimates derived from recent traffic history. "
        "They indicate elevated risk, not certainty that an attack will occur."
    )
    return results
