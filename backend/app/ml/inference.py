"""
Inference service + model registry.

Loads the active artifacts from disk, caches them in memory, and turns
normalized traffic frames into predictions with probabilities, anomaly scores,
risk scores and explanations. When no trained model exists yet the service falls
back to a clearly-labelled heuristic baseline so the platform keeps working.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from app.core.config import settings
from app.core.utils import iso, safe_float, utcnow
from app.ml.features import BENIGN, build_feature_frame
from app.ml.scoring import risk_level, risk_score, severity_from_score
from app.ml.trainer import load_bundle
from app.ml.xai import explain_local
from app.storage import get_store

logger = logging.getLogger("cyberforecast.ml")

HEURISTIC_VERSION = "heuristic-baseline-v1"

_lock = threading.RLock()
_bundle_cache: Dict[str, Tuple[str, Optional[Dict[str, Any]]]] = {}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def active_model_record(task: str = "classification") -> Optional[Dict[str, Any]]:
    store = get_store()
    record = store.find_one("models", {"task": task, "is_active": True, "status": "trained"}, order_by="-trained_at")
    if record:
        return record
    return store.find_one("models", {"task": task, "status": "trained"}, order_by="-trained_at")


def bundle_for(record: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not record:
        return None
    model_id = str(record.get("id"))
    stamp = f"{record.get('trained_at')}:{record.get('artifact_path')}"
    with _lock:
        cached = _bundle_cache.get(model_id)
        if cached and cached[0] == stamp:
            return cached[1]
    bundle = load_bundle(record.get("artifact_path") or "")
    if bundle is None:
        logger.warning("Model %s has no loadable artifact at %s", model_id, record.get("artifact_path"))
    with _lock:
        _bundle_cache[model_id] = (stamp, bundle)
    return bundle


def active_bundle(task: str = "classification") -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    record = active_model_record(task)
    return record, bundle_for(record)


def invalidate_cache(model_id: Optional[str] = None) -> None:
    with _lock:
        if model_id:
            _bundle_cache.pop(str(model_id), None)
        else:
            _bundle_cache.clear()


# ---------------------------------------------------------------------------
# Heuristic fallback (only used when no trained artifact is available)
# ---------------------------------------------------------------------------

def heuristic_predict(row: pd.Series) -> Tuple[str, Dict[str, float], float]:
    pps = safe_float(row.get("packets_per_second"))
    bps = safe_float(row.get("bytes_per_second"))
    packets = safe_float(row.get("packet_count"))
    dst_port = safe_float(row.get("destination_port"))
    duration = safe_float(row.get("flow_duration"))
    failed_ratio = safe_float(row.get("failed_connection_ratio"))
    flags = str(row.get("tcp_flags", "")).upper()

    scores: Dict[str, float] = {c: 0.02 for c in ["DoS", "DDoS", "Port Scan", "Brute Force", "Bot Activity", "Intrusion", "Network Anomaly"]}
    scores[BENIGN] = 0.45  # benign is the prior; attack rules must beat it
    if pps > 800 or packets > 5000:
        scores["DDoS"] = 0.72 + min(0.25, pps / 8000)
    if 250 < pps <= 800:
        scores["DoS"] = 0.55
    if packets <= 4 and duration < 0.05 and flags in ("SYN", "XMAS", "NULL"):
        scores["Port Scan"] = 0.62
    if dst_port in (21, 22, 23, 3389) and (failed_ratio > 0.3 or packets > 120):
        scores["Brute Force"] = 0.58
    if dst_port in (4444, 6667, 6668, 6669, 9999, 1337, 31337):
        scores["Bot Activity"] = 0.66
    if bps > 2_000_000 and duration > 20:
        scores["Intrusion"] = max(scores["Intrusion"], 0.45)
    best = max(scores, key=lambda k: scores[k])
    if best != BENIGN and scores[best] <= scores[BENIGN]:
        best = BENIGN
    total = sum(scores.values()) or 1.0
    probabilities = {k: round(v / total, 4) for k, v in scores.items()}
    confidence = round(min(0.95, probabilities.get(best, 0.0) + 0.2), 4)
    return best, probabilities, confidence


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def _normalized_anomaly(raw: np.ndarray, bundle: Dict[str, Any]) -> np.ndarray:
    low = float(bundle.get("score_low", -0.5))
    high = float(bundle.get("score_high", 0.5))
    span = (high - low) or 1.0
    return np.clip((high - raw) / span, 0.0, 1.0)


def predict_frame(
    df: pd.DataFrame,
    classifier_record: Optional[Dict[str, Any]] = None,
    classifier_bundle: Optional[Dict[str, Any]] = None,
    anomaly_record: Optional[Dict[str, Any]] = None,
    anomaly_bundle: Optional[Dict[str, Any]] = None,
    explain: bool = True,
    max_explanations: int = 500,
) -> Dict[str, Any]:
    """Run the full inference pipeline over a normalized traffic frame."""
    if df.empty:
        return {"predictions": [], "summary": {}, "model": None, "engine": "none"}

    if classifier_bundle is None:
        classifier_record, classifier_bundle = active_bundle("classification")
    if anomaly_bundle is None:
        anomaly_record, anomaly_bundle = active_bundle("anomaly")

    using_model = classifier_bundle is not None
    pre = classifier_bundle.get("preprocessor") if using_model else None
    matrix, feature_names = build_feature_frame(df)
    engineered = matrix  # unscaled canonical matrix (used for explanations)

    if using_model:
        X = pre.transform(df) if hasattr(pre, "transform") else matrix.values
        estimator = classifier_bundle["estimator"]
        classes = list(getattr(estimator, "classes_", classifier_bundle.get("classes", [])))
        predictions_raw = estimator.predict(X)
        proba = estimator.predict_proba(X) if hasattr(estimator, "predict_proba") else None
        deviations = pre.deviations(df)
    else:
        X = matrix.values
        classes, predictions_raw, proba, deviations = [], [], None, None

    # Anomaly scores
    if anomaly_bundle is not None:
        anomaly_pre = anomaly_bundle["preprocessor"]
        Xa = anomaly_pre.transform(df)
        raw_scores = anomaly_bundle["estimator"].score_samples(Xa)
        anomaly_scores = _normalized_anomaly(raw_scores, anomaly_bundle)
        anomaly_flags = anomaly_bundle["estimator"].predict(Xa) == -1
    else:
        # Untrained fallback: deviation magnitude across engineered features.
        # A single-row frame (or a constant column) has no spread, so its std is
        # 0/NaN; those cells must count as "no evidence of deviation" instead of
        # poisoning the anomaly and risk scores with NaN.
        spread = matrix.std(axis=0, ddof=0).replace(0, np.nan)
        z = ((matrix - matrix.mean(axis=0)) / spread).abs().replace([np.inf, -np.inf], np.nan)
        deviation = z.max(axis=1).fillna(0.0)
        anomaly_scores = np.nan_to_num(np.clip(deviation.values / 8.0, 0.0, 1.0), nan=0.0, posinf=1.0, neginf=0.0)
        anomaly_flags = anomaly_scores > 0.6

    model_meta = {
        "engine": "ml" if using_model else "heuristic-fallback",
        "model_id": (classifier_record or {}).get("id") if using_model else None,
        "model_name": (classifier_record or {}).get("name") if using_model else "Heuristic baseline",
        "model_version": (classifier_record or {}).get("version") if using_model else HEURISTIC_VERSION,
        "algorithm": (classifier_record or {}).get("algorithm") if using_model else "rule-based",
        "anomaly_model_id": (anomaly_record or {}).get("id") if anomaly_bundle else None,
        "anomaly_algorithm": "isolation_forest" if anomaly_bundle else "deviation-heuristic",
        "classes": classes or sorted({BENIGN, "DoS", "DDoS", "Port Scan", "Brute Force", "Bot Activity", "Intrusion", "Network Anomaly"}),
        "note": None if using_model else "No trained model is active yet - results come from a transparent heuristic baseline. Train a model in the ML Model Center for real inference.",
    }

    results: List[Dict[str, Any]] = []
    truth = df["attack_type"].astype(str).tolist() if "attack_type" in df.columns else [None] * len(df)

    for index in range(len(df)):
        if using_model:
            row_proba = {str(c): float(p) for c, p in zip(classes, proba[index])} if proba is not None else {}
            attack_type = str(predictions_raw[index])
            confidence = round(float(row_proba.get(attack_type, 0.0)), 4) if row_proba else 0.5
        else:
            attack_type, row_proba, confidence = heuristic_predict(engineered.iloc[index])

        attack_probability = round(1.0 - float(row_proba.get(BENIGN, 0.0 if attack_type != BENIGN else 1.0)), 4)
        anomaly = round(float(anomaly_scores[index]), 4)
        score = risk_score(attack_probability, anomaly, attack_type)
        level = risk_level(score)
        is_anomaly = bool(anomaly_flags[index]) or (attack_type != BENIGN and score >= 0.5)

        record = df.iloc[index]
        explanation = None
        if explain and index < max_explanations:
            if using_model:
                explanation = explain_local(
                    classifier_bundle, engineered.iloc[index], deviations.iloc[index],
                    attack_type, row_proba, anomaly_score=anomaly,
                )
            else:
                explanation = {
                    "method": "heuristic rule trace",
                    "predicted_attack": attack_type,
                    "probabilities": row_proba,
                    "anomaly_score": anomaly,
                    "summary": f"Rule-based baseline classified this flow as '{attack_type}' (confidence {confidence:.2f}).",
                    "contributions": [],
                    "global_feature_importance": [],
                    "disclaimer": model_meta["note"],
                }

        results.append({
            "timestamp": iso(record.get("timestamp")),
            "attack_type": attack_type,
            "confidence": confidence,
            "probabilities": {k: round(v, 4) for k, v in row_proba.items()},
            "attack_probability": attack_probability,
            "risk_score": score,
            "risk_level": level,
            "severity": severity_from_score(score, attack_type),
            "anomaly_score": anomaly,
            "is_anomaly": is_anomaly,
            "is_attack": attack_type != BENIGN,
            "true_attack_type": truth[index] if truth[index] not in (None, "Unknown", "nan") else None,
            "source_ip": str(record.get("source_ip", "")),
            "destination_ip": str(record.get("destination_ip", "")),
            "source_port": int(safe_float(record.get("source_port"))),
            "destination_port": int(safe_float(record.get("destination_port"))),
            "protocol": str(record.get("protocol", "")),
            "tcp_flags": str(record.get("tcp_flags", "")),
            "packet_count": int(safe_float(record.get("packet_count"))),
            "byte_count": int(safe_float(record.get("byte_count"))),
            "packets_per_second": round(safe_float(record.get("packets_per_second")), 3),
            "bytes_per_second": round(safe_float(record.get("bytes_per_second")), 3),
            "flow_duration": round(safe_float(record.get("flow_duration")), 4),
            "explanation": explanation,
        })

    summary = summarize(results)
    summary["engine"] = model_meta["engine"]
    return {"predictions": results, "summary": summary, "model": model_meta}


def summarize(predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not predictions:
        return {"rows": 0}
    frame = pd.DataFrame(predictions)
    counts = frame["attack_type"].value_counts().to_dict()
    labeled = frame[frame["true_attack_type"].notna()]
    correctness = None
    if not labeled.empty:
        correct = int((labeled["attack_type"] == labeled["true_attack_type"]).sum())
        correctness = {
            "labeled_rows": int(len(labeled)),
            "correct": correct,
            "accuracy": round(correct / len(labeled), 4),
            "false_positives": int(((labeled["attack_type"] != BENIGN) & (labeled["true_attack_type"] == BENIGN)).sum()),
            "false_negatives": int(((labeled["attack_type"] == BENIGN) & (labeled["true_attack_type"] != BENIGN)).sum()),
            "true_positives": int(((labeled["attack_type"] != BENIGN) & (labeled["true_attack_type"] != BENIGN)).sum()),
            "true_negatives": int(((labeled["attack_type"] == BENIGN) & (labeled["true_attack_type"] == BENIGN)).sum()),
        }
    return {
        "rows": int(len(frame)),
        "attacks_detected": int((frame["attack_type"] != BENIGN).sum()),
        "anomalies": int(frame["is_anomaly"].sum()),
        "attack_rate": round(float((frame["attack_type"] != BENIGN).mean()), 4),
        "mean_risk_score": round(float(frame["risk_score"].mean()), 4),
        "max_risk_score": round(float(frame["risk_score"].max()), 4),
        "mean_confidence": round(float(frame["confidence"].mean()), 4),
        "class_distribution": {str(k): int(v) for k, v in counts.items()},
        "risk_levels": frame["risk_level"].value_counts().to_dict(),
        "correctness": correctness,
        "evaluated_at": iso(utcnow()),
    }


def predict_records(records: List[Dict[str, Any]], explain: bool = True) -> Dict[str, Any]:
    """Convenience wrapper: list of raw dicts -> predictions."""
    from app.ml.features import normalize_frame, detect_columns

    if not records:
        return {"predictions": [], "summary": {"rows": 0}, "model": None}
    raw = pd.DataFrame(records)
    normalized = normalize_frame(raw, detect_columns(raw))
    return predict_frame(normalized, explain=explain)
