"""
Analytics + dashboard aggregation.

All KPIs are computed from persisted records (traffic, predictions, alerts,
forecasts, ledger). Nothing on the dashboard is a hard-coded number.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from app.blockchain import ledger
from app.core.utils import iso, safe_float, utcnow, window_start
from app.ml.features import BENIGN
from app.services import alert_service, model_service, traffic_service
from app.services.simulation_service import engine as simulation_engine
from app.storage import get_store

logger = logging.getLogger("cyberforecast.analytics")

SEVERITY_WEIGHT = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _traffic_frame(window: str, limit: int = 20000) -> pd.DataFrame:
    filters: Dict[str, Any] = {}
    start = window_start(window)
    if start:
        filters["timestamp"] = {"$gte": start}
    rows, _ = get_store().list("traffic_records", filters=filters or None, order_by="-timestamp", limit=limit)
    if not rows:
        return pd.DataFrame()
    frame = pd.DataFrame(rows)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    frame["verdict"] = frame["predicted_attack_type"].fillna(frame.get("attack_type", BENIGN)).replace({"Unknown": BENIGN})
    return frame.dropna(subset=["timestamp"]).sort_values("timestamp")


def overview(window: str = "24h") -> Dict[str, Any]:
    """KPI card values + threat posture for the main dashboard."""
    store = get_store()
    frame = _traffic_frame(window)
    start = window_start(window) or (utcnow() - timedelta(hours=24))
    now = utcnow()
    span_seconds = max((now - start).total_seconds(), 1.0)

    alert_stats = alert_service.stats(since=start)
    integrity = ledger.stats()
    registry = model_service.registry_status()

    if frame.empty:
        return {
            "window": window,
            "generated_at": iso(now),
            "empty": True,
            "kpis": {
                "packets": 0, "traffic_bytes": 0, "active_connections": 0, "flows": 0,
                "detected_threats": 0, "critical_alerts": alert_stats["critical_open"],
                "anomalies": 0, "forecasted_attacks": 0, "current_risk_score": 0.0,
                "unique_sources": 0, "unique_destinations": 0, "packets_per_second": 0.0,
                "bytes_per_second": 0.0, "abnormal_percentage": 0.0,
            },
            "threat_level": "informational",
            "attack_distribution": [],
            "blockchain": integrity,
            "model": {"engine": registry["inference_engine"],
                      "active_classifier": registry["active_classifier"],
                      "active_anomaly_detector": registry["active_anomaly_detector"]},
            "simulation": simulation_engine.status(),
            "alerts": alert_stats,
            "message": "No traffic in this window. Start the simulation or upload a dataset to populate the dashboard.",
        }

    packets = int(frame["packet_count"].fillna(0).sum())
    byte_total = int(frame["byte_count"].fillna(0).sum())
    attacks = int((frame["verdict"] != BENIGN).sum())
    anomalies = int(frame["is_anomaly"].fillna(False).astype(bool).sum())

    # Forecast horizon expectation (real forecast rows, not a multiplier).
    forecast_rows, _ = store.list("forecasts", order_by="-created_at", limit=400)
    forecasted_attacks = 0.0
    if forecast_rows:
        latest_run = forecast_rows[0].get("run_id")
        latest = [r for r in forecast_rows if r.get("run_id") == latest_run and int(r.get("horizon_minutes") or 0) == 60]
        forecasted_attacks = round(sum(safe_float(r.get("expected_events")) for r in latest), 2)

    risk = frame["risk_score"].fillna(0).astype(float)
    recent = frame[frame["timestamp"] >= now - timedelta(minutes=5)]
    current_risk = round(float(recent["risk_score"].fillna(0).mean()) if not recent.empty else float(risk.iloc[-1]), 4)

    counts = frame["verdict"].value_counts()
    attack_distribution = [{"name": str(k), "value": int(v)} for k, v in counts.items() if k != BENIGN]

    labeled = frame[frame.get("attack_type", pd.Series(dtype=str)).astype(str).isin([BENIGN] + [c for c in counts.index if c != BENIGN])]
    labeled = labeled[labeled["attack_type"].astype(str) != "Unknown"]
    correctness = None
    if not labeled.empty:
        tp = int(((labeled["verdict"] != BENIGN) & (labeled["attack_type"] != BENIGN)).sum())
        tn = int(((labeled["verdict"] == BENIGN) & (labeled["attack_type"] == BENIGN)).sum())
        fp = int(((labeled["verdict"] != BENIGN) & (labeled["attack_type"] == BENIGN)).sum())
        fn = int(((labeled["verdict"] == BENIGN) & (labeled["attack_type"] != BENIGN)).sum())
        total = max(tp + tn + fp + fn, 1)
        correctness = {
            "labeled_rows": int(len(labeled)), "true_positives": tp, "true_negatives": tn,
            "false_positives": fp, "false_negatives": fn,
            "accuracy": round((tp + tn) / total, 4),
            "precision": round(tp / max(tp + fp, 1), 4),
            "recall": round(tp / max(tp + fn, 1), 4),
            "false_positive_rate": round(fp / max(fp + tn, 1), 4),
        }

    threat_level = _threat_level(current_risk, alert_stats["critical_open"])

    return {
        "window": window,
        "generated_at": iso(now),
        "empty": False,
        "kpis": {
            "packets": packets,
            "traffic_bytes": byte_total,
            "traffic_mbps": round(byte_total * 8 / span_seconds / 1e6, 3),
            "active_connections": int(frame["connection_count"].fillna(1).sum()),
            "flows": int(len(frame)),
            "detected_threats": attacks,
            "critical_alerts": alert_stats["critical_open"],
            "anomalies": anomalies,
            "forecasted_attacks": forecasted_attacks,
            "current_risk_score": current_risk,
            "mean_risk_score": round(float(risk.mean()), 4),
            "unique_sources": int(frame["source_ip"].nunique()),
            "unique_destinations": int(frame["destination_ip"].nunique()),
            "packets_per_second": round(packets / span_seconds, 2),
            "bytes_per_second": round(byte_total / span_seconds, 2),
            "abnormal_percentage": round((anomalies + attacks) / max(len(frame), 1) * 100, 2),
            "failed_connections": int(frame["failed_connections"].fillna(0).sum()),
        },
        "threat_level": threat_level,
        "attack_distribution": attack_distribution,
        "class_distribution": {str(k): int(v) for k, v in counts.items()},
        "correctness": correctness,
        "blockchain": integrity,
        "model": {
            "engine": registry["inference_engine"],
            "active_classifier": registry["active_classifier"],
            "active_anomaly_detector": registry["active_anomaly_detector"],
        },
        "simulation": simulation_engine.status(),
        "alerts": alert_stats,
        "data_origin": {
            "simulated_percentage": round(float(frame["is_simulated"].fillna(False).astype(bool).mean()) * 100, 1),
            "dataset_rows": int(frame["dataset_id"].notna().sum()) if "dataset_id" in frame else 0,
        },
    }


def _threat_level(risk: float, critical_alerts: int) -> str:
    level = traffic_service._threat_level(risk)
    if critical_alerts >= 5 and SEVERITY_WEIGHT[level] < 3:
        return "high"
    if critical_alerts >= 15:
        return "critical"
    return level


def trends(window: str = "24h", bucket: Optional[str] = None) -> Dict[str, Any]:
    """Time series + distributions for the Threat Analytics page."""
    frame = _traffic_frame(window)
    store = get_store()
    start = window_start(window) or (utcnow() - timedelta(hours=24))
    now = utcnow()
    span_minutes = max((now - start).total_seconds() / 60.0, 1.0)

    if bucket is None:
        bucket = "1min" if span_minutes <= 90 else ("10min" if span_minutes <= 1440 else "1h")

    payload: Dict[str, Any] = {
        "window": window, "bucket": bucket, "generated_at": iso(now),
        "attacks_over_time": [], "traffic_over_time": [], "anomaly_trend": [],
        "attack_by_category": [], "severity_distribution": [], "protocol_distribution": [],
        "region_distribution": [], "risk_distribution": [], "forecast_trend": [],
        "correctness": None,
    }

    alerts, alert_total = store.list("alerts", filters={"timestamp": {"$gte": start}}, order_by="-timestamp", limit=2000)
    severity_counts: Dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert.get("severity") or "informational"] = severity_counts.get(alert.get("severity") or "informational", 0) + 1
    payload["severity_distribution"] = [{"name": k, "value": v} for k, v in severity_counts.items()]
    payload["alerts_total"] = alert_total

    from app.services import forecast_service

    payload["forecast_trend"] = forecast_service.trend(limit=40)

    if frame.empty:
        payload["empty"] = True
        return payload

    frame["bucket"] = frame["timestamp"].dt.floor(bucket)
    grouped = frame.groupby("bucket")

    attacks_series = grouped.apply(lambda g: pd.Series({
        "attacks": int((g["verdict"] != BENIGN).sum()),
        "flows": int(len(g)),
        "anomalies": int(g["is_anomaly"].fillna(False).astype(bool).sum()),
        "packets": int(g["packet_count"].fillna(0).sum()),
        "bytes": int(g["byte_count"].fillna(0).sum()),
        "mean_risk": round(float(g["risk_score"].fillna(0).mean()), 4),
        "unique_sources": int(g["source_ip"].nunique()),
    }), include_groups=False)

    payload["attacks_over_time"] = [
        {"time": iso(index), "attacks": int(row["attacks"]), "flows": int(row["flows"])}
        for index, row in attacks_series.iterrows()
    ]
    payload["traffic_over_time"] = [
        {"time": iso(index), "packets": int(row["packets"]), "bytes": int(row["bytes"]),
         "megabits_per_second": round(row["bytes"] * 8 / (60 if bucket.endswith("min") else 3600) / 1e6, 3)}
        for index, row in attacks_series.iterrows()
    ]
    payload["anomaly_trend"] = [
        {"time": iso(index), "anomalies": int(row["anomalies"]), "mean_risk": float(row["mean_risk"]),
         "anomaly_rate": round(int(row["anomalies"]) / max(int(row["flows"]), 1), 4)}
        for index, row in attacks_series.iterrows()
    ]

    counts = frame["verdict"].value_counts()
    payload["attack_by_category"] = [{"name": str(k), "value": int(v)} for k, v in counts.items()]
    payload["protocol_distribution"] = [
        {"name": str(k), "value": int(v)} for k, v in frame["protocol"].fillna("OTHER").value_counts().head(10).items()
    ]

    from app.services.simulation_service import region_for_ip

    regions = frame.assign(region=frame["source_ip"].astype(str).apply(region_for_ip))
    region_group = regions.groupby("region").agg(
        flows=("id", "count"), attacks=("verdict", lambda s: int((s != BENIGN).sum()))
    ).reset_index().sort_values("attacks", ascending=False)
    payload["region_distribution"] = [
        {"region": str(row["region"]), "flows": int(row["flows"]), "attacks": int(row["attacks"])}
        for _, row in region_group.head(12).iterrows()
    ]

    risk_bins = pd.cut(frame["risk_score"].fillna(0), bins=[-0.01, 0.12, 0.28, 0.5, 0.75, 1.0],
                       labels=["informational", "low", "medium", "high", "critical"])
    payload["risk_distribution"] = [{"name": str(k), "value": int(v)} for k, v in risk_bins.value_counts().items()]

    labeled = frame[frame["attack_type"].astype(str) != "Unknown"]
    if not labeled.empty:
        tp = int(((labeled["verdict"] != BENIGN) & (labeled["attack_type"] != BENIGN)).sum())
        tn = int(((labeled["verdict"] == BENIGN) & (labeled["attack_type"] == BENIGN)).sum())
        fp = int(((labeled["verdict"] != BENIGN) & (labeled["attack_type"] == BENIGN)).sum())
        fn = int(((labeled["verdict"] == BENIGN) & (labeled["attack_type"] != BENIGN)).sum())
        payload["correctness"] = {
            "labeled_rows": int(len(labeled)), "true_positives": tp, "true_negatives": tn,
            "false_positives": fp, "false_negatives": fn,
            "accuracy": round((tp + tn) / max(tp + tn + fp + fn, 1), 4),
            "precision": round(tp / max(tp + fp, 1), 4),
            "recall": round(tp / max(tp + fn, 1), 4),
            "f1": round(2 * tp / max(2 * tp + fp + fn, 1), 4),
            "false_positive_rate": round(fp / max(fp + tn, 1), 4),
        }
    payload["empty"] = False
    return payload


def top_entities(window: str = "24h", limit: int = 10) -> Dict[str, Any]:
    frame = _traffic_frame(window)
    if frame.empty:
        return {"sources": [], "targets": [], "ports": [], "window": window}
    attacks = frame[frame["verdict"] != BENIGN]
    base = attacks if not attacks.empty else frame
    sources = base.groupby("source_ip").agg(flows=("id", "count"), attacks=("verdict", lambda s: int((s != BENIGN).sum())),
                                            packets=("packet_count", "sum"), risk=("risk_score", "mean"))
    targets = base.groupby("destination_ip").agg(flows=("id", "count"), attacks=("verdict", lambda s: int((s != BENIGN).sum())),
                                                 packets=("packet_count", "sum"), risk=("risk_score", "mean"))
    ports = base.groupby("destination_port").agg(flows=("id", "count"), attacks=("verdict", lambda s: int((s != BENIGN).sum())))
    return {
        "window": window,
        "sources": [{"ip": str(i), "flows": int(r["flows"]), "attacks": int(r["attacks"]),
                     "packets": int(r["packets"]), "risk": round(float(r["risk"] or 0), 4)}
                    for i, r in sources.sort_values("attacks", ascending=False).head(limit).iterrows()],
        "targets": [{"ip": str(i), "flows": int(r["flows"]), "attacks": int(r["attacks"]),
                     "packets": int(r["packets"]), "risk": round(float(r["risk"] or 0), 4)}
                    for i, r in targets.sort_values("attacks", ascending=False).head(limit).iterrows()],
        "ports": [{"port": int(i), "flows": int(r["flows"]), "attacks": int(r["attacks"])}
                  for i, r in ports.sort_values("attacks", ascending=False).head(limit).iterrows()],
    }
