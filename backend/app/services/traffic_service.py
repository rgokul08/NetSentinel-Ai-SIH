"""
Traffic query service: live monitor metrics, summaries, timelines and the
abstracted threat map. Every number is computed from persisted records.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from app.core.utils import iso, mask_ip, safe_float, utcnow, window_start
from app.ml.features import BENIGN
from app.services.simulation_service import region_for_ip
from app.storage import get_store

logger = logging.getLogger("cyberforecast.traffic")

MAX_WINDOW_ROWS = 8000


def _fetch(window: Optional[str] = "1h", limit: int = MAX_WINDOW_ROWS,
           source: Optional[str] = None, extra_filters: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
    filters: Dict[str, Any] = dict(extra_filters or {})
    start = window_start(window)
    if start:
        filters["timestamp"] = {"$gte": start}
    if source:
        filters["source"] = source
    rows, total = get_store().list("traffic_records", filters=filters or None, order_by="-timestamp", limit=limit)
    if not rows:
        return pd.DataFrame()
    frame = pd.DataFrame(rows)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    frame = frame.dropna(subset=["timestamp"]).sort_values("timestamp")
    frame["_total"] = total
    return frame


def verdict(row: pd.Series) -> str:
    return str(row.get("predicted_attack_type") or row.get("attack_type") or BENIGN)


def live_snapshot(window: str = "5m", source: Optional[str] = None) -> Dict[str, Any]:
    """Metrics for the Live Network Monitor page."""
    frame = _fetch(window=window, source=source)
    now = utcnow()
    start = window_start(window, now) or (now - timedelta(minutes=5))
    span_seconds = max((now - start).total_seconds(), 1.0)

    if frame.empty:
        return {
            "status": "idle",
            "window": window,
            "window_seconds": round(span_seconds, 1),
            "flows": 0,
            "packets": 0,
            "bytes": 0,
            "packets_per_second": 0.0,
            "bytes_per_second": 0.0,
            "mbps": 0.0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "connection_count": 0,
            "abnormal_percentage": 0.0,
            "anomalies": 0,
            "attacks": 0,
            "mean_risk_score": 0.0,
            "current_risk_score": 0.0,
            "threat_level": "informational",
            "protocol_distribution": [],
            "layer_distribution": [],
            "flag_distribution": [],
            "attack_distribution": [],
            "top_sources": [],
            "top_destinations": [],
            "timeline": [],
            "simulated_percentage": 0.0,
            "data_origin": "none",
            "generated_at": iso(now),
            "message": "No traffic in this window yet. Start the simulation or upload a dataset.",
        }

    packets = int(frame["packet_count"].fillna(0).sum())
    byte_total = int(frame["byte_count"].fillna(0).sum())
    connections = int(frame["connection_count"].fillna(1).sum())
    anomalies = int(frame["is_anomaly"].fillna(False).astype(bool).sum())
    verdicts = frame.apply(verdict, axis=1)
    attacks = int((verdicts != BENIGN).sum())
    risk = frame["risk_score"].fillna(0.0).astype(float)

    # Recency-weighted "current" risk: last 2 minutes weigh double.
    recent_mask = frame["timestamp"] >= (now - timedelta(minutes=2))
    current_risk = float(np.average(risk[recent_mask], weights=np.linspace(1.0, 2.0, int(recent_mask.sum())))
                         ) if int(recent_mask.sum()) > 1 else float(risk.iloc[-1] if len(risk) else 0.0)

    protocol_counts = frame["protocol"].fillna("OTHER").value_counts().to_dict()
    flag_counts = frame["tcp_flags"].fillna("OTHER").value_counts().to_dict()
    attack_counts = verdicts.value_counts().to_dict()
    layer = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
    for protocol, count in protocol_counts.items():
        key = str(protocol).upper()
        if key in ("TCP", "HTTP", "HTTPS", "SSH"):
            layer["TCP"] += int(count)
        elif key in ("UDP", "DNS"):
            layer["UDP"] += int(count)
        elif key == "ICMP":
            layer["ICMP"] += int(count)
        else:
            layer["OTHER"] += int(count)

    top_sources = (
        frame.assign(_pkts=frame["packet_count"].fillna(0))
        .groupby("source_ip")["_pkts"].sum().sort_values(ascending=False).head(8)
    )
    top_destinations = (
        frame.assign(_pkts=frame["packet_count"].fillna(0))
        .groupby("destination_ip")["_pkts"].sum().sort_values(ascending=False).head(8)
    )

    bucket = "10s" if span_seconds <= 600 else ("1min" if span_seconds <= 7200 else "10min")
    series = frame.set_index("timestamp")
    timeline_frame = pd.DataFrame({
        "packets": series["packet_count"].resample(bucket).sum(),
        "bytes": series["byte_count"].resample(bucket).sum(),
        "flows": series["packet_count"].resample(bucket).count(),
        "risk": series["risk_score"].resample(bucket).mean(),
        "anomalies": series["is_anomaly"].resample(bucket).sum(),
    }).fillna(0.0).tail(90)
    timeline = [{
        "time": iso(index),
        "packets": int(row["packets"]),
        "bytes": int(row["bytes"]),
        "flows": int(row["flows"]),
        "packets_per_second": round(float(row["packets"]) / (10 if bucket == "10s" else (60 if bucket == "1min" else 600)), 2),
        "megabits_per_second": round(float(row["bytes"]) * 8 / (10 if bucket == "10s" else (60 if bucket == "1min" else 600)) / 1e6, 3),
        "mean_risk": round(float(row["risk"]), 4),
        "anomalies": int(row["anomalies"]),
    } for index, row in timeline_frame.iterrows()]

    simulated = float(frame["is_simulated"].fillna(False).astype(bool).mean())

    return {
        "status": "streaming" if len(frame) else "idle",
        "window": window,
        "window_seconds": round(span_seconds, 1),
        "bucket": bucket,
        "flows": int(len(frame)),
        "total_flows_in_window": int(frame["_total"].iloc[0]) if "_total" in frame else int(len(frame)),
        "packets": packets,
        "bytes": byte_total,
        "packets_per_second": round(packets / span_seconds, 2),
        "bytes_per_second": round(byte_total / span_seconds, 2),
        "mbps": round(byte_total * 8 / span_seconds / 1e6, 3),
        "unique_sources": int(frame["source_ip"].nunique()),
        "unique_destinations": int(frame["destination_ip"].nunique()),
        "connection_count": connections,
        "anomalies": anomalies,
        "attacks": attacks,
        "abnormal_percentage": round((anomalies + attacks) / max(len(frame), 1) * 100, 2),
        "mean_risk_score": round(float(risk.mean()), 4),
        "current_risk_score": round(float(current_risk), 4),
        "threat_level": _threat_level(float(current_risk)),
        "protocol_distribution": [{"name": str(k), "value": int(v)} for k, v in protocol_counts.items()],
        "layer_distribution": [{"name": k, "value": v} for k, v in layer.items() if v],
        "flag_distribution": [{"name": str(k), "value": int(v)} for k, v in flag_counts.items()],
        "attack_distribution": [{"name": str(k), "value": int(v)} for k, v in attack_counts.items()],
        "top_sources": [{"ip": str(ip), "masked": mask_ip(str(ip)), "region": region_for_ip(str(ip)),
                         "packets": int(value)} for ip, value in top_sources.items()],
        "top_destinations": [{"ip": str(ip), "masked": mask_ip(str(ip)), "region": region_for_ip(str(ip)),
                              "packets": int(value)} for ip, value in top_destinations.items()],
        "timeline": timeline,
        "simulated_percentage": round(simulated * 100, 1),
        "data_origin": "simulation" if simulated > 0.9 else ("mixed" if simulated > 0 else "dataset"),
        "window_start": iso(start),
        "generated_at": iso(now),
    }


def _threat_level(score: float) -> str:
    if score >= 0.75:
        return "critical"
    if score >= 0.5:
        return "high"
    if score >= 0.28:
        return "medium"
    if score >= 0.12:
        return "low"
    return "informational"


def summary(window: str = "24h", source: Optional[str] = None) -> Dict[str, Any]:
    """Traffic summary used by the dashboard KPI cards and reports."""
    frame = _fetch(window=window, source=source)
    now = utcnow()
    start = window_start(window, now) or (now - timedelta(hours=24))
    span_seconds = max((now - start).total_seconds(), 1.0)
    if frame.empty:
        return {
            "window": window, "flows": 0, "packets": 0, "bytes": 0, "unique_sources": 0,
            "unique_destinations": 0, "attacks": 0, "anomalies": 0, "benign": 0,
            "attack_rate": 0.0, "mean_risk_score": 0.0, "packets_per_second": 0.0,
            "bytes_per_second": 0.0, "top_attack": None, "generated_at": iso(now),
        }
    verdicts = frame.apply(verdict, axis=1)
    counts = verdicts.value_counts()
    attacks = int((verdicts != BENIGN).sum())
    return {
        "window": window,
        "window_seconds": round(span_seconds, 1),
        "flows": int(len(frame)),
        "packets": int(frame["packet_count"].fillna(0).sum()),
        "bytes": int(frame["byte_count"].fillna(0).sum()),
        "packets_per_second": round(float(frame["packet_count"].fillna(0).sum()) / span_seconds, 2),
        "bytes_per_second": round(float(frame["byte_count"].fillna(0).sum()) / span_seconds, 2),
        "unique_sources": int(frame["source_ip"].nunique()),
        "unique_destinations": int(frame["destination_ip"].nunique()),
        "connection_count": int(frame["connection_count"].fillna(1).sum()),
        "failed_connections": int(frame["failed_connections"].fillna(0).sum()),
        "attacks": attacks,
        "anomalies": int(frame["is_anomaly"].fillna(False).astype(bool).sum()),
        "benign": int(counts.get(BENIGN, 0)),
        "attack_rate": round(attacks / max(len(frame), 1), 4),
        "mean_risk_score": round(float(frame["risk_score"].fillna(0).mean()), 4),
        "max_risk_score": round(float(frame["risk_score"].fillna(0).max()), 4),
        "top_attack": str(counts.drop(BENIGN, errors="ignore").idxmax()) if attacks else None,
        "class_distribution": {str(k): int(v) for k, v in counts.items()},
        "simulated_percentage": round(float(frame["is_simulated"].fillna(False).astype(bool).mean()) * 100, 1),
        "generated_at": iso(now),
    }


def recent_events(limit: int = 25, source: Optional[str] = None) -> List[Dict[str, Any]]:
    """Recently analyzed flows for the dashboard "Live Activity" panel."""
    frame = _fetch(window=None, limit=limit, source=source)
    if frame.empty:
        return []
    events = []
    for _, row in frame.tail(limit).iloc[::-1].iterrows():
        events.append({
            "record_id": row.get("id"),
            "timestamp": iso(row.get("timestamp")),
            "source_ip": row.get("source_ip"),
            "destination_ip": row.get("destination_ip"),
            "destination_port": int(safe_float(row.get("destination_port"))),
            "protocol": row.get("protocol"),
            "packet_count": int(safe_float(row.get("packet_count"))),
            "byte_count": int(safe_float(row.get("byte_count"))),
            "packets_per_second": round(safe_float(row.get("packets_per_second")), 2),
            "verdict": verdict(row),
            "ground_truth": row.get("attack_type") if row.get("attack_type") != "Unknown" else None,
            "risk_score": round(safe_float(row.get("risk_score")), 4),
            "risk_level": (row.get("risk_level") or "LOW").lower(),
            "anomaly_score": round(safe_float(row.get("anomaly_score")), 4),
            "is_anomaly": bool(row.get("is_anomaly")),
            "model_version": row.get("model_version"),
            "source": row.get("source"),
            "is_simulated": bool(row.get("is_simulated")),
        })
    return events


def list_records(limit: int = 50, offset: int = 0, window: Optional[str] = "24h",
                 attack_type: Optional[str] = None, risk_level: Optional[str] = None,
                 anomalies_only: bool = False, source: Optional[str] = None,
                 search: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
    filters: Dict[str, Any] = {}
    start = window_start(window)
    if start:
        filters["timestamp"] = {"$gte": start}
    if attack_type:
        filters["predicted_attack_type"] = attack_type
    if risk_level:
        filters["risk_level"] = risk_level.upper()
    if anomalies_only:
        filters["is_anomaly"] = True
    if source:
        filters["source"] = source
    rows, total = get_store().list(
        "traffic_records", filters=filters or None, order_by="-timestamp", limit=limit, offset=offset,
        search=search, search_fields=["source_ip", "destination_ip", "protocol", "predicted_attack_type"],
    )
    return rows, total


def threat_map(window: str = "24h", limit: int = 40) -> Dict[str, Any]:
    """Abstracted source/target visualization (no raw IPs exposed by default)."""
    frame = _fetch(window=window)
    if frame.empty:
        return {"nodes": [], "links": [], "regions": [], "window": window, "generated_at": iso(utcnow())}

    frame["verdict"] = frame.apply(verdict, axis=1)
    frame["region"] = frame["source_ip"].astype(str).apply(region_for_ip)

    nodes: List[Dict[str, Any]] = []
    for ip, group in frame.groupby("source_ip"):
        attacks = int((group["verdict"] != BENIGN).sum())
        nodes.append({
            "id": str(ip), "masked": mask_ip(str(ip)), "region": region_for_ip(str(ip)),
            "role": "source", "flows": int(len(group)), "attacks": attacks,
            "packets": int(group["packet_count"].fillna(0).sum()),
            "risk": round(float(group["risk_score"].fillna(0).mean()), 4),
        })
    for ip, group in frame.groupby("destination_ip"):
        attacks = int((group["verdict"] != BENIGN).sum())
        nodes.append({
            "id": str(ip), "masked": mask_ip(str(ip)), "region": region_for_ip(str(ip)),
            "role": "target", "flows": int(len(group)), "attacks": attacks,
            "packets": int(group["packet_count"].fillna(0).sum()),
            "risk": round(float(group["risk_score"].fillna(0).mean()), 4),
        })
    nodes.sort(key=lambda item: (item["attacks"], item["flows"]), reverse=True)

    links = (
        frame.groupby(["source_ip", "destination_ip", "verdict"])
        .agg(flows=("id", "count"), packets=("packet_count", "sum"), risk=("risk_score", "mean"))
        .reset_index()
        .sort_values("flows", ascending=False)
        .head(limit)
    )
    link_payload = [{
        "source": str(row["source_ip"]), "target": str(row["destination_ip"]),
        "attack_type": str(row["verdict"]), "flows": int(row["flows"]),
        "packets": int(row["packets"]), "risk": round(float(row["risk"] or 0.0), 4),
        "is_attack": str(row["verdict"]) != BENIGN,
        "source_region": region_for_ip(str(row["source_ip"])),
    } for _, row in links.iterrows()]

    regions = (
        frame.groupby("region")
        .agg(flows=("id", "count"), attacks=("verdict", lambda s: int((s != BENIGN).sum())),
             packets=("packet_count", "sum"), risk=("risk_score", "mean"))
        .reset_index().sort_values("attacks", ascending=False)
    )
    region_payload = [{
        "region": str(row["region"]), "flows": int(row["flows"]), "attacks": int(row["attacks"]),
        "packets": int(row["packets"]), "risk": round(float(row["risk"] or 0.0), 4),
    } for _, row in regions.iterrows()]

    return {
        "nodes": nodes[: limit * 2],
        "links": link_payload,
        "regions": region_payload,
        "window": window,
        "privacy": "IP addresses are abstracted to /16 prefixes and mapped to synthetic regions; raw IPs are only shown to admin/analyst roles.",
        "generated_at": iso(utcnow()),
    }


def timeline(window: str = "24h", limit: int = 120) -> Dict[str, Any]:
    """Interactive attack timeline built from real records."""
    frame = _fetch(window=window)
    events: List[Dict[str, Any]] = []

    if not frame.empty:
        frame["verdict"] = frame.apply(verdict, axis=1)
        attacks = frame[frame["verdict"] != BENIGN]
        for _, row in attacks.tail(limit).iterrows():
            events.append({
                "id": str(row.get("id")),
                "type": "attack",
                "timestamp": iso(row.get("timestamp")),
                "title": f"{row['verdict']} detected",
                "severity": (row.get("risk_level") or "MEDIUM").lower(),
                "attack_type": str(row["verdict"]),
                "source_ip": row.get("source_ip"),
                "destination_ip": row.get("destination_ip"),
                "destination_port": int(safe_float(row.get("destination_port"))),
                "risk_score": round(safe_float(row.get("risk_score")), 4),
                "is_simulated": bool(row.get("is_simulated")),
                "detail": {
                    "packets": int(safe_float(row.get("packet_count"))),
                    "bytes": int(safe_float(row.get("byte_count"))),
                    "pps": round(safe_float(row.get("packets_per_second")), 2),
                    "protocol": row.get("protocol"),
                    "tcp_flags": row.get("tcp_flags"),
                    "model_version": row.get("model_version"),
                },
            })
        anomalies = frame[frame["is_anomaly"].fillna(False).astype(bool) & (frame["verdict"] == BENIGN)]
        for _, row in anomalies.tail(limit // 2).iterrows():
            events.append({
                "id": str(row.get("id")),
                "type": "anomaly",
                "timestamp": iso(row.get("timestamp")),
                "title": "Statistical anomaly",
                "severity": "medium" if safe_float(row.get("anomaly_score")) > 0.6 else "low",
                "attack_type": "Network Anomaly",
                "source_ip": row.get("source_ip"),
                "destination_ip": row.get("destination_ip"),
                "risk_score": round(safe_float(row.get("risk_score")), 4),
                "is_simulated": bool(row.get("is_simulated")),
                "detail": {"anomaly_score": round(safe_float(row.get("anomaly_score")), 4),
                           "protocol": row.get("protocol")},
            })

    alerts, _ = get_store().list("alerts", order_by="-timestamp", limit=max(20, limit // 3))
    start = window_start(window)
    for alert in alerts:
        if start and alert.get("timestamp") and pd.Timestamp(alert["timestamp"]) < start:
            continue
        events.append({
            "id": str(alert.get("id")),
            "type": "alert",
            "timestamp": alert.get("timestamp"),
            "title": alert.get("title"),
            "severity": alert.get("severity"),
            "attack_type": alert.get("attack_type"),
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
            "risk_score": alert.get("risk_score"),
            "status": alert.get("status"),
            "is_simulated": bool(alert.get("is_simulated")),
            "detail": {"alert_code": alert.get("alert_code"), "origin": alert.get("origin"),
                       "blockchain_status": alert.get("blockchain_status"),
                       "recommendation": alert.get("recommendation")},
        })

    forecasts, _ = get_store().list("forecasts", filters={"attack_type": {"$ne": BENIGN}}, order_by="-created_at", limit=200)
    seen_runs = set()
    for row in forecasts:
        run = row.get("run_id")
        if run in seen_runs:
            continue
        seen_runs.add(run)
        events.append({
            "id": str(row.get("id")),
            "type": "forecast",
            "timestamp": row.get("created_at"),
            "title": f"Forecast: {row.get('attack_type')} risk {round(safe_float(row.get('probability')) * 100)}%",
            "severity": (row.get("risk_level") or "medium"),
            "attack_type": row.get("attack_type"),
            "risk_score": round(safe_float(row.get("probability")), 4),
            "is_simulated": bool(row.get("is_simulated")),
            "detail": {"horizon_minutes": row.get("horizon_minutes"), "confidence": row.get("confidence"),
                       "recommendation": row.get("recommendation")},
        })

    events.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return {
        "events": events[:limit],
        "window": window,
        "counts": {
            "attacks": sum(1 for e in events if e["type"] == "attack"),
            "anomalies": sum(1 for e in events if e["type"] == "anomaly"),
            "alerts": sum(1 for e in events if e["type"] == "alert"),
            "forecasts": sum(1 for e in events if e["type"] == "forecast"),
        },
        "generated_at": iso(utcnow()),
    }
