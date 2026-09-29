"""
The analysis pipeline shared by every ingestion path.

    normalized traffic frame
      -> ML inference (classifier + anomaly detector)
      -> risk scoring
      -> persistence (traffic_records + predictions)
      -> alert engine
      -> integrity ledger

Dataset uploads, the simulation engine and manual flow analysis all call into
`analyze_frame`, so simulated and uploaded data are analyzed identically.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import pandas as pd

from app.blockchain import ledger
from app.core.utils import iso, new_id, safe_int, utcnow
from app.ml.features import BENIGN
from app.ml.inference import predict_frame, predict_records
from app.services import alert_service
from app.storage import get_store

logger = logging.getLogger("cyberforecast.pipeline")

ALERT_DESCRIPTIONS = {
    "DDoS": "Distributed flood pattern: sustained packet surge from many sources towards a single target, matching volumetric DDoS behaviour.",
    "DoS": "Denial-of-service pattern: a single source is saturating the target service with an abnormal request rate.",
    "Port Scan": "Reconnaissance pattern: ultra-short flows probing sequential service ports with scan-like TCP flag combinations.",
    "Brute Force": "Credential attack pattern: repeated authentication attempts against a login-capable service, with a high failure ratio.",
    "Bot Activity": "Command-and-control pattern: periodic low-volume beaconing towards a port commonly used by botnets.",
    "Intrusion": "Intrusion pattern: sustained high-throughput session to an external endpoint consistent with exfiltration or exploit traffic.",
    "Network Anomaly": "Statistical anomaly: the flow deviates strongly from the trained traffic baseline without matching a known attack signature.",
}


def analyze_frame(
    frame: pd.DataFrame,
    dataset_id: Optional[str] = None,
    source: str = "dataset",
    persist: bool = True,
    create_alerts: bool = True,
    explain: bool = True,
    max_explanations: int = 500,
    user: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run inference over a normalized frame and optionally persist the results."""
    if frame is None or frame.empty:
        return {"predictions": [], "summary": {"rows": 0}, "model": None, "persisted": 0, "alerts_created": 0}

    result = predict_frame(frame, explain=explain, max_explanations=max_explanations)
    predictions = result["predictions"]
    model_meta = result["model"] or {}
    is_simulated = source in ("simulation", "demo")

    persisted = 0
    alerts_created = 0
    alerts_suppressed = 0

    if persist:
        store = get_store()
        traffic_rows: List[Dict[str, Any]] = []
        prediction_rows: List[Dict[str, Any]] = []
        record_ids: List[str] = []
        prediction_ids: List[str] = []

        for index, prediction in enumerate(predictions):
            row = frame.iloc[index]
            record_id = new_id()
            prediction_id = new_id()
            record_ids.append(record_id)
            prediction_ids.append(prediction_id)

            truth = prediction.get("true_attack_type")
            traffic_rows.append({
                "id": record_id,
                "dataset_id": dataset_id,
                "timestamp": prediction.get("timestamp") or iso(utcnow()),
                "source_ip": prediction.get("source_ip"),
                "destination_ip": prediction.get("destination_ip"),
                "source_port": prediction.get("source_port"),
                "destination_port": prediction.get("destination_port"),
                "protocol": prediction.get("protocol"),
                "packet_count": safe_int(row.get("packet_count"), 1),
                "byte_count": safe_int(row.get("byte_count"), 0),
                "packet_length": float(row.get("packet_length") or 0.0),
                "flow_duration": float(row.get("flow_duration") or 0.0),
                "packets_per_second": float(row.get("packets_per_second") or 0.0),
                "bytes_per_second": float(row.get("bytes_per_second") or 0.0),
                "connection_count": safe_int(row.get("connection_count"), 1),
                "tcp_flags": prediction.get("tcp_flags"),
                "failed_connections": safe_int(row.get("failed_connections"), 0),
                "request_frequency": float(row.get("request_frequency") or 0.0),
                "attack_type": truth or "Unknown",
                "predicted_attack_type": prediction.get("attack_type"),
                "prediction_id": prediction_id,
                "model_version": model_meta.get("model_version"),
                "is_labeled": bool(truth),
                "is_anomaly": bool(prediction.get("is_anomaly")),
                "anomaly_score": float(prediction.get("anomaly_score") or 0.0),
                "risk_score": float(prediction.get("risk_score") or 0.0),
                "risk_level": (prediction.get("risk_level") or "low").upper(),
                "source": source,
                "is_simulated": is_simulated,
            })

            prediction_rows.append({
                "id": prediction_id,
                "timestamp": prediction.get("timestamp") or iso(utcnow()),
                "traffic_record_id": record_id,
                "dataset_id": dataset_id,
                "attack_type": prediction.get("attack_type"),
                "confidence": float(prediction.get("confidence") or 0.0),
                "risk_score": float(prediction.get("risk_score") or 0.0),
                "risk_level": (prediction.get("risk_level") or "low").upper(),
                "anomaly_score": float(prediction.get("anomaly_score") or 0.0),
                "is_anomaly": bool(prediction.get("is_anomaly")),
                "probabilities": prediction.get("probabilities") or {},
                "explanation": prediction.get("explanation") or {},
                "model_id": model_meta.get("model_id"),
                "model_version": model_meta.get("model_version") or "",
                "is_correct": (prediction.get("attack_type") == truth) if truth else None,
                "true_attack_type": truth,
                "source": source,
                "is_simulated": is_simulated,
            })

        persisted = store.create_many("traffic_records", traffic_rows)
        store.create_many("predictions", prediction_rows)

    if create_alerts:
        for index, prediction in enumerate(predictions):
            attack_type = prediction.get("attack_type") or BENIGN
            severity = prediction.get("severity") or "informational"
            if not alert_service.should_alert(severity, attack_type):
                continue
            explanation = prediction.get("explanation") or {}
            drivers = ", ".join(
                f"{item['label']} {item['impact']}" for item in (explanation.get("contributions") or [])[:3]
            ) or "model probability"
            alert, suppressed = alert_service.raise_alert(
                attack_type=attack_type,
                severity=severity,
                risk_score=prediction.get("risk_score") or 0.0,
                confidence=prediction.get("confidence") or 0.0,
                description=(
                    f"{ALERT_DESCRIPTIONS.get(attack_type, 'Abnormal traffic detected')} "
                    f"Model confidence {round((prediction.get('confidence') or 0) * 100)}%, "
                    f"risk score {round((prediction.get('risk_score') or 0) * 100)}/100. Main drivers: {drivers}."
                ),
                source_ip=prediction.get("source_ip"),
                destination_ip=prediction.get("destination_ip"),
                source_port=prediction.get("source_port"),
                destination_port=prediction.get("destination_port"),
                origin="detection",
                prediction_id=prediction_ids[index] if persist and index < len(prediction_ids) else None,
                traffic_record_id=record_ids[index] if persist and index < len(record_ids) else None,
                is_simulated=is_simulated,
                user_email=(user or {}).get("email"),
            )
            if alert:
                alerts_created += 1
            elif suppressed:
                alerts_suppressed += 1

    summary = dict(result.get("summary") or {})
    summary.update({
        "persisted": persisted,
        "alerts_created": alerts_created,
        "alerts_suppressed": alerts_suppressed,
        "dataset_id": dataset_id,
        "source": source,
        "is_simulated": is_simulated,
        "analyzed_at": iso(utcnow()),
    })
    return {
        "predictions": predictions,
        "summary": summary,
        "model": model_meta,
        "persisted": persisted,
        "alerts_created": alerts_created,
        "alerts_suppressed": alerts_suppressed,
    }


def analyze_records(records: List[Dict[str, Any]], source: str = "manual", persist: bool = False,
                    create_alerts: bool = False, user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Analyze raw flow dicts (single-flow inspector, batch API, simulation)."""
    if not records:
        return {"predictions": [], "summary": {"rows": 0}, "model": None}
    result = predict_records(records, explain=True)
    if persist:
        from app.ml.features import detect_columns, normalize_frame

        frame = normalize_frame(pd.DataFrame(records), detect_columns(pd.DataFrame(records)))
        return analyze_frame(frame, source=source, persist=True, create_alerts=create_alerts, user=user)
    result.setdefault("summary", {})["source"] = source
    return result


def record_dataset_event(dataset: Dict[str, Any], user: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Anchor a dataset ingestion event in the integrity ledger."""
    try:
        return ledger.record_event(
            event_type="dataset_ingested",
            payload={
                "dataset_id": dataset.get("id"),
                "filename": dataset.get("original_filename"),
                "rows": dataset.get("rows"),
                "columns": dataset.get("columns"),
                "size_bytes": dataset.get("size_bytes"),
                "analysis": dataset.get("analysis") or {},
            },
            related_id=dataset.get("id"),
            recorded_by=(user or {}).get("email", "system"),
        )
    except Exception as exc:  # pragma: no cover
        logger.warning("Ledger write failed for dataset %s: %s", dataset.get("id"), exc)
        return None
