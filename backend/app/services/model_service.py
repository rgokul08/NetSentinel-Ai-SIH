"""
ML model registry: training, evaluation, activation and comparison.

Artifacts are joblib bundles on disk; metadata lives in the `models` collection.
A model can only become active after it loads and passes validation, so the
production model is never replaced blindly.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import joblib
import pandas as pd

from app.blockchain import ledger
from app.core.config import settings
from app.core.utils import iso, new_id, safe_float, utcnow
from app.ml import inference
from app.ml.algorithms import catalogue, get_algorithm
from app.ml.features import ATTACK_CLASSES, BENIGN, detect_columns, normalize_frame
from app.ml.trainer import evaluate_bundle, save_bundle, train_anomaly_detector, train_classifier
from app.storage import get_store

logger = logging.getLogger("cyberforecast.models")

MIN_ACTIVATION_ACCURACY = 0.5


class ModelError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _artifact_path(model_id: str) -> str:
    return os.path.join(settings.model_dir, f"{model_id}.joblib")


def _next_version(algorithm: str) -> str:
    rows, _ = get_store().list("models", filters={"algorithm": algorithm}, order_by="-trained_at", limit=50)
    return f"{len(rows) + 1}.0.0"


def list_models(task: Optional[str] = None, limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
    filters = {"task": task} if task else None
    rows, total = get_store().list("models", filters=filters, order_by="-trained_at", limit=limit, offset=offset)
    for row in rows:
        row["artifact_available"] = bool(row.get("artifact_path")) and os.path.isfile(row.get("artifact_path") or "")
        row["artifact_status"] = "available" if row["artifact_available"] else "missing"
    return rows, total


def get_model(model_id: str) -> Optional[Dict[str, Any]]:
    record = get_store().get("models", model_id)
    if record:
        record["artifact_available"] = bool(record.get("artifact_path")) and os.path.isfile(record.get("artifact_path") or "")
    return record


def active_model(task: str = "classification") -> Optional[Dict[str, Any]]:
    record = inference.active_model_record(task)
    if record:
        record["artifact_available"] = bool(record.get("artifact_path")) and os.path.isfile(record.get("artifact_path") or "")
    return record


def _training_frame(dataset_id: Optional[str], rows: Optional[int]) -> pd.DataFrame:
    """Collect labeled traffic for training from a dataset file or the database."""
    if dataset_id:
        from app.services import dataset_service

        record = dataset_service.get_dataset(dataset_id)
        if not record:
            raise ModelError(f"Dataset '{dataset_id}' not found", status_code=404)
        raw = dataset_service.read_raw_frame(record)
        if raw is None or raw.empty:
            raise ModelError("Dataset file is no longer available for training.")
        frame = normalize_frame(raw, detect_columns(raw))
    else:
        store = get_store()
        records, _ = store.list("traffic_records", filters={"is_labeled": True}, order_by="-timestamp",
                                limit=min(rows or settings.prediction_sample_limit, 20000))
        if not records:
            # Fall back to simulated records: the generator knows the ground truth.
            records, _ = store.list("traffic_records", filters={"attack_type": {"$ne": "Unknown"}},
                                    order_by="-timestamp", limit=min(rows or 20000, 20000))
        if not records:
            raise ModelError("No labeled traffic available. Upload a labeled dataset or run the simulation first.")
        frame = pd.DataFrame(records)
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)

    frame = frame[frame["attack_type"].astype(str) != "Unknown"]
    if rows:
        frame = frame.head(int(rows))
    if frame.empty:
        raise ModelError("Training set is empty after removing unlabeled rows.")
    return frame.reset_index(drop=True)


def train(
    algorithm: str = "random_forest",
    dataset_id: Optional[str] = None,
    rows: Optional[int] = None,
    contamination: Optional[float] = None,
    user: Optional[Dict[str, Any]] = None,
    train_anomaly: bool = True,
) -> Dict[str, Any]:
    """Train (and register) a classifier and, optionally, an anomaly detector."""
    spec = get_algorithm(algorithm)
    frame = _training_frame(dataset_id, rows)
    dataset_record = get_store().get("datasets", dataset_id) if dataset_id else None

    trained: List[Dict[str, Any]] = []
    errors: List[str] = []

    # --- classifier -------------------------------------------------------
    model_id = new_id()
    version = _next_version(spec["key"])
    artifact = _artifact_path(model_id)
    try:
        bundle, metrics = train_classifier(frame, algorithm=spec["key"])
        save_bundle(bundle, artifact)
        record = get_store().create("models", {
            "id": model_id,
            "name": f"{spec['label']} attack classifier",
            "version": version,
            "algorithm": spec["key"],
            "task": "classification",
            "dataset_id": dataset_id,
            "dataset_name": (dataset_record or {}).get("original_filename") or "database traffic_records",
            "training_rows": int(metrics.get("training_rows") or len(frame)),
            "classes": metrics.get("classes") or [],
            "features": bundle.get("feature_names") or [],
            "metrics": metrics,
            "confusion_matrix": metrics.get("confusion_matrix") or {"labels": metrics.get("classes") or [], "matrix": []},
            "class_report": bundle.get("class_report") or [],
            "feature_importance": bundle.get("importance") or [],
            "accuracy": safe_float(metrics.get("accuracy")),
            "precision_score": safe_float(metrics.get("precision_weighted")),
            "recall_score": safe_float(metrics.get("recall_weighted")),
            "f1_score": safe_float(metrics.get("f1_weighted")),
            "roc_auc": metrics.get("roc_auc_ovr"),
            "artifact_path": artifact,
            "artifact_status": "available",
            "is_active": False,
            "status": "trained",
            "trained_by": (user or {}).get("email", "system"),
            "trained_at": utcnow(),
            "notes": f"Trained on {metrics.get('training_rows')} labeled flows ({metrics.get('n_classes')} classes).",
        })
        trained.append(record)
    except Exception as exc:
        logger.exception("classifier training failed")
        errors.append(f"classifier: {exc}")

    # --- anomaly detector -------------------------------------------------
    if train_anomaly:
        from app.services import settings_service

        anomaly_id = new_id()
        anomaly_artifact = _artifact_path(anomaly_id)
        try:
            bundle, metrics = train_anomaly_detector(
                frame,
                contamination=contamination if contamination is not None
                else float(settings_service.get("anomaly_contamination", settings.anomaly_contamination)),
            )
            save_bundle(bundle, anomaly_artifact)
            record = get_store().create("models", {
                "id": anomaly_id,
                "name": "Isolation Forest anomaly detector",
                "version": _next_version("isolation_forest"),
                "algorithm": "isolation_forest",
                "task": "anomaly",
                "dataset_id": dataset_id,
                "dataset_name": (dataset_record or {}).get("original_filename") or "database traffic_records",
                "training_rows": int(metrics.get("training_rows") or len(frame)),
                "classes": ["normal", "anomaly"],
                "features": bundle.get("feature_names") or [],
                "metrics": metrics,
                "accuracy": safe_float(metrics.get("accuracy")),
                "artifact_path": anomaly_artifact,
                "artifact_status": "available",
                "is_active": False,
                "status": "trained",
                "trained_by": (user or {}).get("email", "system"),
                "trained_at": utcnow(),
                "notes": f"Unsupervised; flagged {metrics.get('anomalies_flagged')} anomalies in training data.",
            })
            trained.append(record)
        except Exception as exc:
            logger.exception("anomaly training failed")
            errors.append(f"anomaly: {exc}")

    if not trained:
        raise ModelError("Training failed: " + "; ".join(errors) or "unknown error", status_code=500)

    try:
        ledger.record_event(
            event_type="model_trained",
            payload={
                "models": [{"id": m.get("id"), "algorithm": m.get("algorithm"), "version": m.get("version"),
                            "accuracy": m.get("accuracy"), "task": m.get("task")} for m in trained],
                "dataset_id": dataset_id,
                "training_rows": int(len(frame)),
            },
            related_id=trained[0].get("id"),
            recorded_by=(user or {}).get("email", "system"),
        )
    except Exception:  # pragma: no cover
        logger.warning("ledger write failed for model training")

    inference.invalidate_cache()
    return {"trained": trained, "errors": errors, "training_rows": int(len(frame)), "trained_at": iso(utcnow())}


def validate(model_id: str, dataset_id: Optional[str] = None) -> Dict[str, Any]:
    """Evaluate a candidate model before activation (never activate blind)."""
    record = get_model(model_id)
    if not record:
        raise ModelError(f"Model '{model_id}' not found", status_code=404)
    if record.get("task") != "classification":
        return {"valid": True, "reason": "Anomaly detectors have no supervised validation set; artifact load is checked only.",
                "artifact_loads": bool(inference.bundle_for(record))}
    bundle = inference.bundle_for(record)
    if bundle is None:
        return {"valid": False, "reason": "Artifact could not be loaded from disk."}
    frame = None
    if dataset_id:
        from app.services import dataset_service

        ds = dataset_service.get_dataset(dataset_id)
        if ds:
            raw = dataset_service.read_raw_frame(ds)
            if raw is not None:
                frame = normalize_frame(raw, detect_columns(raw))
    if frame is None or frame.empty:
        frame = _training_frame(None, 5000)
    evaluation = evaluate_bundle(bundle, frame)
    accuracy = safe_float(evaluation.get("accuracy"))
    valid = accuracy >= MIN_ACTIVATION_ACCURACY
    return {
        "valid": valid,
        "accuracy": accuracy,
        "min_required_accuracy": MIN_ACTIVATION_ACCURACY,
        "evaluation": evaluation,
        "reason": None if valid else f"Accuracy {accuracy:.3f} is below the activation threshold {MIN_ACTIVATION_ACCURACY}.",
    }


def activate(model_id: str, user: Optional[Dict[str, Any]] = None, dataset_id: Optional[str] = None,
             force: bool = False) -> Dict[str, Any]:
    record = get_model(model_id)
    if not record:
        raise ModelError(f"Model '{model_id}' not found", status_code=404)
    if not record.get("artifact_path") or not os.path.isfile(record["artifact_path"]):
        raise ModelError("This model has no artifact on disk and cannot be activated.", status_code=409)

    validation = validate(model_id, dataset_id) if not force else {"valid": True, "reason": "forced by admin"}
    if not validation.get("valid"):
        raise ModelError(f"Activation blocked: {validation.get('reason')}", status_code=422)

    store = get_store()
    task = record.get("task") or "classification"
    current, _ = store.list("models", filters={"task": task, "is_active": True}, limit=10)
    for row in current:
        if row["id"] != model_id:
            store.update("models", row["id"], {"is_active": False})
    updated = store.update("models", model_id, {"is_active": True, "status": "trained"})
    inference.invalidate_cache()

    try:
        ledger.record_event(
            event_type="model_activated",
            payload={"model_id": model_id, "task": task, "version": record.get("version"),
                     "algorithm": record.get("algorithm"), "accuracy": record.get("accuracy"),
                     "validation": {k: v for k, v in validation.items() if k != "evaluation"},
                     "actor": (user or {}).get("email", "system")},
            related_id=model_id,
            recorded_by=(user or {}).get("email", "system"),
        )
    except Exception:  # pragma: no cover
        pass
    return {"model": updated, "validation": validation}


def deactivate(model_id: str, user: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    updated = get_store().update("models", model_id, {"is_active": False})
    inference.invalidate_cache(model_id)
    if updated:
        try:
            ledger.record_event("model_deactivated", {"model_id": model_id, "actor": (user or {}).get("email", "system")},
                                related_id=model_id, recorded_by=(user or {}).get("email", "system"))
        except Exception:  # pragma: no cover
            pass
    return updated


def delete_model(model_id: str) -> bool:
    record = get_model(model_id)
    if not record:
        return False
    if record.get("is_active"):
        raise ModelError("Cannot delete the active model. Activate another model first.", status_code=409)
    path = record.get("artifact_path")
    if path and os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass
    inference.invalidate_cache(model_id)
    return get_store().delete("models", model_id)


def upload_bundle(content: bytes, filename: str, name: Optional[str] = None,
                  user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Register an externally trained joblib bundle (admin only route)."""
    if not filename.lower().endswith((".joblib", ".pkl")):
        raise ModelError("Only .joblib or .pkl model bundles can be uploaded.")
    if len(content) > 60 * 1024 * 1024:
        raise ModelError("Model bundle exceeds the 60 MB limit.")
    try:
        bundle = joblib.load(__import__("io").BytesIO(content))
    except Exception as exc:
        raise ModelError(f"Bundle could not be loaded: {exc}")
    if not isinstance(bundle, dict) or "estimator" not in bundle or "preprocessor" not in bundle:
        raise ModelError("Bundle is not a CyberForecast model (missing estimator/preprocessor keys).")

    model_id = new_id()
    path = _artifact_path(model_id)
    save_bundle(bundle, path)
    task = bundle.get("task", "classification")
    algorithm = bundle.get("algorithm", "unknown")
    metrics = bundle.get("metrics") or {}
    record = get_store().create("models", {
        "id": model_id,
        "name": name or f"Uploaded {algorithm} model",
        "version": bundle.get("version") or _next_version(algorithm),
        "algorithm": algorithm,
        "task": task,
        "dataset_name": metrics.get("dataset_name") or "external",
        "training_rows": int(metrics.get("training_rows") or 0),
        "classes": bundle.get("classes") or [],
        "features": bundle.get("feature_names") or [],
        "metrics": metrics,
        "feature_importance": bundle.get("importance") or [],
        "accuracy": safe_float(metrics.get("accuracy")),
        "precision_score": safe_float(metrics.get("precision_weighted")),
        "recall_score": safe_float(metrics.get("recall_weighted")),
        "f1_score": safe_float(metrics.get("f1_weighted")),
        "roc_auc": metrics.get("roc_auc_ovr"),
        "artifact_path": path,
        "artifact_status": "available",
        "is_active": False,
        "status": "trained",
        "trained_by": (user or {}).get("email", "system"),
        "trained_at": utcnow(),
        "notes": "Uploaded externally; validation runs before activation.",
    })
    inference.invalidate_cache()
    return record


def compare(model_ids: List[str]) -> Dict[str, Any]:
    records = [get_model(mid) for mid in model_ids]
    records = [r for r in records if r]
    if len(records) < 2:
        raise ModelError("Provide at least two existing model ids to compare.", status_code=400)
    metric_keys = ["accuracy", "precision_weighted", "recall_weighted", "f1_weighted", "f1_macro",
                   "roc_auc_ovr", "roc_auc_binary_attack", "log_loss", "cv_accuracy_mean", "training_rows"]
    return {
        "models": [{
            "id": r.get("id"), "name": r.get("name"), "version": r.get("version"),
            "algorithm": r.get("algorithm"), "task": r.get("task"), "is_active": r.get("is_active"),
            "trained_at": r.get("trained_at"), "artifact_available": r.get("artifact_available"),
            "metrics": {key: (r.get("metrics") or {}).get(key) for key in metric_keys},
        } for r in records],
        "metric_keys": metric_keys,
        "best": {
            key: max(
                (r for r in records if (r.get("metrics") or {}).get(key) is not None),
                key=lambda r: safe_float((r.get("metrics") or {}).get(key)),
                default=None,
            ).get("id") if any((r.get("metrics") or {}).get(key) is not None for r in records) else None
            for key in metric_keys
        },
    }


def registry_status() -> Dict[str, Any]:
    classifier = active_model("classification")
    anomaly = active_model("anomaly")
    total = get_store().count("models")
    return {
        "total_models": total,
        "active_classifier": classifier,
        "active_anomaly_detector": anomaly,
        "inference_engine": "ml" if inference.bundle_for(classifier) else "heuristic-fallback",
        "available_algorithms": catalogue(),
        "min_activation_accuracy": MIN_ACTIVATION_ACCURACY,
    }
