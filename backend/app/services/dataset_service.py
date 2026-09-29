"""
Dataset upload, validation, profiling and ingestion.

Handles CSV/JSON, enforces size and row limits, profiles the data (dtypes,
missing values, duplicates, class distribution), stores the raw file (local disk
or Appwrite Storage) and hands normalized rows to the analysis pipeline.
"""

from __future__ import annotations

import io
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from app.core.config import settings
from app.core.utils import iso, new_id, utcnow
from app.ml.features import ATTACK_CLASSES, CANONICAL_COLUMNS, detect_columns, normalize_frame
from app.storage import get_appwrite_store, get_store

logger = logging.getLogger("cyberforecast.datasets")

MAX_PREVIEW_ROWS = 25


class DatasetError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def validate_upload(filename: str, size_bytes: int) -> Tuple[str, str]:
    name = os.path.basename(filename or "").strip()
    if not name:
        raise DatasetError("A file name is required.")
    extension = os.path.splitext(name)[1].lower()
    if extension not in settings.allowed_upload_extensions:
        raise DatasetError(
            f"Unsupported file type '{extension or 'unknown'}'. Allowed: {', '.join(settings.allowed_upload_extensions)}"
        )
    if size_bytes <= 0:
        raise DatasetError("The uploaded file is empty.")
    if size_bytes > settings.max_upload_mb * 1024 * 1024:
        raise DatasetError(f"File exceeds the {settings.max_upload_mb} MB upload limit.")
    return name, extension.lstrip(".")


def parse_content(content: bytes, file_format: str) -> pd.DataFrame:
    try:
        text = content.decode("utf-8-sig", errors="replace")
    except Exception as exc:  # pragma: no cover
        raise DatasetError(f"Could not decode the file as UTF-8 text: {exc}")

    try:
        if file_format == "json":
            payload = json.loads(text)
            if isinstance(payload, dict):
                for key in ("data", "records", "rows", "flows", "results"):
                    if isinstance(payload.get(key), list):
                        payload = payload[key]
                        break
                else:
                    payload = [payload]
            if not isinstance(payload, list):
                raise DatasetError("JSON datasets must contain an array of flow records.")
            frame = pd.json_normalize(payload)
        else:
            frame = _read_csv_text(text)
    except DatasetError:
        raise
    except Exception as exc:
        raise DatasetError(f"Could not parse the file: {exc}")

    if frame is None or frame.empty:
        raise DatasetError("The dataset contains no rows.")
    if len(frame) > settings.max_upload_rows:
        raise DatasetError(f"Dataset has {len(frame):,} rows; the limit is {settings.max_upload_rows:,}.")
    return frame


def _read_csv_text(text: str) -> pd.DataFrame:
    """Read CSV with delimiter sniffing (tabs/semicolons/pipes are common in SIEM exports)."""
    import csv as _csv

    sample = text[:8192]
    delimiter = ","
    try:
        dialect = _csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delimiter = dialect.delimiter
    except _csv.Error:
        first_line = sample.splitlines()[0] if sample.splitlines() else ""
        for candidate in (";", "\t", "|"):
            if first_line.count(candidate) > first_line.count(","):
                delimiter = candidate
                break
    return pd.read_csv(io.StringIO(text), sep=delimiter, engine="c", on_bad_lines="skip", low_memory=False)


def profile_frame(raw: pd.DataFrame, normalized: pd.DataFrame, detection: Dict[str, Any]) -> Dict[str, Any]:
    """Dataset quality report shown in the Traffic Dataset Analyzer."""
    numeric_columns = [str(c) for c in raw.columns if pd.api.types.is_numeric_dtype(raw[c])]
    categorical_columns = [str(c) for c in raw.columns if c not in numeric_columns]
    missing = raw.isna().sum()
    duplicate_rows = int(raw.duplicated().sum())

    class_distribution: Dict[str, int] = {}
    if "attack_type" in normalized.columns:
        class_distribution = {
            str(k): int(v) for k, v in normalized["attack_type"].value_counts().items()
        }

    feature_summary = []
    for column in normalized.columns:
        if column in ("timestamp", "source_ip", "destination_ip", "attack_type"):
            continue
        series = pd.to_numeric(normalized[column], errors="coerce")
        if series.notna().sum() == 0:
            continue
        feature_summary.append({
            "feature": column,
            "mean": round(float(series.mean()), 4),
            "std": round(float(series.std() or 0.0), 4),
            "min": round(float(series.min()), 4),
            "p50": round(float(series.median()), 4),
            "max": round(float(series.max()), 4),
        })

    return {
        "rows": int(len(raw)),
        "columns": int(len(raw.columns)),
        "column_names": [str(c) for c in raw.columns],
        "dtypes": {str(c): str(t) for c, t in raw.dtypes.items()},
        "numerical_features": numeric_columns,
        "categorical_features": categorical_columns,
        "missing_values": {str(k): int(v) for k, v in missing[missing > 0].items()},
        "missing_value_total": int(missing.sum()),
        "missing_value_percentage": round(float(missing.sum()) / max(len(raw) * len(raw.columns), 1) * 100, 2),
        "duplicate_rows": duplicate_rows,
        "duplicate_percentage": round(duplicate_rows / max(len(raw), 1) * 100, 2),
        "class_distribution": class_distribution,
        "labeled": bool(detection["mapping"].get("attack_type") or any(v == "attack_type" for v in detection["mapping"].values())),
        "column_mapping": detection["mapping"],
        "canonical_columns_detected": detection["canonical_found"],
        "canonical_columns_missing": detection["missing_canonical"],
        "unmapped_columns": detection["unmapped_columns"],
        "schema_coverage": detection["coverage"],
        "feature_summary": sorted(feature_summary, key=lambda item: item["feature"])[:40],
        "preview": json.loads(normalized.head(MAX_PREVIEW_ROWS).to_json(orient="records", date_format="iso")),
        "preprocessing": {
            "timestamp_parsed": bool(normalized["timestamp"].notna().all()),
            "missing_numerics_imputed": True,
            "protocol_normalized": True,
            "tcp_flags_normalized": True,
            "labels_normalized_to_taxonomy": True,
            "duplicates_dropped_on_ingest": duplicate_rows > 0,
        },
        "profiled_at": iso(utcnow()),
    }


def store_raw_file(content: bytes, filename: str, file_format: str) -> Tuple[str, str, Optional[str]]:
    """Persist the raw upload. Returns (stored_filename, backend, appwrite_file_id)."""
    stored_name = f"{new_id()}.{file_format}"
    appwrite_store = get_appwrite_store()
    if appwrite_store:
        file_id = appwrite_store.upload_file(content, filename, "application/json" if file_format == "json" else "text/csv")
        if file_id:
            # Keep a local copy too: serverless filesystems are ephemeral and the
            # analysis pipeline reads from disk.
            _write_local(stored_name, content)
            return stored_name, "appwrite", file_id
    _write_local(stored_name, content)
    return stored_name, "local", None


def _write_local(stored_name: str, content: bytes) -> str:
    path = os.path.join(settings.upload_dir, stored_name)
    os.makedirs(settings.upload_dir, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(content)
    return path


def local_path(stored_name: str) -> str:
    return os.path.join(settings.upload_dir, stored_name)


def ingest(
    filename: str,
    content: bytes,
    user: Optional[Dict[str, Any]] = None,
    run_analysis: bool = True,
    analysis_limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Validate -> profile -> store -> analyze. Returns the dataset record."""
    from app.services import pipeline_service

    name, file_format = validate_upload(filename, len(content))
    raw = parse_content(content, file_format)
    detection = detect_columns(raw)
    normalized = normalize_frame(raw, detection)
    normalized = normalized.drop_duplicates()
    profile = profile_frame(raw, normalized, detection)

    stored_name, backend, file_id = store_raw_file(content, name, file_format)

    record = get_store().create("datasets", {
        "id": new_id(),
        "user_id": (user or {}).get("id"),
        "filename": stored_name,
        "original_filename": name,
        "file_format": file_format,
        "size_bytes": len(content),
        "rows": int(len(normalized)),
        "columns": int(len(raw.columns)),
        "column_names": profile["column_names"],
        "profile": profile,
        "storage_file_id": file_id,
        "storage_backend": backend,
        "status": "processed",
        "uploaded_at": utcnow(),
    })

    if run_analysis:
        limit = analysis_limit or settings.prediction_sample_limit
        analysis = pipeline_service.analyze_frame(
            normalized.head(limit),
            dataset_id=record["id"],
            source="dataset",
            persist=True,
            create_alerts=True,
        )
        record["analysis"] = analysis["summary"]
        record["analysis_model"] = analysis.get("model")
    return record


def list_datasets(limit: int = 20, offset: int = 0, user_id: Optional[str] = None,
                  search: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
    filters = {"user_id": user_id} if user_id else None
    return get_store().list("datasets", filters=filters, order_by="-uploaded_at", limit=limit, offset=offset,
                            search=search, search_fields=["original_filename", "filename", "status"])


def get_dataset(dataset_id: str) -> Optional[Dict[str, Any]]:
    return get_store().get("datasets", dataset_id)


def delete_dataset(dataset_id: str) -> bool:
    record = get_dataset(dataset_id)
    if not record:
        return False
    path = local_path(record.get("filename") or "")
    if os.path.isfile(path):
        try:
            os.remove(path)
        except OSError:
            pass
    return get_store().delete("datasets", dataset_id)


def read_raw_frame(record: Dict[str, Any]) -> Optional[pd.DataFrame]:
    """Re-read a stored dataset from disk (or Appwrite Storage)."""
    path = local_path(record.get("filename") or "")
    content: Optional[bytes] = None
    if os.path.isfile(path):
        with open(path, "rb") as handle:
            content = handle.read()
    elif record.get("storage_file_id"):
        appwrite_store = get_appwrite_store()
        if appwrite_store:
            content = appwrite_store.download_file(record["storage_file_id"])
    if content is None:
        return None
    try:
        return parse_content(content, record.get("file_format") or "csv")
    except DatasetError:
        return None


def reprofile(dataset_id: str) -> Optional[Dict[str, Any]]:
    """Recompute and persist the quality profile for a stored dataset.

    Bundled samples are registered with a lightweight profile at seed time; this
    fills in dtypes, missing values, duplicates, class balance, feature summary
    and a normalized preview without re-uploading anything.
    """
    record = get_dataset(dataset_id)
    if not record:
        return None
    raw = read_raw_frame(record)
    if raw is None:
        raise DatasetError("The stored file for this dataset could not be read.", status_code=409)
    detection = detect_columns(raw)
    normalized = normalize_frame(raw, detection).drop_duplicates()
    profile = profile_frame(raw, normalized, detection)
    if record.get("profile", {}).get("note"):
        profile["note"] = record["profile"]["note"]
    get_store().update("datasets", dataset_id, {
        "profile": profile,
        "rows": int(len(normalized)),
        "columns": int(len(raw.columns)),
        "column_names": profile["column_names"],
        "status": "processed",
        "error_message": None,
    })
    return get_dataset(dataset_id)


def preview(dataset_id: str, limit: int = 25) -> Optional[Dict[str, Any]]:
    """Return normalized sample rows plus the detected column mapping."""
    record = get_dataset(dataset_id)
    if not record:
        return None
    raw = read_raw_frame(record)
    if raw is None:
        raise DatasetError("The stored file for this dataset could not be read.", status_code=409)
    detection = detect_columns(raw)
    normalized = normalize_frame(raw, detection)
    head = normalized.head(limit)
    return {
        "dataset_id": dataset_id,
        "filename": record.get("original_filename") or record.get("filename"),
        "requested": int(limit),
        "returned": int(len(head)),
        "total_rows": int(len(normalized)),
        "columns": [str(c) for c in normalized.columns],
        "raw_columns": [str(c) for c in raw.columns],
        "column_mapping": detection["mapping"],
        "canonical_missing": detection["missing_canonical"],
        "unmapped_columns": detection["unmapped_columns"],
        "rows": json.loads(head.to_json(orient="records", date_format="iso")),
        "labeled": bool(detection["mapping"].get("attack_type")),
    }


def sample_datasets() -> List[Dict[str, Any]]:
    """Bundled sample datasets available for one-click testing."""
    directory = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "datasets")
    items: List[Dict[str, Any]] = []
    if not os.path.isdir(directory):
        return items
    for name in sorted(os.listdir(directory)):
        if not name.endswith((".csv", ".json")):
            continue
        path = os.path.join(directory, name)
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        items.append({"name": name, "path": path, "size_bytes": size,
                      "format": "csv" if name.endswith(".csv") else "json"})
    return items
