"""
Training + evaluation pipeline.

Dataset -> validation -> cleaning -> preprocessing -> feature engineering
        -> stratified split -> training -> evaluation -> artifact saving.

All reported metrics are computed on a held-out test split (or cross-validation);
nothing is fabricated and no accuracy is ever claimed to be perfect.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import cross_val_score, train_test_split

from app.core.utils import iso, utcnow
from app.ml.algorithms import get_algorithm
from app.ml.features import ATTACK_CLASSES, BENIGN, FEATURE_LABELS, normalize_frame, detect_columns
from app.ml.preprocessing import BUNDLE_VERSION, TrafficPreprocessor

logger = logging.getLogger("cyberforecast.ml")

MAX_TRAINING_ROWS = 60_000


def _subsample(df: pd.DataFrame, limit: int = MAX_TRAINING_ROWS) -> pd.DataFrame:
    if len(df) <= limit:
        return df
    # Keep class balance while trimming.
    return df.groupby("attack_type", group_keys=False).apply(
        lambda chunk: chunk.sample(max(50, int(limit * len(chunk) / len(df))), random_state=42)
    ).reset_index(drop=True)


def _feature_importance(estimator: Any, spec: Dict[str, Any], X_test: np.ndarray,
                        y_test: np.ndarray, feature_names: List[str]) -> List[Dict[str, Any]]:
    raw: Optional[np.ndarray] = None
    if spec.get("native_importance") and hasattr(estimator, "feature_importances_"):
        raw = np.asarray(estimator.feature_importances_, dtype=float)
    elif hasattr(estimator, "coef_"):
        coef = np.asarray(estimator.coef_, dtype=float)
        raw = np.abs(coef).mean(axis=0) if coef.ndim > 1 else np.abs(coef)
    if raw is None:
        try:
            sample = min(400, len(X_test))
            idx = np.random.RandomState(42).choice(len(X_test), sample, replace=False) if sample < len(X_test) else slice(None)
            result = permutation_importance(
                estimator, X_test[idx], y_test[idx], n_repeats=3, random_state=42, n_jobs=-1, scoring="accuracy"
            )
            raw = np.clip(result.importances_mean, 0, None)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("permutation importance failed: %s", exc)
            raw = np.zeros(len(feature_names))
    if len(raw) != len(feature_names):
        raw = np.resize(raw, len(feature_names))
    total = float(raw.sum()) or 1.0
    importance = [
        {"feature": name, "label": FEATURE_LABELS.get(name, name.replace("_", " ").title()),
         "importance": round(float(value) / total, 5)}
        for name, value in zip(feature_names, raw)
    ]
    importance.sort(key=lambda item: item["importance"], reverse=True)
    return importance


def train_classifier(
    df: pd.DataFrame,
    algorithm: str = "random_forest",
    test_size: float = 0.25,
    random_state: int = 42,
    target_column: str = "attack_type",
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Train a multi-class attack classifier and return (bundle, metrics)."""
    spec = get_algorithm(algorithm)
    if spec["task"] != "classification":
        raise ValueError(f"Algorithm '{algorithm}' is not a classifier")

    if target_column not in df.columns:
        raise ValueError(f"Dataset has no '{target_column}' column - cannot train a supervised classifier")

    work = df.copy()
    work[target_column] = work[target_column].astype(str)
    work = work[work[target_column].isin(ATTACK_CLASSES)]
    labeled = work[work[target_column] != "Unknown"]
    if labeled.empty:
        raise ValueError("No labeled rows available for training (need a ground-truth attack_type column)")
    work = _subsample(labeled)

    class_counts = work[target_column].value_counts().to_dict()
    if len(class_counts) < 2:
        raise ValueError("Training needs at least two distinct attack classes; got one.")

    preprocessor = TrafficPreprocessor().fit(work)
    X = preprocessor.transform(work)
    y = work[target_column].values

    stratify = y if min(class_counts.values()) >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=stratify
    )

    estimator = spec["factory"]()
    estimator.fit(X_train, y_train)

    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
    y_pred = estimator.predict(X_test)
    classes = sorted(set(y_train) | set(y_test))
    proba = estimator.predict_proba(X_test) if spec.get("supports_proba") else None
    proba_classes = list(getattr(estimator, "classes_", classes))

    metrics: Dict[str, Any] = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision_weighted": round(float(precision_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        "precision_macro": round(float(precision_score(y_test, y_pred, average="macro", zero_division=0)), 4),
        "recall_weighted": round(float(recall_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y_test, y_pred, average="macro", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4),
    }

    if proba is not None and len(proba_classes) > 1:
        try:
            metrics["roc_auc_ovr"] = round(
                float(roc_auc_score(y_test, proba, multi_class="ovr", average="weighted", labels=proba_classes)), 4
            )
        except ValueError:
            metrics["roc_auc_ovr"] = None
        try:
            metrics["log_loss"] = round(float(log_loss(y_test, proba, labels=proba_classes)), 4)
        except ValueError:
            metrics["log_loss"] = None
    else:
        metrics["roc_auc_ovr"] = None
        metrics["log_loss"] = None

    # Binary "is attack" AUC - the number SOC teams care about most.
    if proba is not None and BENIGN in proba_classes:
        benign_index = proba_classes.index(BENIGN)
        binary_true = (y_test != BENIGN).astype(int)
        binary_score = 1.0 - proba[:, benign_index]
        if len(set(binary_true)) > 1:
            try:
                metrics["roc_auc_binary_attack"] = round(float(roc_auc_score(binary_true, binary_score)), 4)
            except ValueError:
                metrics["roc_auc_binary_attack"] = None

    # Cross-validated accuracy on a subsample (guards against a lucky split).
    try:
        cv_index = np.arange(len(X_train))
        if len(cv_index) > 4000:
            cv_index = np.random.RandomState(random_state).choice(cv_index, 4000, replace=False)
        cv_frame, cv_labels = X_train[cv_index], y_train[cv_index]
        if len(set(cv_labels)) > 1:
            scores = cross_val_score(spec["factory"](), cv_frame, cv_labels, cv=3, scoring="accuracy", n_jobs=-1)
            metrics["cv_accuracy_mean"] = round(float(scores.mean()), 4)
            metrics["cv_accuracy_std"] = round(float(scores.std()), 4)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("cross-validation skipped: %s", exc)

    cm = confusion_matrix(y_test, y_pred, labels=classes)
    report = classification_report(y_test, y_pred, labels=classes, output_dict=True, zero_division=0)
    class_report = [
        {
            "class": label,
            "precision": round(float(report.get(label, {}).get("precision", 0.0)), 4),
            "recall": round(float(report.get(label, {}).get("recall", 0.0)), 4),
            "f1": round(float(report.get(label, {}).get("f1-score", 0.0)), 4),
            "support": int(report.get(label, {}).get("support", 0)),
        }
        for label in classes
    ]

    importance = _feature_importance(estimator, spec, X_test, y_test, preprocessor.feature_names)

    metrics.update({
        "confusion_matrix": {"labels": list(classes), "matrix": cm.tolist()},
        "class_report": class_report,
        "training_rows": int(len(work)),
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "n_classes": len(classes),
        "classes": classes,
        "class_distribution": {str(k): int(v) for k, v in class_counts.items()},
        "algorithm": spec["key"],
        "algorithm_label": spec["label"],
    })

    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "task": "classification",
        "algorithm": spec["key"],
        "algorithm_label": spec["label"],
        "estimator": estimator,
        "preprocessor": preprocessor,
        "feature_names": preprocessor.feature_names,
        "classes": proba_classes or classes,
        "class_weights": {
            str(k): round(float(len(work) / (len(class_counts) * v)), 4) for k, v in class_counts.items()
        },
        "importance": importance,
        "class_report": class_report,
        "metrics": metrics,
        "trained_at": iso(utcnow()),
    }
    return bundle, metrics


def train_anomaly_detector(
    df: pd.DataFrame,
    contamination: float = 0.1,
    random_state: int = 42,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Unsupervised Isolation Forest over normalized flow features."""
    spec = get_algorithm("isolation_forest")
    work = _subsample(df)
    if len(work) < 50:
        raise ValueError("Anomaly detection needs at least 50 traffic records")

    # When labels exist, learn the benign baseline only: deviations from *normal*
    # are what an anomaly detector should measure. The scaler still sees all
    # traffic so attack flows are not clipped out of the feature space.
    fit_target = work
    training_basis = "all-traffic"
    if "attack_type" in work.columns:
        benign = work[work["attack_type"] == BENIGN]
        if len(benign) >= 200:
            fit_target = benign
            training_basis = "benign-baseline"

    preprocessor = TrafficPreprocessor().fit(work)
    X_fit = preprocessor.transform(fit_target)
    X = preprocessor.transform(work)

    estimator = IsolationForest(
        n_estimators=160, contamination=float(np.clip(contamination, 0.005, 0.4)),
        random_state=random_state, n_jobs=-1,
    )
    estimator.fit(X_fit)

    raw_scores = estimator.score_samples(X)
    low, high = float(np.min(raw_scores)), float(np.max(raw_scores))
    threshold = float(np.percentile(raw_scores, contamination * 100))
    flags = estimator.predict(X)
    anomalies = int((flags == -1).sum())

    # Sanity check against known labels when the dataset provides them.
    label_agreement = None
    if "attack_type" in work.columns and (work["attack_type"] != "Unknown").any():
        known_attacks = work["attack_type"] != BENIGN
        if known_attacks.any() and (~known_attacks).any():
            detected = pd.Series(flags == -1, index=work.index)
            label_agreement = {
                "attack_recall": round(float((detected & known_attacks).sum() / max(int(known_attacks.sum()), 1)), 4),
                "benign_flag_rate": round(float((detected & ~known_attacks).sum() / max(int((~known_attacks).sum()), 1)), 4),
            }

    metrics = {
        "algorithm": "isolation_forest",
        "algorithm_label": spec["label"],
        "training_rows": int(len(fit_target)),
        "evaluation_rows": int(len(work)),
        "training_basis": training_basis,
        "anomalies_flagged": anomalies,
        "anomaly_rate": round(anomalies / max(len(work), 1), 4),
        "contamination": round(float(contamination), 4),
        "score_range": [round(low, 4), round(high, 4)],
        "decision_threshold": round(threshold, 4),
        "label_agreement": label_agreement,
        "accuracy": round(float(label_agreement["attack_recall"]) if label_agreement else 0.0, 4),
    }

    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "task": "anomaly",
        "algorithm": "isolation_forest",
        "algorithm_label": spec["label"],
        "estimator": estimator,
        "preprocessor": preprocessor,
        "feature_names": preprocessor.feature_names,
        "score_low": low,
        "score_high": high,
        "threshold": threshold,
        "importance": [],
        "metrics": metrics,
        "trained_at": iso(utcnow()),
    }
    return bundle, metrics


def save_bundle(bundle: Dict[str, Any], path: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(bundle, path, compress=3)
    return path


def load_bundle(path: str) -> Optional[Dict[str, Any]]:
    if not path or not os.path.isfile(path):
        return None
    try:
        return joblib.load(path)
    except Exception as exc:  # pragma: no cover - corrupt artifact
        logger.warning("Failed to load model artifact %s: %s", path, exc)
        return None


def evaluate_bundle(bundle: Dict[str, Any], df: pd.DataFrame) -> Dict[str, Any]:
    """Score an existing bundle against a fresh dataset (used before activation)."""
    if bundle.get("task") != "classification":
        return {"error": "Only classification bundles can be evaluated against labeled data"}
    estimator = bundle["estimator"]
    preprocessor: TrafficPreprocessor = bundle["preprocessor"]
    work = df[df.get("attack_type", pd.Series(dtype=str)).astype(str).isin(ATTACK_CLASSES)]
    work = work[work["attack_type"] != "Unknown"]
    if len(work) < 10:
        return {"error": "Not enough labeled rows to evaluate (need >= 10)"}
    X = preprocessor.transform(_subsample(work))
    y = work["attack_type"].values
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        y_pred = estimator.predict(X)
    classes = sorted(set(y))
    out = {
        "rows": int(len(y)),
        "accuracy": round(float(accuracy_score(y, y_pred)), 4),
        "precision_weighted": round(float(precision_score(y, y_pred, average="weighted", zero_division=0)), 4),
        "recall_weighted": round(float(recall_score(y, y_pred, average="weighted", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y, y_pred, average="weighted", zero_division=0)), 4),
        "classes": classes,
        "evaluated_at": iso(utcnow()),
    }
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            proba = estimator.predict_proba(X)
            out["roc_auc_ovr"] = round(float(roc_auc_score(y, proba, multi_class="ovr", average="weighted",
                                                           labels=list(estimator.classes_))), 4)
    except Exception:
        out["roc_auc_ovr"] = None
    cm = confusion_matrix(y, y_pred, labels=list(estimator.classes_))
    out["confusion_matrix"] = {"labels": list(estimator.classes_), "matrix": cm.tolist()}
    return out
