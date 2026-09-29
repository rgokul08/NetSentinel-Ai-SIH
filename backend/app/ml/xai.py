"""
Explainable AI.

Local attributions are computed from the trained model itself:

    attribution(feature) = model_importance(feature) x z-score(feature vs baseline)

The sign gives the direction (raises / lowers risk) and the magnitude is
normalized into a percentage contribution. This is a linear surrogate in the
spirit of LIME/SHAP: it explains what the model latched onto, and is explicitly
NOT a causal proof. Global importances come from the trained estimator
(tree importances / logistic coefficients / permutation importance).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from app.ml.features import FEATURE_LABELS


def global_importance(bundle: Dict[str, Any], top: int = 12) -> List[Dict[str, Any]]:
    items = list(bundle.get("importance") or [])[:top]
    return [
        {
            "feature": item["feature"],
            "label": item.get("label") or FEATURE_LABELS.get(item["feature"], item["feature"]),
            "importance": round(float(item.get("importance", 0.0)) * 100, 2),
        }
        for item in items
    ]


def _friendly(name: str) -> str:
    if name in FEATURE_LABELS:
        return FEATURE_LABELS[name]
    if name.startswith("proto_"):
        return f"Protocol = {name.split('_', 1)[1]}"
    if name.startswith("flag_"):
        return f"TCP flags = {name.split('_', 1)[1]}"
    return name.replace("_", " ").title()


def explain_local(
    bundle: Dict[str, Any],
    raw_features: pd.Series,
    deviations: pd.Series,
    predicted_class: str,
    probabilities: Dict[str, float],
    anomaly_score: Optional[float] = None,
    top: int = 6,
) -> Dict[str, Any]:
    """Per-prediction attribution built from real model internals."""
    importance = {item["feature"]: float(item.get("importance", 0.0)) for item in (bundle.get("importance") or [])}
    if not importance:
        importance = {name: 1.0 / max(len(bundle.get("feature_names", [])), 1) for name in bundle.get("feature_names", [])}

    pre = bundle.get("preprocessor")
    baseline_mean: Dict[str, float] = getattr(pre, "baseline_mean", {}) or {}
    percentiles: Dict[str, Dict[str, float]] = getattr(pre, "baseline_percentiles", {}) or {}

    contributions: List[Dict[str, Any]] = []
    for feature, weight in importance.items():
        if weight <= 0 or feature not in deviations.index:
            continue
        z = float(deviations.get(feature, 0.0))
        if not np.isfinite(z):
            continue
        score = weight * z
        observed = float(raw_features.get(feature, 0.0)) if feature in raw_features.index else None
        baseline = percentiles.get(feature, {})
        contributions.append({
            "feature": feature,
            "label": _friendly(feature),
            "observed": round(observed, 4) if observed is not None else None,
            "baseline_mean": round(float(baseline_mean.get(feature, 0.0)), 4),
            "baseline_p90": round(float(baseline.get("p90", 0.0)), 4),
            "deviation_sigma": round(z, 2),
            "weight": round(weight, 5),
            "attribution": round(score, 6),
            "direction": "risk_increase" if score > 0 else "risk_decrease",
        })

    contributions.sort(key=lambda item: abs(item["attribution"]), reverse=True)
    total = sum(abs(item["attribution"]) for item in contributions) or 1.0
    for item in contributions:
        share = abs(item["attribution"]) / total
        pct = round(share * 100, 1)
        sign = "+" if item["direction"] == "risk_increase" else "-"
        item["impact"] = f"{sign}{pct}%"
        item["impact_pct"] = pct
        if item["baseline_mean"]:
            ratio = (item["observed"] or 0.0) / item["baseline_mean"]
            item["ratio_vs_baseline"] = round(float(ratio), 2) if np.isfinite(ratio) else None
        else:
            item["ratio_vs_baseline"] = None
        item["explanation"] = _describe(item)

    selected = contributions[:top]
    rising = [c for c in selected if c["direction"] == "risk_increase"][:3]

    if rising:
        summary = (
            f"Model attributes this '{predicted_class}' verdict mainly to "
            + ", ".join(f"{c['label']} ({c['impact']})" for c in rising)
            + ". Attributions are model-internal, not causal proof."
        )
    else:
        summary = (
            f"No feature deviates enough to support an attack verdict; the flow stays inside the "
            f"trained baseline (highest positive attribution: "
            f"{selected[0]['label'] if selected else 'n/a'})."
        )

    return {
        "method": "importance-weighted deviation attribution (LIME-style linear surrogate)",
        "predicted_attack": predicted_class,
        "probabilities": {k: round(float(v), 4) for k, v in probabilities.items()},
        "anomaly_score": round(float(anomaly_score), 4) if anomaly_score is not None else None,
        "summary": summary,
        "contributions": selected,
        "all_contributions": contributions[:15],
        "global_feature_importance": global_importance(bundle),
        "disclaimer": "Explanations describe what the model used; they are not a causal proof of attacker intent.",
    }


def _describe(item: Dict[str, Any]) -> str:
    label = item["label"]
    sigma = item["deviation_sigma"]
    ratio = item.get("ratio_vs_baseline")
    observed = item.get("observed")
    direction = "above" if sigma >= 0 else "below"
    parts = [f"{label} is {abs(sigma):.1f}σ {direction} the trained baseline"]
    if ratio and ratio > 1.5:
        parts.append(f"({ratio:.1f}x the mean")
        if observed is not None:
            parts[-1] += f", observed {observed:g})"
        else:
            parts[-1] += ")"
    elif observed is not None:
        parts.append(f"(observed {observed:g})")
    return " ".join(parts) + "."
