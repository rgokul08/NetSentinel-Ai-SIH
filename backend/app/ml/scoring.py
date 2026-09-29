"""Risk scoring: turns model output into a comparable 0..1 risk score + level."""

from __future__ import annotations

import math
from typing import Any, Dict

from app.ml.features import BENIGN


def _finite(value: Any, default: float = 0.0) -> float:
    """Coerce model output to a finite float.

    NaN must never reach the API: it serializes to ``null`` and silently breaks
    every comparison in the UI (a NaN risk score would render as "informational").
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default

# Relative operational impact of each attack category (used as a small weight).
SEVERITY_WEIGHTS: Dict[str, float] = {
    "DDoS": 1.00,
    "Intrusion": 0.95,
    "Bot Activity": 0.90,
    "Brute Force": 0.82,
    "DoS": 0.80,
    "Port Scan": 0.55,
    "Network Anomaly": 0.50,
    BENIGN: 0.05,
}

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def risk_score(attack_probability: float, anomaly_score: float, attack_type: str) -> float:
    """
    risk = 0.72 * P(attack) + 0.16 * anomaly + 0.12 * severity_weight(class)

    Documented and deterministic so that alerts, dashboards and forecasts stay
    comparable over time.
    """
    weight = _finite(SEVERITY_WEIGHTS.get(str(attack_type), 0.5), 0.5)
    score = (0.72 * _finite(attack_probability) + 0.16 * _finite(anomaly_score) + 0.12 * weight)
    return round(min(max(score, 0.0), 1.0), 4)


def risk_level(score: float) -> str:
    score = _finite(score)
    if score >= 0.75:
        return "critical"
    if score >= 0.5:
        return "high"
    if score >= 0.28:
        return "medium"
    if score >= 0.12:
        return "low"
    return "informational"


def severity_from_score(score: float, attack_type: str = BENIGN) -> str:
    """Alert severity = risk level, downgraded one step for benign verdicts."""
    level = risk_level(_finite(score))
    if attack_type == BENIGN and level in ("high", "critical"):
        return "medium"
    return level


def score_to_display_level(score: float) -> str:
    """Uppercase label used by the UI threat meter."""
    return risk_level(score).upper()
