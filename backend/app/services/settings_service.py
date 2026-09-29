"""Runtime-tunable application settings (admin console).

Values default from the environment and can be adjusted while the process runs;
changes are audited and immediately affect the alert engine, anomaly detector
training and the simulation autostart behaviour.
"""

from __future__ import annotations

import threading
from typing import Any, Dict

from app.core.config import settings

_lock = threading.Lock()

DEFAULTS: Dict[str, Any] = {
    "alert_throttle_minutes": 5,
    "anomaly_contamination": settings.anomaly_contamination,
    "simulation_autostart": settings.simulation_autostart,
    "simulation_default_rate": settings.simulation_default_rate,
    "max_forecast_history_rows": 20000,
    "seed_traffic_records": settings.seed_traffic_records,
}

_runtime: Dict[str, Any] = dict(DEFAULTS)


def get_all() -> Dict[str, Any]:
    with _lock:
        return dict(_runtime)


def get(key: str, default: Any = None) -> Any:
    with _lock:
        return _runtime.get(key, DEFAULTS.get(key, default))


def update(values: Dict[str, Any]) -> Dict[str, Any]:
    changed: Dict[str, Any] = {}
    with _lock:
        for key, value in values.items():
            if key not in DEFAULTS:
                continue
            if value is None:
                continue
            expected = type(DEFAULTS[key])
            try:
                coerced = expected(value) if expected is not bool else bool(value)
            except (TypeError, ValueError):
                continue
            if coerced != _runtime.get(key):
                changed[key] = {"from": _runtime.get(key), "to": coerced}
                _runtime[key] = coerced
    return changed


def reset() -> Dict[str, Any]:
    with _lock:
        _runtime.clear()
        _runtime.update(DEFAULTS)
        return dict(_runtime)
