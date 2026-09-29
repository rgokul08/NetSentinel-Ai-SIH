"""
Filesystem path resolution for the CyberForecast AI backend.

The backend must run unchanged in three environments:

1. Local development    -> writable repo checkout under backend/
2. Docker               -> /app with volumes
3. Serverless (Vercel)  -> read-only bundle; only /tmp is writable

Every directory we write to is probed and transparently falls back to a temp
directory when the deployment bundle is read-only.
"""

from __future__ import annotations

import os
import sys
import tempfile

BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # .../backend
REPO_ROOT = os.path.dirname(BACKEND_ROOT)


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def _writable(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write_probe")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(probe)
        return True
    except OSError:
        return False


def _writable_or_tmp(preferred: str, fallback_name: str) -> str:
    if _writable(preferred):
        return preferred
    tmp = os.path.join(tempfile.gettempdir(), fallback_name)
    if _writable(tmp):
        return tmp
    return preferred


def get_models_dir() -> str:
    """Serialized ML artifacts (*.joblib, registry.json)."""
    return _writable_or_tmp(os.path.join(BACKEND_ROOT, "models"), "cyberforecast_models")


def get_upload_dir() -> str:
    """Writable directory for uploaded datasets."""
    return _writable_or_tmp(os.path.join(BACKEND_ROOT, "uploads"), "cyberforecast_uploads")


def get_data_dir() -> str:
    """Writable directory for the SQLite fallback database."""
    return _writable_or_tmp(os.path.join(BACKEND_ROOT, "data"), "cyberforecast_data")


def get_datasets_dir() -> str:
    """Read-only bundled sample datasets."""
    return os.path.join(BACKEND_ROOT, "datasets")


def get_reports_dir() -> str:
    return _writable_or_tmp(os.path.join(BACKEND_ROOT, "reports"), "cyberforecast_reports")


def add_backend_to_path() -> str:
    if BACKEND_ROOT not in sys.path:
        sys.path.insert(0, BACKEND_ROOT)
    return BACKEND_ROOT
