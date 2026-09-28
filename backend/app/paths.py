"""
Central filesystem path resolution for the backend.

The backend must run unchanged in three environments:

1. Local development   -> backend/ml, backend/dataset (writable repo checkout)
2. Docker              -> /app/ml baked into the image, uploads under /app/dataset
3. Vercel (serverless) -> everything ships inside the service root (backend/),
                          but the runtime filesystem is read-only except /tmp

Any directory that needs to be written to is probed for writability and
transparently falls back to a temp directory when the bundle is read-only.
"""

import os
import sys
import tempfile

# Vercel (and compatible serverless hosts) set VERCEL=1 during builds/runtime.
IS_SERVERLESS = bool(os.environ.get("VERCEL"))

_BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../backend
_REPO_ROOT = os.path.dirname(_BACKEND_ROOT)


def _first_existing(*candidates: str) -> str:
    """Return the first candidate directory that exists (or the first as a last resort)."""
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return candidates[0]


def get_ml_dir() -> str:
    """Directory holding the ML modules (preprocessing, forecasting, xai, demo_stream, train...)."""
    return _first_existing(
        os.path.join(_BACKEND_ROOT, "ml"),   # canonical location (local, Docker, Vercel)
        os.path.join(_REPO_ROOT, "ml"),      # legacy repo-root layout
        "/ml",                               # legacy docker-compose mount
    )


def get_dataset_dir() -> str:
    """Directory holding sample datasets and the CSV upload target."""
    return _first_existing(
        os.path.join(_BACKEND_ROOT, "dataset"),   # canonical location
        os.path.join(_REPO_ROOT, "dataset"),      # legacy repo-root layout
        "/dataset",                               # legacy docker-compose mount
    )


def ensure_writable_dir(path: str) -> str | None:
    """Create `path` and verify it can actually be written to. Returns None on failure."""
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write_probe")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(probe)
        return path
    except OSError:
        return None


def _writable_or_tmp(preferred: str, fallback_name: str) -> str:
    return ensure_writable_dir(preferred) or ensure_writable_dir(
        os.path.join(tempfile.gettempdir(), fallback_name)
    ) or preferred


def get_upload_dir() -> str:
    """Writable directory for uploaded CSV datasets (falls back to /tmp on serverless)."""
    return _writable_or_tmp(os.path.join(get_dataset_dir(), "uploads"), "netsentinel_uploads")


def get_models_dir() -> str:
    """Writable directory for serialized model artifacts (falls back to /tmp on serverless)."""
    return _writable_or_tmp(os.path.join(get_ml_dir(), "models"), "netsentinel_models")


def add_ml_to_path() -> str:
    """Make the ML modules importable as top-level modules (preprocessing, xai, ...)."""
    ml_dir = get_ml_dir()
    if ml_dir not in sys.path:
        sys.path.insert(0, ml_dir)
    return ml_dir
