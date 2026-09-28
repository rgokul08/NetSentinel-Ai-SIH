"""
Vercel Services entrypoint for the FastAPI backend.

vercel.json points the "backend" service at this module via:

    "backend": { "root": "backend", "framework": "fastapi", "entrypoint": "main:app" }

Vercel's Python runtime loads the top-level `app` ASGI instance from this file.
The real application lives in app/main.py and is unchanged, so local development
(`uvicorn app.main:app`) and Docker keep working exactly as before.
"""

from app.main import app  # noqa: F401  (re-exported for the Vercel runtime)

__all__ = ["app"]
