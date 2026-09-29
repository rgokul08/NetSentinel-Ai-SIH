"""
Serverless (Vercel) entrypoint.

vercel.json points the "backend" service at this module via
    "entrypoint": "main:app"
so the ASGI instance below is what the runtime loads. The real application lives
in app/main.py and is identical for local development and Docker.
"""

from app.main import app  # noqa: F401  (re-exported for the serverless runtime)

__all__ = ["app"]
