"""
CyberForecast AI - FastAPI application entry point.

AI-Based Network Attack Forecasting & Blockchain-Assured Cybersecurity
Smart India Hackathon | Theme: Blockchain & Cybersecurity
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Support direct execution (`python app/main.py`).
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.api import api_router
from app.core.config import settings
from app.core.utils import iso, new_id, utcnow
from app.security.ratelimit import limiter
from app.services.realtime import hub
from app.storage.orm import init_db

logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("cyberforecast")

# Third-party libraries are extremely chatty at DEBUG level (web3 logs every
# JSON-RPC frame); keep them at WARNING unless explicitly overridden.
for _noisy in ("web3", "urllib3", "websockets", "httpx", "httpcore", "asyncio", "PIL"):
    logging.getLogger(_noisy).setLevel(max(logging.WARNING, logging.getLogger(_noisy).level))


ON_SERVERLESS = settings.is_serverless
DOCS_PREFIX = "/api" if ON_SERVERLESS else ""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Boot: create tables, bind the realtime loop, seed demo data, start simulation."""
    import asyncio

    init_db()
    hub.bind_loop(asyncio.get_running_loop())
    logger.info("%s v%s starting (storage=%s, blockchain=%s)",
                settings.app_name, settings.version, settings.storage_backend,
                "evm" if settings.blockchain_anchor else "local-hash-chain")

    if settings.seed_demo_data and not ON_SERVERLESS:
        from app.services import seed_service
        from app.services.simulation_service import engine as simulation_engine

        def bootstrap() -> None:
            seed_service.seed_all()
            from app.services import settings_service

            if simulation_engine.status()["status"] == "stopped" and settings_service.get("simulation_autostart"):
                simulation_engine.start(scenario="mixed", intensity=settings.simulation_default_rate // 2 or 5,
                                        duration_seconds=1800)
                logger.info("Simulation autostart engaged (labelled synthetic traffic)")

        threading.Thread(target=bootstrap, name="cyberforecast-bootstrap", daemon=True).start()

    yield
    logger.info("Shutting down CyberForecast AI backend")


app = FastAPI(
    title=f"{settings.app_name} API",
    description=(
        f"{settings.app_subtitle}\n\n"
        "AI/ML network-traffic analysis, multi-class attack classification, anomaly detection, "
        "time-series attack forecasting, explainable AI, threat alerting, reporting and a "
        "tamper-evident integrity ledger (local hash chain with optional EVM anchoring).\n\n"
        "**Simulation Mode**: synthetic traffic is clearly labelled and never presented as live capture."
    ),
    version=settings.version,
    lifespan=lifespan,
    docs_url=f"{DOCS_PREFIX}/docs",
    redoc_url=f"{DOCS_PREFIX}/redoc",
    openapi_url=f"{DOCS_PREFIX}/openapi.json",
    contact={"name": "CyberForecast AI", "url": "https://github.com/rgokul08/NetSentinel-ai"},
    license_info={"name": "MIT"},
)

# --- middleware -------------------------------------------------------------
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.cors_allow_all else settings.cors_origins,
    allow_credentials=not settings.cors_allow_all,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["Content-Disposition"],
    max_age=600,
)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.middleware("http")
async def add_request_metadata(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or new_id(length=12)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        response = JSONResponse(
            status_code=500,
            content={
                "detail": "An internal error occurred while processing this request.",
                "error_type": "internal_error",
                "path": request.url.path,
                "request_id": request_id,
                "timestamp": iso(utcnow()),
            },
        )
    duration_ms = round((time.perf_counter() - started) * 1000, 1)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-ms"] = str(duration_ms)
    response.headers["X-Simulation-Mode"] = "synthetic-data-supported"
    if request.url.path.startswith("/api") and duration_ms > 1500:
        logger.warning("slow request %s %s took %sms", request.method, request.url.path, duration_ms)
    return response


# --- structured error handling ---------------------------------------------

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "detail": "Rate limit exceeded. Please slow down and retry shortly.",
            "error_type": "rate_limited",
            "path": request.url.path,
            "timestamp": iso(utcnow()),
        },
        headers={"Retry-After": "30"},
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = []
    for error in exc.errors()[:12]:
        location = [str(part) for part in error.get("loc", []) if part not in ("body", "query")]
        errors.append({"field": ".".join(location) or "request", "message": error.get("msg"),
                       "type": error.get("type")})
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Request validation failed.", "error_type": "validation_error",
                 "errors": errors, "path": request.url.path, "timestamp": iso(utcnow())},
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Any) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"detail": f"No route matches {request.method} {request.url.path}",
                 "error_type": "not_found", "path": request.url.path, "timestamp": iso(utcnow())},
    )


# --- routes -----------------------------------------------------------------
app.include_router(api_router)


@app.get("/", include_in_schema=False)
def root() -> Dict[str, Any]:
    return {
        "status": "ONLINE",
        "system": settings.app_name,
        "subtitle": settings.app_subtitle,
        "version": settings.version,
        "theme": "Blockchain & Cybersecurity (Smart India Hackathon)",
        "api_prefix": "/api",
        "docs": f"{DOCS_PREFIX}/docs",
        "health": "/api/health",
        "storage_backend": settings.storage_backend,
        "blockchain_mode": "evm" if settings.blockchain_anchor else "local-hash-chain",
        "simulation_mode": "available (synthetic traffic is always labelled)",
    }


@app.get("/health", include_in_schema=False)
def root_health() -> Dict[str, Any]:
    from app.services import health_service

    summary = health_service.full_health(include_counts=False)
    return {"status": summary["status"], "app": settings.app_name, "checked_at": summary["checked_at"],
            "components": {k: v.get("status") or ("online" if v.get("ok") else "offline")
                           for k, v in summary["components"].items()}}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=not ON_SERVERLESS)
