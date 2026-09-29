"""API router aggregation - everything is mounted under /api."""

from __future__ import annotations

from fastapi import APIRouter

from app.api import (
    admin,
    alerts,
    analytics,
    audit,
    auth,
    blockchain,
    datasets,
    forecast,
    models,
    predict,
    reports,
    simulation,
    system,
    traffic,
)

api_router = APIRouter(prefix="/api")
api_router.include_router(system.router)
api_router.include_router(auth.router)
api_router.include_router(analytics.router)
api_router.include_router(traffic.router)
api_router.include_router(datasets.router)
api_router.include_router(predict.router)
api_router.include_router(forecast.router)
api_router.include_router(alerts.router)
api_router.include_router(models.router)
api_router.include_router(blockchain.router)
api_router.include_router(reports.router)
api_router.include_router(audit.router)
api_router.include_router(simulation.router)
api_router.include_router(admin.router)

__all__ = ["api_router"]
