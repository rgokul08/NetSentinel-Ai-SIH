"""
FastAPI Backend Application Entry Point
AI-Based Network Attack Forecasting Platform (SIH 2026)
"""

import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Support direct execution (`python app/main.py`) by putting the backend root
# on sys.path so the `app` package resolves the same way as `uvicorn app.main:app`.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database.session import engine, Base, SessionLocal
from app.services.traffic_service import seed_initial_data
from app.api import (
    auth,
    dashboard,
    traffic,
    detection,
    forecast,
    anomalies,
    analytics,
    alerts,
    datasets,
    models,
    reports,
    admin
)

# On Vercel every request reaches us through the /api rewrite, so the built-in
# docs/openapi endpoints must live under /api as well (e.g. /api/docs).
ON_VERCEL = bool(os.getenv("VERCEL"))
DOCS_PREFIX = "/api" if ON_VERCEL else ""

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes tables and seeds baseline demonstration data upon startup"""
    # Create DB tables
    Base.metadata.create_all(bind=engine)

    # Seed initial users & mock traffic data (never let seeding break the app)
    db = SessionLocal()
    try:
        seed_initial_data(db)
    except Exception as exc:  # pragma: no cover - defensive serverless startup
        db.rollback()
        print(f"Warning: initial data seeding failed: {exc}")
    finally:
        db.close()

    print("AI Network Attack Forecasting Backend initialized successfully!")
    yield
    print("Shutting down SOC Backend...")

app = FastAPI(
    title="AI-Based Network Attack Forecasting API",
    description="Cybersecurity AI Platform for Network Traffic Anomaly Detection, Multi-Class Attack Classification, and Time-Series Threat Forecasting (Smart India Hackathon)",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=f"{DOCS_PREFIX}/docs",
    redoc_url=f"{DOCS_PREFIX}/redoc",
    openapi_url=f"{DOCS_PREFIX}/openapi.json",
)

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register All API Routers
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(traffic.router)
app.include_router(detection.router)
app.include_router(forecast.router)
app.include_router(anomalies.router)
app.include_router(analytics.router)
app.include_router(alerts.router)
app.include_router(datasets.router)
app.include_router(models.router)
app.include_router(reports.router)
app.include_router(admin.router)

@app.get("/")
def root_status():
    return {
        "status": "ONLINE",
        "system": "AI-Based Network Attack Forecasting Engine",
        "version": "1.0.0",
        "hackathon": "Smart India Hackathon (SIH)",
        "docs_url": f"{DOCS_PREFIX}/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
