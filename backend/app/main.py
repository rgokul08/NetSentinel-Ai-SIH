"""
FastAPI Backend Application Entry Point
AI-Based Network Attack Forecasting Platform (SIH 2026)
"""

import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes tables and seeds baseline demonstration data upon startup"""
    # Create DB tables
    Base.metadata.create_all(bind=engine)
    
    # Seed initial users & mock traffic data
    db = SessionLocal()
    try:
        seed_initial_data(db)
    finally:
        db.close()
        
    print("AI Network Attack Forecasting Backend initialized successfully!")
    yield
    print("Shutting down SOC Backend...")

app = FastAPI(
    title="AI-Based Network Attack Forecasting API",
    description="Cybersecurity AI Platform for Network Traffic Anomaly Detection, Multi-Class Attack Classification, and Time-Series Threat Forecasting (Smart India Hackathon)",
    version="1.0.0",
    lifespan=lifespan
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
        "docs_url": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
