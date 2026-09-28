"""
Time-Series Attack Forecasting API Endpoints
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.schemas.schemas import ForecastResponse
from app.services.ml_service import ml_service

router = APIRouter(prefix="/api/forecast", tags=["Forecasting"])

@router.get("", response_model=ForecastResponse)
def get_attack_forecast(
    hours: int = Query(24, ge=1, le=72),
    db: Session = Depends(get_db)
):
    """
    Generates time-series projection comparing historical attacks vs forecasted attacks.
    Predicts probability, expected attack type, confidence interval, and risk level.
    """
    forecast_data = ml_service.get_forecast(hours_ahead=hours)
    return forecast_data

@router.get("/summary")
def get_forecast_summary_quick(db: Session = Depends(get_db)):
    forecast_data = ml_service.get_forecast(hours_ahead=24)
    return forecast_data["summary"]
