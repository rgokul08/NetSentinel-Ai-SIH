"""
Security Threat Alerts Management API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.session import get_db
from app.models.models import Alert
from app.schemas.schemas import AlertOut, AlertStatusUpdate

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertOut])
def get_all_alerts(
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieves all generated security threat alerts with optional filtering"""
    q = db.query(Alert)
    if severity and severity != "ALL":
        q = q.filter(Alert.severity == severity)
    if status_filter and status_filter != "ALL":
        q = q.filter(Alert.status == status_filter)
        
    return q.order_by(desc(Alert.timestamp)).all()

@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_alert_status(
    alert_id: int,
    req: AlertStatusUpdate,
    db: Session = Depends(get_db)
):
    """Updates the status of an alert (Open -> Investigating -> Resolved)"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
        
    alert.status = req.status
    if req.resolved_by:
        alert.resolved_by = req.resolved_by
        
    db.commit()
    db.refresh(alert)
    return alert
