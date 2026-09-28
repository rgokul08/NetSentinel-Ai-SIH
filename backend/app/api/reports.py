"""
Security Threat Intelligence Reports API Endpoints
"""

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.services.report_service import generate_threat_report_summary, generate_pdf_report

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.get("/summary")
def get_report_summary(db: Session = Depends(get_db)):
    """Returns structured JSON threat report summary"""
    return generate_threat_report_summary(db)

@router.get("/download-pdf")
def download_pdf_report(db: Session = Depends(get_db)):
    """Generates and streams a downloadable PDF threat intelligence report"""
    summary = generate_threat_report_summary(db)
    pdf_buffer = generate_pdf_report(summary)
    
    headers = {
        'Content-Disposition': f'attachment; filename="SOC_Attack_Forecast_Report_{summary["report_id"]}.pdf"'
    }
    return Response(
        content=pdf_buffer.getvalue(),
        media_type="application/pdf",
        headers=headers
    )
