"""Security report generation and download endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from app.api.common import Paging, envelope, paging_params, service_error
from app.schemas.schemas import ReportRequest
from app.security.deps import client_ip, get_current_user, require_capability
from app.security.ratelimit import limiter
from app.services import audit_service, report_service
from app.storage import get_store

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/generate")
@limiter.limit("10/minute")
def generate(payload: ReportRequest, request: Request,
             user: Dict[str, Any] = Depends(require_capability("reports.generate"))) -> Dict[str, Any]:
    try:
        record = report_service.generate(
            report_type=payload.report_type, window=payload.window, fmt=payload.format,
            title=payload.title, user=user,
        )
    except Exception as exc:
        raise service_error(exc, default_status=500)
    audit_service.log("report.generated", category="report", user=user, resource="report",
                      resource_id=record["id"], metadata={"window": payload.window, "format": payload.format,
                                                          "size_bytes": record.get("size_bytes")},
                      ip_address=client_ip(request))
    summary = record.pop("data", None)
    record["report_data_available"] = bool(summary)
    return record


@router.get("")
def list_reports(paging: Paging = Depends(paging_params),
                 user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    rows, total = report_service.list_reports(limit=paging.limit, offset=paging.offset)
    return envelope(rows, total, paging)


@router.get("/{report_id}")
def get_report(report_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    record = report_service.get_report(report_id)
    if not record:
        raise HTTPException(status_code=404, detail="Report not found.")
    return record


@router.get("/{report_id}/download")
def download(report_id: str, request: Request,
             user: Dict[str, Any] = Depends(require_capability("reports.view"))) -> Response:
    record = report_service.get_report(report_id)
    if not record:
        raise HTTPException(status_code=404, detail="Report not found.")
    content = report_service.read_report_file(record)
    if content is None:
        raise HTTPException(status_code=410, detail="Report content could not be regenerated.")
    get_store().update("reports", report_id, {"download_count": int(record.get("download_count") or 0) + 1})
    audit_service.log("report.downloaded", category="report", user=user, resource="report", resource_id=report_id,
                      metadata={"format": record.get("format")}, ip_address=client_ip(request))
    media = "application/pdf" if record.get("format") == "pdf" else "text/csv"
    filename = f"cyberforecast-report-{report_id}.{record.get('format', 'pdf')}"
    return Response(content=content, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/{report_id}/csv")
def download_csv(report_id: str, user: Dict[str, Any] = Depends(require_capability("reports.view"))) -> Response:
    record = report_service.get_report(report_id)
    if not record:
        raise HTTPException(status_code=404, detail="Report not found.")
    window = (record.get("range") or {}).get("window", "24h")
    data = report_service.build_report_data(window, record.get("report_type") or "security_summary")
    return Response(content=report_service.render_csv(data), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="cyberforecast-report-{report_id}.csv"'})


@router.delete("/{report_id}")
def delete_report(report_id: str, request: Request,
                  user: Dict[str, Any] = Depends(require_capability("reports.generate"))) -> Dict[str, Any]:
    if not report_service.delete_report(report_id):
        raise HTTPException(status_code=404, detail="Report not found.")
    audit_service.log("report.deleted", category="report", user=user, resource="report", resource_id=report_id,
                      ip_address=client_ip(request))
    return {"ok": True, "deleted": report_id}
