"""ML model registry endpoints (train, validate, activate, compare, upload)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile

from app.api.common import Paging, envelope, paging_params, service_error
from app.ml.algorithms import catalogue
from app.schemas.schemas import ActivateModelRequest, CompareModelsRequest, TrainModelRequest
from app.security.deps import client_ip, get_current_user, require_capability
from app.security.ratelimit import limiter
from app.services import audit_service, model_service
from app.storage import get_store

router = APIRouter(prefix="/models", tags=["Models"])


@router.get("/algorithms")
def algorithms(task: Optional[str] = Query(None), user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return {"items": catalogue(task), "default": "random_forest"}


@router.get("/registry")
def registry(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return model_service.registry_status()


@router.get("")
def list_models(paging: Paging = Depends(paging_params), task: Optional[str] = Query(None),
                user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    rows, total = model_service.list_models(task=task, limit=paging.limit, offset=paging.offset)
    return envelope(rows, total, paging)


@router.post("/train")
@limiter.limit("6/minute")
def train_model(payload: TrainModelRequest, request: Request,
                user: Dict[str, Any] = Depends(require_capability("models.train"))) -> Dict[str, Any]:
    try:
        result = model_service.train(
            algorithm=payload.algorithm, dataset_id=payload.dataset_id, rows=payload.rows,
            contamination=payload.contamination, user=user, train_anomaly=payload.train_anomaly,
        )
        if payload.activate:
            for record in result.get("trained", []):
                try:
                    activation = model_service.activate(record["id"], user=user, dataset_id=payload.dataset_id)
                    record["activation"] = {"activated": True, "validation": activation.get("validation")}
                except Exception as exc:
                    record["activation"] = {"activated": False, "reason": str(exc)}
    except Exception as exc:
        audit_service.log("model.train_failed", category="model", user=user, outcome="failure",
                          metadata={"algorithm": payload.algorithm, "reason": str(exc)[:200]},
                          ip_address=client_ip(request))
        raise service_error(exc, default_status=500)
    audit_service.log("model.trained", category="model", user=user, resource="model",
                      metadata={"algorithm": payload.algorithm, "rows": result.get("training_rows"),
                                "models": [r["id"] for r in result.get("trained", [])]},
                      ip_address=client_ip(request))
    return result


@router.post("/upload")
@limiter.limit("6/minute")
async def upload_model(request: Request, file: UploadFile = File(...), name: Optional[str] = Query(None),
                       user: Dict[str, Any] = Depends(require_capability("models.upload"))) -> Dict[str, Any]:
    content = await file.read()
    try:
        record = model_service.upload_bundle(content, file.filename or "model.joblib", name=name, user=user)
    except Exception as exc:
        raise service_error(exc)
    audit_service.log("model.uploaded", category="model", user=user, resource="model", resource_id=record["id"],
                      metadata={"filename": file.filename, "algorithm": record.get("algorithm")},
                      ip_address=client_ip(request))
    return record


@router.post("/compare")
def compare_models(payload: CompareModelsRequest, user: Dict[str, Any] = Depends(require_capability("models.view"))) -> Dict[str, Any]:
    try:
        return model_service.compare(payload.model_ids)
    except Exception as exc:
        raise service_error(exc)


@router.get("/{model_id}")
def get_model(model_id: str, user: Dict[str, Any] = Depends(require_capability("models.view"))) -> Dict[str, Any]:
    record = model_service.get_model(model_id)
    if not record:
        raise HTTPException(status_code=404, detail="Model not found.")
    return record


@router.get("/{model_id}/validate")
def validate_model(model_id: str, dataset_id: Optional[str] = Query(None),
                   user: Dict[str, Any] = Depends(require_capability("models.view"))) -> Dict[str, Any]:
    try:
        return model_service.validate(model_id, dataset_id)
    except Exception as exc:
        raise service_error(exc)


@router.post("/{model_id}/activate")
def activate_model(model_id: str, payload: ActivateModelRequest, request: Request,
                   user: Dict[str, Any] = Depends(require_capability("models.activate"))) -> Dict[str, Any]:
    try:
        result = model_service.activate(model_id, user=user, dataset_id=payload.dataset_id, force=payload.force)
    except Exception as exc:
        audit_service.log("model.activation_failed", category="model", user=user, outcome="failure",
                          metadata={"model_id": model_id, "reason": str(exc)[:200]}, ip_address=client_ip(request))
        raise service_error(exc, default_status=409)
    audit_service.log("model.activated", category="model", user=user, resource="model", resource_id=model_id,
                      metadata={"validation": result.get("validation", {}).get("accuracy")},
                      ip_address=client_ip(request))
    return result


@router.post("/{model_id}/deactivate")
def deactivate_model(model_id: str, request: Request,
                     user: Dict[str, Any] = Depends(require_capability("models.activate"))) -> Dict[str, Any]:
    updated = model_service.deactivate(model_id, user=user)
    if not updated:
        raise HTTPException(status_code=404, detail="Model not found.")
    audit_service.log("model.deactivated", category="model", user=user, resource="model", resource_id=model_id,
                      ip_address=client_ip(request))
    return updated


@router.delete("/{model_id}")
def delete_model(model_id: str, request: Request,
                 user: Dict[str, Any] = Depends(require_capability("models.activate"))) -> Dict[str, Any]:
    try:
        deleted = model_service.delete_model(model_id)
    except Exception as exc:
        raise service_error(exc, default_status=409)
    if not deleted:
        raise HTTPException(status_code=404, detail="Model not found.")
    audit_service.log("model.deleted", category="model", user=user, resource="model", resource_id=model_id,
                      ip_address=client_ip(request))
    return {"ok": True, "deleted": model_id}
