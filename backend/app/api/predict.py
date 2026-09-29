"""Single-flow and batch prediction endpoints (real ML inference)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.common import Paging, envelope, paging_params
from app.core.utils import iso, utcnow
from app.ml import inference
from app.schemas.schemas import PredictBatchRequest, PredictRequest
from app.security.deps import client_ip, get_current_user, require_capability
from app.security.ratelimit import limiter
from app.services import audit_service, pipeline_service
from app.storage import get_store

router = APIRouter(tags=["Prediction"])


def _model_meta() -> Dict[str, Any]:
    record = inference.active_model_record("classification")
    anomaly_record = inference.active_model_record("anomaly")
    return {
        "engine": "ml" if inference.bundle_for(record) else "heuristic-fallback",
        "model_id": (record or {}).get("id"),
        "model_name": (record or {}).get("name"),
        "model_version": (record or {}).get("version"),
        "algorithm": (record or {}).get("algorithm"),
        "trained_at": (record or {}).get("trained_at"),
        "anomaly_model_id": (anomaly_record or {}).get("id"),
        "note": None if inference.bundle_for(record) else
                "No trained classifier active - using the transparent heuristic baseline.",
    }


@router.post("/predict")
@limiter.limit("120/minute")
def predict(payload: PredictRequest, request: Request,
            user: Dict[str, Any] = Depends(require_capability("predict.run"))) -> Dict[str, Any]:
    """Classify one flow and explain the verdict."""
    record = payload.flow.model_dump(exclude_none=True)
    result = inference.predict_records([record], explain=payload.explain)
    prediction = (result.get("predictions") or [None])[0]
    if prediction is None:
        raise HTTPException(status_code=422, detail="Prediction could not be produced for this flow.")
    prediction["model"] = _model_meta()
    prediction["predicted_at"] = iso(utcnow())
    audit_service.log("prediction.single", category="prediction", user=user, resource="prediction",
                      metadata={"attack_type": prediction.get("attack_type"),
                                "risk_score": prediction.get("risk_score")}, ip_address=client_ip(request))
    return prediction


@router.post("/predict/batch")
@limiter.limit("30/minute")
def predict_batch(payload: PredictBatchRequest, request: Request,
                  user: Dict[str, Any] = Depends(require_capability("predict.run"))) -> Dict[str, Any]:
    records = [flow.model_dump(exclude_none=True) for flow in payload.flows]
    result = pipeline_service.analyze_records(records, source="api", persist=payload.persist,
                                              create_alerts=payload.persist, user=user)
    result["model"] = _model_meta()
    result["requested_by"] = user.get("email")
    audit_service.log("prediction.batch", category="prediction", user=user, resource="prediction",
                      metadata={"rows": len(records), "persist": payload.persist,
                                "attacks": (result.get("summary") or {}).get("attacks_detected")},
                      ip_address=client_ip(request))
    return result


@router.get("/predictions")
def list_predictions(paging: Paging = Depends(paging_params),
                     attack_type: Optional[str] = Query(None),
                     risk_level: Optional[str] = Query(None),
                     window: Optional[str] = Query("24h"),
                     source: Optional[str] = Query(None),
                     anomalies_only: bool = Query(False),
                     search: Optional[str] = Query(None),
                     user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    from app.core.utils import window_start

    filters: Dict[str, Any] = {}
    start = window_start(window)
    if start:
        filters["timestamp"] = {"$gte": start}
    if attack_type:
        filters["attack_type"] = attack_type
    if risk_level:
        filters["risk_level"] = risk_level.upper()
    if source:
        filters["source"] = source
    if anomalies_only:
        filters["is_anomaly"] = True
    rows, total = get_store().list("predictions", filters=filters or None, order_by="-timestamp",
                                   limit=paging.limit, offset=paging.offset, search=search,
                                   search_fields=["attack_type", "model_version", "source"])
    return envelope(rows, total, paging, model=_model_meta())


@router.get("/predictions/{prediction_id}")
def get_prediction(prediction_id: str, user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    record = get_store().get("predictions", prediction_id)
    if not record:
        raise HTTPException(status_code=404, detail="Prediction not found.")
    traffic = get_store().get("traffic_records", record.get("traffic_record_id") or "")
    record["traffic_record"] = traffic
    record["model"] = _model_meta()
    return record


@router.get("/explain")
def explain_model(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Global explainability: what the active model actually learned."""
    record, bundle = inference.active_bundle("classification")
    if bundle is None:
        return {"available": False, "engine": "heuristic-fallback",
                "message": "No trained model is active; train one in the ML Model Center to see learned importances."}
    from app.ml.xai import global_importance

    return {
        "available": True,
        "engine": "ml",
        "model_id": record.get("id"),
        "model_name": record.get("name"),
        "algorithm": record.get("algorithm"),
        "version": record.get("version"),
        "classes": record.get("classes"),
        "metrics": record.get("metrics"),
        "feature_importance": global_importance(bundle, top=20),
        "method": "Native tree importances / logistic coefficient magnitudes / permutation importance",
        "disclaimer": "Global importances describe model behaviour on the training distribution, not causal proof.",
    }
