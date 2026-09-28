"""
ML Model Management, Retraining & Explainability API Endpoints
"""

import os
import sys
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.models import MLModel, AuditLog, User
from app.schemas.schemas import MLTrainRequest, MLModelMetricsOut
from app.services.auth_service import get_current_user

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../ml")))
from train import train_and_evaluate_model
from xai import ExplainableAIEngine

router = APIRouter(prefix="/api/model", tags=["ML Models"])

@router.get("/metrics", response_model=MLModelMetricsOut)
def get_model_metrics(db: Session = Depends(get_db)):
    """Retrieves current model evaluation metrics, confusion matrix, and feature importances"""
    model = db.query(MLModel).filter(MLModel.is_active == True).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active ML model found"
        )
    return model

@router.post("/train")
def trigger_model_training(
    req: MLTrainRequest,
    db: Session = Depends(get_db)
):
    """Triggers model training or retraining on dataset and updates metrics"""
    sample_csv = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../dataset/sample_network_traffic.csv"))
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../ml/models"))
    
    try:
        # Run training pipeline
        results = train_and_evaluate_model(sample_csv, models_dir)
        
        # Update or create model record in database
        model = db.query(MLModel).first()
        if not model:
            model = MLModel(name="Random Forest Attack Classifier", model_type=req.model_type)
            db.add(model)
            
        model.accuracy = results["accuracy"]
        model.precision_score = results["precision"]
        model.recall_score = results["recall"]
        model.f1_score = results["f1_score"]
        model.confusion_matrix = results["confusion_matrix"]
        model.feature_importance = results["feature_importance"]
        model.version = f"1.{int(model.version.split('.')[1]) + 1}.0" if "." in model.version else "1.3.0"
        
        db.commit()
        db.refresh(model)

        return {
            "status": "SUCCESS",
            "message": "Model trained and deployed successfully",
            "metrics": results
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Training failed: {str(e)}"
        )

@router.get("/explain")
def get_global_feature_importance():
    """Returns global explainable AI feature ranking"""
    xai = ExplainableAIEngine()
    return {
        "algorithm": "SHAP Proxy & Tree-based Mean Gini Impurity Reduction",
        "global_importance": [
            {"feature": k, "importance_percent": round(v * 100, 1)}
            for k, v in xai.global_feature_importance.items()
        ]
    }
