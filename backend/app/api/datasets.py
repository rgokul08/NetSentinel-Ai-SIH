"""
Dataset Management & CSV Upload API Endpoints
"""

import os
import shutil
import pandas as pd
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.models import Dataset, User
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/api/dataset", tags=["Datasets"])

UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../dataset/uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

REQUIRED_COLUMNS = [
    "source_port", "destination_port", "protocol",
    "packet_count", "packet_size", "flow_duration"
]

@router.post("/upload")
async def upload_csv_dataset(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Uploads and validates a network traffic CSV dataset"""
    if not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only CSV format datasets are supported"
        )
        
    save_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(save_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        df = pd.read_csv(save_path)
        row_count = len(df)
        file_size = os.path.getsize(save_path)
        
        # Check missing or basic validation
        missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
        
        dataset_entry = Dataset(
            filename=file.filename,
            file_path=save_path,
            row_count=row_count,
            file_size_bytes=file_size,
            status="Validated & Ready" if not missing_cols else f"Missing columns: {', '.join(missing_cols)}"
        )
        db.add(dataset_entry)
        db.commit()
        db.refresh(dataset_entry)

        return {
            "id": dataset_entry.id,
            "filename": dataset_entry.filename,
            "row_count": row_count,
            "columns": list(df.columns),
            "preview": df.head(5).to_dict(orient="records"),
            "status": dataset_entry.status,
            "missing_required_columns": missing_cols
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error parsing CSV file: {str(e)}"
        )

@router.get("/list")
def list_uploaded_datasets(db: Session = Depends(get_db)):
    """Returns list of uploaded network datasets"""
    datasets = db.query(Dataset).order_by(Dataset.created_at.desc()).all()
    
    # Also include default sample dataset
    sample_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../dataset/sample_network_traffic.csv"))
    default_dataset = {
        "id": 0,
        "filename": "sample_network_traffic.csv (System Default)",
        "row_count": 3500,
        "file_size_bytes": os.path.getsize(sample_path) if os.path.exists(sample_path) else 125000,
        "status": "Validated & Active",
        "created_at": "2026-09-27 10:00:00"
    }

    result = [default_dataset]
    for d in datasets:
        result.append({
            "id": d.id,
            "filename": d.filename,
            "row_count": d.row_count,
            "file_size_bytes": d.file_size_bytes,
            "status": d.status,
            "created_at": d.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return result
