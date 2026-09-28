"""
Model Training & Evaluation Pipeline
Trains multi-class attack classifiers, computes evaluation metrics, and serializes the model.
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

from preprocessing import NetworkTrafficPreprocessor, ATTACK_CLASSES

def train_and_evaluate_model(dataset_path: str, model_save_dir: str = "models") -> Dict[str, Any]:
    os.makedirs(model_save_dir, exist_ok=True)
    
    # 1. Load dataset
    df = pd.read_csv(dataset_path)
    
    # 2. Preprocess features
    preprocessor = NetworkTrafficPreprocessor()
    X = preprocessor.fit_transform(df)
    y = df['attack_type'].values
    
    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    
    # 4. Train Random Forest Model
    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    
    # 5. Predictions & Metrics
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)
    
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average='weighted', zero_division=0))
    rec = float(recall_score(y_test, y_pred, average='weighted', zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average='weighted', zero_division=0))
    
    # 6. Confusion Matrix
    unique_labels = sorted(list(set(y)))
    cm = confusion_matrix(y_test, y_pred, labels=unique_labels)
    cm_matrix = {
        "labels": unique_labels,
        "matrix": cm.tolist()
    }
    
    # 7. Feature Importance
    raw_importances = clf.feature_importances_
    feature_imp_list = []
    for name, imp in zip(preprocessor.feature_names, raw_importances):
        feature_imp_list.append({
            "feature": name,
            "importance": round(float(imp), 4)
        })
    feature_imp_list.sort(key=lambda x: x["importance"], reverse=True)
    
    # 8. Save Artifacts
    model_path = os.path.join(model_save_dir, "attack_classifier.joblib")
    preprocessor_path = os.path.join(model_save_dir, "preprocessor.joblib")
    metrics_path = os.path.join(model_save_dir, "metrics.json")
    
    joblib.dump(clf, model_path)
    joblib.dump(preprocessor, preprocessor_path)
    
    metrics = {
        "model_name": "RandomForest Network Classifier (Ensemble)",
        "version": "1.2.0",
        "dataset_size": len(df),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "classes": unique_labels,
        "confusion_matrix": cm_matrix,
        "feature_importance": feature_imp_list[:10]
    }
    
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
        
    print(f"Training Complete! Accuracy: {acc:.4f}, F1: {f1:.4f}")
    return metrics

if __name__ == "__main__":
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    train_and_evaluate_model(
        os.path.join(base, "dataset", "sample_network_traffic.csv"),
        os.path.join(base, "ml", "models"),
    )
