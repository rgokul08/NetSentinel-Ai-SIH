"""Scaling + baseline statistics shared by training and inference."""

from __future__ import annotations

from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from app.ml.features import build_feature_frame

BUNDLE_VERSION = "2.0.0"


class TrafficPreprocessor:
    """Fits a scaler on the canonical feature matrix and keeps baseline stats.

    The baseline (mean/std per feature) is what makes local explanations
    possible: an attribution is the model importance weighted by how far the
    observed value deviates from the traffic baseline.
    """

    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.fitted: bool = False
        self.baseline_mean: Dict[str, float] = {}
        self.baseline_std: Dict[str, float] = {}
        self.baseline_percentiles: Dict[str, Dict[str, float]] = {}

    def build(self, df: pd.DataFrame) -> pd.DataFrame:
        matrix, names = build_feature_frame(df)
        if self.fitted:
            missing = [c for c in self.feature_names if c not in matrix.columns]
            for column in missing:
                matrix[column] = 0.0
            matrix = matrix[self.feature_names]
        else:
            self.feature_names = names
        return matrix.astype(float)

    def fit(self, df: pd.DataFrame) -> "TrafficPreprocessor":
        matrix = self.build(df)
        self.feature_names = list(matrix.columns)
        self.scaler.fit(matrix.values)
        self.baseline_mean = {c: float(v) for c, v in zip(self.feature_names, matrix.mean(axis=0))}
        std = matrix.std(axis=0).replace(0, 1.0)
        self.baseline_std = {c: float(v) for c, v in zip(self.feature_names, std)}
        quantiles = matrix.quantile([0.5, 0.9, 0.99])
        self.baseline_percentiles = {
            column: {"p50": float(quantiles.loc[0.5, column]), "p90": float(quantiles.loc[0.9, column]),
                     "p99": float(quantiles.loc[0.99, column])}
            for column in self.feature_names
        }
        self.fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if not self.fitted:
            self.fit(df)
        matrix = self.build(df)
        return self.scaler.transform(matrix.values)

    def raw_matrix(self, df: pd.DataFrame) -> pd.DataFrame:
        """Unscaled features (needed for human-readable attributions)."""
        if not self.fitted:
            self.fit(df)
        return self.build(df)

    def deviations(self, df: pd.DataFrame) -> pd.DataFrame:
        """Z-score of every feature against the training baseline."""
        matrix = self.raw_matrix(df)
        means = pd.Series({c: self.baseline_mean.get(c, 0.0) for c in matrix.columns})
        stds = pd.Series({c: self.baseline_std.get(c, 1.0) or 1.0 for c in matrix.columns})
        return ((matrix - means) / stds).clip(-12, 12)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature_names": self.feature_names,
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "baseline_percentiles": self.baseline_percentiles,
        }
