"""
Anomaly Detection Pipeline using Isolation Forest
Detects zero-day, stealthy, and abnormal network flow behaviors without requiring labeled attack signatures.
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, List
from sklearn.ensemble import IsolationForest

class NetworkAnomalyDetector:
    def __init__(self, contamination: float = 0.12, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.fitted = False

    def fit(self, X: np.ndarray) -> 'NetworkAnomalyDetector':
        self.model.fit(X)
        self.fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Returns:
        1 for Normal traffic
        -1 for Anomalous traffic
        """
        if not self.fitted:
            self.fit(X)
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Returns normalized anomaly score between 0.0 (normal) and 1.0 (highly anomalous)
        """
        if not self.fitted:
            self.fit(X)
        raw_scores = self.model.score_samples(X)
        # raw_scores typically range between -0.8 and -0.2 (lower means more anomalous)
        # Normalize into 0 to 1 range
        normalized = 1.0 / (1.0 + np.exp(raw_scores * 6.0))
        return np.clip(normalized, 0.0, 1.0)

    def analyze_flow(self, row: Dict[str, Any], score: float) -> Dict[str, Any]:
        """Explains why a flow received an anomalous score"""
        reasons = []
        pps = float(row.get('packets_per_second', 0.0))
        bps = float(row.get('bytes_per_second', 0.0))
        pkt_cnt = float(row.get('packet_count', 0.0))
        dur = float(row.get('flow_duration', 0.0))
        flags = str(row.get('tcp_flags', 'ACK')).upper()
        dst_port = int(row.get('destination_port', 80))

        if pps > 400.0:
            reasons.append(f"Abnormally high packet rate ({pps:.1f} pkts/sec)")
        if bps > 1000000.0:
            reasons.append(f"Excessive bandwidth spike ({bps/1024/1024:.2f} MB/s)")
        if flags in ['NULL', 'XMAS', 'FIN-PSH-URG', 'RST']:
            reasons.append(f"Suspicious TCP Flag pattern ({flags})")
        if pkt_cnt < 3 and dur < 0.01:
            reasons.append("Ultra-short burst probing connection")
        if dst_port in [22, 3389, 4444, 6667, 9999]:
            reasons.append(f"Critical or non-standard administration port ({dst_port})")

        if not reasons:
            reasons.append("Statistical deviation from baseline normal traffic profile")

        return {
            "is_anomaly": bool(score > 0.65),
            "anomaly_score": round(float(score), 4),
            "primary_reason": " & ".join(reasons[:2]),
            "all_reasons": reasons
        }
