"""
Preprocessing & Feature Engineering Pipeline for Network Attack Classification
Extracts, scales, and encodes network flow attributes for machine learning inference and training.
"""

import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, List
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Canonical feature lists
NUMERICAL_FEATURES = [
    "source_port",
    "destination_port",
    "packet_count",
    "packet_size",
    "flow_duration",
    "bytes_per_second",
    "packets_per_second"
]

CATEGORICAL_FEATURES = [
    "protocol",
    "tcp_flags"
]

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "OTHER"]
TCP_FLAGS = ["SYN", "ACK", "PSH-ACK", "SYN-ACK", "FIN-ACK", "RST", "FIN-PSH-URG", "XMAS", "NULL", "OTHER"]

ATTACK_CLASSES = [
    "Normal",
    "DoS",
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Botnet",
    "Malware",
    "Other Attack"
]

class NetworkTrafficPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.fitted = False
        self.feature_names: List[str] = []
        
    def _extract_engineered_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extracts derivative network metrics like byte ratio and high-risk port indicators"""
        df = df.copy()
        
        # Ensure numerical columns exist with defaults
        for col in NUMERICAL_FEATURES:
            if col not in df.columns:
                df[col] = 0.0
            else:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
                
        # Fill missing categoricals
        if 'protocol' not in df.columns:
            df['protocol'] = 'TCP'
        else:
            df['protocol'] = df['protocol'].fillna('TCP').astype(str).str.upper()
            
        if 'tcp_flags' not in df.columns:
            df['tcp_flags'] = 'ACK'
        else:
            df['tcp_flags'] = df['tcp_flags'].fillna('ACK').astype(str).str.upper()

        # Engineered features
        df['bytes_per_packet'] = np.where(df['packet_count'] > 0, df['packet_size'] / (df['packet_count'] + 1e-5), 0.0)
        df['is_well_known_port'] = (df['destination_port'] <= 1024).astype(float)
        df['is_ephemeral_port'] = (df['source_port'] >= 49152).astype(float)
        df['high_pps_indicator'] = (df['packets_per_second'] > 500.0).astype(float)
        
        # One-hot encoding for protocol
        for proto in PROTOCOLS:
            df[f'proto_{proto}'] = (df['protocol'] == proto).astype(float)
            
        # One-hot encoding for TCP flags
        for flag in TCP_FLAGS:
            df[f'flag_{flag}'] = (df['tcp_flags'] == flag).astype(float)
            
        return df

    def fit(self, df: pd.DataFrame) -> 'NetworkTrafficPreprocessor':
        df_proc = self._extract_engineered_features(df)
        feature_cols = [c for c in df_proc.columns if c.startswith('proto_') or c.startswith('flag_') or c in NUMERICAL_FEATURES or c in ['bytes_per_packet', 'is_well_known_port', 'is_ephemeral_port', 'high_pps_indicator']]
        self.feature_names = feature_cols
        self.scaler.fit(df_proc[self.feature_names])
        self.fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if not self.fitted:
            # If not fitted yet, initialize with default scaling
            self.fit(df)
        df_proc = self._extract_engineered_features(df)
        for col in self.feature_names:
            if col not in df_proc.columns:
                df_proc[col] = 0.0
        return self.scaler.transform(df_proc[self.feature_names])

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        self.fit(df)
        return self.transform(df)
