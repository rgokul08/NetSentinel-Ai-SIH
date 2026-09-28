"""
Pydantic Data Validation Schemas
Defines request and response schemas for all REST API endpoints.
"""

from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# --- AUTH SCHEMAS ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    full_name: str
    role: Optional[str] = "Security Analyst"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class UserOut(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    created_at: datetime
    class Config:
        from_attributes = True

# --- NETWORK TRAFFIC & PREDICTION SCHEMAS ---
class PacketPredictRequest(BaseModel):
    source_ip: str = "192.168.1.45"
    destination_ip: str = "10.0.0.1"
    source_port: int = 54321
    destination_port: int = 80
    protocol: str = "TCP"
    packet_count: int = 50
    packet_size: int = 1200
    flow_duration: float = 2.5
    bytes_per_second: Optional[float] = None
    packets_per_second: Optional[float] = None
    tcp_flags: str = "SYN"

class PredictionResponse(BaseModel):
    attack_type: str
    confidence: float
    risk_level: str # LOW, MEDIUM, HIGH, CRITICAL
    is_anomaly: bool
    anomaly_score: float
    timestamp: str
    source_ip: str
    destination_ip: str
    explanation: Dict[str, Any]

class TrafficFlowOut(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_count: int
    packet_size: int
    flow_duration: float
    bytes_per_second: float
    packets_per_second: float
    tcp_flags: str
    attack_type: str
    confidence: float
    risk_level: str
    is_anomaly: bool
    is_demo: bool
    class Config:
        from_attributes = True

# --- FORECAST SCHEMAS ---
class ForecastPoint(BaseModel):
    time: str
    full_timestamp: str
    forecasted_attacks: int
    upper_bound: int
    lower_bound: int
    attack_probability: float
    expected_attack_type: str
    risk_level: str
    confidence: float

class ForecastSummary(BaseModel):
    forecast_horizon_hours: int
    overall_attack_probability: float
    overall_threat_level: str
    overall_confidence: float
    peak_threat_time: str
    peak_threat_probability: float
    peak_expected_attack: str
    peak_risk_level: str
    projected_attack_count_24h: int
    forecast_model: str

class ForecastResponse(BaseModel):
    summary: ForecastSummary
    historical_trend: List[Dict[str, Any]]
    forecast_trend: List[ForecastPoint]
    attack_type_distribution: List[Dict[str, Any]]

# --- ALERT SCHEMAS ---
class AlertOut(BaseModel):
    id: int
    alert_code: str
    severity: str
    attack_type: str
    source_ip: str
    destination_ip: str
    description: str
    status: str
    timestamp: datetime
    resolved_by: Optional[str] = None
    class Config:
        from_attributes = True

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(Open|Investigating|Resolved)$")
    resolved_by: Optional[str] = None

# --- DASHBOARD STATS SCHEMAS ---
class DashboardStatsOut(BaseModel):
    total_network_traffic: int
    normal_traffic_percentage: float
    suspicious_traffic_percentage: float
    detected_attacks_count: int
    forecasted_attacks_count: int
    current_threat_level: str
    attack_probability: float
    network_health_score: int
    active_alerts_count: int
    top_attack_vector: str

# --- MODEL METRICS SCHEMAS ---
class MLTrainRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    dataset_id: Optional[int] = None
    model_type: str = "Random Forest"
    n_estimators: int = 120

class MLModelMetricsOut(BaseModel):
    model_config = {"protected_namespaces": (), "from_attributes": True}
    id: int
    name: str
    model_type: str
    version: str
    accuracy: float
    precision_score: float
    recall_score: float
    f1_score: float
    confusion_matrix: Optional[Dict[str, Any]] = None
    feature_importance: Optional[List[Dict[str, Any]]] = None
    updated_at: datetime

# --- AUDIT LOG SCHEMAS ---
class AuditLogOut(BaseModel):
    id: int
    action: str
    details: Optional[str]
    ip_address: str
    timestamp: datetime
    user_email: Optional[str] = None
