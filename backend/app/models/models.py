"""
SQLAlchemy ORM Database Models
Defines tables for users, network flows, predictions, forecasts, anomalies, alerts, datasets, and audit logs.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), default="Security Analyst") # "Admin" or "Security Analyst"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    audit_logs = relationship("AuditLog", back_populates="user")
    datasets = relationship("Dataset", back_populates="uploader")

class NetworkTraffic(Base):
    __tablename__ = "network_traffic"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True, nullable=False)
    destination_ip = Column(String(45), index=True, nullable=False)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, index=True, nullable=False)
    protocol = Column(String(20), index=True, nullable=False)
    packet_count = Column(Integer, default=1)
    packet_size = Column(Integer, default=64)
    flow_duration = Column(Float, default=0.0)
    bytes_per_second = Column(Float, default=0.0)
    packets_per_second = Column(Float, default=0.0)
    tcp_flags = Column(String(50), default="ACK")
    label = Column(Integer, default=0) # 0 = Normal, 1 = Attack
    attack_type = Column(String(50), default="Normal", index=True)
    confidence = Column(Float, default=0.95)
    risk_level = Column(String(20), default="LOW") # LOW, MEDIUM, HIGH, CRITICAL
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)
    is_demo = Column(Boolean, default=False)

    predictions = relationship("AttackPrediction", back_populates="traffic", cascade="all, delete-orphan")
    anomalies = relationship("Anomaly", back_populates="traffic", cascade="all, delete-orphan")

class AttackPrediction(Base):
    __tablename__ = "attack_predictions"

    id = Column(Integer, primary_key=True, index=True)
    traffic_id = Column(Integer, ForeignKey("network_traffic.id"), nullable=True)
    attack_type = Column(String(50), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)
    contributing_features = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    traffic = relationship("NetworkTraffic", back_populates="predictions")

class AttackForecast(Base):
    __tablename__ = "attack_forecasts"

    id = Column(Integer, primary_key=True, index=True)
    forecast_time = Column(DateTime, nullable=False, index=True)
    predicted_probability = Column(Float, nullable=False)
    expected_attack_type = Column(String(50), nullable=False)
    risk_level = Column(String(20), nullable=False)
    confidence = Column(Float, default=0.85)
    horizon_hours = Column(Integer, default=24)
    forecast_model = Column(String(100), default="Ensemble Time-Series Forecaster")
    created_at = Column(DateTime, default=datetime.utcnow)

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    traffic_id = Column(Integer, ForeignKey("network_traffic.id"), nullable=True)
    anomaly_score = Column(Float, nullable=False)
    reason = Column(Text, nullable=False)
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    traffic = relationship("NetworkTraffic", back_populates="anomalies")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_code = Column(String(50), unique=True, index=True)
    severity = Column(String(20), index=True, nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    attack_type = Column(String(50), nullable=False)
    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(30), default="Open", index=True) # Open, Investigating, Resolved
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_by = Column(String(100), nullable=True)

class Dataset(Base):
    __tablename__ = "datasets"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    row_count = Column(Integer, default=0)
    file_size_bytes = Column(Integer, default=0)
    status = Column(String(50), default="Processed")
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    uploader = relationship("User", back_populates="datasets")

class MLModel(Base):
    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    model_type = Column(String(50), nullable=False)
    version = Column(String(20), default="1.0.0")
    accuracy = Column(Float, default=0.0)
    precision_score = Column(Float, default=0.0)
    recall_score = Column(Float, default=0.0)
    f1_score = Column(Float, default=0.0)
    confusion_matrix = Column(JSON, nullable=True)
    feature_importance = Column(JSON, nullable=True)
    is_active = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), default="127.0.0.1")
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", back_populates="audit_logs")
