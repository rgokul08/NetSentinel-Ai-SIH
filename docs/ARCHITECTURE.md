# System Architecture & Technical Specifications

## 1. High-Level Architecture

```
                                  +------------------------------------+
                                  |     React 18 + Vite + Tailwind     |
                                  |    SOC Cybersecurity Dashboard     |
                                  +-----------------+------------------+
                                                    | REST APIs / Axios
                                                    v
                                  +------------------------------------+
                                  |       FastAPI Python Backend       |
                                  |      JWT Auth & Role Security      |
                                  +--------+------------------+--------+
                                           |                  |
                 +-------------------------+                  +--------------------------+
                 |                                                                       |
                 v                                                                       v
+------------------------------------+                                 +------------------------------------+
|          AI / ML Engine            |                                 |          Database Layer            |
| - Preprocessing & Feature Eng.     |                                 | - PostgreSQL / SQLite Fallback     |
| - Multi-class Attack Classifier    |                                 | - SQLAlchemy ORM Models            |
| - Isolation Forest Anomaly Engine  |                                 | - Users, Traffic, Alerts, Audits   |
| - Time-Series Forecasting Model    |                                 | - Forecasts, Datasets, ML Metrics  |
| - Explainable AI (SHAP proxy)      |                                 +------------------------------------+
+------------------------------------+
```

## 2. Database Schema (PostgreSQL / SQLAlchemy)

- **users**: id, email, hashed_password, full_name, role, is_active, created_at
- **network_traffic**: id, timestamp, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, packet_size, flow_duration, bytes_per_second, packets_per_second, tcp_flags, label, attack_type, confidence, risk_level, is_anomaly, anomaly_score, is_demo
- **attack_predictions**: id, traffic_id, attack_type, confidence, risk_level, contributing_features, timestamp
- **attack_forecasts**: id, forecast_time, predicted_probability, expected_attack_type, risk_level, confidence, horizon_hours, forecast_model, created_at
- **anomalies**: id, traffic_id, anomaly_score, reason, source_ip, destination_ip, timestamp
- **alerts**: id, alert_code, severity, attack_type, source_ip, destination_ip, description, status, timestamp, resolved_by
- **datasets**: id, filename, file_path, row_count, file_size_bytes, status, user_id, created_at
- **ml_models**: id, name, model_type, version, accuracy, precision_score, recall_score, f1_score, confusion_matrix, feature_importance, is_active, updated_at
- **audit_logs**: id, user_id, action, details, ip_address, timestamp

## 3. Threat Level System
- **LOW**: Attack probability < 30%
- **MEDIUM**: Attack probability 30% - 60%
- **HIGH**: Attack probability 60% - 80%
- **CRITICAL**: Attack probability > 80%
