"""Pydantic request/response models (validation happens server-side)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.storage.schema import ALERT_STATUSES, ROLES, SEVERITIES

Role = Literal["admin", "analyst", "viewer"]
Severity = Literal["informational", "low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: Optional[str] = Field(default="viewer", description="Requested role; admin requires promotion")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    mfa_code: Optional[str] = Field(default=None, min_length=6, max_length=8,
                                    description="TOTP code, required once the account has MFA enabled")


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=8, max_length=256)
    password: str = Field(min_length=8, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    avatar_color: Optional[str] = Field(default=None, max_length=16)


class UserOut(BaseModel):
    id: str
    name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = True
    avatar_color: Optional[str] = None
    created_at: Optional[str] = None
    last_login: Optional[str] = None
    capabilities: Optional[List[str]] = None
    auth_provider: Optional[str] = "local"
    mfa_enabled: Optional[bool] = False
    mfa_confirmed_at: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    expires_at: Optional[str] = None
    user: Optional[UserOut] = None
    require_mfa: bool = False
    mfa_message: Optional[str] = None


class MFAVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8, description="Six digit authenticator code")


class AdminUserUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=120)
    role: Optional[Role] = None
    is_active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def _valid_role(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return value


# ---------------------------------------------------------------------------
# Traffic / prediction
# ---------------------------------------------------------------------------

class TrafficFlow(BaseModel):
    """A single network flow. Only source/destination/flow metadata is accepted."""

    timestamp: Optional[Any] = None
    source_ip: Optional[str] = Field(default=None, max_length=64)
    destination_ip: Optional[str] = Field(default=None, max_length=64)
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = Field(default=None, max_length=16)
    packet_count: Optional[float] = Field(default=None, ge=0)
    byte_count: Optional[float] = Field(default=None, ge=0)
    packet_length: Optional[float] = Field(default=None, ge=0)
    flow_duration: Optional[float] = Field(default=None, ge=0)
    packets_per_second: Optional[float] = Field(default=None, ge=0)
    bytes_per_second: Optional[float] = Field(default=None, ge=0)
    connection_count: Optional[float] = Field(default=None, ge=0)
    tcp_flags: Optional[str] = Field(default=None, max_length=24)
    failed_connections: Optional[float] = Field(default=None, ge=0)
    request_frequency: Optional[float] = Field(default=None, ge=0)
    attack_type: Optional[str] = Field(default=None, max_length=64, description="Optional ground-truth label")


class AnalyzeRequest(BaseModel):
    flows: List[TrafficFlow] = Field(min_length=1, max_length=5000)
    persist: bool = Field(default=False, description="Store the flows and their predictions")
    create_alerts: bool = Field(default=False)
    explain: bool = Field(default=True)
    source: str = Field(default="manual", max_length=24)


class PredictRequest(BaseModel):
    flow: TrafficFlow
    explain: bool = True


class PredictBatchRequest(BaseModel):
    flows: List[TrafficFlow] = Field(min_length=1, max_length=5000)
    explain: bool = True
    persist: bool = False


# ---------------------------------------------------------------------------
# Forecast
# ---------------------------------------------------------------------------

class ForecastRequest(BaseModel):
    horizons: Optional[List[int]] = Field(default=None, description="Horizon minutes, e.g. [5, 15, 30, 60]")
    dataset_id: Optional[str] = None
    window: str = Field(default="24h", max_length=12)
    persist: bool = True
    create_alerts: bool = True

    @field_validator("horizons")
    @classmethod
    def _valid_horizons(cls, value: Optional[List[int]]) -> Optional[List[int]]:
        if value is None:
            return None
        cleaned = sorted({int(v) for v in value if v and 1 <= int(v) <= 1440})
        if not cleaned:
            raise ValueError("Provide at least one horizon between 1 and 1440 minutes")
        return cleaned


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=4000)
    recommendation: Optional[str] = Field(default=None, max_length=4000)
    notes: Optional[str] = Field(default=None, max_length=4000, description="Analyst triage note appended to the alert history")
    assigned_to: Optional[str] = Field(default=None, max_length=160, description="Analyst owning the alert")

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {ALERT_STATUSES}")
        return value


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TrainModelRequest(BaseModel):
    algorithm: str = Field(default="random_forest", max_length=40)
    dataset_id: Optional[str] = None
    rows: Optional[int] = Field(default=None, ge=100, le=200000)
    contamination: Optional[float] = Field(default=None, ge=0.005, le=0.4)
    train_anomaly: bool = True
    activate: bool = Field(default=False, description="Activate after passing validation")


class ActivateModelRequest(BaseModel):
    dataset_id: Optional[str] = None
    force: bool = Field(default=False, description="Skip validation (admin override)")


class CompareModelsRequest(BaseModel):
    model_ids: List[str] = Field(min_length=2, max_length=6)


# ---------------------------------------------------------------------------
# Blockchain
# ---------------------------------------------------------------------------

class BlockchainRecordRequest(BaseModel):
    event_type: str = Field(default="manual_event", max_length=64)
    payload: Dict[str, Any] = Field(default_factory=dict)
    related_id: Optional[str] = Field(default=None, max_length=64)
    anchor: bool = True
    is_tamper_demo: bool = Field(default=False, description="Create a deliberately broken entry for demos")


class BlockchainVerifyRequest(BaseModel):
    """Verification request.

    Two modes are supported:

    * ``event_id`` -> the server recomputes the hash from the stored record and
      reports the authoritative verdict (optionally compared with a submitted hash).
    * ``event_type`` + ``event_hash`` (+ ``timestamp`` / ``payload`` / ``prev_hash``)
      -> the hash is recomputed from the supplied fields alone, which lets a third
      party verify an entry without access to the database.
    """

    event_id: Optional[str] = Field(default=None, max_length=64)
    event_hash: Optional[str] = Field(default=None, max_length=128)
    event_type: Optional[str] = Field(default=None, max_length=64)
    timestamp: Optional[Any] = None
    payload: Optional[Dict[str, Any]] = None
    prev_hash: Optional[str] = Field(default=None, max_length=128,
                                     description="Hash of the preceding ledger entry (genesis is 64 zeroes)")

    @field_validator("event_hash", "prev_hash")
    @classmethod
    def _hex(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip().lower().removeprefix("0x")
        if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
            raise ValueError("hash fields must be 64-character SHA-256 hex digests")
        return cleaned


# ---------------------------------------------------------------------------
# Reports / simulation / admin
# ---------------------------------------------------------------------------

class ReportRequest(BaseModel):
    report_type: str = Field(default="security_summary", max_length=40)
    window: str = Field(default="24h", max_length=12)
    format: Literal["pdf", "csv"] = "pdf"
    title: Optional[str] = Field(default=None, max_length=160)


class SimulationStartRequest(BaseModel):
    scenario: str = Field(default="mixed", max_length=24)
    intensity: int = Field(default=5, ge=1, le=10)
    duration_seconds: int = Field(default=600, ge=30, le=7200)
    tick_seconds: float = Field(default=1.0, ge=0.25, le=5.0)


class SimulationUpdateRequest(BaseModel):
    scenario: Optional[str] = Field(default=None, max_length=24)
    intensity: Optional[int] = Field(default=None, ge=1, le=10)
    duration_seconds: Optional[int] = Field(default=None, ge=30, le=7200)


class SeedRequest(BaseModel):
    force: bool = Field(default=False, description="Re-seed even when data already exists")
    traffic_records: Optional[int] = Field(default=None, ge=100, le=20000)


class SettingsUpdate(BaseModel):
    """Runtime-tunable values accepted by PATCH /admin/settings."""

    alert_throttle_minutes: Optional[int] = Field(default=None, ge=0, le=1440)
    simulation_autostart: Optional[bool] = None
    anomaly_contamination: Optional[float] = Field(default=None, ge=0.005, le=0.4)
    simulation_default_rate: Optional[int] = Field(default=None, ge=1, le=10)
    max_forecast_history_rows: Optional[int] = Field(default=None, ge=100, le=200000)
    seed_traffic_records: Optional[int] = Field(default=None, ge=100, le=20000)


class ErrorResponse(BaseModel):
    detail: str
    error_type: Optional[str] = None
    path: Optional[str] = None
    timestamp: Optional[str] = None
