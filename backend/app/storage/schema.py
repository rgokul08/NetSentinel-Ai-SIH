"""
Canonical data schema for CyberForecast AI.

ONE source of truth describing every collection used by the platform. It drives:

* SQLAlchemy ORM model generation  (app.storage.orm)
* the Appwrite collection adapter  (app.storage.appwrite_store)
* the Appwrite provisioning script (backend/scripts/setup_appwrite.py)

Keeping the definition in a single place guarantees that database field names
match application code in every backend mode.

Field types: string | text | integer | float | boolean | datetime | json
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Dict, List


@dataclass(frozen=True)
class Field:
    name: str
    type: str = "string"
    required: bool = False
    default: object = None
    size: int = 255          # only meaningful for `string`
    indexed: bool = False
    description: str = ""


@dataclass(frozen=True)
class Index:
    name: str
    fields: List[str] = dc_field(default_factory=list)
    unique: bool = False


@dataclass(frozen=True)
class Collection:
    name: str
    fields: List[Field]
    indexes: List[Index] = dc_field(default_factory=list)
    permissions: List[str] = dc_field(default_factory=lambda: ["private"])
    description: str = ""

    def field_map(self) -> Dict[str, Field]:
        return {f.name: f for f in self.fields}

    @property
    def names(self) -> List[str]:
        return [f.name for f in self.fields]


def _f(name, type="string", **kw) -> Field:
    return Field(name=name, type=type, **kw)


# ---------------------------------------------------------------------------
# Collection definitions
# ---------------------------------------------------------------------------

USERS = Collection(
    name="users",
    description="Platform accounts (local auth) or mirrors of Appwrite users.",
    fields=[
        _f("id", indexed=True, description="Stable user identifier"),
        _f("name", required=True),
        _f("email", required=True, description="Login email"),
        _f("role", required=True, default="viewer", description="admin | analyst | viewer"),
        _f("password_hash", type="text", description="bcrypt hash (empty when Appwrite owns auth)"),
        _f("appwrite_user_id", description="Id of the mirrored Appwrite user"),
        _f("is_active", type="boolean", default=True),
        _f("avatar_color", default="#22d3ee"),
        _f("last_login", type="datetime"),
        _f("mfa_enabled", type="boolean", default=False, description="TOTP multi-factor authentication active"),
        _f("mfa_secret", type="text", description="Base32 TOTP secret (server side only, never exposed)"),
        _f("mfa_confirmed_at", type="datetime", description="When the enrolment code was verified"),
        _f("created_at", type="datetime", required=True),
    ],
    indexes=[Index("users_email_unique", ["email"], unique=True), Index("users_role_idx", ["role"])],
)

PASSWORD_RESETS = Collection(
    name="password_resets",
    description="Short-lived password reset tokens (only the SHA-256 hash is stored).",
    fields=[
        _f("id", indexed=True),
        _f("user_id", required=True, indexed=True),
        _f("token_hash", required=True),
        _f("expires_at", type="datetime", required=True),
        _f("used_at", type="datetime"),
        _f("created_at", type="datetime", required=True),
    ],
    indexes=[Index("password_resets_user_idx", ["user_id"])],
)

DATASETS = Collection(
    name="datasets",
    description="Uploaded CSV/JSON traffic datasets and their profiling results.",
    fields=[
        _f("id", indexed=True),
        _f("user_id", indexed=True),
        _f("filename", required=True),
        _f("original_filename", required=True),
        _f("file_format", default="csv"),
        _f("size_bytes", type="integer", default=0),
        _f("rows", type="integer", default=0),
        _f("columns", type="integer", default=0),
        _f("column_names", type="json", default=list),
        _f("profile", type="json", default=dict, description="dtypes, missing values, duplicates, class distribution"),
        _f("storage_file_id", description="Appwrite Storage file id (empty for local disk)"),
        _f("storage_backend", default="local"),
        _f("status", default="processed", indexed=True, description="processed | failed | training"),
        _f("error_message", type="text"),
        _f("uploaded_at", type="datetime", required=True, indexed=True),
    ],
    indexes=[Index("datasets_uploaded_idx", ["uploaded_at"]), Index("datasets_user_idx", ["user_id"])],
)

TRAFFIC_RECORDS = Collection(
    name="traffic_records",
    description="Normalized network flow records ingested from datasets, simulation or live capture.",
    fields=[
        _f("id", indexed=True),
        _f("dataset_id", indexed=True),
        _f("timestamp", type="datetime", required=True, indexed=True),
        _f("source_ip", indexed=True),
        _f("destination_ip", indexed=True),
        _f("source_port", type="integer", default=0),
        _f("destination_port", type="integer", default=0, indexed=True),
        _f("protocol", indexed=True),
        _f("packet_count", type="integer", default=1),
        _f("byte_count", type="integer", default=0),
        _f("packet_length", type="float", default=0.0),
        _f("flow_duration", type="float", default=0.0),
        _f("packets_per_second", type="float", default=0.0),
        _f("bytes_per_second", type="float", default=0.0),
        _f("connection_count", type="integer", default=1),
        _f("tcp_flags", default="ACK"),
        _f("failed_connections", type="integer", default=0),
        _f("request_frequency", type="float", default=0.0),
        _f("attack_type", indexed=True, description="Ground-truth label when known, else 'Unknown'"),
        _f("predicted_attack_type", indexed=True, description="Model verdict for this flow"),
        _f("prediction_id", indexed=True, description="Id of the stored prediction record"),
        _f("model_version", description="Model that produced the verdict"),
        _f("is_labeled", type="boolean", default=False),
        _f("is_anomaly", type="boolean", default=False, indexed=True),
        _f("anomaly_score", type="float", default=0.0),
        _f("risk_score", type="float", default=0.0),
        _f("risk_level", default="LOW", indexed=True),
        _f("source", default="simulation", indexed=True, description="simulation | dataset | live | manual"),
        _f("is_simulated", type="boolean", default=True),
        _f("region", description="Abstracted source region for the threat map"),
    ],
    indexes=[
        Index("traffic_timestamp_idx", ["timestamp"]),
        Index("traffic_source_time_idx", ["source", "timestamp"]),
        Index("traffic_attack_idx", ["attack_type"]),
    ],
)

PREDICTIONS = Collection(
    name="predictions",
    description="Model inference results with explanation payloads.",
    fields=[
        _f("id", indexed=True),
        _f("timestamp", type="datetime", required=True, indexed=True),
        _f("traffic_record_id", indexed=True),
        _f("dataset_id", indexed=True),
        _f("attack_type", required=True, indexed=True),
        _f("confidence", type="float", default=0.0),
        _f("risk_score", type="float", default=0.0),
        _f("risk_level", default="LOW", indexed=True),
        _f("anomaly_score", type="float", default=0.0),
        _f("is_anomaly", type="boolean", default=False),
        _f("probabilities", type="json", default=dict, description="Per-class probabilities"),
        _f("explanation", type="json", default=dict, description="Feature attributions + narrative"),
        _f("model_id", indexed=True),
        _f("model_version", default=""),
        _f("is_correct", type="boolean", description="Set when ground truth exists"),
        _f("true_attack_type", description="Ground truth label (when labeled data)"),
        _f("source", default="simulation", indexed=True),
        _f("is_simulated", type="boolean", default=True),
    ],
    indexes=[Index("predictions_timestamp_idx", ["timestamp"]), Index("predictions_attack_idx", ["attack_type"])],
)

FORECASTS = Collection(
    name="forecasts",
    description="Time-series attack forecasts per horizon and category.",
    fields=[
        _f("id", indexed=True),
        _f("run_id", required=True, indexed=True, description="Groups all rows produced by one forecast run"),
        _f("created_at", type="datetime", required=True, indexed=True),
        _f("horizon_minutes", type="integer", required=True, indexed=True),
        _f("forecast_time", type="datetime", required=True),
        _f("attack_type", required=True, indexed=True),
        _f("probability", type="float", default=0.0, description="P(at least one event in the horizon)"),
        _f("per_bucket_probability", type="float", default=0.0, description="Mean probability per time bucket"),
        _f("peak_bucket_probability", type="float", default=0.0, description="Highest single-bucket probability"),
        _f("confidence", type="float", default=0.0),
        _f("expected_events", type="float", default=0.0),
        _f("lower_bound", type="float", default=0.0),
        _f("upper_bound", type="float", default=0.0),
        _f("risk_level", default="LOW", indexed=True),
        _f("contributing_features", type="json", default=list),
        _f("method", description="ridge-lag-regression | ewma-baseline-rate"),
        _f("residual_rmse", type="float", default=0.0),
        _f("historical_events", type="integer", default=0),
        _f("recommendation", type="text"),
        _f("model_version", default=""),
        _f("based_on_records", type="integer", default=0),
        _f("is_simulated", type="boolean", default=True),
    ],
    indexes=[Index("forecasts_created_idx", ["created_at"]), Index("forecasts_run_idx", ["run_id"])],
)

ALERTS = Collection(
    name="alerts",
    description="Security alerts raised by the detection/forecast engines.",
    fields=[
        _f("id", indexed=True),
        _f("alert_code", required=True, indexed=True),
        _f("timestamp", type="datetime", required=True, indexed=True),
        _f("severity", required=True, indexed=True, description="informational|low|medium|high|critical"),
        _f("attack_type", required=True, indexed=True),
        _f("risk_score", type="float", default=0.0),
        _f("confidence", type="float", default=0.0),
        _f("status", default="open", indexed=True, description="open|reviewed|resolved|false_positive"),
        _f("title", required=True),
        _f("description", type="text", required=True),
        _f("recommendation", type="text"),
        _f("source_ip"),
        _f("destination_ip"),
        _f("source_port", type="integer", default=0),
        _f("destination_port", type="integer", default=0),
        _f("prediction_id", indexed=True),
        _f("traffic_record_id", indexed=True),
        _f("blockchain_event_id", indexed=True),
        _f("blockchain_status", default="pending", indexed=True),
        _f("origin", default="detection", indexed=True, description="detection | forecast | anomaly | manual"),
        _f("reviewed_by"),
        _f("reviewed_at", type="datetime"),
        _f("resolved_by"),
        _f("resolved_at", type="datetime"),
        _f("notes", type="text", description="Analyst triage notes"),
        _f("assigned_to", indexed=True, description="Analyst currently owning the alert"),
        _f("history", type="json", default=list, description="Append-only triage trail"),
        _f("is_simulated", type="boolean", default=True),
    ],
    indexes=[
        Index("alerts_timestamp_idx", ["timestamp"]),
        Index("alerts_severity_idx", ["severity"]),
        Index("alerts_status_idx", ["status"]),
    ],
)

BLOCKCHAIN_EVENTS = Collection(
    name="blockchain_events",
    description="Hash-chained integrity records for security events; only hashes/metadata are stored.",
    fields=[
        _f("id", indexed=True),
        _f("event_type", required=True, indexed=True),
        _f("event_hash", required=True, indexed=True),
        _f("prev_hash", description="Hash of the previous ledger entry (tamper-evident chain)"),
        _f("chain_position", type="integer", default=0),
        _f("payload", type="json", default=dict, description="Non-sensitive fields that were hashed"),
        _f("related_id", indexed=True, description="Id of the alert/prediction/audit entry"),
        _f("anchor_mode", default="local", indexed=True, description="local | evm"),
        _f("tx_hash", indexed=True),
        _f("block_number", type="integer"),
        _f("chain_id", type="integer"),
        _f("contract_address"),
        _f("recorder_address"),
        _f("verification_status", default="pending", indexed=True, description="verified | pending | failed"),
        _f("verified_at", type="datetime"),
        _f("recorded_by"),
        _f("created_at", type="datetime", required=True, indexed=True),
        _f("is_tamper_demo", type="boolean", default=False, description="Clearly marked integrity-failure demo"),
    ],
    indexes=[Index("bc_created_idx", ["created_at"]), Index("bc_event_type_idx", ["event_type"])],
)

AUDIT_LOGS = Collection(
    name="audit_logs",
    description="Hash-chained audit trail of security-relevant user and system actions.",
    fields=[
        _f("id", indexed=True),
        _f("timestamp", type="datetime", required=True, indexed=True),
        _f("user_id", indexed=True),
        _f("user_email"),
        _f("user_role"),
        _f("action", required=True, indexed=True),
        _f("category", default="system", indexed=True),
        _f("resource"),
        _f("resource_id"),
        _f("outcome", default="success", indexed=True),
        _f("metadata", type="json", default=dict),
        _f("ip_address", default="127.0.0.1"),
        _f("integrity_hash", description="SHA-256 over the entry plus the previous hash"),
        _f("prev_hash"),
    ],
    indexes=[Index("audit_timestamp_idx", ["timestamp"]), Index("audit_action_idx", ["action"])],
)

MODELS = Collection(
    name="models",
    description="ML model registry (one active classifier + one active anomaly detector).",
    fields=[
        _f("id", indexed=True),
        _f("name", required=True),
        _f("version", required=True),
        _f("algorithm", required=True, indexed=True),
        _f("task", default="classification", indexed=True, description="classification | anomaly"),
        _f("dataset_id", indexed=True),
        _f("dataset_name"),
        _f("training_rows", type="integer", default=0),
        _f("classes", type="json", default=list),
        _f("features", type="json", default=list),
        _f("metrics", type="json", default=dict),
        _f("confusion_matrix", type="json", default=dict),
        _f("class_report", type="json", default=list),
        _f("feature_importance", type="json", default=list),
        _f("accuracy", type="float", default=0.0),
        _f("precision_score", type="float", default=0.0),
        _f("recall_score", type="float", default=0.0),
        _f("f1_score", type="float", default=0.0),
        _f("roc_auc", type="float"),
        _f("artifact_path", type="text"),
        _f("artifact_status", default="missing", indexed=True, description="available | missing"),
        _f("is_active", type="boolean", default=False, indexed=True),
        _f("status", default="trained", indexed=True, description="trained | failed | retired"),
        _f("error_message", type="text"),
        _f("trained_by"),
        _f("trained_at", type="datetime", required=True, indexed=True),
        _f("notes", type="text"),
    ],
    indexes=[Index("models_task_active_idx", ["task", "is_active"]), Index("models_trained_idx", ["trained_at"])],
)

REPORTS = Collection(
    name="reports",
    description="Generated security reports (PDF/CSV) and their summaries.",
    fields=[
        _f("id", indexed=True),
        _f("title", required=True),
        _f("report_type", default="security_summary", indexed=True),
        _f("created_at", type="datetime", required=True, indexed=True),
        _f("created_by"),
        _f("format", default="pdf", indexed=True),
        _f("range", type="json", default=dict),
        _f("summary", type="json", default=dict),
        _f("sections", type="json", default=list),
        _f("file_path", type="text"),
        _f("storage_file_id"),
        _f("size_bytes", type="integer", default=0),
        _f("download_count", type="integer", default=0),
    ],
    indexes=[Index("reports_created_idx", ["created_at"])],
)

COLLECTIONS: Dict[str, Collection] = {
    c.name: c
    for c in [
        USERS,
        PASSWORD_RESETS,
        DATASETS,
        TRAFFIC_RECORDS,
        PREDICTIONS,
        FORECASTS,
        ALERTS,
        BLOCKCHAIN_EVENTS,
        AUDIT_LOGS,
        MODELS,
        REPORTS,
    ]
}

# Attack taxonomy used across ML, alerts and forecasts.
ATTACK_CLASSES: List[str] = [
    "Benign",
    "DoS",
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Bot Activity",
    "Intrusion",
    "Network Anomaly",
]

BENIGN_CLASS = "Benign"

SEVERITIES: List[str] = ["informational", "low", "medium", "high", "critical"]
ALERT_STATUSES: List[str] = ["open", "reviewed", "resolved", "false_positive"]
ROLES: List[str] = ["admin", "analyst", "viewer"]

# Human-readable defensive guidance per attack category.
RECOMMENDATIONS: Dict[str, str] = {
    "DDoS": "Enable upstream rate limiting and SYN-cookie protection, activate CDN/scrubbing for the targeted VIP, and temporarily geo-block the dominant source ranges.",
    "DoS": "Throttle the offending source prefix, raise connection limits on the targeted service, and verify autoscaling headroom before the next burst.",
    "Port Scan": "Confirm host firewall deny-by-default, drop unanswered SYNs at the edge, and check whether the scanner reached any exposed management port.",
    "Brute Force": "Enforce lockout and MFA on the targeted service, block the source IP for 30 minutes, and review authentication logs for successful sign-ins.",
    "Bot Activity": "Isolate the beaconing host, block the C2 destination at the proxy, and capture a full packet trace before remediation.",
    "Intrusion": "Escalate to incident response, snapshot the affected host, revoke active sessions and rotate credentials for exposed accounts.",
    "Network Anomaly": "Baseline the affected segment, compare against the same window last week, and request a targeted capture if the deviation persists.",
    "Benign": "No action required. Continue monitoring and keep the baseline model refreshed with recent traffic.",
}


def get_collection(name: str) -> Collection:
    try:
        return COLLECTIONS[name]
    except KeyError as exc:  # pragma: no cover - programming error
        raise KeyError(f"Unknown collection '{name}'") from exc
