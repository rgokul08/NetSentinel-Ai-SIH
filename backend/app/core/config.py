"""
CyberForecast AI - central application configuration.

Every tunable value is read from the environment (see backend/.env.example).
Nothing secret is ever hard-coded here; defaults are safe for local demos.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import List

from dotenv import load_dotenv

from app.core.paths import BACKEND_ROOT, ensure_dir, get_data_dir, get_models_dir, get_upload_dir

# Load backend/.env then repo-root .env (first value wins).
load_dotenv(os.path.join(BACKEND_ROOT, ".env"))
load_dotenv(os.path.join(os.path.dirname(BACKEND_ROOT), ".env"))


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _list(name: str, default: List[str]) -> List[str]:
    raw = os.getenv(name)
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


class Settings:
    """Typed view over the process environment."""

    def __init__(self) -> None:
        # --- Application -------------------------------------------------
        self.app_name: str = os.getenv("APP_NAME", "CyberForecast AI")
        self.app_subtitle: str = os.getenv(
            "APP_SUBTITLE", "AI-Based Network Attack Forecasting & Blockchain-Assured Cybersecurity"
        )
        self.version: str = os.getenv("APP_VERSION", "2.0.0")
        self.environment: str = os.getenv("APP_ENV", "development")
        self.debug: bool = _bool("DEBUG", False)
        self.is_serverless: bool = bool(os.getenv("VERCEL"))

        # --- Security ----------------------------------------------------
        self.jwt_secret: str = os.getenv("JWT_SECRET_KEY", "") or os.getenv(
            "SECRET_KEY", "cyberforecast-local-development-secret-change-me"
        )
        self.jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
        self.access_token_minutes: int = _int("ACCESS_TOKEN_EXPIRE_MINUTES", 720)
        self.reset_token_minutes: int = _int("RESET_TOKEN_EXPIRE_MINUTES", 60)
        self.max_upload_mb: int = _int("MAX_UPLOAD_MB", 25)
        self.allowed_upload_extensions: List[str] = _list(
            "ALLOWED_UPLOAD_EXTENSIONS", [".csv", ".json"]
        )
        self.max_upload_rows: int = _int("MAX_UPLOAD_ROWS", 250_000)
        self.cors_origins: List[str] = _list(
            "CORS_ORIGINS",
            [
                "http://localhost:3000",
                "http://localhost:5173",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:5173",
            ],
        )
        self.cors_allow_all: bool = _bool("CORS_ALLOW_ALL", False)
        self.rate_limit: str = os.getenv("RATE_LIMIT", "300/minute")
        self.auth_rate_limit: str = os.getenv("AUTH_RATE_LIMIT", "20/minute")

        # --- Database / Appwrite ----------------------------------------
        self.database_url: str = os.getenv("DATABASE_URL", "") or f"sqlite:///{os.path.join(get_data_dir(), 'cyberforecast.db')}"
        self.appwrite_endpoint: str = os.getenv("APPWRITE_ENDPOINT", "").rstrip("/")
        self.appwrite_project_id: str = os.getenv("APPWRITE_PROJECT_ID", "")
        self.appwrite_api_key: str = os.getenv("APPWRITE_API_KEY", "")
        self.appwrite_database_id: str = os.getenv("APPWRITE_DATABASE_ID", "cyberforecast")
        self.appwrite_bucket_id: str = os.getenv("APPWRITE_BUCKET_ID", "cyberforecast-datasets")
        # When true the platform delegates auth + persistence to Appwrite.
        self.appwrite_enabled: bool = _bool(
            "APPWRITE_ENABLED",
            bool(self.appwrite_endpoint and self.appwrite_project_id and self.appwrite_api_key),
        )

        # --- Machine learning -------------------------------------------
        self.model_dir: str = ensure_dir(os.getenv("MODEL_PATH", "") or get_models_dir())
        self.upload_dir: str = ensure_dir(get_upload_dir())
        self.default_classifier: str = os.getenv("DEFAULT_CLASSIFIER", "random_forest")
        self.auto_train_on_startup: bool = _bool("AUTO_TRAIN_ON_STARTUP", True)
        self.anomaly_contamination: float = _float("ANOMALY_CONTAMINATION", 0.1)
        self.seed_dataset: str = os.getenv(
            "SEED_DATASET", os.path.join(BACKEND_ROOT, "datasets", "sample_network_traffic.csv")
        )
        self.prediction_sample_limit: int = _int("PREDICTION_SAMPLE_LIMIT", 20_000)

        # --- Blockchain --------------------------------------------------
        self.blockchain_rpc_url: str = os.getenv("BLOCKCHAIN_RPC_URL", "")
        self.blockchain_private_key: str = os.getenv("BLOCKCHAIN_PRIVATE_KEY", "")
        self.blockchain_contract_address: str = os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS", "")
        self.blockchain_chain_id: int = _int("BLOCKCHAIN_CHAIN_ID", 31337)
        self.blockchain_anchor: bool = _bool(
            "BLOCKCHAIN_ANCHOR_ENABLED",
            bool(self.blockchain_rpc_url and self.blockchain_private_key and self.blockchain_contract_address),
        )
        self.blockchain_tx_timeout: int = _int("BLOCKCHAIN_TX_TIMEOUT", 25)

        # --- Simulation --------------------------------------------------
        self.simulation_autostart: bool = _bool("SIMULATION_AUTOSTART", True)
        self.simulation_default_rate: int = _int("SIMULATION_DEFAULT_RATE", 12)

        # --- Seeding -----------------------------------------------------
        self.seed_demo_data: bool = _bool("SEED_DEMO_DATA", True)
        self.seed_traffic_records: int = _int("SEED_TRAFFIC_RECORDS", 900)
        self.demo_admin_email: str = os.getenv("DEMO_ADMIN_EMAIL", "admin@cyberforecast.ai")
        self.demo_admin_password: str = os.getenv("DEMO_ADMIN_PASSWORD", "Admin@1234")
        self.demo_analyst_email: str = os.getenv("DEMO_ANALYST_EMAIL", "analyst@cyberforecast.ai")
        self.demo_analyst_password: str = os.getenv("DEMO_ANALYST_PASSWORD", "Analyst@1234")
        self.demo_viewer_email: str = os.getenv("DEMO_VIEWER_EMAIL", "viewer@cyberforecast.ai")
        self.demo_viewer_password: str = os.getenv("DEMO_VIEWER_PASSWORD", "Viewer@1234")

    # -- convenience ------------------------------------------------------
    @property
    def storage_backend(self) -> str:
        return "appwrite" if self.appwrite_enabled else "sql"

    def public_config(self) -> dict:
        """Non-secret configuration safe to expose to the frontend."""
        return {
            "app_name": self.app_name,
            "app_subtitle": self.app_subtitle,
            "version": self.version,
            "environment": self.environment,
            "storage_backend": self.storage_backend,
            "appwrite_enabled": self.appwrite_enabled,
            "blockchain_mode": "evm" if self.blockchain_anchor else "local-hash-chain",
            "blockchain_chain_id": self.blockchain_chain_id if self.blockchain_anchor else None,
            "blockchain_contract_address": self.blockchain_contract_address if self.blockchain_anchor else None,
            "simulation_enabled": True,
            "max_upload_mb": self.max_upload_mb,
            "allowed_upload_extensions": self.allowed_upload_extensions,
            "default_classifier": self.default_classifier,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
