"""Centralized Security-Hardened Configuration & Secrets Management.

Eliminates raw plaintext secret handling by wrapping API keys in Pydantic `SecretStr`,
supporting Kubernetes/Docker mounted secret files (`/run/secrets/*`), environment
variables, and Cloud Secret Manager resolution without exposing credentials in logs or stack traces.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

from app.models import BaseModel, Field

try:
    from pydantic import SecretStr, field_validator
except ImportError:
    class SecretStr:  # type: ignore[no-redef]
        def __init__(self, value: str = "") -> None:
            self._secret_value = str(value or "")

        def get_secret_value(self) -> str:
            return self._secret_value

        def __repr__(self) -> str:
            return "SecretStr('**********')" if self._secret_value else "SecretStr('')"

        def __str__(self) -> str:
            return "**********" if self._secret_value else ""

    def field_validator(*args: Any, **kwargs: Any) -> Any:  # type: ignore[no-redef]
        def _decorator(fn: Any) -> Any:
            return fn
        return _decorator

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def _load_secret_value(env_key: str, default: str = "") -> str:
    """Loads a secret from `<ENV_KEY>_FILE` (Docker/K8s secret mount) or `<ENV_KEY>` env var.

    Args:
        env_key: Name of the environment variable holding the secret (e.g., 'GEMINI_API_KEY').
        default: Default fallback value if neither secret file nor environment variable is set.

    Returns:
        The resolved secret string stripped of surrounding whitespace.
    """
    file_env_key = f"{env_key}_FILE"
    secret_file_path = os.getenv(file_env_key, "").strip()
    if not secret_file_path:
        k8s_default_path = Path(f"/run/secrets/{env_key.lower()}")
        if k8s_default_path.is_file():
            secret_file_path = str(k8s_default_path)

    if secret_file_path:
        try:
            path_obj = Path(secret_file_path)
            if path_obj.is_file():
                return path_obj.read_text(encoding="utf-8").strip()
        except OSError:
            pass

    return os.getenv(env_key, default).strip()


class AppSettings(BaseModel):
    """Validated application configuration with masked SecretStr API credentials."""

    app_name: str = Field(
        default="vendor-risk-compliance-multi-agent",
        description="Canonical service name used across OpenTelemetry and structured logs.",
    )
    app_version: str = Field(default="2.1.0", description="Semantic version of the service.")
    environment: str = Field(
        default_factory=lambda: os.getenv("ENVIRONMENT", "development").lower(),
        description="Deployment environment (development, staging, production).",
    )
    execution_mode: str = Field(
        default_factory=lambda: os.getenv("EXECUTION_MODE", "auto").lower(),
        description="LLM execution mode: 'auto', 'live', or 'simulation'.",
    )
    preferred_provider: str = Field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "gemini").lower(),
        description="Preferred LLM provider: 'gemini' or 'openai'.",
    )

    # Masked SecretStr credentials prevent accidental leakage in logs, dicts, or tracebacks
    gemini_api_key: SecretStr = Field(
        default_factory=lambda: SecretStr(_load_secret_value("GEMINI_API_KEY", "")),
        description="Google Gemini API key loaded from env or mounted secret file.",
    )
    gemini_fast_model: str = Field(
        default_factory=lambda: os.getenv("GEMINI_FAST_MODEL", "gemini-2.5-flash"),
        description="Low-latency Gemini model for Coordinator, Intake, and Support agents.",
    )
    gemini_pro_model: str = Field(
        default_factory=lambda: os.getenv("GEMINI_PRO_MODEL", "gemini-2.5-pro"),
        description="Reasoning Gemini model for Policy Checking, InfoSec, Legal, and Compliance Officer agents.",
    )

    openai_api_key: SecretStr = Field(
        default_factory=lambda: SecretStr(_load_secret_value("OPENAI_API_KEY", "")),
        description="OpenAI API key loaded from env or mounted secret file.",
    )
    openai_fast_model: str = Field(
        default_factory=lambda: os.getenv("OPENAI_FAST_MODEL", "gpt-4o-mini"),
        description="Low-latency OpenAI model for Coordinator, Intake, and Support agents.",
    )
    openai_pro_model: str = Field(
        default_factory=lambda: os.getenv("OPENAI_PRO_MODEL", "gpt-4o"),
        description="Reasoning OpenAI model for Policy Checking and risk evaluation agents.",
    )

    # Observability & OpenTelemetry settings
    otel_enabled: bool = Field(
        default_factory=lambda: os.getenv("OTEL_ENABLED", "true").lower() in ("1", "true", "yes"),
        description="Whether OpenTelemetry distributed tracing is enabled.",
    )
    otel_exporter_otlp_endpoint: Optional[str] = Field(
        default_factory=lambda: os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip() or None,
        description="Optional OTLP collector endpoint (e.g. http://otel-collector:4317).",
    )
    log_level: str = Field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO").upper(),
        description="Structured logger verbosity level.",
    )

    # Database & Async Memory settings
    sqlite_db_path: str = Field(
        default_factory=lambda: os.getenv(
            "SQLITE_DB_PATH",
            str(Path(__file__).resolve().parent.parent / "vendor_sessions.db"),
        ),
        description="Filesystem path to the SQLite session database.",
    )

    @field_validator("execution_mode")
    @classmethod
    def _validate_execution_mode(cls, value: str) -> str:
        allowed = {"auto", "live", "simulation"}
        clean = value.strip().lower()
        return clean if clean in allowed else "auto"

    @field_validator("preferred_provider")
    @classmethod
    def _validate_provider(cls, value: str) -> str:
        allowed = {"gemini", "openai"}
        clean = value.strip().lower()
        return clean if clean in allowed else "gemini"

    def has_gemini_key(self) -> bool:
        """Returns True if a non-empty Gemini API key is configured."""
        return bool(self.gemini_api_key.get_secret_value().strip())

    def has_openai_key(self) -> bool:
        """Returns True if a non-empty OpenAI API key is configured."""
        return bool(self.openai_api_key.get_secret_value().strip())

    def masked_summary(self) -> Dict[str, Any]:
        """Returns a safe, redacted configuration summary suitable for health endpoints and logs."""
        return {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "environment": self.environment,
            "execution_mode": self.execution_mode,
            "preferred_provider": self.preferred_provider,
            "gemini_key_configured": self.has_gemini_key(),
            "gemini_key_masked": "**********" if self.has_gemini_key() else None,
            "openai_key_configured": self.has_openai_key(),
            "openai_key_masked": "**********" if self.has_openai_key() else None,
            "otel_enabled": self.otel_enabled,
            "otel_exporter_otlp_endpoint": self.otel_exporter_otlp_endpoint,
            "log_level": self.log_level,
        }


def get_settings() -> AppSettings:
    """Instantiates settings from the current environment."""
    return AppSettings()


settings = get_settings()
