from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Dict, Any, Optional
import os


class ConfigurationError(ValueError):
    """Raised when environment or production configuration fails security validation."""
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str = "your-super-secret-key"
    
    # API Keys
    GEMINI_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    SAFE_BROWSING_API_KEY: str = ""
    FACT_CHECK_API_KEY: str = ""
    
    # Local AI
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    GEMMA_MODEL_VERSION: str = "gemma-2b-v3"

    # Database
    DATABASE_URL: str = "sqlite:///./thelix.db"

    # LLM Settings
    LLM_PROVIDER: str = "gemini"
    GEMINI_MODEL: str = "gemini-3.5-flash-lite"
    LLM_TIMEOUT_SECONDS: float = 20.0
    LLM_MAX_RETRIES: int = 1

    # Supabase Auth & Database
    SUPABASE_URL: str = ""
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""
    SUPABASE_JWT_SECRET: str = ""

    # Sandbox Settings - Keep False until genuine OS/network isolation exists
    SANDBOX_TIMEOUT_SECONDS: float = 10.0
    SAFE_LOCAL_SANDBOX_ENABLED: bool = False

    # Service Security
    INTERNAL_SERVICE_TOKEN: str = "thelix-internal-token-change-in-prod"

    # CORS and Network Boundaries
    ALLOWED_ORIGINS: str = "*"
    TRUSTED_PROXIES: str = ""  # Comma-separated list of trusted upstream reverse proxy IPs (e.g. "127.0.0.1,10.0.0.1")

    # OCR Capabilities
    OCR_REQUIRED: bool = False

    # Operational Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_STORE: str = "memory"  # "memory" | "redis"
    REDIS_URL: str = ""  # e.g. "redis://localhost:6379/0"
    RATE_LIMIT_PER_MINUTE: int = 120
    RATE_LIMIT_BURST: int = 30
    RATE_LIMIT_TIMEOUT_SECONDS: float = 2.0

    # Input & Upload Caps
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
    MAX_TARGET_LENGTH: int = 4096
    MAX_CONTEXT_LENGTH: int = 50000
    MAX_TEXT_CONTENT_LENGTH: int = 500000

    # Pilot Safety Controls
    PILOT_MODE_ENABLED: bool = False
    PILOT_ALLOWED_EMAILS: str = ""  # Comma-separated list of allowed user emails or sub IDs
    PILOT_MAX_SCANS_PER_USER_PER_DAY: int = 50
    EMERGENCY_SHUTDOWN: bool = False  # Global kill-switch: immediately halts all scan submissions and uploads

    # Privacy & Retention Controls
    SCAN_RETENTION_DAYS: int = 30
    ARTIFACT_RETENTION_DAYS: int = 7
    AUDIT_LOG_RETENTION_DAYS: int = 90
    REDACT_EXTRACTED_CONTENT_IN_STORAGE: bool = True
    STUCK_SCAN_TIMEOUT_MINUTES: int = 15

    @property
    def parsed_allowed_origins(self) -> list[str]:
        if not self.ALLOWED_ORIGINS or self.ALLOWED_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    @property
    def parsed_pilot_allowed_emails(self) -> set[str]:
        if not self.PILOT_ALLOWED_EMAILS:
            return set()
        return {e.strip().lower() for e in self.PILOT_ALLOWED_EMAILS.split(",") if e.strip()}

    @property
    def parsed_trusted_proxies(self) -> set[str]:
        if not self.TRUSTED_PROXIES:
            return set()
        return {p.strip() for p in self.TRUSTED_PROXIES.split(",") if p.strip()}


    def validate_for_environment(self) -> None:
        """
        Validates configuration against environment requirements.
        Enforces strict security invariants in production and pilot modes.
        Preserves frictionless development and testing modes.
        """
        env = self.ENVIRONMENT.lower().strip()
        if env in ("production", "pilot"):
            insecure_secret_keys = {
                "your-super-secret-key",
                "replace-with-a-secure-random-secret-key",
                "secret",
                "changeme",
            }
            if not self.SECRET_KEY or self.SECRET_KEY in insecure_secret_keys or len(self.SECRET_KEY) < 32:
                raise ConfigurationError(
                    "Production/Pilot security violation: SECRET_KEY must be a cryptographically strong value of at least 32 characters."
                )

            insecure_tokens = {
                "thelix-internal-token-change-in-prod",
                "replace-with-internal-service-hmac-token",
                "token",
            }
            if not self.INTERNAL_SERVICE_TOKEN or self.INTERNAL_SERVICE_TOKEN in insecure_tokens or len(self.INTERNAL_SERVICE_TOKEN) < 16:
                raise ConfigurationError(
                    "Production/Pilot security violation: INTERNAL_SERVICE_TOKEN must be configured with a secure random token."
                )

            if not self.SUPABASE_JWT_SECRET or len(self.SUPABASE_JWT_SECRET) < 16:
                raise ConfigurationError(
                    "Production/Pilot security violation: SUPABASE_JWT_SECRET is mandatory to prevent authentication bypass."
                )

            if self.ALLOWED_ORIGINS == "*" or "*" in self.parsed_allowed_origins:
                raise ConfigurationError(
                    "Production/Pilot security violation: Wildcard CORS ('*') is prohibited. Explicit allowed origins must be specified."
                )

            if self.SAFE_LOCAL_SANDBOX_ENABLED:
                raise ConfigurationError(
                    "Production/Pilot security violation: SAFE_LOCAL_SANDBOX_ENABLED must remain False until OS/containerized isolation is provisioned."
                )

            if self.DEBUG:
                raise ConfigurationError(
                    "Production/Pilot security violation: DEBUG mode must not be enabled."
                )

            if env == "production" and self.DATABASE_URL.startswith("sqlite") and ":memory:" not in self.DATABASE_URL:
                raise ConfigurationError(
                    "Production security violation: SQLite is prohibited in production. A production PostgreSQL instance is required."
                )

            if self.RATE_LIMIT_STORE == "redis" and not self.REDIS_URL:
                raise ConfigurationError(
                    "Configuration violation: REDIS_URL must be specified when RATE_LIMIT_STORE='redis'."
                )

            if env == "production" and self.RATE_LIMIT_STORE == "memory" and ":memory:" not in self.DATABASE_URL:
                raise ConfigurationError(
                    "Production security violation: In-memory rate limiting is prohibited in production. A distributed shared store (e.g. Redis) is required."
                )

    def sanitize_for_logging(self) -> Dict[str, Any]:
        """
        Returns a dictionary of configuration settings with all secrets, tokens,
        passwords, and private keys redacted for audit logs or monitoring endpoints.
        """
        raw_dict = self.model_dump()
        sensitive_keys = {
            "SECRET_KEY",
            "INTERNAL_SERVICE_TOKEN",
            "GEMINI_API_KEY",
            "VIRUSTOTAL_API_KEY",
            "SAFE_BROWSING_API_KEY",
            "FACT_CHECK_API_KEY",
            "SUPABASE_ANON_KEY",
            "SUPABASE_SERVICE_ROLE_KEY",
            "SUPABASE_JWT_SECRET",
            "DATABASE_URL",
            "REDIS_URL",
        }
        sanitized = {}
        for k, v in raw_dict.items():
            if k in sensitive_keys:
                if isinstance(v, str) and v:
                    if k in ("DATABASE_URL", "REDIS_URL") and "@" in v:
                        # Mask credentials in DB/Redis URL: protocol://user:pass@host/db -> protocol://user:[REDACTED]@host/db
                        prefix, rest = v.split("://", 1)
                        if "@" in rest:
                            creds, host_part = rest.split("@", 1)
                            user = creds.split(":")[0] if ":" in creds else creds
                            sanitized[k] = f"{prefix}://{user}:[REDACTED]@{host_part}"
                        else:
                            sanitized[k] = f"{prefix}://[REDACTED]"
                    else:
                        sanitized[k] = f"***[CONFIGURED: len={len(v)}]***"
                else:
                    sanitized[k] = "[UNSET]"
            else:
                sanitized[k] = v
        return sanitized


settings = Settings()

