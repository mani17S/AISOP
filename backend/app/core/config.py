"""
AISOP Configuration Management.

Centralizes all application settings using Pydantic Settings.
Values are loaded from environment variables with fallback to defaults.
A .env file in the project root is automatically loaded if present.

Usage:
    from app.core.config import get_settings

    settings = get_settings()
    print(settings.OLLAMA_BASE_URL)
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict



class ProductionConfigError(RuntimeError):
    """Refusal to start in production with an unsafe configuration. Messages never contain secret values."""


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Each field maps to an environment variable of the same name.
    For example, setting ``OLLAMA_MODEL=qwen3:4b`` in your .env file overrides the default.
    A non-local ``OLLAMA_BASE_URL`` (for example ``http://gpu-server:11434``) is refused unless ``LLM_ALLOW_NON_LOCAL_ENDPOINT=true``
    is also set (local-first policy); AI assistance can be switched off with ``LLM_ENABLED=false``.

    Groups are organized by subsystem. Fields that default to empty
    strings indicate optional values that the operator provides when
    that subsystem is enabled.
    """

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "AISOP"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False

    # ── API ──────────────────────────────────────────────────────
    API_V1_PREFIX: str = "/api/v1"
    API_AUTH_ENABLED: bool = Field(
        default=True,
        description="Whether API ingress authentication is enforced on protected /api/v1/* routes",
    )
    API_AUTH_KEYS: list[str] = Field(
        default_factory=list,
        description="Configured valid API keys/tokens for machine/client authentication",
    )
    API_AUTH_ALLOW_LEGACY_KEYS: bool = Field(
        default=False,
        description="Whether legacy static API keys in API_AUTH_KEYS are permitted when database token lookup fails or before migration",
    )

    # ── Rate Limiting & Abuse Prevention (P3-H4) ────────────────
    RATE_LIMIT_ENABLED: bool = Field(
        default=True,
        description="Whether API ingress rate limiting is enforced on API endpoints",
    )
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = Field(
        default=120,
        gt=0,
        description="Standard request allowance per minute per client key/IP",
    )
    RATE_LIMIT_BURST_CAPACITY: int = Field(
        default=60,
        gt=0,
        description="Maximum burst bucket token capacity per client",
    )
    RATE_LIMIT_TRUSTED_PROXIES: list[str] = Field(
        default=["127.0.0.1", "::1"],
        description="List of reverse proxy IP addresses allowed to provide X-Forwarded-For headers",
    )

    # ── Security Headers ─────────────────────────────────────────
    SECURITY_HEADERS_ENABLED: bool = Field(
        default=True,
        description="Whether strict security response headers (CSP, HSTS, X-Content-Type, etc.) are injected",
    )

    # ── Database (PostgreSQL) ────────────────────────────────────
    DB_POOL_SIZE: int = Field(default=10, gt=0, description="Persistent database connections per process")
    DB_MAX_OVERFLOW: int = Field(default=20, ge=0, description="Extra connections allowed under load")
    DB_POOL_TIMEOUT_SECONDS: int = Field(default=10, gt=0, description="Seconds a request waits for a free connection before failing")
    DATABASE_URL: str = "postgresql+psycopg://aisop:aisop@127.0.0.1:5432/aisop_dev"
    DATABASE_ECHO: bool = False  # SQLAlchemy: echo SQL to stdout

    # ── Ollama (Local LLM — ADR-001) ────────────────────────────
    OLLAMA_BASE_URL: str = Field(
        default="http://localhost:11434",
        description="Base URL for local Ollama HTTP API endpoint",
    )
    OLLAMA_MODEL: str = Field(
        default="llama3.1:8b",
        description="Default target model tag for local inference",
    )
    OLLAMA_TIMEOUT_SECONDS: int = Field(
        default=120,
        gt=0,
        description="Timeout in seconds for inference operations",
    )
    OLLAMA_TEMPERATURE: float = Field(
        default=0.2,
        ge=0.0,
        le=2.0,
        description="Sampling temperature for deterministic security reasoning (0.0-0.3 recommended)",
    )
    OLLAMA_MAX_RETRIES: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum retry attempts for transient network/server failures",
    )
    OLLAMA_KEEP_ALIVE: str = Field(
        default="5m",
        description="Duration to keep model in Ollama memory after request",
    )
    LLM_PROVIDER: str = Field(
        default="ollama",
        description="Active LLM provider name. 'ollama' (local, free) is built in; others are added with register_llm_provider and must follow the same local-first rules. An unregistered name fails closed. Never inferred from API keys.",
    )
    LLM_ENABLED: bool = Field(
        default=True,
        description=(
            "Global AI-assistance switch. False = AI disabled: no provider client is built, no model/health/embedding call is made, "
            "and every deterministic path keeps working with AI results reported as 'disabled'."
        ),
    )
    LLM_ALLOW_NON_LOCAL_ENDPOINT: bool = Field(
        default=False,
        description=(
            "Local-first guard: OLLAMA_BASE_URL must point at this machine (localhost, 127.0.0.0/8, ::1) unless the operator sets this to true. "
            "Sending prompts and evidence to another host is an explicit, opt-in decision."
        ),
    )

    # ── Hosted AI for the public demo: Cloudflare Workers AI, OPT-IN only (ADR-016) ──────────────
    LLM_ALLOW_EXTERNAL_PROVIDER: bool = Field(
        default=False,
        description=(
            "Local-first guard for third-party AI services. False (default): only the local provider can be built. True is an explicit "
            "decision to send prompts and evidence text to an external AI service (Cloudflare Workers AI). Use for synthetic demo data only."
        ),
    )
    CLOUDFLARE_ACCOUNT_ID: str | None = Field(default=None, description="Cloudflare account id (not secret). Needed only for the external provider.")
    CLOUDFLARE_AI_API_TOKEN: SecretStr | None = Field(
        default=None,
        description="Cloudflare API token limited to Workers AI. Secret: set it only in the host's environment, never in the repository.",
    )
    CLOUDFLARE_AI_MODEL: str = Field(default="@cf/meta/llama-3.3-70b-instruct-fp8-fast", description="Workers AI chat model id.")
    CLOUDFLARE_AI_EMBEDDING_MODEL: str = Field(default="@cf/baai/bge-base-en-v1.5", description="Workers AI embedding model id (768 dimensions).")
    CLOUDFLARE_AI_TIMEOUT_SECONDS: int = Field(default=120, gt=0)
    CLOUDFLARE_AI_DAILY_NEURON_LIMIT: int = Field(
        default=9000,
        gt=0,
        description="Neurons this process may spend per UTC day. Workers AI's free allowance is 10,000; stopping below it keeps a public demo free.",
    )
    EMBEDDING_PROVIDER: str = Field(
        default="ollama",
        description="'ollama' (local, default) or 'cloudflare_workers_ai' (external, needs LLM_ALLOW_EXTERNAL_PROVIDER). Vectors from different models are not comparable: re-embed the knowledge base when this changes.",
    )

    # ── ATT&CK reference (optional, local, offline) ─────────────
    ATTACK_REFERENCE_PATH: str | None = Field(
        default=None,
        description=(
            "Optional local path to the pinned MITRE ATT&CK Enterprise STIX file. Unset = not configured (no taxonomy "
            "validation, behaviour unchanged). Loaded lazily at most once per process; no network, never a startup requirement."
        ),
    )

    # ── Embeddings (pgvector — ADR-002) ─────────────────────────
    EMBEDDING_DIMENSIONS: int = 768
    EMBEDDING_MODEL: str = "nomic-embed-text"

    # ── Knowledge Ingestion & RAG (P2-H3) ───────────────────────
    KNOWLEDGE_BASE_PATH: str = Field(
        default="knowledge_base",
        description="Path to knowledge_base/ directory relative to the project root",
    )
    KNOWLEDGE_CHUNK_SIZE: int = Field(
        default=512,
        gt=0,
        description="Target chunk size in words for sliding-window document splitting",
    )
    KNOWLEDGE_CHUNK_OVERLAP: int = Field(
        default=64,
        ge=0,
        description="Word overlap between consecutive chunks for context continuity",
    )
    EMBEDDING_TIMEOUT_SECONDS: int = Field(
        default=30,
        gt=0,
        description="Timeout in seconds for Ollama /api/embeddings HTTP calls",
    )
    RETRIEVAL_TOP_K: int = Field(
        default=5,
        gt=0,
        le=20,
        description="Default number of chunks returned by cosine similarity retrieval",
    )

    # ── Threat Intelligence ──────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    ALIENVAULT_OTX_API_KEY: str = ""
    LOCAL_TI_FEED_DIR: str = Field(
        default="data/feeds",
        description="Path to local threat intelligence feed directory relative to project root",
    )
    LOCAL_TI_MAX_FEED_AGE_HOURS: float = Field(
        default=24.0,
        gt=0.0,
        description="Threshold in hours after which local feed indicators are treated as stale",
    )
    # Phase 4A: external threat-intelligence controls. Everything here is OFF/closed by default, and no API key above enables a source.
    TI_EXTERNAL_ENABLED: bool = Field(
        default=False,
        description="Global switch for external (remote) threat-intelligence lookups. Off by default; a per-query opt-in is also required",
    )
    TI_ENABLED_SOURCES: list[str] = Field(
        default_factory=list,
        description="Allowlist of external source IDs the operator enables (comma-separated or JSON list). Unknown IDs never enable anything",
    )
    TI_INTERNAL_DOMAIN_SUFFIXES: list[str] = Field(
        default_factory=list,
        description="Operator-maintained internal domain suffixes (for example .corp.example-company.com) that must never be sent externally",
    )
    TI_INTERNAL_NETWORKS: list[str] = Field(
        default_factory=list,
        description="Operator-maintained internal CIDR ranges beyond the built-in private ranges that must never be sent externally",
    )
    TI_ALLOW_PUBLIC_DOMAIN_LOOKUPS: bool = Field(
        default=False,
        description="Whether domains that pass the internal-name checks may be sent to an enabled external source. Closed by default because a domain cannot be proven public without DNS",
    )

    # ── Logging ──────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: Literal["json", "text"] = "json"
    LOG_FILE_PATH: str = "logs/aisop.log"
    LOG_ROTATION: str = "10 MB"
    LOG_RETENTION: str = "30 days"

    # Restricted diagnostic record for server errors (Phase 2.4). Baseline fields are allowlisted and contain no exception text.
    DIAGNOSTIC_LOG_PATH: str = ""  # when set, diagnostic records go to this file only (not the general sink); empty = general sink with component=diagnostic
    DIAGNOSTIC_LOG_MESSAGE_SHAPE: bool = False  # opt-in masked exception-message shape; see app/core/diagnostics.py for limits

    # ── CORS ─────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # ── API abuse controls (OWASP API2/API4 review) ──────────────
    AUTH_BRUTE_FORCE_PROTECTION_ENABLED: bool = Field(
        default=True,
        description="Lock out a client address after repeated rejected API keys (in-memory, per process)",
    )
    AUTH_FAILURE_MAX_PER_IP: int = Field(
        default=20, gt=0, description="Rejected credentials per client address within 5 minutes before lockout"
    )
    AUTH_LOCKOUT_SECONDS: int = Field(
        default=60, gt=0, description="Initial lockout duration; doubles on each repeat lockout up to 15 minutes"
    )
    RATE_LIMIT_EXPENSIVE_PER_MINUTE: int = Field(
        default=20, gt=0, description="Per-credential allowance for LLM-capable synthesis and report-export endpoints"
    )

    @field_validator("API_AUTH_KEYS", mode="before")
    @classmethod
    def _parse_api_auth_keys(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            cleaned = v.strip()
            if not cleaned:
                return []
            if cleaned.startswith("[") and cleaned.endswith("]"):
                import json
                try:
                    loaded = json.loads(cleaned)
                    if isinstance(loaded, list):
                        return [str(k).strip() for k in loaded if str(k).strip()]
                except Exception:
                    pass
            return [k.strip() for k in cleaned.split(",") if k.strip()]
        if isinstance(v, (list, tuple, set)):
            return [str(k).strip() for k in v if str(k).strip()]
        return []

    @field_validator("TI_ENABLED_SOURCES", "TI_INTERNAL_DOMAIN_SUFFIXES", "TI_INTERNAL_NETWORKS", mode="before")
    @classmethod
    def _parse_ti_lists(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            cleaned = v.strip()
            if not cleaned:
                return []
            if cleaned.startswith("[") and cleaned.endswith("]"):
                import json
                try:
                    loaded = json.loads(cleaned)
                    if isinstance(loaded, list):
                        return [str(k).strip() for k in loaded if str(k).strip()]
                except Exception:
                    pass
            return [k.strip() for k in cleaned.split(",") if k.strip()]
        if isinstance(v, (list, tuple, set)):
            return [str(k).strip() for k in v if str(k).strip()]
        return []

    @field_validator("RATE_LIMIT_TRUSTED_PROXIES", mode="before")
    @classmethod
    def _parse_trusted_proxies(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            cleaned = v.strip()
            if not cleaned:
                return ["127.0.0.1", "::1"]
            if cleaned.startswith("[") and cleaned.endswith("]"):
                import json
                try:
                    loaded = json.loads(cleaned)
                    if isinstance(loaded, list):
                        return [str(k).strip() for k in loaded if str(k).strip()]
                except Exception:
                    pass
            return [k.strip() for k in cleaned.split(",") if k.strip()]
        if isinstance(v, (list, tuple, set)):
            return [str(k).strip() for k in v if str(k).strip()]
        return ["127.0.0.1", "::1"]

    @model_validator(mode="after")
    def _validate_auth_invariants(self) -> Self:
        if self.ENVIRONMENT == "production" and not self.API_AUTH_ENABLED:
            raise ValueError("API_AUTH_ENABLED cannot be False in production environment")
        return self

    @model_validator(mode="after")
    def _validate_cors_origins(self) -> Self:
        if self.ENVIRONMENT in ("staging", "production") and any(o.strip() == "*" for o in self.CORS_ORIGINS):
            raise ValueError("CORS_ORIGINS must list explicit origins (no wildcard) outside development")
        return self

    # ── MITRE D3FEND reference (optional, local, offline) ───────
    DEFENSE_REFERENCE_PATH: str | None = Field(
        default=None,
        description=(
            "Optional local directory holding the pinned MITRE D3FEND release files (d3fend-full-mappings.csv, d3fend.csv). "
            "Unset = not configured (no countermeasure section, behaviour unchanged). Hash-verified, loaded lazily once, no network."
        ),
    )

    CASE_CREATE_MAX_PER_HOUR: int = Field(
        default=20,
        ge=1,
        le=1000,
        description=(
            "Most cases one account may create per hour. A stolen key could otherwise flood the case list; the refusal is a 429 and "
            "shows on the Security page. Raise it only for a team that promotes alerts in bulk."
        ),
    )
    LLM_MAX_CONCURRENCY: int = Field(
        default=1,
        ge=1,
        le=8,
        description=(
            "Maximum model calls in flight at once in this process. A local CPU model serves one request at a time, so extra "
            "callers wait here instead of all running together and all timing out. Raise it only for a server with spare capacity."
        ),
    )

    # ── Ollama context window (docs/06_AI/AI_Latency.md) ───────
    OLLAMA_NUM_CTX: int | None = Field(
        default=8192,
        ge=1024,
        le=32768,
        description=(
            "Ollama context window (tokens) sent as options.num_ctx. The application's prompt is about 5 400 tokens and the "
            "answer up to 1 024, so the window must exceed that: when a prompt does not fit, Ollama silently keeps only the last "
            "half of the window and the model answers without its instructions. The provider refuses such an answer. "
            "Default 8192. A larger window needs more GPU memory: on a 4 GB GPU use a small model (see AI_Latency.md)."
        ),
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return a cached Settings instance.

    Uses ``@lru_cache`` so the .env file is read exactly once per
    process lifetime.  In tests, call ``get_settings.cache_clear()``
    before constructing a new Settings with overridden env vars.
    """
    return Settings()


_WEAK_DB_PASSWORDS = frozenset({"", "aisop", "password", "postgres", "changeme", "admin", "secret"})


def validate_production_settings(settings: Settings) -> None:
    """
    Start-up gate for ENVIRONMENT=production (OWASP API8:2023). Raises ProductionConfigError when the database uses the
    shipped demo credentials or another trivially weak password, or CORS_ORIGINS contains a wildcard (also rejected earlier by
    the Settings validator). Does nothing outside production. The error names the problem only, never the credential.
    """
    if settings.ENVIRONMENT != "production":
        return
    from sqlalchemy.engine import make_url

    problems: list[str] = []
    try:
        url = make_url(settings.DATABASE_URL)
        password = url.password or ""
        if password.lower() in _WEAK_DB_PASSWORDS or password == url.username:
            problems.append("DATABASE_URL uses a default or weak database password")
    except Exception:
        problems.append("DATABASE_URL could not be parsed")
    if any(o.strip() == "*" for o in settings.CORS_ORIGINS):
        problems.append("CORS_ORIGINS contains a wildcard")
    if problems:
        raise ProductionConfigError("Refusing to start in production: " + "; ".join(problems) + ".")
