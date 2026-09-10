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
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Each field maps to an environment variable of the same name.
    For example, setting ``OLLAMA_BASE_URL=http://gpu-server:11434``
    in your .env file overrides the default.

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

    # ── Database (PostgreSQL) ────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+psycopg://aisop:aisop@localhost:5432/aisop_dev"
    )
    DATABASE_ECHO: bool = False  # SQLAlchemy: echo SQL to stdout

    # ── Ollama (Local LLM) ──────────────────────────────────────
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1:8b"
    OLLAMA_TIMEOUT_SECONDS: int = 120

    # ── Embeddings (pgvector — ADR-002) ─────────────────────────
    EMBEDDING_DIMENSIONS: int = 768
    EMBEDDING_MODEL: str = "nomic-embed-text"

    # ── Threat Intelligence ──────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    ALIENVAULT_OTX_API_KEY: str = ""

    # ── Logging ──────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: Literal["json", "text"] = "json"
    LOG_FILE_PATH: str = "logs/aisop.log"
    LOG_ROTATION: str = "10 MB"
    LOG_RETENTION: str = "30 days"

    # ── CORS ─────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

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
