"""
Unit tests for AISOP configuration management.

These tests verify that:
- Default values are safe and sensible
- Environment variables correctly override defaults
- Invalid values are rejected at construction time
- The get_settings() cache behaves correctly
"""

import pytest

from app.core.config import Settings, get_settings


class TestSettingsDefaults:
    """Verify that Settings loads safely when no .env file is present."""

    def test_app_name_defaults_to_aisop(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.APP_NAME == "AISOP"

    def test_version_defaults_to_semver(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.APP_VERSION == "0.1.0"

    def test_environment_defaults_to_development(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.ENVIRONMENT == "development"

    def test_debug_defaults_to_false(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.DEBUG is False

    def test_api_prefix_defaults_to_v1(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.API_V1_PREFIX == "/api/v1"

    def test_database_url_targets_postgresql(self) -> None:
        """We design for PostgreSQL from Day 1 — never SQLite."""
        settings = Settings(_env_file=None)
        assert settings.DATABASE_URL.startswith("postgresql")

    def test_ollama_defaults_are_usable(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.OLLAMA_BASE_URL == "http://localhost:11434"
        assert settings.OLLAMA_MODEL == "llama3.1:8b"
        assert settings.OLLAMA_TIMEOUT_SECONDS == 120

    def test_threat_intel_keys_default_to_empty(self) -> None:
        """TI keys are optional — empty string means 'not configured'."""
        settings = Settings(_env_file=None)
        assert settings.VIRUSTOTAL_API_KEY == ""
        assert settings.ABUSEIPDB_API_KEY == ""
        assert settings.ALIENVAULT_OTX_API_KEY == ""

    def test_cors_allows_localhost_frontend(self) -> None:
        settings = Settings(_env_file=None)
        assert "http://localhost:3000" in settings.CORS_ORIGINS

    def test_embedding_defaults_are_usable(self) -> None:
        """pgvector embedding config has sensible defaults (ADR-002)."""
        settings = Settings(_env_file=None)
        assert settings.EMBEDDING_DIMENSIONS == 768
        assert settings.EMBEDDING_MODEL == "nomic-embed-text"


class TestSettingsOverrides:
    """Verify that environment variables override defaults correctly."""

    def test_debug_overridden_by_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DEBUG", "true")
        settings = Settings(_env_file=None)
        assert settings.DEBUG is True

    def test_log_level_overridden_by_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        settings = Settings(_env_file=None)
        assert settings.LOG_LEVEL == "DEBUG"

    def test_environment_overridden_to_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ENVIRONMENT", "production")
        settings = Settings(_env_file=None)
        assert settings.ENVIRONMENT == "production"

    def test_database_url_overridden_by_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        custom_url = "postgresql+psycopg://prod:secret@db.example.com:5432/aisop_prod"
        monkeypatch.setenv("DATABASE_URL", custom_url)
        settings = Settings(_env_file=None)
        assert settings.DATABASE_URL == custom_url


class TestSettingsValidation:
    """Verify that invalid values are rejected at construction time."""

    def test_invalid_environment_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ENVIRONMENT must be one of: development, staging, production."""
        monkeypatch.setenv("ENVIRONMENT", "banana")
        with pytest.raises(Exception):
            Settings(_env_file=None)

    def test_invalid_log_format_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """LOG_FORMAT must be 'json' or 'text'."""
        monkeypatch.setenv("LOG_FORMAT", "xml")
        with pytest.raises(Exception):
            Settings(_env_file=None)


class TestGetSettings:
    """Verify the get_settings() caching behaviour."""

    def test_returns_same_instance_on_repeated_calls(self) -> None:
        """get_settings() is a singleton — same object every time."""
        get_settings.cache_clear()
        first = get_settings()
        second = get_settings()
        assert first is second
        get_settings.cache_clear()

    def test_cache_clear_produces_new_instance(self) -> None:
        """After cache_clear(), a fresh Settings is created."""
        get_settings.cache_clear()
        first = get_settings()
        get_settings.cache_clear()
        second = get_settings()
        assert first is not second
        get_settings.cache_clear()
