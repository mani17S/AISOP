"""
AISOP LLM Provider Manager & Factory.

Instantiates and configures LLMProvider implementations based on application settings.
In accordance with ADR-001: Provides a single, clean factory interface for application
services to acquire the configured provider.
"""

from __future__ import annotations

from app.core.config import Settings, get_settings
from app.modules.ai.llm.exceptions import LLMError
from app.modules.ai.llm.inert import InertLLMProvider
from app.modules.ai.llm.locality import assert_endpoint_allowed
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.ai.providers.ollama.provider import OllamaProvider


def get_llm_provider(settings: Settings | None = None) -> LLMProvider:
    """
    Factory to retrieve the configured LLM provider instance.

    Args:
        settings: Optional Settings instance. If None, resolved via get_settings().

    Returns:
        Configured LLMProvider instance.

    Local-first rules (Task 2): AI disabled returns an inert provider (no client, no network); the provider is chosen only by
    ``LLM_PROVIDER`` (never inferred from API keys); unknown names and non-local endpoints fail closed; there is no fallback to another provider.

    Raises:
        LLMError: If the configured provider name is unknown or unsupported (``LLMConfigurationError`` for an unsafe endpoint).
    """
    cfg = settings or get_settings()
    if not cfg.LLM_ENABLED:
        return InertLLMProvider.disabled()
    provider_name = (cfg.LLM_PROVIDER or "ollama").strip().lower()

    if provider_name == "ollama":
        assert_endpoint_allowed(cfg.OLLAMA_BASE_URL, cfg.LLM_ALLOW_NON_LOCAL_ENDPOINT)
        return OllamaProvider(
            base_url=cfg.OLLAMA_BASE_URL,
            model=cfg.OLLAMA_MODEL,
            timeout_seconds=cfg.OLLAMA_TIMEOUT_SECONDS,
            temperature=cfg.OLLAMA_TEMPERATURE,
            max_retries=cfg.OLLAMA_MAX_RETRIES,
            keep_alive=cfg.OLLAMA_KEEP_ALIVE,
        )

    raise LLMError("Unsupported LLM provider. Supported providers: ['ollama']")


def get_llm_provider_or_inert(settings: Settings | None = None) -> LLMProvider:
    """
    Dependency-safe variant: a configuration error must not break deterministic endpoints that merely accept a provider.
    Returns an inert provider (typed ``LLMConfigurationError`` on use) instead of raising; never falls back to another provider.
    """
    try:
        return get_llm_provider(settings)
    except LLMError:
        return InertLLMProvider.misconfigured()
