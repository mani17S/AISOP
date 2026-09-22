"""
AISOP LLM Provider Manager & Factory.

Instantiates and configures LLMProvider implementations based on application settings.
In accordance with ADR-001: Provides a single, clean factory interface for application
services to acquire the configured provider.
"""

from __future__ import annotations

from app.core.config import Settings, get_settings
from app.modules.ai.llm.exceptions import LLMError
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.ai.providers.ollama.provider import OllamaProvider


def get_llm_provider(settings: Settings | None = None) -> LLMProvider:
    """
    Factory to retrieve the configured LLM provider instance.

    Args:
        settings: Optional Settings instance. If None, resolved via get_settings().

    Returns:
        Configured LLMProvider instance.

    Raises:
        LLMError: If the configured provider name is unknown or unsupported.
    """
    cfg = settings or get_settings()
    provider_name = (cfg.LLM_PROVIDER or "ollama").strip().lower()

    if provider_name == "ollama":
        return OllamaProvider(
            base_url=cfg.OLLAMA_BASE_URL,
            model=cfg.OLLAMA_MODEL,
            timeout_seconds=cfg.OLLAMA_TIMEOUT_SECONDS,
            temperature=cfg.OLLAMA_TEMPERATURE,
            max_retries=cfg.OLLAMA_MAX_RETRIES,
            keep_alive=cfg.OLLAMA_KEEP_ALIVE,
        )

    raise LLMError(
        f"Unsupported LLM provider: '{provider_name}'. Supported providers: ['ollama']"
    )
