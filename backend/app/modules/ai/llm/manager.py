"""
AISOP LLM Provider Manager & Factory.

Instantiates and configures LLMProvider implementations based on application settings.
In accordance with ADR-001: Provides a single, clean factory interface for application
services to acquire the configured provider.
"""

from __future__ import annotations

import re
from typing import Callable

from app.core.config import Settings, get_settings
from app.modules.ai.llm.exceptions import LLMConfigurationError, LLMError
from app.modules.ai.llm.inert import InertLLMProvider
from app.modules.ai.llm.locality import assert_endpoint_allowed
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.ai.providers.ollama.provider import OllamaProvider


ProviderFactory = Callable[[Settings], LLMProvider]
_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_FACTORIES: dict[str, ProviderFactory] = {}


def register_llm_provider(name: str, factory: ProviderFactory, *, replace: bool = False) -> None:
    """
    Add an LLM provider by name, without editing this module. ``factory(settings)`` must return an object that satisfies the
    ``LLMProvider`` protocol. A provider is used only when the operator selects it with ``LLM_PROVIDER=<name>``; registering one never
    activates it, there is no fallback between providers, and a provider that talks to another host must enforce the same local-first
    rule (``assert_endpoint_allowed``). Verify a new provider with ``backend/scripts/llm_provider_contract.py``.
    """
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise LLMConfigurationError("LLM provider name is invalid (lower case letters, digits, '_' or '-', 2 to 32 characters).")
    if name in _FACTORIES and not replace:
        raise LLMConfigurationError("An LLM provider with this name is already registered.")
    _FACTORIES[name] = factory


def registered_llm_providers() -> list[str]:
    return sorted(_FACTORIES)


def _ollama_factory(cfg: Settings) -> LLMProvider:
    assert_endpoint_allowed(cfg.OLLAMA_BASE_URL, cfg.LLM_ALLOW_NON_LOCAL_ENDPOINT)
    return OllamaProvider(
        base_url=cfg.OLLAMA_BASE_URL,
        model=cfg.OLLAMA_MODEL,
        timeout_seconds=cfg.OLLAMA_TIMEOUT_SECONDS,
        temperature=cfg.OLLAMA_TEMPERATURE,
        max_retries=cfg.OLLAMA_MAX_RETRIES,
        keep_alive=cfg.OLLAMA_KEEP_ALIVE,
        num_ctx=getattr(cfg, "OLLAMA_NUM_CTX", None),
    )


register_llm_provider("ollama", _ollama_factory)  # built in: local, free, the default


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

    factory = _FACTORIES.get(provider_name)
    if factory is None:
        raise LLMError(f"Unsupported LLM provider. Supported providers: {registered_llm_providers()}")
    try:
        provider = factory(cfg)
    except LLMError:
        raise
    except Exception:  # noqa: BLE001 - a third-party factory must never leak its error text (it may hold a secret)
        raise LLMConfigurationError("LLM provider could not be built from the configuration.") from None
    if not isinstance(provider, LLMProvider):
        raise LLMConfigurationError("LLM provider does not satisfy the provider contract.")
    return provider


def get_llm_provider_or_inert(settings: Settings | None = None) -> LLMProvider:
    """
    Dependency-safe variant: a configuration error must not break deterministic endpoints that merely accept a provider.
    Returns an inert provider (typed ``LLMConfigurationError`` on use) instead of raising; never falls back to another provider.
    """
    try:
        return get_llm_provider(settings)
    except LLMError:
        return InertLLMProvider.misconfigured()
