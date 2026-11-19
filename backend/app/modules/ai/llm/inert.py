"""
Inert LLM provider: stands in when AI is disabled or the configuration cannot be used.

It builds no HTTP client and never touches the network. ``generate`` raises a typed, secret-free error that every existing investigation path
already converts into a deterministic fallback, so deterministic results stay available and the AI status is reported honestly.
"""

from __future__ import annotations

from app.modules.ai.llm.exceptions import LLMConfigurationError, LLMDisabledError, LLMError
from app.schemas.ai import LLMRequest, LLMResponse, ProviderHealthResponse


class InertLLMProvider:
    is_inert = True

    def __init__(self, error_type: type[LLMError] = LLMDisabledError, model: str = "none") -> None:
        self._error_type = error_type
        self._model = model

    @property
    def model_name(self) -> str:
        return self._model

    @classmethod
    def disabled(cls) -> "InertLLMProvider":
        return cls(LLMDisabledError)

    @classmethod
    def misconfigured(cls) -> "InertLLMProvider":
        return cls(LLMConfigurationError)

    async def generate(self, request: LLMRequest) -> LLMResponse:
        if self._error_type is LLMDisabledError:
            raise LLMDisabledError("AI assistance is disabled by configuration.")
        raise self._error_type("AI assistance is unavailable because the LLM configuration is invalid.")

    async def health(self) -> ProviderHealthResponse:
        return ProviderHealthResponse(status="unavailable", model=self._model, provider="none", error="AI assistance is not active.")
