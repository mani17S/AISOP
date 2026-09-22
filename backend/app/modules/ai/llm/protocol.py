"""
AISOP LLM Provider Protocol Interface.

In accordance with ADR-001 (Direct Lightweight LLM Abstraction):
Defines the runtime checkable Protocol that all AISOP LLM adapters must implement.
Decouples application logic, SOC hypothesis generation, and report building from specific
model vendors or inference engines.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.schemas.ai import LLMRequest, LLMResponse, ProviderHealthResponse


@runtime_checkable
class LLMProvider(Protocol):
    """Contract for all AISOP LLM inference adapters."""

    @property
    def model_name(self) -> str:
        """The active model identifier configured for this provider (e.g. 'llama3.1:8b')."""
        ...

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Execute a complete, non-streaming chat generation request.

        Args:
            request: Standardized request containing conversation history, optional
                     model override, temperature, max tokens, and JSON mode instruction.

        Returns:
            LLMResponse containing generated content, role, model, and token metrics.

        Raises:
            LLMConnectionError: If the provider daemon is unreachable.
            LLMTimeoutError: If inference execution exceeds configured timeout.
            LLMModelNotFoundError: If requested model is not available on provider.
            LLMResponseError: If provider returns HTTP 5xx or unparseable payload.
        """
        ...

    async def health(self) -> ProviderHealthResponse:
        """
        Perform a non-intrusive probe of provider reachability and model availability.

        Returns:
            ProviderHealthResponse containing status, target model, latency, and error message.
        """
        ...
