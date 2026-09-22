"""
AISOP LLM Module.

Exposes the core provider protocol, domain exception types, and provider factory.
"""

from app.modules.ai.llm.exceptions import (
    LLMConnectionError,
    LLMError,
    LLMModelNotFoundError,
    LLMResponseError,
    LLMTimeoutError,
)
from app.modules.ai.llm.manager import get_llm_provider
from app.modules.ai.llm.protocol import LLMProvider

__all__ = [
    "LLMProvider",
    "LLMError",
    "LLMConnectionError",
    "LLMTimeoutError",
    "LLMModelNotFoundError",
    "LLMResponseError",
    "get_llm_provider",
]
