"""
AISOP Embedding Exception Hierarchy.

In accordance with ADR-001 (Direct Lightweight LLM Abstraction):
Provides typed domain exceptions for the OllamaEmbedder, paralleling the LLMError
hierarchy established in P2-H1. Enables callers to distinguish connection failures,
dimension mismatches, and model-not-found errors without catching generic exceptions.
"""

from __future__ import annotations

from typing import Any


class EmbeddingError(Exception):
    """
    Base class for all AISOP embedding errors.

    Attributes:
        message: Human-readable error description.
        details: Optional structured diagnostic context.
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(message={self.message!r}, details={self.details!r})"
        )


class EmbeddingConnectionError(EmbeddingError):
    """
    Raised when the Ollama embedding endpoint is unreachable after all retry attempts.

    Causes: Ollama daemon not running, wrong base URL, network partition.
    """


class EmbeddingTimeoutError(EmbeddingError):
    """
    Raised when an embedding request to Ollama exceeds the configured timeout.
    """


class EmbeddingDimensionError(EmbeddingError):
    """
    Raised when the embedding returned by Ollama does not match the configured dimension.

    This is a hard guard: silently accepting a wrong-dimension vector would corrupt the
    pgvector embedding space and invalidate all cosine similarity results.

    Attributes:
        expected_dim: The configured EMBEDDING_DIMENSIONS value.
        received_dim: The actual length of the returned embedding vector.
    """

    def __init__(
        self,
        message: str,
        expected_dim: int,
        received_dim: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.expected_dim = expected_dim
        self.received_dim = received_dim


class EmbeddingModelNotFoundError(EmbeddingError):
    """
    Raised when Ollama returns HTTP 404 for the requested embedding model.

    Cause: The model (e.g. 'nomic-embed-text') has not been pulled.
    Resolution: Run 'ollama pull nomic-embed-text' on the host Ollama instance.
    """
