"""
AISOP Embeddings Subsystem.
"""

from app.modules.ai.embeddings.embedder import OllamaEmbedder
from app.modules.ai.embeddings.exceptions import (
    EmbeddingConnectionError,
    EmbeddingDimensionError,
    EmbeddingError,
    EmbeddingModelNotFoundError,
    EmbeddingTimeoutError,
)

__all__ = [
    "EmbeddingConnectionError",
    "EmbeddingDimensionError",
    "EmbeddingError",
    "EmbeddingModelNotFoundError",
    "EmbeddingTimeoutError",
    "OllamaEmbedder",
]
