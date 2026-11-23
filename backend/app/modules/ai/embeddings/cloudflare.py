"""
AISOP Cloudflare Workers AI embedder: an OPT-IN, external embedding service for RAG on the public demo (ADR-016).

Same contract as the local OllamaEmbedder (embed, embed_batch, expected_dimensions, model_name), and the same hard dimension guard, so
a wrong-size vector can never enter the pgvector table. Vectors from different models are NOT comparable: a knowledge base embedded
locally with nomic-embed-text must be re-embedded with this model before it is searched with it (they are separate databases).

The token is held in a SecretStr and only travels in the Authorization header. The text sent is knowledge-base text and the analyst's
retrieval query; the page that enables this says so.
"""

from __future__ import annotations

from typing import Any

import httpx
from loguru import logger

from app.core.config import Settings, get_settings
from app.modules.ai.embeddings.exceptions import (
    EmbeddingConnectionError,
    EmbeddingDimensionError,
    EmbeddingError,
    EmbeddingModelNotFoundError,
    EmbeddingTimeoutError,
)
from app.modules.ai.llm.manager import require_external_opt_in

API_ROOT = "https://api.cloudflare.com/client/v4/accounts"
#: Texts per request. The service accepts a list; a small batch keeps a failure cheap to retry.
BATCH_SIZE = 16


class CloudflareEmbedder:
    def __init__(self, settings: Settings | None = None, client: httpx.AsyncClient | None = None) -> None:
        cfg = settings or get_settings()
        self._account_id, self._token = require_external_opt_in(cfg)
        self._model = cfg.CLOUDFLARE_AI_EMBEDDING_MODEL
        self._expected_dim = cfg.EMBEDDING_DIMENSIONS
        self._timeout = cfg.EMBEDDING_TIMEOUT_SECONDS
        self._client = client
        self._owns_client = client is None

    def __repr__(self) -> str:
        return f"CloudflareEmbedder(model={self._model!r})"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def expected_dimensions(self) -> int:
        return self._expected_dim

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(self._timeout, connect=10.0))
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> "CloudflareEmbedder":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def _embed_many(self, texts: list[str]) -> list[list[float]]:
        try:
            response = await self._get_client().post(
                f"{API_ROOT}/{self._account_id}/ai/run/{self._model}",
                headers={"Authorization": f"Bearer {self._token.get_secret_value()}", "Content-Type": "application/json"},
                json={"text": texts},
                timeout=httpx.Timeout(self._timeout, connect=10.0),
            )
        except httpx.TimeoutException:
            raise EmbeddingTimeoutError("The hosted embedding service did not answer in time.") from None
        except httpx.HTTPError as exc:
            raise EmbeddingConnectionError("The hosted embedding service could not be reached.", details={"error_type": type(exc).__name__}) from None
        if response.status_code in (404, 410):
            raise EmbeddingModelNotFoundError("The configured hosted embedding model is not available.")
        if response.status_code != 200:
            raise EmbeddingError("The hosted embedding service refused the request.", details={"status_code": response.status_code})
        try:
            vectors = response.json()["result"]["data"]
        except (ValueError, KeyError, TypeError):
            raise EmbeddingError("The hosted embedding service returned an unexpected shape.") from None
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise EmbeddingError("The hosted embedding service returned the wrong number of vectors.")
        for vector in vectors:
            if not isinstance(vector, list) or len(vector) != self._expected_dim:
                raise EmbeddingDimensionError(
                    "Embedding dimension mismatch; the vector was refused so the vector table cannot be corrupted.",
                    expected_dim=self._expected_dim,
                    received_dim=len(vector) if isinstance(vector, list) else -1,
                )
        return [[float(x) for x in v] for v in vectors]

    async def embed(self, text: str) -> list[float]:
        return (await self._embed_many([text]))[0]

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        logger.info("Starting hosted batch embedding", model=self._model, batch_size=len(texts))
        out: list[list[float]] = []
        for i in range(0, len(texts), BATCH_SIZE):
            out.extend(await self._embed_many(texts[i : i + BATCH_SIZE]))
        return out
