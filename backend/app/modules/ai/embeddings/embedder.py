"""
AISOP Ollama Embedding Provider.

In accordance with ADR-001 (Direct Lightweight LLM Abstraction) and ADR-002 (pgvector):
Implements OllamaEmbedder by calling Ollama s /api/embeddings endpoint directly via httpx.
Enforces a hard dimension assertion (768) to guarantee embedding space integrity.
Uses tenacity exponential backoff for transient failures, matching OllamaProvider behaviour.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from app.modules.ai.llm.locality import assert_endpoint_allowed
from app.core.config import Settings, get_settings
from app.core.logging import redact_sensitive_data
from app.modules.ai.embeddings.exceptions import (
    EmbeddingConnectionError,
    EmbeddingDimensionError,
    EmbeddingError,
    EmbeddingModelNotFoundError,
    EmbeddingTimeoutError,
)
from loguru import logger
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)


def _is_transient_embedding_error(exc: BaseException) -> bool:
    """Identify transient network and server errors eligible for retry."""
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)):
        return True
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (
        502,
        503,
        504,
    ):
        return True
    return False


class OllamaEmbedder:
    """
    Direct asynchronous HTTP embedder for local Ollama instances.

    Calls Ollama s /api/embeddings endpoint to produce 768-dimensional embeddings
    using the configured nomic-embed-text model. Enforces a hard dimension assertion
    before returning any vector to prevent embedding-space corruption in pgvector.

    Security note: Embedder input (chunk text) is treated as untrusted reference content.
    No chunk text is executed, logged in full, or evaluated as instructions.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        cfg = settings or get_settings()
        assert_endpoint_allowed(cfg.OLLAMA_BASE_URL, cfg.LLM_ALLOW_NON_LOCAL_ENDPOINT)  # local-first: same rule as the chat provider
        self._base_url = cfg.OLLAMA_BASE_URL.rstrip("/")
        self._model = cfg.EMBEDDING_MODEL
        self._expected_dim = cfg.EMBEDDING_DIMENSIONS
        self._timeout_seconds = cfg.EMBEDDING_TIMEOUT_SECONDS
        self._max_retries = cfg.OLLAMA_MAX_RETRIES
        self._client = client
        self._owns_client = client is None

    @property
    def model_name(self) -> str:
        """The configured embedding model identifier."""
        return self._model

    @property
    def expected_dimensions(self) -> int:
        """The required embedding vector dimension (hard-enforced)."""
        return self._expected_dim

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout_seconds, connect=10.0)
            )
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        """Close the underlying HTTP client if owned by this instance."""
        if (
            self._owns_client
            and self._client is not None
            and not self._client.is_closed
        ):
            await self._client.aclose()

    async def __aenter__(self) -> OllamaEmbedder:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def embed(self, text: str) -> list[float]:
        """
        Embed a single text string via Ollama /api/embeddings.

        Args:
            text: Raw text to embed (untrusted reference content).

        Returns:
            A list of exactly EMBEDDING_DIMENSIONS (768) floats.

        Raises:
            EmbeddingDimensionError: If Ollama returns a vector of unexpected length.
            EmbeddingModelNotFoundError: If the embedding model is not available (HTTP 404).
            EmbeddingConnectionError: If Ollama is unreachable after all retry attempts.
            EmbeddingError: For all other embedding failures.
        """
        url = f"{self._base_url}/api/embeddings"
        payload: dict[str, Any] = {"model": self._model, "prompt": text}
        client = self._get_client()

        logger.debug(
            "Dispatching embedding request to Ollama",
            model=self._model,
            endpoint=url,
            text_length=len(text),
        )

        response_data: dict[str, Any] = {}

        try:
            retryer = AsyncRetrying(
                retry=retry_if_exception(_is_transient_embedding_error),
                stop=stop_after_attempt(max(1, self._max_retries)),
                wait=wait_exponential(multiplier=1.0, min=1.0, max=8.0),
                reraise=True,
            )

            async for attempt in retryer:
                with attempt:
                    try:
                        response = await client.post(
                            url,
                            json=payload,
                            timeout=httpx.Timeout(self._timeout_seconds, connect=10.0),
                        )
                        response.raise_for_status()
                        response_data = response.json()
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            raise EmbeddingModelNotFoundError(
                                f"Embedding model '{self._model}' not found in Ollama at "
                                f"{self._base_url}. Run: ollama pull {self._model}",
                                details={
                                    "status_code": 404,
                                    "response": exc.response.text[:200],
                                },
                            ) from exc
                        if 400 <= exc.response.status_code < 500:
                            raise EmbeddingError(
                                f"Ollama embedding client error ({exc.response.status_code}): "
                                f"{exc.response.text[:200]}",
                                details={"status_code": exc.response.status_code},
                            ) from exc
                        raise

        except RetryError as exc:
            last_exc = exc.last_attempt.exception()
            if isinstance(last_exc, (httpx.ConnectError, httpx.ConnectTimeout)):
                raise EmbeddingConnectionError(
                    f"Failed to connect to Ollama at {self._base_url} after "
                    f"{self._max_retries} attempts",
                    details={"base_url": self._base_url},
                ) from last_exc
            if isinstance(last_exc, httpx.HTTPStatusError):
                raise EmbeddingError(
                    f"Ollama embedding server error ({last_exc.response.status_code}) "
                    f"persisted after {self._max_retries} retries",
                    details={"status_code": last_exc.response.status_code},
                ) from last_exc
            raise EmbeddingError(
                f"Ollama embedding failed after retries: {last_exc}"
            ) from last_exc

        except httpx.TimeoutException as exc:
            raise EmbeddingTimeoutError(
                f"Ollama embedding timed out after {self._timeout_seconds}s at {self._base_url}",
                details={
                    "timeout_seconds": self._timeout_seconds,
                    "model": self._model,
                },
            ) from exc

        except httpx.ConnectError as exc:
            raise EmbeddingConnectionError(
                f"Failed to connect to Ollama daemon at {self._base_url}. Is Ollama running?",
                details={"base_url": self._base_url},
            ) from exc

        except (EmbeddingError, EmbeddingModelNotFoundError):
            raise

        except Exception as exc:
            raise EmbeddingError(
                f"Unexpected error during Ollama embedding: {exc}",
                details={"error_type": type(exc).__name__},
            ) from exc

        if not isinstance(response_data, dict):
            raise EmbeddingError(
                f"Expected dict response from Ollama, got {type(response_data).__name__}",
                details={"response": str(response_data)[:200]},
            )

        raw_embedding = response_data.get("embedding")
        if not isinstance(raw_embedding, list):
            raise EmbeddingError(
                "Ollama /api/embeddings response missing 'embedding' field or wrong type",
                details={"response_keys": list(response_data.keys())},
            )

        received_dim = len(raw_embedding)
        if received_dim != self._expected_dim:
            raise EmbeddingDimensionError(
                f"Embedding dimension mismatch: expected {self._expected_dim}, "
                f"received {received_dim} from model '{self._model}'. "
                "This would corrupt the pgvector embedding space -- refusing to proceed.",
                expected_dim=self._expected_dim,
                received_dim=received_dim,
                details={"model": self._model, "base_url": self._base_url},
            )

        embedding: list[float] = [float(v) for v in raw_embedding]

        logger.debug(
            "Embedding generated successfully",
            model=self._model,
            dimensions=received_dim,
        )

        return embedding

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """
        Embed a list of texts sequentially via repeated embed() calls.

        Sequential (not concurrent) to avoid overloading the local Ollama daemon.
        Each text is independently retried; a failure on any text raises immediately
        without returning a partial result.

        Args:
            texts: List of raw text strings to embed.

        Returns:
            Ordered list of embedding vectors, one per input text.

        Raises:
            EmbeddingError (or subclass): On any per-text failure. No partial results
            are returned; the caller receives an exception or the full list.
        """
        if not texts:
            return []

        start_time = time.perf_counter()
        logger.info(
            "Starting batch embedding",
            model=self._model,
            batch_size=len(texts),
        )

        embeddings: list[list[float]] = []
        for idx, text in enumerate(texts):
            try:
                vector = await self.embed(text)
                embeddings.append(vector)
            except EmbeddingError:
                logger.warning(
                    "Batch embedding failed on text",
                    batch_index=idx,
                    batch_size=len(texts),
                    text_preview=text[:100],
                )
                raise

        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.info(
            "Batch embedding completed",
            model=self._model,
            batch_size=len(texts),
            duration_ms=duration_ms,
        )

        return embeddings
