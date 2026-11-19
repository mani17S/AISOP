"""
Unit tests for OllamaEmbedder.

Tests embedding generation, 768-dimension validation, retry behavior,
error handling, and MockTransport HTTP simulations.
Runs completely offline without a live Ollama daemon.
"""

from __future__ import annotations

import httpx
import pytest
from app.core.config import Settings
from app.modules.ai.embeddings.embedder import OllamaEmbedder
from app.modules.ai.embeddings.exceptions import (
    EmbeddingConnectionError,
    EmbeddingDimensionError,
    EmbeddingError,
    EmbeddingModelNotFoundError,
    EmbeddingTimeoutError,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _make_mock_embedder(
    handler,
    dimensions: int = 768,
    model: str = "nomic-embed-text",
    max_retries: int = 2,
    timeout: int = 5,
) -> OllamaEmbedder:
    settings = Settings(
        EMBEDDING_DIMENSIONS=dimensions,
        EMBEDDING_MODEL=model,
        OLLAMA_MAX_RETRIES=max_retries,
        EMBEDDING_TIMEOUT_SECONDS=timeout,
    )
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    return OllamaEmbedder(settings=settings, client=client)


def test_embedder_properties():
    settings = Settings(
        EMBEDDING_DIMENSIONS=768,
        EMBEDDING_MODEL="nomic-embed-text",
    )
    embedder = OllamaEmbedder(settings=settings)
    assert embedder.model_name == "nomic-embed-text"
    assert embedder.expected_dimensions == 768


@pytest.mark.anyio
async def test_embed_success():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/embeddings"
        payload = {"embedding": [0.1] * 768}
        return httpx.Response(200, json=payload)

    embedder = _make_mock_embedder(handler)
    result = await embedder.embed("security incident investigation")
    assert len(result) == 768
    assert result[0] == 0.1
    await embedder.aclose()


@pytest.mark.anyio
async def test_embed_dimension_mismatch_raises_error():
    def handler(request: httpx.Request) -> httpx.Response:
        # Returns 512 dimensions instead of expected 768
        return httpx.Response(200, json={"embedding": [0.1] * 512})

    embedder = _make_mock_embedder(handler, dimensions=768)
    with pytest.raises(EmbeddingDimensionError) as exc_info:
        await embedder.embed("malformed vector length")

    assert exc_info.value.expected_dim == 768
    assert exc_info.value.received_dim == 512
    await embedder.aclose()


@pytest.mark.anyio
async def test_embed_model_not_found_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model 'nomic-embed-text' not found"})

    embedder = _make_mock_embedder(handler)
    with pytest.raises(EmbeddingModelNotFoundError) as exc_info:
        await embedder.embed("test text")

    assert "not found" in str(exc_info.value)
    await embedder.aclose()


@pytest.mark.anyio
async def test_embed_client_error_400_fails_fast():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(400, text="Bad Request: empty prompt")

    embedder = _make_mock_embedder(handler, max_retries=3)
    with pytest.raises(EmbeddingError) as exc_info:
        await embedder.embed("")

    # Must fail immediately without retrying
    assert attempts == 1
    assert "400" in str(exc_info.value)
    await embedder.aclose()


@pytest.mark.anyio
async def test_embed_transient_503_recovers():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503, text="Service Unavailable")
        return httpx.Response(200, json={"embedding": [0.5] * 768})

    embedder = _make_mock_embedder(handler, max_retries=3)
    vec = await embedder.embed("retry test")
    assert attempts == 2
    assert len(vec) == 768
    await embedder.aclose()


@pytest.mark.anyio
async def test_embed_persistent_503_exhausts_retries():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, text="Service Unavailable")

    embedder = _make_mock_embedder(handler, max_retries=2)
    with pytest.raises(EmbeddingError):
        await embedder.embed("fail test")

    assert attempts == 2
    await embedder.aclose()


@pytest.mark.anyio
async def test_embed_batch_success():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"embedding": [0.2] * 768})

    embedder = _make_mock_embedder(handler)
    texts = ["chunk 1", "chunk 2", "chunk 3"]
    vectors = await embedder.embed_batch(texts)
    assert len(vectors) == 3
    for v in vectors:
        assert len(v) == 768
    await embedder.aclose()


@pytest.mark.anyio
async def test_embed_batch_empty():
    embedder = _make_mock_embedder(lambda r: httpx.Response(200))
    vectors = await embedder.embed_batch([])
    assert vectors == []
    await embedder.aclose()


@pytest.mark.anyio
async def test_embed_batch_fails_fast_on_error():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            return httpx.Response(400, text="Bad Request")
        return httpx.Response(200, json={"embedding": [0.1] * 768})

    embedder = _make_mock_embedder(handler)
    texts = ["chunk 1", "chunk 2", "chunk 3"]
    with pytest.raises(EmbeddingError):
        await embedder.embed_batch(texts)

    # Failed on 2nd text; 3rd text was never attempted
    assert attempts == 2
    await embedder.aclose()


@pytest.mark.anyio
async def test_embed_malformed_response_json():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"something_else": 123})

    embedder = _make_mock_embedder(handler)
    with pytest.raises(EmbeddingError) as exc_info:
        await embedder.embed("test")

    assert "missing 'embedding' field" in str(exc_info.value)
    await embedder.aclose()
