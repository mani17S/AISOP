"""
Live Ollama Embedding Integration Tests.

Requires a live Ollama daemon running on http://localhost:11434 with
the nomic-embed-text model pulled.

Marked with @pytest.mark.ollama.
If the daemon is unreachable or the model is missing, the test skips cleanly
with an explicit explanatory message, distinguishing unavailable infrastructure
from test failures.
"""

from __future__ import annotations

import httpx
import pytest
from app.core.config import Settings, get_settings
from app.modules.ai.embeddings.embedder import OllamaEmbedder


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _check_ollama_available(base_url: str, model_name: str) -> tuple[bool, str]:
    """Check if Ollama is running and has the embedding model pulled."""
    try:
        resp = httpx.get(f"{base_url}/api/tags", timeout=3.0)
        if resp.status_code != 200:
            return False, f"Ollama daemon returned HTTP {resp.status_code}"
        models = [m.get("name", "") for m in resp.json().get("models", [])]
        # Match e.g. "nomic-embed-text:latest" or "nomic-embed-text"
        has_model = any(m.startswith(model_name) for m in models)
        if not has_model:
            return (
                False,
                f"Model '{model_name}' not pulled in Ollama. Available: {models}",
            )
        return True, "Available"
    except Exception as exc:
        return False, f"Cannot connect to Ollama at {base_url}: {exc}"


@pytest.mark.ollama
@pytest.mark.anyio
async def test_live_ollama_embed_text():
    settings = get_settings()
    available, reason = _check_ollama_available(
        settings.OLLAMA_BASE_URL, settings.EMBEDDING_MODEL
    )
    if not available:
        pytest.skip(f"Live Ollama infrastructure unavailable: {reason}")

    embedder = OllamaEmbedder(settings=settings)
    try:
        vec = await embedder.embed("Security operations center hypothesis generation")
        assert len(vec) == 768
        assert all(isinstance(x, float) for x in vec)
    finally:
        await embedder.aclose()


@pytest.mark.ollama
@pytest.mark.anyio
async def test_live_ollama_embed_batch():
    settings = get_settings()
    available, reason = _check_ollama_available(
        settings.OLLAMA_BASE_URL, settings.EMBEDDING_MODEL
    )
    if not available:
        pytest.skip(f"Live Ollama infrastructure unavailable: {reason}")

    embedder = OllamaEmbedder(settings=settings)
    try:
        texts = [
            "T1059 Command and Scripting Interpreter",
            "T1055 Process Injection",
        ]
        vectors = await embedder.embed_batch(texts)
        assert len(vectors) == 2
        for v in vectors:
            assert len(v) == 768
    finally:
        await embedder.aclose()
