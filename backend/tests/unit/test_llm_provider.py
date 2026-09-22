"""
Unit tests for AI/LLM Provider Protocol & Ollama Provider Adapter (P2-H1).

All tests execute deterministically in-memory using httpx.MockTransport.
Zero live network calls, zero GPU/daemon requirements, zero test flakiness.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from app.core.config import Settings
from app.modules.ai.llm.exceptions import (
    LLMConnectionError,
    LLMError,
    LLMModelNotFoundError,
    LLMResponseError,
    LLMTimeoutError,
)
from app.modules.ai.llm.manager import get_llm_provider
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.ai.providers.ollama.provider import OllamaProvider
from app.schemas.ai import LLMMessage, LLMRequest, MessageRole


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def sample_messages() -> list[LLMMessage]:
    return [
        LLMMessage(role=MessageRole.SYSTEM, content="You are a security analyst."),
        LLMMessage(
            role=MessageRole.USER,
            content="Analyze this suspicious PowerShell execution.",
        ),
    ]


@pytest.fixture
def mock_ollama_chat_response() -> dict[str, Any]:
    return {
        "model": "llama3.1:8b",
        "created_at": "2026-09-17T12:00:00.000Z",
        "message": {
            "role": "assistant",
            "content": "The execution exhibits characteristics of encoded command execution.",
        },
        "done": True,
        "total_duration": 4_200_000_000,
        "load_duration": 200_000_000,
        "prompt_eval_count": 35,
        "prompt_eval_duration": 500_000_000,
        "eval_count": 150,
        "eval_duration": 3_500_000_000,
    }


def test_llm_provider_protocol_conformance() -> None:
    """Verify OllamaProvider fulfills the LLMProvider runtime Protocol."""
    provider = OllamaProvider()
    assert isinstance(provider, LLMProvider)
    assert provider.model_name == "llama3.1:8b"


@pytest.mark.anyio
async def test_ollama_generate_success(
    sample_messages: list[LLMMessage], mock_ollama_chat_response: dict[str, Any]
) -> None:
    """Verify successful non-streaming chat generation and payload structure."""
    captured_request: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        assert request.url.path == "/api/chat"
        captured_request = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json=mock_ollama_chat_response)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    provider = OllamaProvider(
        base_url="http://mock-ollama:11434",
        model="llama3.1:8b",
        temperature=0.2,
        client=client,
    )

    request = LLMRequest(messages=sample_messages)
    response = await provider.generate(request)

    assert response.role == MessageRole.ASSISTANT
    assert response.model == "llama3.1:8b"
    assert "encoded command" in response.content
    assert response.finish_reason == "stop"

    # Verify captured request serialization
    assert captured_request["model"] == "llama3.1:8b"
    assert captured_request["stream"] is False
    assert captured_request["options"]["temperature"] == 0.2
    assert len(captured_request["messages"]) == 2
    assert captured_request["messages"][0]["role"] == "system"
    assert captured_request["messages"][1]["role"] == "user"


@pytest.mark.anyio
async def test_ollama_generate_json_mode(
    sample_messages: list[LLMMessage], mock_ollama_chat_response: dict[str, Any]
) -> None:
    """Verify format='json' is injected when json_mode=True."""
    captured_request: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        captured_request = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json=mock_ollama_chat_response)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client)

    request = LLMRequest(messages=sample_messages, json_mode=True)
    await provider.generate(request)

    assert captured_request["format"] == "json"


@pytest.mark.anyio
async def test_ollama_generate_custom_parameters(
    sample_messages: list[LLMMessage], mock_ollama_chat_response: dict[str, Any]
) -> None:
    """Verify request-level model, temperature, and max_tokens overrides."""
    captured_request: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        captured_request = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json=mock_ollama_chat_response)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(model="llama3.1:8b", temperature=0.1, client=client)

    request = LLMRequest(
        messages=sample_messages,
        model="custom-sec:8b",
        temperature=0.5,
        max_tokens=500,
    )
    await provider.generate(request)

    assert captured_request["model"] == "custom-sec:8b"
    assert captured_request["options"]["temperature"] == 0.5
    assert captured_request["options"]["num_predict"] == 500


@pytest.mark.anyio
async def test_ollama_token_usage_parsing(
    sample_messages: list[LLMMessage], mock_ollama_chat_response: dict[str, Any]
) -> None:
    """Verify token counting and execution latency parsing."""
    transport = httpx.MockTransport(
        lambda _: httpx.Response(200, json=mock_ollama_chat_response)
    )
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client)

    response = await provider.generate(LLMRequest(messages=sample_messages))

    assert response.usage.prompt_tokens == 35
    assert response.usage.completion_tokens == 150
    assert response.usage.total_tokens == 185
    assert response.usage.duration_ms == 4200.0


@pytest.mark.anyio
async def test_ollama_health_healthy() -> None:
    """Verify health probe succeeds when target model is installed."""
    tags_response = {
        "models": [
            {"name": "llama3.1:8b", "size": 4700000000},
            {"name": "nomic-embed-text:latest", "size": 270000000},
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json=tags_response)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(model="llama3.1:8b", client=client)

    health = await provider.health()
    assert health.status == "healthy"
    assert health.model == "llama3.1:8b"
    assert health.provider == "ollama"
    assert health.error is None
    assert health.latency_ms >= 0.0


@pytest.mark.anyio
async def test_ollama_health_model_missing_degraded() -> None:
    """Verify health probe reports degraded when target model is absent from Ollama."""
    tags_response = {
        "models": [
            {"name": "mistral:7b", "size": 4100000000},
        ]
    }

    transport = httpx.MockTransport(lambda _: httpx.Response(200, json=tags_response))
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(model="llama3.1:8b", client=client)

    health = await provider.health()
    assert health.status == "degraded"
    assert health.error is not None
    assert "not pulled" in health.error


@pytest.mark.anyio
async def test_ollama_health_daemon_down_unavailable() -> None:
    """Verify health probe gracefully returns unavailable on connection refused."""

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused to 127.0.0.1:11434")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client)

    health = await provider.health()
    assert health.status == "unavailable"
    assert health.error is not None
    assert "Connection refused" in health.error


@pytest.mark.anyio
async def test_ollama_timeout_handling(sample_messages: list[LLMMessage]) -> None:
    """Verify timeout produces typed LLMTimeoutError."""

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Inference exceeded threshold")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client, timeout_seconds=10)

    with pytest.raises(LLMTimeoutError) as exc_info:
        await provider.generate(LLMRequest(messages=sample_messages))

    assert "timed out after 10s" in str(exc_info.value)


@pytest.mark.anyio
async def test_ollama_connection_refused_error(
    sample_messages: list[LLMMessage],
) -> None:
    """Verify connection error produces typed LLMConnectionError after retries."""

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client, max_retries=2)

    with pytest.raises(LLMConnectionError) as exc_info:
        await provider.generate(LLMRequest(messages=sample_messages))

    assert "Failed to connect to Ollama" in str(exc_info.value)


@pytest.mark.anyio
async def test_ollama_model_not_found_404(sample_messages: list[LLMMessage]) -> None:
    """Verify HTTP 404 immediately raises LLMModelNotFoundError without retrying."""
    call_count = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            404, text="model 'unknown:tag' not found, try pulling it first"
        )

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client, max_retries=3)

    with pytest.raises(LLMModelNotFoundError) as exc_info:
        await provider.generate(
            LLMRequest(messages=sample_messages, model="unknown:tag")
        )

    assert call_count == 1  # Proves non-retryable
    assert "not found in Ollama" in str(exc_info.value)


@pytest.mark.anyio
async def test_ollama_client_error_400_no_retry(
    sample_messages: list[LLMMessage],
) -> None:
    """Verify HTTP 400 immediately raises LLMResponseError without retrying."""
    call_count = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(400, text="malformed request syntax")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client, max_retries=3)

    with pytest.raises(LLMResponseError) as exc_info:
        await provider.generate(LLMRequest(messages=sample_messages))

    assert call_count == 1  # Proves non-retryable
    assert exc_info.value.status_code == 400


@pytest.mark.anyio
async def test_ollama_transient_retry_success(
    sample_messages: list[LLMMessage], mock_ollama_chat_response: dict[str, Any]
) -> None:
    """Verify transient HTTP 503 retries and recovers successfully on second attempt."""
    call_count = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(503, text="Service Temporarily Unavailable")
        return httpx.Response(200, json=mock_ollama_chat_response)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client, max_retries=3)

    response = await provider.generate(LLMRequest(messages=sample_messages))
    assert call_count == 2
    assert response.content != ""


@pytest.mark.anyio
async def test_ollama_malformed_json_response(
    sample_messages: list[LLMMessage],
) -> None:
    """Verify non-JSON response from Ollama raises typed LLMResponseError."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>502 Bad Gateway Proxy</html>")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client, max_retries=1)

    with pytest.raises(LLMResponseError) as exc_info:
        await provider.generate(LLMRequest(messages=sample_messages))

    assert "Unexpected error during Ollama inference" in str(
        exc_info.value
    ) or "Malformed response" in str(exc_info.value)


@pytest.mark.anyio
async def test_ollama_missing_message_payload(
    sample_messages: list[LLMMessage],
) -> None:
    """Verify response missing 'message.content' raises typed LLMResponseError."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"done": True, "total_duration": 1000})

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client, max_retries=1)

    with pytest.raises(LLMResponseError) as exc_info:
        await provider.generate(LLMRequest(messages=sample_messages))

    assert "missing 'message.content'" in str(exc_info.value)


@pytest.mark.anyio
async def test_ollama_persistent_5xx_exhaustion(
    sample_messages: list[LLMMessage],
) -> None:
    """Verify persistent 503 error exhausts max retries and raises LLMResponseError."""
    call_count = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(503, text="Service Unavailable")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client, max_retries=3)

    with pytest.raises(LLMResponseError) as exc_info:
        await provider.generate(LLMRequest(messages=sample_messages))

    assert call_count == 3
    assert exc_info.value.status_code == 503
    assert "Ollama server error (503)" in str(exc_info.value)


@pytest.mark.anyio
async def test_ollama_health_probe_timeout() -> None:
    """Verify health probe returns unavailable when probe exceeds timeout."""

    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Health probe timeout")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client)

    health = await provider.health()
    assert health.status == "unavailable"
    assert health.error is not None
    assert "timed out" in health.error


@pytest.mark.anyio
async def test_ollama_health_probe_server_error_degraded() -> None:
    """Verify health probe returns degraded when Ollama returns HTTP 500."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal engine failure")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    provider = OllamaProvider(client=client)

    health = await provider.health()
    assert health.status == "degraded"
    assert health.error is not None
    assert "HTTP 500" in health.error


def test_get_llm_provider_factory() -> None:
    """Verify factory returns configured provider and rejects unknown types."""
    settings = Settings(
        LLM_PROVIDER="ollama",
        OLLAMA_BASE_URL="http://test-server:11434",
        OLLAMA_MODEL="llama3.1:8b",
    )
    provider = get_llm_provider(settings)
    assert isinstance(provider, OllamaProvider)
    assert provider.model_name == "llama3.1:8b"

    invalid_settings = Settings(LLM_PROVIDER="unsupported_cloud")
    with pytest.raises(LLMError) as exc_info:
        get_llm_provider(invalid_settings)
    assert "Unsupported LLM provider" in str(exc_info.value)
