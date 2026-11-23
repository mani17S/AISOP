"""
Hosted AI for the public demo: Cloudflare Workers AI as an OPT-IN provider (ADR-016).

Local-first stays the default. The external provider is built only when the operator sets LLM_PROVIDER, LLM_ALLOW_EXTERNAL_PROVIDER
and credentials; the token never appears in an error, a log or a response; a daily budget stops a public demo from burning the free
allowance. No network: httpx.MockTransport.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import httpx
import pytest

from app.core.config import Settings
from app.modules.ai.embeddings.cloudflare import CloudflareEmbedder
from app.modules.ai.embeddings.embedder import OllamaEmbedder, get_embedder
from app.modules.ai.embeddings.exceptions import EmbeddingDimensionError
from app.modules.ai.llm import manager as llm_manager
from app.modules.ai.llm.exceptions import LLMConfigurationError, LLMConnectionError, LLMModelNotFoundError, LLMResponseError, LLMTimeoutError
from app.modules.ai.providers.cloudflare.provider import CloudflareWorkersAIProvider
from app.schemas.ai import LLMMessage, LLMRequest, MessageRole

TOKEN = "cf-secret-token-0123456789abcdef"
ACCOUNT = "a" * 32


def _settings(**over) -> Settings:
    base = dict(
        _env_file=None, LLM_ENABLED=True, LLM_PROVIDER="cloudflare_workers_ai", LLM_ALLOW_EXTERNAL_PROVIDER=True,
        CLOUDFLARE_ACCOUNT_ID=ACCOUNT, CLOUDFLARE_AI_API_TOKEN=TOKEN,
    )
    base.update(over)
    return Settings(**base)


def _request(schema: dict | None = None) -> LLMRequest:
    return LLMRequest(
        messages=[LLMMessage(role=MessageRole.SYSTEM, content="sys"), LLMMessage(role=MessageRole.USER, content="user")],
        model="@cf/meta/llama-3.3-70b-instruct-fp8-fast", max_tokens=300, temperature=0.0, json_mode=True, response_schema=schema,
    )


def _ok(content: str = '{"a": 1}', neurons: float = 200.0, finish: str = "stop") -> httpx.Response:
    return httpx.Response(200, json={
        "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": finish}],
        "usage": {"prompt_tokens": 4660, "completion_tokens": 424, "total_tokens": 5084, "neurons": neurons},
    })


def _provider(handler, **over) -> CloudflareWorkersAIProvider:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return CloudflareWorkersAIProvider(account_id=ACCOUNT, api_token=TOKEN, client=client, **over)


# ── the opt-in gate ───────────────────────────────────────────────────────────────────────────────────────────

def test_the_external_provider_is_not_built_without_the_explicit_opt_in():
    with pytest.raises(LLMConfigurationError) as exc:
        llm_manager.get_llm_provider(_settings(LLM_ALLOW_EXTERNAL_PROVIDER=False))
    assert "external" in str(exc.value).lower() and TOKEN not in str(exc.value)


def test_it_needs_an_account_and_a_token():
    for missing in ({"CLOUDFLARE_ACCOUNT_ID": None}, {"CLOUDFLARE_AI_API_TOKEN": None}):
        with pytest.raises(LLMConfigurationError):
            llm_manager.get_llm_provider(_settings(**missing))


def test_with_the_opt_in_and_credentials_the_provider_is_built_and_the_default_stays_local():
    provider = llm_manager.get_llm_provider(_settings())
    assert isinstance(provider, CloudflareWorkersAIProvider) and provider.model_name.startswith("@cf/")
    assert Settings(_env_file=None).LLM_PROVIDER == "ollama" and Settings(_env_file=None).LLM_ALLOW_EXTERNAL_PROVIDER is False
    assert TOKEN not in repr(provider) and TOKEN not in str(vars(provider).get("_settings", ""))


# ── the request and the response ──────────────────────────────────────────────────────────────────────────────

def test_generate_sends_the_schema_and_the_token_only_in_the_authorization_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return _ok('{"claims": []}')

    schema = {"type": "object", "properties": {"claims": {"type": "array"}}}
    response = asyncio.run(_provider(handler).generate(_request(schema)))
    assert seen["url"] == f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/ai/v1/chat/completions"
    assert seen["auth"] == f"Bearer {TOKEN}"
    body = seen["body"]
    assert body["model"] == "@cf/meta/llama-3.3-70b-instruct-fp8-fast" and body["max_tokens"] == 300 and body["temperature"] == 0.0
    assert body["response_format"]["type"] == "json_schema" and body["response_format"]["json_schema"]["schema"] == schema
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert TOKEN not in json.dumps(body)
    assert response.content == '{"claims": []}' and response.usage.prompt_tokens == 4660 and response.usage.completion_tokens == 424
    assert response.finish_reason == "stop" and response.model == "@cf/meta/llama-3.3-70b-instruct-fp8-fast"


def test_without_a_schema_json_mode_is_requested_and_a_length_stop_is_reported():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return _ok("{", finish="length")

    response = asyncio.run(_provider(handler).generate(_request(None)))
    assert seen["body"]["response_format"] == {"type": "json_object"} and response.finish_reason == "length"


# ── errors never carry the secret ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "status,exc",
    [(401, LLMConfigurationError), (403, LLMConfigurationError), (429, LLMConnectionError), (410, LLMModelNotFoundError), (404, LLMModelNotFoundError), (500, LLMResponseError), (503, LLMResponseError)],
)
def test_http_errors_map_to_typed_errors_without_the_token(status, exc):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"errors": [{"message": f"echo {request.headers.get('authorization')}"}]})

    with pytest.raises(exc) as caught:
        asyncio.run(_provider(handler).generate(_request()))
    assert TOKEN not in str(caught.value) and TOKEN not in repr(getattr(caught.value, "details", ""))


def test_a_timeout_is_a_typed_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(LLMTimeoutError):
        asyncio.run(_provider(handler).generate(_request()))


def test_an_answer_with_no_choices_is_a_response_error():
    with pytest.raises(LLMResponseError):
        asyncio.run(_provider(lambda r: httpx.Response(200, json={"choices": []})).generate(_request()))


# ── the daily budget ──────────────────────────────────────────────────────────────────────────────────────────

def test_the_daily_budget_stops_further_calls_without_sending_them_and_resets_the_next_day():
    from app.modules.ai.providers.cloudflare import provider as cf

    cf.reset_budget_for_tests()
    calls = []
    clock = {"now": datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return _ok(neurons=400.0)

    p = _provider(handler, daily_neuron_limit=700, clock=lambda: clock["now"])
    asyncio.run(p.generate(_request()))
    asyncio.run(p.generate(_request()))  # 800 spent, over 700
    with pytest.raises(LLMConnectionError) as caught:
        asyncio.run(p.generate(_request()))
    assert "daily" in str(caught.value).lower() and len(calls) == 2, "the refused call was never sent"
    clock["now"] = datetime(2026, 11, 24, 0, 1, tzinfo=timezone.utc)
    asyncio.run(p.generate(_request()))
    assert len(calls) == 3


# ── health ────────────────────────────────────────────────────────────────────────────────────────────────────

def test_health_reports_unavailable_when_the_service_cannot_be_reached_and_never_exposes_the_token():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    health = asyncio.run(_provider(handler).health())
    assert health.status == "unavailable" and health.provider == "cloudflare_workers_ai" and TOKEN not in health.model_dump_json()


# ── embeddings for RAG ────────────────────────────────────────────────────────────────────────────────────────

def _embed_handler(dim: int = 768):
    def handler(request: httpx.Request) -> httpx.Response:
        texts = json.loads(request.content)["text"]
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        return httpx.Response(200, json={"success": True, "result": {"shape": [len(texts), dim], "data": [[0.01] * dim for _ in texts]}})

    return handler


def test_the_embedder_returns_768_dimensional_vectors_for_one_text_and_for_a_batch():
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(_embed_handler())) as client:
            e = CloudflareEmbedder(_settings(EMBEDDING_PROVIDER="cloudflare_workers_ai"), client=client)
            one = await e.embed("powershell encoded command")
            many = await e.embed_batch(["a", "b", "c"])
            return e, one, many

    e, one, many = asyncio.run(run())
    assert len(one) == 768 and [len(v) for v in many] == [768, 768, 768] and e.expected_dimensions == 768


def test_a_vector_of_the_wrong_size_is_refused_so_the_vector_table_cannot_be_corrupted():
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(_embed_handler(dim=384))) as client:
            await CloudflareEmbedder(_settings(EMBEDDING_PROVIDER="cloudflare_workers_ai"), client=client).embed("x")

    with pytest.raises(EmbeddingDimensionError):
        asyncio.run(run())


def test_the_embedder_factory_defaults_to_local_and_the_external_one_needs_the_opt_in():
    assert isinstance(get_embedder(Settings(_env_file=None)), OllamaEmbedder)
    assert isinstance(get_embedder(_settings(EMBEDDING_PROVIDER="cloudflare_workers_ai")), CloudflareEmbedder)
    with pytest.raises(LLMConfigurationError):
        get_embedder(_settings(EMBEDDING_PROVIDER="cloudflare_workers_ai", LLM_ALLOW_EXTERNAL_PROVIDER=False))


def test_the_daily_budget_is_shared_by_every_provider_instance_because_the_app_builds_one_per_request():
    from app.modules.ai.providers.cloudflare import provider as cf

    cf.reset_budget_for_tests()
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return _ok(neurons=400.0)

    clock = lambda: datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)  # noqa: E731
    asyncio.run(_provider(handler, daily_neuron_limit=700, clock=clock).generate(_request()))
    asyncio.run(_provider(handler, daily_neuron_limit=700, clock=clock).generate(_request()))
    with pytest.raises(LLMConnectionError):
        asyncio.run(_provider(handler, daily_neuron_limit=700, clock=clock).generate(_request()))
    assert len(calls) == 2, "a brand new provider instance must still see what earlier instances spent"
    cf.reset_budget_for_tests()
