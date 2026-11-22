"""
AI latency pins for the Ollama provider (docs/06_AI/AI_Latency.md): the optional context window and keep-alive reach
the request, and the default payload is unchanged when they are not configured. No network: payload construction only.
"""

from __future__ import annotations

import asyncio

import httpx

from app.core.config import Settings
from app.modules.ai.llm.manager import get_llm_provider
from app.modules.ai.providers.ollama.provider import OllamaProvider
from app.schemas.ai import LLMMessage, LLMRequest, MessageRole


def _request() -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role=MessageRole.USER, content="hello")], model="qwen3:4b", max_tokens=1024, json_mode=True)


def test_default_payload_has_no_num_ctx_and_keeps_the_model_loaded():
    payload = OllamaProvider(model="qwen3:4b", keep_alive="30m")._build_payload(_request())
    assert "num_ctx" not in payload["options"]
    assert payload["keep_alive"] == "30m" and payload["options"]["num_predict"] == 1024 and payload["think"] is False


def test_configured_num_ctx_is_sent_as_an_option():
    payload = OllamaProvider(model="qwen3:4b", num_ctx=3072)._build_payload(_request())
    assert payload["options"]["num_ctx"] == 3072


def test_settings_default_window_is_8192_and_the_factory_passes_a_configured_one_through():
    assert Settings(_env_file=None).OLLAMA_NUM_CTX == 8192  # the default window holds the whole prompt; see test_ollama_truncation_guard
    cfg = Settings(_env_file=None, OLLAMA_NUM_CTX=3072, LLM_ENABLED=True)
    provider = get_llm_provider(cfg)
    assert provider._build_payload(_request())["options"]["num_ctx"] == 3072


def test_a_single_call_is_made_for_a_valid_response_and_latency_fields_are_tolerated():
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append({"url": str(request.url)})
        return httpx.Response(200, json={
            "message": {"content": "{}"}, "done": True, "done_reason": "stop", "prompt_eval_count": 2000, "eval_count": 500,
            "total_duration": 60_000_000_000, "load_duration": 10_000_000, "prompt_eval_duration": 900_000_000, "eval_duration": 59_000_000_000,
        })

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await OllamaProvider(model="qwen3:4b", num_ctx=2048, client=client).generate(_request())

    response = asyncio.run(run())
    assert len(calls) == 1 and response.usage.prompt_tokens == 2000 and response.usage.completion_tokens == 500
