"""
Concurrent model calls are capped (OWASP API4, unrestricted resource consumption): a local CPU model serves one
request at a time, so extra callers wait instead of all running together and all timing out. No network.
"""

from __future__ import annotations

import asyncio

import httpx

from app.core.config import Settings
from app.modules.ai.llm import manager as _manager  # noqa: F401  (imported first, as the other provider tests do)
from app.modules.ai.providers.ollama import provider as provider_module
from app.modules.ai.providers.ollama.provider import OllamaProvider
from app.schemas.ai import LLMMessage, LLMRequest, MessageRole


def _request() -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role=MessageRole.USER, content="hi")], model="qwen3:4b", max_tokens=64, json_mode=True)


async def _peak_in_flight(callers: int) -> int:
    state = {"now": 0, "peak": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(0.05)
        state["now"] -= 1
        return httpx.Response(200, json={"message": {"content": "{}"}, "done": True, "done_reason": "stop"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        # A new provider per call, as the application does, so the cap must be shared across instances.
        await asyncio.gather(*[OllamaProvider(model="qwen3:4b", client=client).generate(_request()) for _ in range(callers)])
    return state["peak"]


def test_default_setting_allows_one_model_call_at_a_time():
    assert Settings(_env_file=None).LLM_MAX_CONCURRENCY == 1


def test_four_simultaneous_calls_reach_the_model_one_at_a_time(monkeypatch):
    monkeypatch.setattr(provider_module, "_configured_limit", lambda: 1)
    assert asyncio.run(_peak_in_flight(4)) == 1


def test_a_higher_configured_limit_is_honoured(monkeypatch):
    monkeypatch.setattr(provider_module, "_configured_limit", lambda: 2)
    assert asyncio.run(_peak_in_flight(4)) == 2
