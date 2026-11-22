"""
A prompt larger than the model's context window is silently cut by Ollama (it keeps the last half of the window), so the
model answers without its instructions or most of the evidence. The provider must fail closed instead of returning that
answer, so the pipeline falls back to the deterministic result with a clear reason. No network.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.core.config import Settings
from app.modules.ai.llm import manager as _manager  # noqa: F401  (imported first, as the other provider tests do)
from app.modules.ai.llm.exceptions import LLMResponseError
from app.modules.ai.providers.ollama.provider import OllamaProvider
from app.schemas.ai import LLMMessage, LLMRequest, MessageRole


def _request(chars: int) -> LLMRequest:
    return LLMRequest(messages=[LLMMessage(role=MessageRole.USER, content="x" * chars)], model="qwen3:4b", max_tokens=64, json_mode=True)


def _generate(prompt_chars: int, prompt_tokens: int, num_ctx: int | None):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": "{}"}, "done": True, "done_reason": "stop",
                                         "prompt_eval_count": prompt_tokens, "eval_count": 100})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await OllamaProvider(model="qwen3:4b", num_ctx=num_ctx, client=client).generate(_request(prompt_chars))

    return asyncio.run(run())


def test_the_exact_truncation_signature_for_the_configured_window_is_refused():
    # Measured: a 5366 token prompt with num_ctx 3072 was read as 1538 tokens (half the window plus 2).
    with pytest.raises(LLMResponseError) as exc:
        _generate(prompt_chars=14_229, prompt_tokens=3072 // 2 + 2, num_ctx=3072)
    assert "context window" in str(exc.value) and "OLLAMA_NUM_CTX" in str(exc.value)


def test_a_prompt_far_smaller_than_its_text_is_refused_even_when_the_window_is_unknown():
    # Measured with the model's own default window: 14 229 characters read as 2 050 tokens.
    with pytest.raises(LLMResponseError):
        _generate(prompt_chars=14_229, prompt_tokens=2_050, num_ctx=None)


def test_a_prompt_that_fits_is_returned_unchanged():
    response = _generate(prompt_chars=14_229, prompt_tokens=5_366, num_ctx=8_192)
    assert response.usage.prompt_tokens == 5_366 and response.content == "{}"


def test_short_and_ordinary_prompts_are_not_false_positives():
    assert _generate(prompt_chars=5, prompt_tokens=3, num_ctx=2_048).usage.prompt_tokens == 3
    assert _generate(prompt_chars=4_000, prompt_tokens=1_100, num_ctx=None).usage.prompt_tokens == 1_100


def test_default_context_window_covers_the_whole_prompt_the_application_builds():
    # The application's prompts are about 5 400 tokens; the window must hold them plus the output ceiling.
    assert Settings(_env_file=None).OLLAMA_NUM_CTX is not None and Settings(_env_file=None).OLLAMA_NUM_CTX >= 8192
