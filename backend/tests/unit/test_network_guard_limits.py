"""
Task 2 acceptance: what the httpx/DNS test guard can and cannot see, and what the application itself does about redirects.

Mocked transports only: no real network, no real redirect target is ever contacted.
Findings encoded here (see the acceptance report, 02_NETWORK_GUARD_COVERAGE_AND_LIMITATIONS.md):
  * the application never enables ``follow_redirects`` (httpx default is off), so a 3xx from the model endpoint is an error, never a hop;
  * a guard installed at ``httpx.AsyncClient.send`` sees ONLY the initial request: redirect hops are issued below ``send`` (documented blind spot).
"""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest

from app.core.config import Settings
from app.modules.ai.embeddings.embedder import OllamaEmbedder
from app.modules.ai.llm.exceptions import LLMError
from app.modules.ai.providers.ollama.provider import OllamaProvider
from app.schemas.ai import LLMMessage, LLMRequest
from app.modules.ai.embeddings.exceptions import EmbeddingError

REQ = LLMRequest(messages=[LLMMessage(role="system", content="s"), LLMMessage(role="user", content="u")])
EVIL = "http://redirect-target.invalid/"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_application_code_never_enables_automatic_redirect_following():
    root = Path(__file__).resolve().parents[2] / "app"
    offenders = []
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.keyword) and node.arg == "follow_redirects":
                offenders.append(f"{path.name}:{getattr(node.value, 'value', '?')}")
    assert offenders == [], offenders                                              # httpx default (False) applies everywhere


def _redirecting(seen: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(302, headers={"Location": EVIL}) if request.url.host == "localhost" else httpx.Response(200, json={})
    return httpx.MockTransport(handler)


@pytest.mark.anyio
async def test_chat_provider_does_not_follow_a_redirect_to_a_non_loopback_host():
    seen: list[str] = []
    p = OllamaProvider(base_url="http://localhost:11434", model="m:1", timeout_seconds=5, max_retries=1,
                       client=httpx.AsyncClient(transport=_redirecting(seen)))
    with pytest.raises(LLMError):
        await p.generate(REQ)
    assert seen == ["localhost"]                                                   # the redirect target was never contacted


@pytest.mark.anyio
async def test_embedder_does_not_follow_a_redirect_to_a_non_loopback_host():
    seen: list[str] = []
    e = OllamaEmbedder(Settings(_env_file=None), client=httpx.AsyncClient(transport=_redirecting(seen)))
    with pytest.raises(EmbeddingError):
        await e.embed("text")
    assert seen and set(seen) == {"localhost"}                                     # possibly retried against localhost only; never the target


@pytest.mark.anyio
async def test_send_level_guard_sees_only_the_initial_request_when_a_client_follows_redirects(monkeypatch):
    """Documents the blind spot: a guard at ``send`` cannot observe redirect hops of a client that follows redirects (the project's clients do not)."""
    guard_saw: list[str] = []
    real_send = httpx.AsyncClient.send

    async def recording_send(self, request, *a, **k):
        guard_saw.append(request.url.host)
        return await real_send(self, request, *a, **k)

    monkeypatch.setattr(httpx.AsyncClient, "send", recording_send)
    transport_saw: list[str] = []
    async with httpx.AsyncClient(transport=_redirecting(transport_saw), follow_redirects=True) as client:
        await client.get("http://localhost:11434/api/tags")
    assert guard_saw == ["localhost"]                                              # the guard saw one request
    assert transport_saw == ["localhost", "redirect-target.invalid"]               # the transport served two: the hop was invisible to the guard
