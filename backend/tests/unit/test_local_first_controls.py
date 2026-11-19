"""
Task 2: local-first controls, explicit provider selection, AI-disabled mode and the offline/egress boundary.

Everything runs against the REAL factory, dependencies, services and API with scripted or mocked transports. No Ollama, no network, no model download.
What this does NOT prove: actual packet-level silence of a running deployment (only the guarded Python HTTP/DNS seams are observed), behaviour of a
real Ollama daemon, or third-party library telemetry.
"""

from __future__ import annotations

import ast
import asyncio
import json
import socket
from pathlib import Path
from typing import Any

import httpx
import pytest
from loguru import logger

import app.modules.ai.llm.manager as manager
from app.core.config import Settings
from app.modules.ai.embeddings.embedder import OllamaEmbedder
from app.modules.ai.llm.exceptions import (
    LLMConfigurationError,
    LLMConnectionError,
    LLMDisabledError,
    LLMError,
    LLMModelNotFoundError,
    LLMTimeoutError,
)
from app.modules.ai.llm.inert import InertLLMProvider
from app.modules.ai.llm.locality import assert_endpoint_allowed
from app.modules.ai.llm.manager import get_llm_provider, get_llm_provider_or_inert
from app.modules.ai.providers.ollama.provider import OllamaProvider
from app.modules.correlation.demo_data import intrusion_chain
from app.schemas.ai import LLMMessage, LLMRequest, LLMResponse, TokenUsage
from tests.unit.test_case_synthesis_api import app_instance, auth_settings  # noqa: F401  (fixtures)
from tests.unit.test_multisource_api import START, Keep, ScriptedProvider, bearer, setup

SECRET = "sk-TASK2-SECRET-VALUE-123456"
REQ = LLMRequest(messages=[LLMMessage(role="system", content="s"), LLMMessage(role="user", content="u")])


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def clean_env(monkeypatch):
    for name in ("LLM_PROVIDER", "LLM_ENABLED", "LLM_ALLOW_NON_LOCAL_ENDPOINT", "OLLAMA_BASE_URL", "OLLAMA_MODEL", "OLLAMA_MAX_RETRIES"):
        monkeypatch.delenv(name, raising=False)


def fresh(**kw: Any) -> Settings:
    return Settings(_env_file=None, **kw)


class Egress:
    """Every httpx request that leaves the in-process test app and every DNS lookup is recorded and refused."""

    def __init__(self) -> None:
        self.http: list[str] = []
        self.dns: list[str] = []


@pytest.fixture
def egress(monkeypatch) -> Egress:
    rec = Egress()
    real_send = httpx.AsyncClient.send

    async def guarded_send(self, request, *a, **k):
        if not isinstance(self._transport_for_url(request.url), httpx.ASGITransport):   # only the in-process ASGI test client is exempt (by transport type, not by host name)
            rec.http.append(f"{request.method} {request.url.host}")
            raise httpx.ConnectError("egress blocked by test guard")
        return await real_send(self, request, *a, **k)

    def guarded_sync_send(self, request, *a, **k):
        rec.http.append(f"{request.method} {request.url.host}")
        raise httpx.ConnectError("egress blocked by test guard")

    def guarded_dns(host, *a, **k):
        rec.dns.append(str(host))
        raise OSError("dns blocked by test guard")

    monkeypatch.setattr(httpx.AsyncClient, "send", guarded_send)
    monkeypatch.setattr(httpx.Client, "send", guarded_sync_send)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_dns)
    return rec


# ── defaults and explicit selection ──────────────────────────────────────────────────────────────────
def test_fresh_defaults_are_local_first(clean_env):
    s = fresh()
    assert s.LLM_PROVIDER == "ollama" and s.LLM_ENABLED is True and s.LLM_ALLOW_NON_LOCAL_ENDPOINT is False
    assert s.OLLAMA_BASE_URL.startswith("http://localhost")
    assert not s.VIRUSTOTAL_API_KEY and not s.ABUSEIPDB_API_KEY and not s.ALIENVAULT_OTX_API_KEY
    assert 1 <= s.OLLAMA_MAX_RETRIES <= 10 and 0 < s.OLLAMA_TIMEOUT_SECONDS <= 600                  # bounded retries and timeout
    p = get_llm_provider(s)
    assert isinstance(p, OllamaProvider) and p._base_url.startswith("http://localhost")


def test_provider_is_never_inferred_from_api_keys_or_foreign_env(clean_env, monkeypatch):
    for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "AZURE_OPENAI_API_KEY"):
        monkeypatch.setenv(k, SECRET)
    s = Settings(_env_file=None)
    assert s.LLM_PROVIDER == "ollama" and isinstance(get_llm_provider(s), OllamaProvider)
    for name in ("openai", "anthropic", "OpenAI ", "gemini", "ollama-cloud"):
        with pytest.raises(LLMError) as ei:
            get_llm_provider(fresh(LLM_PROVIDER=name))
        assert SECRET not in str(ei.value) and "Unsupported LLM provider" in str(ei.value)          # unknown provider fails closed, no fallback


@pytest.mark.anyio
async def test_remote_provider_config_present_but_not_selected_makes_no_call(clean_env, monkeypatch, egress):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.example/v1")
    provider = get_llm_provider(Settings(_env_file=None))
    with pytest.raises(LLMError):
        await provider.generate(REQ)                                                                  # the guard refuses; it only records the target host
    assert egress.http and all(h.endswith("localhost") for h in egress.http)                         # only the selected local endpoint was ever addressed
    assert not any("openai" in h for h in egress.http + egress.dns)


@pytest.mark.parametrize("url", ["http://gpu-server:11434", "https://api.example.com", "http://10.0.0.5:11434", "http://localhost.evil.example:11434"])
def test_non_local_endpoints_fail_closed_unless_explicitly_allowed(url):
    with pytest.raises(LLMConfigurationError) as ei:
        get_llm_provider(fresh(OLLAMA_BASE_URL=url))
    assert url not in str(ei.value) and "LLM_ALLOW_NON_LOCAL_ENDPOINT" in str(ei.value)
    assert isinstance(get_llm_provider(fresh(OLLAMA_BASE_URL=url, LLM_ALLOW_NON_LOCAL_ENDPOINT=True)), OllamaProvider)


@pytest.mark.parametrize("url", ["http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434", "http://127.0.0.7:11434", "http://LOCALHOST:11434"])
def test_loopback_endpoints_are_accepted(url):
    assert_endpoint_allowed(url, False)


@pytest.mark.parametrize("url", [f"http://user:{SECRET}@localhost:11434", "ftp://localhost", "localhost:11434", "http://", "http://localhost:notaport"])
def test_invalid_or_credentialed_endpoints_are_rejected_even_when_non_local_is_allowed_and_never_echoed(url):
    sink: list[str] = []
    hid = logger.add(lambda m: sink.append(str(m)), level="DEBUG")
    try:
        with pytest.raises(LLMConfigurationError) as ei:
            get_llm_provider(fresh(OLLAMA_BASE_URL=url, LLM_ALLOW_NON_LOCAL_ENDPOINT=True))
    finally:
        logger.remove(hid)
    assert SECRET not in str(ei.value) and SECRET not in "".join(sink)


def test_embedder_shares_the_local_first_guard():
    with pytest.raises(LLMConfigurationError):
        OllamaEmbedder(fresh(OLLAMA_BASE_URL="http://gpu-server:11434"))
    OllamaEmbedder(fresh())


@pytest.mark.anyio
async def test_misconfiguration_yields_an_inert_provider_never_another_provider():
    for s in (fresh(LLM_PROVIDER="openai"), fresh(OLLAMA_BASE_URL="http://gpu-server:11434")):
        p = get_llm_provider_or_inert(s)
        assert isinstance(p, InertLLMProvider)
        with pytest.raises(LLMConfigurationError):
            await p.generate(REQ)


# ── AI disabled ──────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_disabled_builds_no_client_and_makes_no_call(monkeypatch, egress):
    monkeypatch.setattr(OllamaProvider, "__init__", lambda *a, **k: (_ for _ in ()).throw(AssertionError("Ollama provider constructed")))
    p = get_llm_provider(fresh(LLM_ENABLED=False))
    assert isinstance(p, InertLLMProvider) and p.is_inert
    with pytest.raises(LLMDisabledError):
        await p.generate(REQ)
    assert (await p.health()).status == "unavailable"
    assert egress.http == [] and egress.dns == []


@pytest.mark.anyio
async def test_readiness_reports_disabled_without_probing_the_provider(monkeypatch):
    import app.api.v1.endpoints.health as health

    async def ok_db(*a, **k):
        return {"status": "ok"}, True

    monkeypatch.setattr(health, "get_settings", lambda: fresh(LLM_ENABLED=False))
    monkeypatch.setattr(health, "_probe_database", ok_db)
    monkeypatch.setattr(health, "get_llm_provider", lambda *a, **k: (_ for _ in ()).throw(AssertionError("provider probed while AI disabled")))
    body = await health.get_readiness(session=None)
    assert body["status"] == "ok" and body["checks"]["llm_provider"]["status"] == "disabled"


def test_retrieval_dependency_is_off_when_ai_is_disabled(monkeypatch):
    import app.api.dependencies as deps

    sentinel = object()

    class State:
        knowledge_retriever = sentinel

    class App:
        state = State

    class Req:
        app = App

    monkeypatch.setattr(deps, "get_settings", lambda: fresh(LLM_ENABLED=False))
    assert deps.get_knowledge_retriever(Req) is None
    monkeypatch.setattr(deps, "get_settings", lambda: fresh())
    assert deps.get_knowledge_retriever(Req) is sentinel


# ── local provider failure modes (mocked transport, no daemon) ────────────────────────────────────────
def _provider(handler, retries: int = 3) -> tuple[OllamaProvider, list[str]]:
    seen: list[str] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url.host}{request.url.path}")
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(wrapped))
    return OllamaProvider(base_url="http://localhost:11434", model="m:1", timeout_seconds=5, max_retries=retries, client=client), seen


@pytest.fixture
def fast_sleep(monkeypatch):
    async def instant(*a, **k):
        return None

    monkeypatch.setattr(asyncio, "sleep", instant)


@pytest.mark.anyio
async def test_unavailable_daemon_is_bounded_local_only_and_typed(fast_sleep):
    def refuse(request):
        raise httpx.ConnectError("refused")

    p, seen = _provider(refuse, retries=3)
    with pytest.raises(LLMConnectionError):
        await p.generate(REQ)
    assert len(seen) == 3 and all(s.split()[1].startswith("localhost") for s in seen)                # exactly max_retries attempts, never another host


@pytest.mark.anyio
async def test_missing_model_is_a_typed_error_and_no_pull_is_attempted(fast_sleep):
    p, seen = _provider(lambda r: httpx.Response(404, json={"error": "model not found"}))
    with pytest.raises(LLMModelNotFoundError):
        await p.generate(REQ)
    assert len(seen) == 1 and not any("/api/pull" in s or "/api/create" in s for s in seen)


@pytest.mark.anyio
async def test_timeout_is_typed_and_not_retried_uncontrollably(fast_sleep):
    def slow(request):
        raise httpx.ReadTimeout("slow")

    p, seen = _provider(slow, retries=3)
    with pytest.raises(LLMTimeoutError):
        await p.generate(REQ)
    assert len(seen) <= 3


# ── real API: AI off / on / unavailable / malformed keep the deterministic result identical ───────────
def _stable(inc: dict[str, Any]) -> dict[str, Any]:
    suff = json.loads(json.dumps(inc["sufficiency"]))
    suff.get("rationale", {}).get("status", {}).pop("llm_status", None)
    return {"timeline": inc["timeline"], "mitre": inc["mitre"], "sufficiency": suff, "context_sha256": inc["context_sha256"],
            "severity": inc["severity"], "event_count": inc["event_count"], "link_counts": inc["link_counts"]}


class Garbage:
    model_name = "llama3.1:8b"

    async def generate(self, request):
        return LLMResponse(content="}{ not json", model=self.model_name, usage=TokenUsage())


class RaisingConnect:
    model_name = "llama3.1:8b"

    async def generate(self, request):
        raise LLMConnectionError("daemon down")


@pytest.mark.anyio
async def test_deterministic_fields_are_identical_across_ai_modes_through_the_api(db_session, app_instance, monkeypatch, egress):
    from app.api.v1.endpoints.cases import get_case_llm_provider

    scripted = ScriptedProvider()
    client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), provider=scripted, prefix="lf1")
    results: dict[str, dict[str, Any]] = {}
    async with Keep(client):
        results["off"] = (await client.post(START.format(cid=case.id), json={}, headers=bearer(token))).json()["incidents"][0]
        assert scripted.calls == 0
        for name, prov in (("on", scripted), ("malformed", Garbage()), ("unavailable", RaisingConnect())):
            app_instance.dependency_overrides[get_case_llm_provider] = lambda p=prov: p
            r = await client.post(START.format(cid=case.id), json={"use_llm": True, "force": True}, headers=bearer(token))
            assert r.status_code == 201, r.text
            results[name] = r.json()["incidents"][0]
        # AI disabled through the REAL dependency (no override): real factory -> inert provider
        app_instance.dependency_overrides.pop(get_case_llm_provider, None)
        monkeypatch.setattr(manager, "get_settings", lambda: fresh(LLM_ENABLED=False))
        r = await client.post(START.format(cid=case.id), json={"use_llm": True, "force": True}, headers=bearer(token))
        assert r.status_code == 201, r.text
        results["disabled"] = r.json()["incidents"][0]
    assert results["disabled"]["llm_status"] == "disabled" and results["off"]["llm_status"] == "not_requested"
    assert results["unavailable"]["llm_status"].startswith("fallback:") and results["on"]["llm_status"] == "validated"
    assert results["malformed"]["llm_status"].startswith("fallback:")
    base = _stable(results["off"])
    for name, inc in results.items():
        assert _stable(inc) == base, f"deterministic fields changed in mode {name}"                  # AI status and narrative are the only fields allowed to vary
    assert egress.http == [] and egress.dns == []                                                    # no outbound HTTP or DNS from any covered mode


@pytest.mark.anyio
async def test_several_investigations_with_ai_disabled_make_no_calls_and_do_not_crash(db_session, app_instance, monkeypatch, egress):
    monkeypatch.setattr(manager, "get_settings", lambda: fresh(LLM_ENABLED=False))
    statuses = []
    for i in range(3):
        client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain() if i == 0 else [], prefix=f"lfm{i}")
        async with Keep(client):
            r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
            assert r.status_code == 201, r.text
            statuses.append(r.json()["status"])
    assert statuses == ["completed"] * 3 and egress.http == [] and egress.dns == []


@pytest.mark.anyio
async def test_secrets_never_reach_api_errors_or_logs(db_session, app_instance, monkeypatch, egress):
    monkeypatch.setattr(manager, "get_settings", lambda: fresh(OLLAMA_BASE_URL=f"http://user:{SECRET}@gpu-server:11434", VIRUSTOTAL_API_KEY=SECRET))
    sink: list[str] = []
    hid = logger.add(lambda m: sink.append(str(m)), level="DEBUG")
    try:
        client, token, _lead, case = await setup(db_session, app_instance, intrusion_chain(), prefix="lfs")
        async with Keep(client):
            r = await client.post(START.format(cid=case.id), json={"use_llm": True}, headers=bearer(token))
    finally:
        logger.remove(hid)
    assert r.status_code == 201 and r.json()["incidents"][0]["llm_status"] == "fallback:LLMConfigurationError"
    assert SECRET not in r.text and SECRET not in "".join(sink) and egress.http == []


# ── threat intelligence stays separate and inert by default ──────────────────────────────────────────
def test_remote_ti_providers_are_never_constructed_by_application_code():
    root = Path(__file__).resolve().parents[2] / "app"
    names = {"VirusTotalProvider", "AbuseIPDBProvider", "AlienVaultOTXProvider", "MISPProvider", "ThreatIntelOrchestrator"}
    offenders = []
    for path in root.rglob("*.py"):
        if "threatintel" in path.parts:                                                              # the provider packages themselves
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                f = node.func
                n = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
                if n in names:
                    offenders.append(f"{path.name}:{n}")
    assert offenders == [], offenders


def test_no_concrete_remote_ti_provider_exists_in_the_codebase():
    """The VirusTotal/AbuseIPDB/OTX/MISP packages are empty: only the abstract base exists, so no remote TI call is reachable today."""
    root = Path(__file__).resolve().parents[2] / "app"
    concrete = []
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ClassDef) and any(getattr(b, "id", getattr(b, "attr", "")) == "BaseThreatIntelProvider" for b in node.bases):
                concrete.append(f"{path.name}:{node.name}")
    assert concrete == [], concrete


@pytest.mark.anyio
async def test_unconfigured_ti_provider_makes_no_request(egress):
    """If a provider is ever added, the base class refuses to send anything without explicitly configured credentials."""
    from app.modules.threatintel.base import BaseThreatIntelProvider
    from app.modules.threatintel.models import ObservableType, ThreatIntelRequest

    class Probe(BaseThreatIntelProvider):
        provider_name = "probe"
        supported_observable_types = frozenset(ObservableType)

        async def _execute_lookup(self, observable, client):  # pragma: no cover - must never run
            raise AssertionError("lookup executed without credentials")

    p = Probe(api_key="")
    assert p.has_credentials is False
    result = await p.lookup(ThreatIntelRequest(observable="198.51.100.9", observable_type="ipv4"))
    assert result.status.value != "success" and egress.http == [] and egress.dns == []
