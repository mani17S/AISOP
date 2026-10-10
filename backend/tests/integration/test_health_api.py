"""
Integration tests for AISOP Health endpoints.

GET /api/v1/health        — Liveness check
GET /api/v1/health/ready  — Readiness check (database + LLM provider probes)

Follows the established project patterns:
- httpx.ASGITransport for endpoint-level testing
- app.dependency_overrides to inject the in-memory SQLite session
- httpx.MockTransport to control OllamaProvider HTTP responses (P2-H1 pattern)
"""

from __future__ import annotations

import httpx
import pytest
from app.db.session import get_db_session
from app.main import app
from app.modules.ai.providers.ollama.provider import OllamaProvider


# ── Shared fixture ─────────────────────────────────────────────────────────────

@pytest.fixture
def test_app(db_session):
    """Override the database dependency with the isolated in-memory SQLite session."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_get_db
    yield app
    app.dependency_overrides.clear()


# ── Helper ─────────────────────────────────────────────────────────────────────

def _ollama_transport(status_code: int, body: dict) -> httpx.MockTransport:
    """Return a MockTransport that always responds with the given status and JSON body."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=body)

    return httpx.MockTransport(handler)


def _ollama_connect_error_transport() -> httpx.MockTransport:
    """Return a MockTransport that always raises ConnectError (daemon down)."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    return httpx.MockTransport(handler)


# ── Liveness tests  (GET /api/v1/health) ──────────────────────────────────────

class TestLivenessEndpoint:
    @pytest.mark.anyio
    async def test_returns_200(self, test_app):
        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health")
        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_response_shape(self, test_app):
        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            data = (await client.get("/api/v1/health")).json()
        assert data["status"] == "ok"
        assert data["app"] == "AISOP"
        assert data["version"] == "0.1.0"
        assert "environment" in data

    @pytest.mark.anyio
    async def test_does_not_require_database(self, test_app):
        """Liveness must never touch the database — it is a pure process check."""
        # Remove the DB override so any accidental DB call would use the real engine
        # and almost certainly fail in the test environment.
        app.dependency_overrides.clear()
        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health")
        assert response.status_code == 200


# ── Readiness tests  (GET /api/v1/health/ready) ───────────────────────────────

class TestReadinessEndpoint:
    @pytest.mark.anyio
    async def test_all_ok_when_db_and_provider_healthy(self, test_app, monkeypatch):
        """HTTP 200 when both the database and LLM provider are healthy."""
        healthy_transport = _ollama_transport(
            200,
            {"models": [{"name": "llama3.1:8b"}]},
        )
        provider = OllamaProvider(
            client=httpx.AsyncClient(transport=healthy_transport)
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.health.get_llm_provider", lambda s=None: provider
        )

        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["checks"]["database"]["status"] == "ok"
        assert data["checks"]["llm_provider"]["status"] == "healthy"

    @pytest.mark.anyio
    async def test_503_when_provider_unavailable(self, test_app, monkeypatch):
        """HTTP 503 when the LLM daemon is unreachable; database check still shown as ok."""
        provider = OllamaProvider(
            client=httpx.AsyncClient(transport=_ollama_connect_error_transport())
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.health.get_llm_provider", lambda s=None: provider
        )

        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        assert detail["checks"]["database"]["status"] == "ok"
        assert detail["checks"]["llm_provider"]["status"] == "unavailable"

    @pytest.mark.anyio
    async def test_200_when_provider_degraded(self, test_app, monkeypatch):
        """HTTP 200 (not 503) when provider is reachable but the target model is not pulled.

        'degraded' means Ollama is up but the model tag is missing.  The service
        is still operational (the operator can pull the model), so we do not
        block traffic with a 503 — we surface the detail in the response body.
        """
        degraded_transport = _ollama_transport(
            200,
            {"models": [{"name": "mistral:7b"}]},   # llama3.1:8b is absent
        )
        provider = OllamaProvider(
            model="llama3.1:8b",
            client=httpx.AsyncClient(transport=degraded_transport),
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.health.get_llm_provider", lambda s=None: provider
        )

        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        # Degraded provider does NOT trigger 503 — service can still operate
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["checks"]["llm_provider"]["status"] == "degraded"

    @pytest.mark.anyio
    async def test_response_contains_provider_metadata(self, test_app, monkeypatch):
        """Response body includes provider name, model tag, and latency_ms."""
        healthy_transport = _ollama_transport(
            200,
            {"models": [{"name": "llama3.1:8b"}]},
        )
        provider = OllamaProvider(
            client=httpx.AsyncClient(transport=healthy_transport)
        )
        monkeypatch.setattr(
            "app.api.v1.endpoints.health.get_llm_provider", lambda s=None: provider
        )

        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            data = (await client.get("/api/v1/health/ready")).json()

        llm = data["checks"]["llm_provider"]
        assert llm["provider"] == "ollama"
        assert llm["model"] == "llama3.1:8b"
        assert isinstance(llm["latency_ms"], float)
