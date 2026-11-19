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

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from app.db.session import get_db_session
from app.main import app
from app.modules.ai.providers.ollama.provider import OllamaProvider
from sqlalchemy.ext.asyncio import AsyncSession


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


# ── Mock Session Helpers for Deep Database Readiness ──────────────────────────

def _mock_postgres_session(
    *,
    select_1_exc: Exception | None = None,
    pg_extension_row: tuple | None = ("vector", "0.8.0"),
    pg_extension_exc: Exception | None = None,
    table_exists: bool = True,
    col_row: tuple | None = ("embedding", 768, "vector"),
) -> AsyncMock:
    """Build a mock AsyncSession that simulates PostgreSQL engine and catalog responses."""
    mock_session = AsyncMock(spec=AsyncSession)
    mock_bind = MagicMock()
    mock_bind.dialect.name = "postgresql"
    mock_session.bind = mock_bind

    if select_1_exc is not None:
        mock_session.execute.side_effect = select_1_exc
        return mock_session

    if pg_extension_exc is not None:
        res1 = MagicMock()
        mock_session.execute.side_effect = [res1, pg_extension_exc]
        return mock_session

    res1 = MagicMock()  # SELECT 1

    res2 = MagicMock()  # pg_extension query
    if pg_extension_row is not None:
        ext_row_mock = MagicMock()
        ext_row_mock.__getitem__.side_effect = lambda idx: pg_extension_row[idx]
        ext_row_mock.extversion = pg_extension_row[1]
        res2.first.return_value = ext_row_mock
    else:
        res2.first.return_value = None

    res3 = MagicMock()  # table existence query
    res3.scalar.return_value = table_exists

    res4 = MagicMock()  # column query
    if col_row is not None:
        col_row_mock = MagicMock()
        col_row_mock.__getitem__.side_effect = lambda idx: col_row[idx]
        col_row_mock.attname = col_row[0]
        col_row_mock.atttypmod = col_row[1]
        col_row_mock.typname = col_row[2]
        res4.first.return_value = col_row_mock
    else:
        res4.first.return_value = None

    mock_session.execute.side_effect = [res1, res2, res3, res4]
    return mock_session


def _mock_sqlite_session(
    *,
    select_1_exc: Exception | None = None,
    table_exists: bool = True,
    schema_exc: Exception | None = None,
) -> AsyncMock:
    """Build a mock AsyncSession that simulates SQLite engine responses."""
    mock_session = AsyncMock(spec=AsyncSession)
    mock_bind = MagicMock()
    mock_bind.dialect.name = "sqlite"
    mock_session.bind = mock_bind

    if select_1_exc is not None:
        mock_session.execute.side_effect = select_1_exc
        return mock_session

    if schema_exc is not None:
        res1 = MagicMock()
        mock_session.execute.side_effect = [res1, schema_exc]
        return mock_session

    res1 = MagicMock()
    res2 = MagicMock()
    res2.first.return_value = ("knowledge_embeddings",) if table_exists else None
    mock_session.execute.side_effect = [res1, res2]
    return mock_session


# ── Deep Database & pgvector Readiness Tests (REQ-14.3) ──────────────────────

class TestDeepDatabaseReadinessEndpoint:
    """
    Verifies deep database and pgvector readiness checks (Milestone P4-HARDENING-03 / REQ-14.3).
    Ensures:
    - PostgreSQL connectivity, vector extension, knowledge schema, and dimension checks.
    - Graceful error reporting without credential/internal leakages.
    - SQLite test/development fallback semantics.
    """

    def _setup_healthy_ollama(self, monkeypatch):
        healthy_transport = _ollama_transport(200, {"models": [{"name": "llama3.1:8b"}]})
        provider = OllamaProvider(client=httpx.AsyncClient(transport=healthy_transport))
        monkeypatch.setattr("app.api.v1.endpoints.health.get_llm_provider", lambda s=None: provider)

    @pytest.mark.anyio
    async def test_postgres_reachable_and_pgvector_healthy(self, test_app, monkeypatch):
        """HTTP 200 when PostgreSQL is reachable, pgvector extension exists, and schema matches."""
        self._setup_healthy_ollama(monkeypatch)
        mock_session = _mock_postgres_session(
            pg_extension_row=("vector", "0.8.0"),
            table_exists=True,
            col_row=("embedding", 768, "vector"),
        )

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        db = data["checks"]["database"]
        assert db["status"] == "ok"
        assert db["engine"] == "postgresql"
        assert db["pgvector"]["status"] == "ok"
        assert db["pgvector"]["installed"] is True
        assert db["pgvector"]["version"] == "0.8.0"
        assert db["schema"]["status"] == "ok"
        assert db["schema"]["table"] == "knowledge_embeddings"
        assert db["schema"]["dimension"] == 768

    @pytest.mark.anyio
    async def test_database_unreachable_returns_503_without_leaking_secrets(self, test_app, monkeypatch):
        """HTTP 503 when DB connection fails; verifies zero internal credential leakage."""
        self._setup_healthy_ollama(monkeypatch)
        sensitive_error = Exception(
            "FATAL: password authentication failed for user 'aisop_admin' password=secret_password_123 host=192.168.1.50"
        )
        mock_session = _mock_postgres_session(select_1_exc=sensitive_error)

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        db = detail["checks"]["database"]
        assert db["status"] == "error"
        assert db["detail"] == "Database connection unreachable"

        # Verify no secret or internal IP leaked into HTTP response body
        assert "secret_password_123" not in response.text
        assert "aisop_admin" not in response.text
        assert "192.168.1.50" not in response.text

    @pytest.mark.anyio
    async def test_postgres_reachable_but_vector_extension_missing(self, test_app, monkeypatch):
        """HTTP 503 when PostgreSQL is connected but the 'vector' extension is not installed."""
        self._setup_healthy_ollama(monkeypatch)
        mock_session = _mock_postgres_session(pg_extension_row=None)

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        db = detail["checks"]["database"]
        assert db["status"] == "error"
        assert db["pgvector"]["status"] == "error"
        assert db["pgvector"]["installed"] is False
        assert db["detail"] == "PostgreSQL vector extension missing"

    @pytest.mark.anyio
    async def test_postgres_reachable_but_knowledge_schema_missing(self, test_app, monkeypatch):
        """HTTP 503 when PostgreSQL and pgvector exist, but 'knowledge_embeddings' table is absent."""
        self._setup_healthy_ollama(monkeypatch)
        mock_session = _mock_postgres_session(
            pg_extension_row=("vector", "0.8.0"),
            table_exists=False,
        )

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        db = detail["checks"]["database"]
        assert db["status"] == "error"
        assert db["pgvector"]["status"] == "ok"
        assert db["schema"]["status"] == "error"
        assert db["detail"] == "Knowledge embedding schema missing"

    @pytest.mark.anyio
    async def test_postgres_reachable_but_embedding_column_missing(self, test_app, monkeypatch):
        """HTTP 503 when table exists but 'embedding' column is missing."""
        self._setup_healthy_ollama(monkeypatch)
        mock_session = _mock_postgres_session(
            pg_extension_row=("vector", "0.8.0"),
            table_exists=True,
            col_row=None,
        )

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        db = detail["checks"]["database"]
        assert db["status"] == "error"
        assert db["detail"] == "Vector embedding column missing"

    @pytest.mark.anyio
    async def test_postgres_vector_dimension_mismatch(self, test_app, monkeypatch):
        """HTTP 503 when embedding column dimension does not match application settings (768)."""
        self._setup_healthy_ollama(monkeypatch)
        mock_session = _mock_postgres_session(
            pg_extension_row=("vector", "0.8.0"),
            table_exists=True,
            col_row=("embedding", 1536, "vector"),  # 1536 != 768
        )

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        db = detail["checks"]["database"]
        assert db["status"] == "error"
        assert db["schema"]["configured_dimension"] == 1536
        assert db["schema"]["expected_dimension"] == 768
        assert db["detail"] == "Vector dimension configuration mismatch"

    @pytest.mark.anyio
    async def test_postgres_unexpected_catalog_error_returns_503(self, test_app, monkeypatch):
        """HTTP 503 when catalog query raises unexpected exception without leaking query text."""
        self._setup_healthy_ollama(monkeypatch)
        mock_session = _mock_postgres_session(
            pg_extension_exc=Exception("catalog lock timeout or permission denied")
        )

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        db = detail["checks"]["database"]
        assert db["status"] == "error"
        assert db["detail"] == "Database catalog inspection failed"

    @pytest.mark.anyio
    async def test_sqlite_fallback_reports_test_mode_and_skipped_vector(self, test_app, monkeypatch):
        """HTTP 200 in SQLite fallback mode with explicit 'skipped' pgvector marker."""
        self._setup_healthy_ollama(monkeypatch)

        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        db = data["checks"]["database"]
        assert db["status"] == "ok"
        assert db["engine"] == "sqlite"
        assert db["mode"] == "test_fallback"
        assert db["pgvector"]["status"] == "skipped"
        assert db["pgvector"]["available"] is False
        assert db["schema"]["status"] == "ok"
        assert db["schema"]["table"] == "knowledge_embeddings"

    @pytest.mark.anyio
    async def test_sqlite_fallback_table_missing(self, test_app, monkeypatch):
        """HTTP 200 in SQLite fallback mode when knowledge table is uninitialized."""
        self._setup_healthy_ollama(monkeypatch)
        mock_session = _mock_sqlite_session(table_exists=False)

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        db = data["checks"]["database"]
        assert db["schema"]["status"] == "uninitialized"

    @pytest.mark.anyio
    async def test_sqlite_unexpected_error_returns_503(self, test_app, monkeypatch):
        """HTTP 503 when SQLite schema inspection encounters unexpected error."""
        self._setup_healthy_ollama(monkeypatch)
        mock_session = _mock_sqlite_session(schema_exc=Exception("disk I/O error"))

        async def override_get_db():
            yield mock_session

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/health/ready")

        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        db = detail["checks"]["database"]
        assert db["status"] == "error"
        assert db["detail"] == "Database schema inspection failed"

