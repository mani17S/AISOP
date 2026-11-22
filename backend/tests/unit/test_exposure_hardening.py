"""Exposure hardening: API docs are development-only and CORS is an allow-list of methods and headers."""

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import create_app


def _client(monkeypatch, environment: str) -> TestClient:
    monkeypatch.setenv("ENVIRONMENT", environment)
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    get_settings.cache_clear()
    try:
        return TestClient(create_app())
    finally:
        get_settings.cache_clear()


def test_docs_and_schema_are_served_in_development(monkeypatch):
    client = _client(monkeypatch, "development")
    assert client.get("/docs").status_code == 200
    assert client.get("/api/v1/openapi.json").status_code == 200


def test_docs_and_schema_are_not_served_in_production(monkeypatch):
    client = _client(monkeypatch, "production")
    for path in ("/docs", "/redoc", "/api/v1/openapi.json"):
        assert client.get(path).status_code == 404, path


def test_cors_preflight_rejects_unknown_origin_and_unlisted_header(monkeypatch):
    client = _client(monkeypatch, "development")
    bad_origin = client.options(
        "/api/v1/cases",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in bad_origin.headers
    odd_header = client.options(
        "/api/v1/cases",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-something-unlisted",
        },
    )
    assert odd_header.status_code == 400


def test_default_database_address_is_ipv4_loopback_not_localhost():
    """On Windows with Docker Desktop, `localhost` can resolve to ::1 first and a new connection then stalls for the
    whole connect timeout (measured: 60 s per attempt). The default must name the IPv4 loopback address."""
    from app.core.config import Settings

    default = Settings.model_fields["DATABASE_URL"].default
    assert "@127.0.0.1:" in default and "localhost" not in default
