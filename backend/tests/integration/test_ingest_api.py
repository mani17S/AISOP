"""
Integration tests for Evidence Ingestion & Health API endpoints.
"""

import httpx
import pytest

from app.db.session import get_db_session
from app.main import app


@pytest.fixture
def test_app(db_session):
    """Override database dependency to use isolated in-memory SQLite session."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_get_db
    yield app
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_health_check_endpoint(test_app):
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["app"] == "AISOP"
        assert data["version"] == "0.1.0"


@pytest.mark.anyio
async def test_root_endpoint(test_app):
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["platform"] == "AISOP"


@pytest.mark.anyio
async def test_ingest_telemetry_endpoint(test_app):
    transport = httpx.ASGITransport(app=test_app)
    payload = {
        "source_type": "sysmon",
        "source_identifier": "TEST-HOST-01",
        "events": [
            {
                "EventID": 1,
                "UtcTime": "2026-09-09 14:00:00.000",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "Computer": "TEST-HOST-01",
                "User": "TEST\\alice",
                "ProcessId": 1234,
                "Hashes": "SHA256=1234567890ABCDEF",
            },
            {
                "EventID": 3,
                "UtcTime": "2026-09-09 14:01:00.000",
                "SourceIp": "10.0.0.2",
                "DestinationIp": "198.51.100.33",
                "DestinationPort": 443,
                "Protocol": "tcp",
                "Computer": "TEST-HOST-01",
                "ProcessId": 1234,
            },
        ],
    }

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/evidence/ingest", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["total_received"] == 2
        assert data["total_normalized"] == 2
        assert data["total_entities_extracted"] > 0
        assert len(data["errors"]) == 0

        # Query back via GET /api/v1/evidence/events
        query_res = await client.get("/api/v1/evidence/events?limit=10")
        assert query_res.status_code == 200
        events_list = query_res.json()
        assert len(events_list) == 2

        # Check filter by event_type
        filter_res = await client.get("/api/v1/evidence/events?event_type=process_creation")
        assert filter_res.status_code == 200
        filtered_list = filter_res.json()
        assert len(filtered_list) == 1
        assert filtered_list[0]["event_type"] == "process_creation"
