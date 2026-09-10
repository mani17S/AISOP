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
        assert data["total_skipped_duplicates"] == 0
        assert data["total_entities_extracted"] > 0
        assert len(data["errors"]) == 0

        # Ingest exact same payload again to verify API-level deduplication
        dup_res = await client.post("/api/v1/evidence/ingest", json=payload)
        assert dup_res.status_code == 200
        dup_data = dup_res.json()
        assert dup_data["total_received"] == 2
        assert dup_data["total_normalized"] == 0
        assert dup_data["total_skipped_duplicates"] == 2
        assert len(dup_data["existing_evidence_ids"]) == 2

        # Query back via GET /api/v1/evidence/events - must strictly remain 2 events
        query_res = await client.get("/api/v1/evidence/events?limit=10")
        assert query_res.status_code == 200
        events_list = query_res.json()
        assert len(events_list) == 2

        # Check filter by event_type
        filter_res = await client.get(
            "/api/v1/evidence/events?event_type=process_creation"
        )
        assert filter_res.status_code == 200
        filtered_list = filter_res.json()
        assert len(filtered_list) == 1
        assert filtered_list[0]["event_type"] == "process_creation"


@pytest.mark.anyio
async def test_ingest_endpoint_rejects_oversized_payload(test_app):
    """P1-H4: HTTP POST with event payload > 64 KB is rejected with 422 Unprocessable Entity."""
    transport = httpx.ASGITransport(app=test_app)
    oversized_payload = {
        "source_type": "sysmon",
        "source_identifier": "TEST-HOST",
        "events": [{"EventID": 1, "Payload": "X" * 70000}],
    }

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/evidence/ingest", json=oversized_payload)
        assert response.status_code == 422
        err = response.json()
        assert "exceeds maximum allowed payload size" in str(err)


@pytest.mark.anyio
async def test_ingest_endpoint_rejects_invalid_source_type(test_app):
    """P1-H4: HTTP POST with invalid source_type is rejected with 422 Unprocessable Entity."""
    transport = httpx.ASGITransport(app=test_app)

    # Test empty source_type
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res1 = await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "",
                "source_identifier": "HOST",
                "events": [],
            },
        )
        assert res1.status_code == 422

        # Test illegal characters in source_type
        res2 = await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "sysmon; DROP TABLE",
                "source_identifier": "HOST",
                "events": [],
            },
        )
        assert res2.status_code == 422


@pytest.mark.anyio
async def test_ingest_endpoint_accepts_empty_batch(test_app):
    """P1-H4: HTTP POST with empty events list returns 200 with zero counts."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "sysmon",
                "source_identifier": "HOST",
                "events": [],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_received"] == 0
        assert data["total_normalized"] == 0
        assert data["total_skipped_duplicates"] == 0
        assert len(data["errors"]) == 0
