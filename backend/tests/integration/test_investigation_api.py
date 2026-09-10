"""
Integration tests for AISOP SOC Investigation Query API endpoints.

Tests HTTP endpoints:
- GET /api/v1/evidence/events
- GET /api/v1/evidence/events/{event_id}
- GET /api/v1/evidence/entities
- GET /api/v1/evidence/by-hash/{sha256_hash}
- GET /api/v1/evidence/{evidence_id}

Covers empty DB, single event, multiple events, boundary conditions,
time range validations, deterministic ordering, pagination states,
entity lookups, and parameter bounds.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from app.db.session import get_db_session
from app.main import app
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence


@pytest.fixture
def test_app(db_session):
    """Override database dependency to use isolated in-memory SQLite session."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_get_db
    yield app
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_investigation_empty_db(test_app):
    """Querying an empty database returns 200 with empty items and appropriate 404s for lookups."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Events list on empty DB
        res_events = await client.get("/api/v1/evidence/events")
        assert res_events.status_code == 200
        data_events = res_events.json()
        assert data_events["items"] == []
        assert data_events["total"] == 0
        assert data_events["page"] == 1
        assert data_events["limit"] == 50
        assert data_events["total_pages"] == 0
        assert data_events["has_next"] is False
        assert data_events["has_previous"] is False

        # 2. Entities list on empty DB
        res_entities = await client.get("/api/v1/evidence/entities")
        assert res_entities.status_code == 200
        data_entities = res_entities.json()
        assert data_entities["items"] == []
        assert data_entities["total"] == 0

        # 3. Non-existent event ID -> 404
        res_event_404 = await client.get(f"/api/v1/evidence/events/{uuid.uuid4()}")
        assert res_event_404.status_code == 404

        # 4. Non-existent evidence ID -> 404
        res_evidence_404 = await client.get(f"/api/v1/evidence/{uuid.uuid4()}")
        assert res_evidence_404.status_code == 404

        # 5. Non-existent hash -> 404
        res_hash_404 = await client.get(f"/api/v1/evidence/by-hash/{'0' * 64}")
        assert res_hash_404.status_code == 404


@pytest.mark.anyio
async def test_investigation_single_event_lifecycle(test_app):
    """Ingest a single event and verify retrieval across all investigation endpoints."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest 1 Sysmon event
        ingest_res = await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "sysmon",
                "source_identifier": "ENDPOINT-SOC-01",
                "events": [
                    {
                        "EventID": 1,
                        "Image": "C:\\Windows\\System32\\cmd.exe",
                        "CommandLine": "cmd.exe /c whoami",
                        "ParentImage": "C:\\Windows\\explorer.exe",
                        "UtcTime": "2026-09-10 12:00:00.000",
                        "User": "CORP\\analyst",
                    }
                ],
            },
        )
        assert ingest_res.status_code == 200
        ingest_data = ingest_res.json()
        assert ingest_data["total_normalized"] == 1

        # 1. Query /events
        events_res = await client.get("/api/v1/evidence/events")
        assert events_res.status_code == 200
        events_data = events_res.json()
        assert events_data["total"] == 1
        event_summary = events_data["items"][0]
        assert event_summary["event_type"] == "process_creation"
        assert event_summary["source_type"] == "sysmon"
        assert event_summary["source_identifier"] == "ENDPOINT-SOC-01"
        event_id = event_summary["id"]
        evidence_id = event_summary["raw_evidence_id"]

        # 2. Get event detail /events/{event_id}
        event_detail_res = await client.get(f"/api/v1/evidence/events/{event_id}")
        assert event_detail_res.status_code == 200
        event_detail = event_detail_res.json()
        assert event_detail["id"] == event_id
        assert event_detail["raw_sha256_hash"] is not None
        assert len(event_detail["entities"]) > 0
        sha256_hash = event_detail["raw_sha256_hash"]

        # 3. Get raw evidence by UUID
        evidence_res = await client.get(f"/api/v1/evidence/{evidence_id}")
        assert evidence_res.status_code == 200
        evidence_data = evidence_res.json()
        assert evidence_data["id"] == evidence_id
        assert evidence_data["sha256_hash"] == sha256_hash
        assert len(evidence_data["normalized_events"]) == 1
        assert evidence_data["normalized_events"][0]["id"] == event_id

        # 4. Get raw evidence by hash
        hash_res = await client.get(f"/api/v1/evidence/by-hash/{sha256_hash}")
        assert hash_res.status_code == 200
        hash_data = hash_res.json()
        assert hash_data["id"] == evidence_id


@pytest.mark.anyio
async def test_investigation_pagination_and_bounds(test_app):
    """Verify pagination progression (first, middle, final, beyond) and limit boundaries."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest 25 distinct events
        batch_events = [
            {
                "EventID": 1,
                "Image": f"C:\\Tools\\app_{i}.exe",
                "UtcTime": f"2026-09-10 12:{i:02d}:00.000",
                "User": f"CORP\\user_{i}",
            }
            for i in range(25)
        ]
        ingest_res = await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "sysmon",
                "source_identifier": "PAGINATION-HOST",
                "events": batch_events,
            },
        )
        assert ingest_res.status_code == 200

        # Page 1: 10 items
        p1 = await client.get("/api/v1/evidence/events?page=1&limit=10")
        assert p1.status_code == 200
        d1 = p1.json()
        assert len(d1["items"]) == 10
        assert d1["total"] == 25
        assert d1["page"] == 1
        assert d1["total_pages"] == 3
        assert d1["has_next"] is True
        assert d1["has_previous"] is False

        # Page 2: 10 items
        p2 = await client.get("/api/v1/evidence/events?page=2&limit=10")
        assert p2.status_code == 200
        d2 = p2.json()
        assert len(d2["items"]) == 10
        assert d2["page"] == 2
        assert d2["has_next"] is True
        assert d2["has_previous"] is True

        # Page 3: 5 items
        p3 = await client.get("/api/v1/evidence/events?page=3&limit=10")
        assert p3.status_code == 200
        d3 = p3.json()
        assert len(d3["items"]) == 5
        assert d3["page"] == 3
        assert d3["has_next"] is False
        assert d3["has_previous"] is True

        # Page 4: beyond available data
        p4 = await client.get("/api/v1/evidence/events?page=4&limit=10")
        assert p4.status_code == 200
        d4 = p4.json()
        assert len(d4["items"]) == 0
        assert d4["page"] == 4
        assert d4["total_pages"] == 3
        assert d4["has_next"] is False
        assert d4["has_previous"] is False

        # Validation: page=0 -> 422
        bad_page = await client.get("/api/v1/evidence/events?page=0")
        assert bad_page.status_code == 422

        # Validation: limit=0 -> 422
        bad_limit = await client.get("/api/v1/evidence/events?limit=0")
        assert bad_limit.status_code == 422

        # Validation: limit=201 (exceeds MAX_PAGE_SIZE=200) -> 422
        max_limit_exceeded = await client.get("/api/v1/evidence/events?limit=201")
        assert max_limit_exceeded.status_code == 422

        # Validation: limit=200 (exact maximum allowed) -> 200 OK
        max_limit_ok = await client.get("/api/v1/evidence/events?limit=200")
        assert max_limit_ok.status_code == 200


@pytest.mark.anyio
async def test_investigation_time_range_filtering_and_validation(test_app):
    """Test time-range filtering and rejection of invalid or reversed time ranges."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest 3 events at specific hours
        events = [
            {
                "EventID": 1,
                "Image": "cmd.exe",
                "UtcTime": "2026-09-10 10:00:00.000",
                "User": "u1",
            },
            {
                "EventID": 1,
                "Image": "powershell.exe",
                "UtcTime": "2026-09-10 11:00:00.000",
                "User": "u2",
            },
            {
                "EventID": 1,
                "Image": "calc.exe",
                "UtcTime": "2026-09-10 12:00:00.000",
                "User": "u3",
            },
        ]
        await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "sysmon",
                "source_identifier": "TIME-HOST",
                "events": events,
            },
        )

        # 1. Filter window [10:30, 11:30] -> matches powershell.exe only
        res = await client.get(
            "/api/v1/evidence/events?start_time=2026-09-10T10:30:00Z&end_time=2026-09-10T11:30:00Z"
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert (
            "powershell.exe"
            in data["items"][0]["normalized_payload"]["process"]["image_path"]
        )

        # 2. Reversed time range -> 400 Bad Request
        rev_res = await client.get(
            "/api/v1/evidence/events?start_time=2026-09-10T12:00:00Z&end_time=2026-09-10T10:00:00Z"
        )
        assert rev_res.status_code == 400
        assert "start_time cannot be after end_time" in rev_res.json()["detail"]

        # 3. Malformed datetime string -> 422 Unprocessable Entity
        bad_dt_res = await client.get("/api/v1/evidence/events?start_time=not-a-date")
        assert bad_dt_res.status_code == 422


@pytest.mark.anyio
async def test_investigation_entity_endpoints(test_app):
    """Test IOC/entity query endpoint with type and value filters."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest Sysmon network connection event (EventID 3)
        await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "sysmon",
                "source_identifier": "NETWORK-HOST",
                "events": [
                    {
                        "EventID": 3,
                        "Image": "C:\\Windows\\System32\\curl.exe",
                        "SourceIp": "192.168.1.150",
                        "SourcePort": 49152,
                        "DestinationIp": "93.184.216.34",
                        "DestinationPort": 443,
                        "Protocol": "tcp",
                        "UtcTime": "2026-09-10 12:30:00.000",
                    }
                ],
            },
        )

        # 1. Query /entities for IP
        ent_res = await client.get("/api/v1/evidence/entities?entity_type=ip")
        assert ent_res.status_code == 200
        ent_data = ent_res.json()
        assert ent_data["total"] >= 2  # SourceIp and DestinationIp
        values = [item["entity_value"] for item in ent_data["items"]]
        assert "192.168.1.150" in values
        assert "93.184.216.34" in values

        # 2. Query /events by entity_value
        ev_by_ent = await client.get(
            "/api/v1/evidence/events?entity_value=93.184.216.34"
        )
        assert ev_by_ent.status_code == 200
        ev_data = ev_by_ent.json()
        assert ev_data["total"] == 1
        assert ev_data["items"][0]["event_type"] == "network_connection"


@pytest.mark.anyio
async def test_investigation_hash_validation(test_app):
    """Validate SHA-256 path parameter constraints on /by-hash endpoint."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Too short (not 64 chars) -> 422
        res_short = await client.get("/api/v1/evidence/by-hash/abcd")
        assert res_short.status_code == 422

        # Non-hex characters -> 422
        res_non_hex = await client.get(f"/api/v1/evidence/by-hash/{'g' * 64}")
        assert res_non_hex.status_code == 422

        # Valid 64-character hex but non-existent -> 404
        res_valid_404 = await client.get(f"/api/v1/evidence/by-hash/{'a' * 64}")
        assert res_valid_404.status_code == 404


@pytest.mark.anyio
async def test_investigation_malformed_uuid_handling(test_app):
    """Path parameters expecting UUIDs reject non-UUID strings with 422 Unprocessable Entity."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res_event = await client.get("/api/v1/evidence/events/not-a-uuid-1234")
        assert res_event.status_code == 422

        res_evidence = await client.get("/api/v1/evidence/not-a-uuid-1234")
        assert res_evidence.status_code == 422


@pytest.mark.anyio
async def test_investigation_deterministic_tie_breaker_http(test_app):
    """Verify HTTP pagination returns disjoint, deterministically sorted items when timestamps collide."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest 4 events with identical UtcTime
        events = [
            {
                "EventID": 1,
                "Image": f"C:\\Program_{i}.exe",
                "UtcTime": "2026-09-10 12:00:00.000",
                "User": f"user_{i}",
            }
            for i in range(4)
        ]
        await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "sysmon",
                "source_identifier": "TIE-HOST",
                "events": events,
            },
        )

        p1_res = await client.get("/api/v1/evidence/events?page=1&limit=2")
        assert p1_res.status_code == 200
        p1 = p1_res.json()

        p2_res = await client.get("/api/v1/evidence/events?page=2&limit=2")
        assert p2_res.status_code == 200
        p2 = p2_res.json()

        p1_ids = [item["id"] for item in p1["items"]]
        p2_ids = [item["id"] for item in p2["items"]]

        assert len(p1_ids) == 2
        assert len(p2_ids) == 2
        # Zero overlap
        assert len(set(p1_ids + p2_ids)) == 4
        # UUID tie breaker is descending
        assert p1_ids[0] > p1_ids[1]
        assert p1_ids[1] > p2_ids[0]
        assert p2_ids[0] > p2_ids[1]


@pytest.mark.anyio
async def test_investigation_multi_filter_combination_http(test_app):
    """Test multi-filter combination across event_type, source_type, and source_identifier."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Ingest from host 1
        await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "sysmon",
                "source_identifier": "CORP-WS-01",
                "events": [
                    {
                        "EventID": 1,
                        "Image": "powershell.exe",
                        "UtcTime": "2026-09-10 12:00:00.000",
                    }
                ],
            },
        )
        # Ingest from host 2
        await client.post(
            "/api/v1/evidence/ingest",
            json={
                "source_type": "sysmon",
                "source_identifier": "CORP-WS-02",
                "events": [
                    {
                        "EventID": 1,
                        "Image": "cmd.exe",
                        "UtcTime": "2026-09-10 12:00:00.000",
                    }
                ],
            },
        )

        # Match only host 1
        res = await client.get(
            "/api/v1/evidence/events?source_identifier=CORP-WS-01&event_type=process_creation"
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["items"][0]["source_identifier"] == "CORP-WS-01"
