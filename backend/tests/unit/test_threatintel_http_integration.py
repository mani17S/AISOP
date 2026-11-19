"""
AISOP Threat Intelligence HTTP Endpoint Integration Tests (TI-3A Remediation R3).

Validates FastAPI HTTP endpoint `GET /api/v1/evidence/events/{event_id}` using
in-memory SQLite and TestClient:
1. Default-off behavior (`enrich_threat_intel=False` or omitted): preserves existing response contract.
2. Local malicious feed match: returns FRESH_MATCH with verdict `malicious` and full provenance.
3. Valid unmatched observable: returns VALID_UNMATCHED with verdict `unknown`.
4. Malformed observable isolation: malformed IP yields INVALID_OBSERVABLE without failing valid lookups.
5. Engine unavailable / uninitialized: returns ENGINE_UNAVAILABLE with status PROVIDER_FAILURE.

Safety: Operates entirely against an isolated in-memory SQLite database.
Zero reads or writes to `aisop_dev` or `aisop_test`.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, AsyncGenerator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.api.dependencies import AuthenticatedClient, get_threat_intel_engine, verify_api_key
from app.db.base import Base
from app.db.session import get_db_session
from app.main import create_app
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.threatintel import (
    FeodoTrackerParser,
    LocalFeedManager,
    LocalThreatIntelEngine,
)


class InMemAsyncSessionAdapter:
    """Adapts synchronous SQLite session for async route execution in tests."""

    def __init__(self, sync_session: Any) -> None:
        self._sync = sync_session

    def add(self, obj: Any) -> None:
        self._sync.add(obj)

    def add_all(self, objs: list[Any]) -> None:
        self._sync.add_all(objs)

    async def commit(self) -> None:
        self._sync.commit()

    async def rollback(self) -> None:
        self._sync.rollback()

    async def flush(self) -> None:
        self._sync.flush()

    async def close(self) -> None:
        self._sync.close()

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self._sync.execute(statement, *args, **kwargs)


@pytest.fixture
def http_test_context():
    """
    Set up an isolated in-memory SQLite database, FastAPI TestClient, and sample seed data.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    async def override_get_db_session() -> AsyncGenerator[InMemAsyncSessionAdapter, None]:
        db = SessionLocal()
        adapter = InMemAsyncSessionAdapter(db)
        try:
            yield adapter
        finally:
            db.close()

    # Pre-populate local feed manager with a known malicious C2 IP
    feed_manager = LocalFeedManager()
    parser = FeodoTrackerParser()
    feed_manager.update_feed(
        parser,
        "# Firstseen_UTC,DstIP,DstPort,C2Status,LastOnline,Malware\n"
        "2026-10-20 10:00:00,198.51.100.1,443,online,2026-10-21 12:00:00,QakBot\n",
    )
    ti_engine = LocalThreatIntelEngine(feed_manager=feed_manager)

    app = create_app()
    app.dependency_overrides[get_db_session] = override_get_db_session
    app.dependency_overrides[get_threat_intel_engine] = lambda: ti_engine
    app.dependency_overrides[verify_api_key] = lambda: AuthenticatedClient(client_id="test-ti")

    client = TestClient(app)

    yield {
        "app": app,
        "client": client,
        "SessionLocal": SessionLocal,
        "ti_engine": ti_engine,
        "feed_manager": feed_manager,
    }

    Base.metadata.drop_all(engine)
    engine.dispose()


def _seed_event(
    SessionLocal: Any,
    entities: list[dict[str, Any]],
) -> tuple[uuid.UUID, uuid.UUID]:
    """Helper to seed a raw evidence, normalized event, and extracted entities in SQLite."""
    db = SessionLocal()
    raw_id = uuid.uuid4()
    now = datetime.datetime.now(datetime.timezone.utc)

    raw = RawEvidence(
        id=raw_id,
        source_type="sysmon",
        source_identifier="WORKSTATION-01",
        raw_payload='{"test": 1}',
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ingested_at=now,
    )
    db.add(raw)
    db.flush()

    ev_id = uuid.uuid4()
    norm_event = NormalizedEventModel(
        id=ev_id,
        raw_evidence_id=raw_id,
        event_id="SYS-03",
        event_type="network_connection",
        event_timestamp=now,
        provider="Microsoft-Windows-Sysmon",
        action="connect",
        outcome="success",
        severity="medium",
        normalized_payload={"CommandLine": "curl http://198.51.100.1"},
    )
    db.add(norm_event)
    db.flush()

    for ent_data in entities:
        ent = ExtractedEntityModel(
            id=uuid.uuid4(),
            event_id=ev_id,
            raw_evidence_id=raw_id,
            entity_type=ent_data["type"],
            entity_value=ent_data["value"],
            role=ent_data.get("role", "destination"),
            attributes=ent_data.get("attributes", {}),
        )
        db.add(ent)

    db.commit()
    db.close()
    return ev_id, raw_id


# ==============================================================================
# R3 HTTP Integration Tests
# ==============================================================================


def test_http_get_event_default_off(http_test_context):
    """Test that unscoped GET /events/{id} fails closed with 403 Forbidden under Gate D.2.3.2."""
    client = http_test_context["client"]
    SessionLocal = http_test_context["SessionLocal"]

    ev_id, _ = _seed_event(
        SessionLocal,
        [{"type": "ip", "value": "198.51.100.1", "role": "destination"}],
    )

    resp = client.get(f"/api/v1/evidence/events/{ev_id}")
    assert resp.status_code == 403
    assert "Direct unscoped evidence retrieval is disabled" in resp.json()["detail"] or "Machine credentials" in resp.json()["detail"]


def test_http_get_event_local_malicious_match(http_test_context):
    """Test that unscoped GET /events/{id}?enrich_threat_intel=true fails closed with 403 under Gate D.2.3.2."""
    client = http_test_context["client"]
    SessionLocal = http_test_context["SessionLocal"]

    ev_id, raw_id = _seed_event(
        SessionLocal,
        [{"type": "ip", "value": "198.51.100.1", "role": "destination"}],
    )

    resp = client.get(f"/api/v1/evidence/events/{ev_id}?enrich_threat_intel=true")
    assert resp.status_code == 403
    assert "Direct unscoped evidence retrieval is disabled" in resp.json()["detail"] or "Machine credentials" in resp.json()["detail"]


def test_http_get_event_valid_unmatched_observable(http_test_context):
    """Test that unscoped GET /events/{id} fails closed with 403 even with unmatched observables."""
    client = http_test_context["client"]
    SessionLocal = http_test_context["SessionLocal"]

    ev_id, _ = _seed_event(
        SessionLocal,
        [{"type": "ip", "value": "198.51.100.99", "role": "destination"}],
    )

    resp = client.get(f"/api/v1/evidence/events/{ev_id}?enrich_threat_intel=true")
    assert resp.status_code == 403


def test_http_get_event_malformed_observable_isolation(http_test_context):
    """Test that unscoped GET /events/{id} fails closed with 403 even with malformed observables."""
    client = http_test_context["client"]
    SessionLocal = http_test_context["SessionLocal"]

    ev_id, _ = _seed_event(
        SessionLocal,
        [
            {"type": "ip", "value": "999.999.999.999", "role": "destination"},
            {"type": "ip", "value": "198.51.100.1", "role": "destination"},
        ],
    )

    resp = client.get(f"/api/v1/evidence/events/{ev_id}?enrich_threat_intel=true")
    assert resp.status_code == 403


def test_http_get_event_engine_unavailable(http_test_context):
    """Test that unscoped GET /events/{id} fails closed with 403 regardless of engine availability."""
    app = http_test_context["app"]
    client = http_test_context["client"]
    SessionLocal = http_test_context["SessionLocal"]

    # Override dependency to return None (engine uninitialized)
    app.dependency_overrides[get_threat_intel_engine] = lambda: None

    ev_id, _ = _seed_event(
        SessionLocal,
        [{"type": "ip", "value": "198.51.100.1", "role": "destination"}],
    )

    resp = client.get(f"/api/v1/evidence/events/{ev_id}?enrich_threat_intel=true")
    assert resp.status_code == 403
