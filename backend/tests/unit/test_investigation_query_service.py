"""
Unit tests for InvestigationQueryService.

Validates deterministic queries, bounds validation, time-range boundaries,
entity/IOC filtering, pagination states, tie-breaker ordering, and eager loading.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.services.query_service import InvestigationQueryService


@pytest.fixture
def query_service() -> InvestigationQueryService:
    return InvestigationQueryService()


async def _create_test_event(
    session,
    raw_evidence: RawEvidence,
    event_id_str: str,
    event_type: str,
    timestamp: datetime,
    severity: str = "informational",
    outcome: str = "success",
    action: str = "observed",
    provider: str = "Microsoft-Windows-Sysmon",
    payload: dict | None = None,
) -> NormalizedEventModel:
    norm = NormalizedEventModel(
        id=uuid.uuid4(),
        raw_evidence_id=raw_evidence.id,
        event_id=event_id_str,
        event_type=event_type,
        event_timestamp=timestamp,
        provider=provider,
        action=action,
        outcome=outcome,
        severity=severity,
        normalized_payload=payload or {"test": True},
    )
    session.add(norm)
    await session.flush()
    return norm


async def _create_test_raw_evidence(
    session,
    source_type: str = "sysmon",
    source_identifier: str = "HOST-01",
    sha256_hash: str | None = None,
) -> RawEvidence:
    raw = RawEvidence(
        id=uuid.uuid4(),
        source_type=source_type,
        source_identifier=source_identifier,
        sha256_hash=sha256_hash or uuid.uuid4().hex + uuid.uuid4().hex,
        raw_payload={"raw": "test"},
        ingested_at=datetime.now(timezone.utc),
    )
    session.add(raw)
    await session.flush()
    return raw


@pytest.mark.anyio
async def test_empty_database_queries(db_session, query_service):
    """Empty database returns zero items, total=0, and clean pagination metadata."""
    res_events = await query_service.query_events(db_session)
    assert res_events.items == []
    assert res_events.total == 0
    assert res_events.page == 1
    assert res_events.limit == 50
    assert res_events.total_pages == 0
    assert res_events.has_next is False
    assert res_events.has_previous is False

    res_entities = await query_service.query_entities(db_session)
    assert res_entities.items == []
    assert res_entities.total == 0
    assert res_entities.total_pages == 0

    assert await query_service.get_event_by_id(db_session, uuid.uuid4()) is None
    assert await query_service.get_evidence_by_id(db_session, uuid.uuid4()) is None
    assert await query_service.get_evidence_by_hash(db_session, "a" * 64) is None


@pytest.mark.anyio
async def test_query_bounds_and_validation(db_session, query_service):
    """Service enforces valid page, limit, and non-reversed time ranges."""
    with pytest.raises(ValueError, match="page must be greater than or equal to 1"):
        await query_service.query_events(db_session, page=0)

    with pytest.raises(ValueError, match="limit must be between 1 and 200"):
        await query_service.query_events(db_session, limit=0)

    with pytest.raises(ValueError, match="limit must be between 1 and 200"):
        await query_service.query_events(db_session, limit=201)

    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError, match="start_time cannot be after end_time"):
        await query_service.query_events(
            db_session,
            start_time=now,
            end_time=now - timedelta(hours=1),
        )


@pytest.mark.anyio
async def test_time_range_boundaries_inclusive(db_session, query_service):
    """Time-range filtering is inclusive of exact start and end timestamps."""
    raw = await _create_test_raw_evidence(db_session)
    t0 = datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=10)
    t2 = t0 + timedelta(minutes=20)
    t3 = t0 + timedelta(minutes=30)
    t4 = t0 + timedelta(minutes=40)

    e0 = await _create_test_event(db_session, raw, "1", "type_a", t0)
    e1 = await _create_test_event(db_session, raw, "2", "type_a", t1)
    e2 = await _create_test_event(db_session, raw, "3", "type_a", t2)
    e3 = await _create_test_event(db_session, raw, "4", "type_a", t3)
    e4 = await _create_test_event(db_session, raw, "5", "type_a", t4)
    await db_session.commit()

    # Query window [t1, t3] inclusive
    res = await query_service.query_events(
        db_session,
        start_time=t1,
        end_time=t3,
    )
    assert res.total == 3
    retrieved_ids = [item.id for item in res.items]
    assert e0.id not in retrieved_ids
    assert e1.id in retrieved_ids
    assert e2.id in retrieved_ids
    assert e3.id in retrieved_ids
    assert e4.id not in retrieved_ids


@pytest.mark.anyio
async def test_deterministic_ordering_with_timestamp_collision(
    db_session, query_service
):
    """Multiple events sharing the exact same timestamp are ordered deterministically by id DESC."""
    raw = await _create_test_raw_evidence(db_session)
    shared_timestamp = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    events = []
    for i in range(6):
        e = await _create_test_event(
            db_session, raw, str(i), "collision_test", shared_timestamp
        )
        events.append(e)
    await db_session.commit()

    # Query in 3 pages with limit=2
    p1 = await query_service.query_events(db_session, limit=2, page=1)
    p2 = await query_service.query_events(db_session, limit=2, page=2)
    p3 = await query_service.query_events(db_session, limit=2, page=3)

    p1_ids = [item.id for item in p1.items]
    p2_ids = [item.id for item in p2.items]
    p3_ids = [item.id for item in p3.items]

    # Verify each page returned exactly 2 items
    assert len(p1_ids) == 2
    assert len(p2_ids) == 2
    assert len(p3_ids) == 2

    # Verify zero overlap between pages (strict partition)
    all_retrieved = p1_ids + p2_ids + p3_ids
    assert len(set(all_retrieved)) == 6

    # Verify deterministic tie-breaker order: id DESC across all items
    sorted_expected = sorted([e.id for e in events], reverse=True)
    assert all_retrieved == sorted_expected


@pytest.mark.anyio
async def test_pagination_state_transitions(db_session, query_service):
    """Pagination transitions correctly between first, middle, final, and beyond pages."""
    raw = await _create_test_raw_evidence(db_session)
    base_time = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(25):
        await _create_test_event(
            db_session,
            raw,
            str(i),
            "page_test",
            base_time + timedelta(seconds=i),
        )
    await db_session.commit()

    # 1. First page (limit 10)
    p1 = await query_service.query_events(db_session, page=1, limit=10)
    assert len(p1.items) == 10
    assert p1.total == 25
    assert p1.page == 1
    assert p1.limit == 10
    assert p1.total_pages == 3
    assert p1.has_next is True
    assert p1.has_previous is False

    # 2. Middle page (limit 10)
    p2 = await query_service.query_events(db_session, page=2, limit=10)
    assert len(p2.items) == 10
    assert p2.page == 2
    assert p2.total_pages == 3
    assert p2.has_next is True
    assert p2.has_previous is True

    # 3. Final page (limit 10)
    p3 = await query_service.query_events(db_session, page=3, limit=10)
    assert len(p3.items) == 5
    assert p3.page == 3
    assert p3.total_pages == 3
    assert p3.has_next is False
    assert p3.has_previous is True

    # 4. Page beyond available data
    p4 = await query_service.query_events(db_session, page=4, limit=10)
    assert len(p4.items) == 0
    assert p4.page == 4
    assert p4.total_pages == 3
    assert p4.has_next is False
    assert p4.has_previous is False


@pytest.mark.anyio
async def test_source_and_multi_field_filtering(db_session, query_service):
    """Filtering by source_type, source_identifier, severity, outcome, and event_type."""
    raw1 = await _create_test_raw_evidence(
        db_session, source_type="sysmon", source_identifier="WORKSTATION-01"
    )
    raw2 = await _create_test_raw_evidence(
        db_session, source_type="zeek", source_identifier="SENSOR-DMZ"
    )

    now = datetime.now(timezone.utc)
    e1 = await _create_test_event(
        db_session,
        raw1,
        "1",
        "process_creation",
        now,
        severity="critical",
        outcome="success",
    )
    e2 = await _create_test_event(
        db_session,
        raw1,
        "2",
        "process_creation",
        now,
        severity="low",
        outcome="success",
    )
    e3 = await _create_test_event(
        db_session,
        raw2,
        "3",
        "network_connection",
        now,
        severity="critical",
        outcome="failure",
    )
    await db_session.commit()

    # Filter source_type="sysmon" -> returns e1 and e2
    res_source = await query_service.query_events(db_session, source_type="sysmon")
    assert res_source.total == 2
    assert {item.id for item in res_source.items} == {e1.id, e2.id}

    # Filter severity="critical" AND outcome="success" -> returns e1 only
    res_crit_succ = await query_service.query_events(
        db_session, severity="critical", outcome="success"
    )
    assert res_crit_succ.total == 1
    assert res_crit_succ.items[0].id == e1.id
    assert res_crit_succ.items[0].source_identifier == "WORKSTATION-01"


@pytest.mark.anyio
async def test_entity_ioc_subquery_and_no_duplication(db_session, query_service):
    """Entity-based event filtering uses subquery to prevent row multiplication."""
    raw = await _create_test_raw_evidence(db_session)
    now = datetime.now(timezone.utc)
    event1 = await _create_test_event(db_session, raw, "1", "network_connection", now)
    event2 = await _create_test_event(db_session, raw, "2", "dns_query", now)

    # Attach MULTIPLE entities to event1
    ent1a = ExtractedEntityModel(
        id=uuid.uuid4(),
        event_id=event1.id,
        raw_evidence_id=raw.id,
        entity_type="ip",
        entity_value="192.168.1.100",
        role="source",
    )
    ent1b = ExtractedEntityModel(
        id=uuid.uuid4(),
        event_id=event1.id,
        raw_evidence_id=raw.id,
        entity_type="ip",
        entity_value="10.0.0.1",
        role="destination",
    )
    # Attach single entity to event2
    ent2 = ExtractedEntityModel(
        id=uuid.uuid4(),
        event_id=event2.id,
        raw_evidence_id=raw.id,
        entity_type="domain",
        entity_value="evil.com",
        role="query",
    )
    db_session.add_all([ent1a, ent1b, ent2])
    await db_session.commit()

    # Query events containing entity_type="ip"
    # Even though event1 has 2 IP entities, event1 must appear EXACTLY ONCE
    res_ip = await query_service.query_events(db_session, entity_type="ip")
    assert res_ip.total == 1
    assert len(res_ip.items) == 1
    assert res_ip.items[0].id == event1.id

    # Query events containing entity_value="evil.com"
    res_domain = await query_service.query_events(db_session, entity_value="evil.com")
    assert res_domain.total == 1
    assert res_domain.items[0].id == event2.id


@pytest.mark.anyio
async def test_single_event_and_evidence_retrieval(db_session, query_service):
    """Fetching individual events and raw evidence eagerly loads child relationships."""
    test_hash = "f" * 64
    raw = await _create_test_raw_evidence(
        db_session,
        source_type="sysmon",
        source_identifier="WORKSTATION-X",
        sha256_hash=test_hash,
    )
    now = datetime.now(timezone.utc)
    event = await _create_test_event(
        db_session, raw, "4688", "process_creation", now, severity="high"
    )
    ent = ExtractedEntityModel(
        id=uuid.uuid4(),
        event_id=event.id,
        raw_evidence_id=raw.id,
        entity_type="user",
        entity_value="admin",
        role="actor",
        attributes={"sid": "S-1-5-18"},
    )
    db_session.add(ent)
    await db_session.commit()

    # 1. Fetch event detail by ID
    event_detail = await query_service.get_event_by_id(db_session, event.id)
    assert event_detail is not None
    assert event_detail.id == event.id
    assert event_detail.source_type == "sysmon"
    assert event_detail.source_identifier == "WORKSTATION-X"
    assert event_detail.raw_sha256_hash == test_hash
    assert len(event_detail.entities) == 1
    assert event_detail.entities[0].entity_type == "user"
    assert event_detail.entities[0].entity_value == "admin"

    # 2. Fetch raw evidence by ID
    evidence_by_id = await query_service.get_evidence_by_id(db_session, raw.id)
    assert evidence_by_id is not None
    assert evidence_by_id.sha256_hash == test_hash
    assert len(evidence_by_id.normalized_events) == 1
    assert evidence_by_id.normalized_events[0].id == event.id

    # 3. Fetch raw evidence by SHA-256 hash
    evidence_by_hash = await query_service.get_evidence_by_hash(db_session, test_hash)
    assert evidence_by_hash is not None
    assert evidence_by_hash.id == raw.id
    assert len(evidence_by_hash.normalized_events) == 1
