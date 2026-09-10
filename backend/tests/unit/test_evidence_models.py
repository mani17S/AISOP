"""
Unit tests for Evidence ORM Models.
"""

from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy import select

from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence


@pytest.mark.anyio
async def test_raw_evidence_crud(db_session):
    raw = RawEvidence(
        id=uuid.uuid4(),
        source_type="sysmon",
        source_identifier="WORKSTATION-01",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        raw_payload={"EventID": 1, "Image": "cmd.exe"},
        ingested_at=datetime.now(timezone.utc),
    )
    db_session.add(raw)
    await db_session.commit()

    result = await db_session.execute(select(RawEvidence).where(RawEvidence.source_type == "sysmon"))
    fetched = result.scalars().first()
    assert fetched is not None
    assert fetched.source_identifier == "WORKSTATION-01"
    assert fetched.sha256_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.anyio
async def test_normalized_event_and_entity_relationship(db_session):
    raw_id = uuid.uuid4()
    raw = RawEvidence(
        id=raw_id,
        source_type="sysmon",
        source_identifier="WORKSTATION-01",
        sha256_hash="dummy_hash_12345",
        raw_payload={"EventID": 3},
        ingested_at=datetime.now(timezone.utc),
    )
    db_session.add(raw)
    await db_session.flush()

    event_id = uuid.uuid4()
    event = NormalizedEventModel(
        id=event_id,
        raw_evidence_id=raw_id,
        event_id="3",
        event_type="network_connection",
        event_timestamp=datetime.now(timezone.utc),
        provider="Microsoft-Windows-Sysmon",
        action="connected",
        outcome="success",
        severity="informational",
        normalized_payload={"source_ip": "10.0.0.1"},
    )
    db_session.add(event)
    await db_session.flush()

    entity = ExtractedEntityModel(
        id=uuid.uuid4(),
        event_id=event_id,
        raw_evidence_id=raw_id,
        entity_type="ip",
        entity_value="10.0.0.1",
        role="source",
        attributes={"port": 54321},
    )
    db_session.add(entity)
    await db_session.commit()

    # Query back
    result = await db_session.execute(select(ExtractedEntityModel).where(ExtractedEntityModel.entity_type == "ip"))
    fetched_entity = result.scalars().first()
    assert fetched_entity is not None
    assert fetched_entity.entity_value == "10.0.0.1"
    assert fetched_entity.role == "source"
