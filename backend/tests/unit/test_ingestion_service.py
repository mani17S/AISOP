"""
Unit tests for IngestionService.
"""

import pytest
from sqlalchemy import select

from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.schemas.ingest import IngestRequest
from app.services.ingestion_service import IngestionService


@pytest.mark.anyio
async def test_ingest_batch_success(db_session):
    service = IngestionService()

    events = [
        {
            "EventID": 1,
            "UtcTime": "2026-09-09 10:00:00.000",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "Computer": "HOST-01",
            "User": "CORP\\bob",
            "ProcessId": 1000,
        },
        {
            "EventID": 3,
            "UtcTime": "2026-09-09 10:01:00.000",
            "SourceIp": "192.168.1.10",
            "DestinationIp": "198.51.100.20",
            "DestinationPort": 80,
            "Computer": "HOST-01",
            "ProcessId": 1000,
        },
    ]

    request = IngestRequest(
        source_type="sysmon",
        source_identifier="HOST-01",
        events=events,
    )

    response = await service.ingest_batch(db_session, request)

    assert response.total_received == 2
    assert response.total_normalized == 2
    assert response.total_entities_extracted > 0
    assert len(response.errors) == 0

    # Verify persistence in database
    raw_rows = (await db_session.execute(select(RawEvidence))).scalars().all()
    assert len(raw_rows) == 2

    norm_rows = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
    assert len(norm_rows) == 2

    entity_rows = (await db_session.execute(select(ExtractedEntityModel))).scalars().all()
    assert len(entity_rows) > 0


@pytest.mark.anyio
async def test_ingest_batch_deduplication(db_session):
    service = IngestionService()

    identical_event = {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe",
        "Computer": "HOST-01",
        "ProcessId": 2222,
    }

    request = IngestRequest(
        source_type="sysmon",
        source_identifier="HOST-01",
        events=[identical_event],
    )

    # Ingest once
    res1 = await service.ingest_batch(db_session, request)
    assert res1.total_normalized == 1

    # Ingest same event again
    res2 = await service.ingest_batch(db_session, request)
    assert res2.total_normalized == 1

    # Only 1 RawEvidence record should exist due to identical SHA-256
    raw_rows = (await db_session.execute(select(RawEvidence))).scalars().all()
    assert len(raw_rows) == 1
