"""
Unit tests validating ingestion of realistic sample datasets.
"""

import json
from pathlib import Path

import pytest
from app.schemas.ingest import IngestRequest
from app.services.ingestion_service import IngestionService


@pytest.mark.anyio
async def test_ingest_attack_chain_dataset(db_session):
    dataset_path = (
        Path(__file__).resolve().parent.parent.parent.parent
        / "datasets"
        / "samples"
        / "sysmon"
        / "sysmon_attack_chain.json"
    )
    assert dataset_path.exists()

    with open(dataset_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    assert len(events) == 4

    request = IngestRequest(
        source_type="sysmon",
        source_identifier="CORP-FIN-WS01",
        events=events,
    )

    service = IngestionService()
    response = await service.ingest_batch(db_session, request)

    assert response.total_received == 4
    assert response.total_normalized == 4
    assert response.total_entities_extracted >= 8
    assert len(response.errors) == 0


@pytest.mark.anyio
async def test_ingest_p1_h8_new_sysmon_events_dataset(db_session):
    samples_dir = (
        Path(__file__).resolve().parent.parent.parent.parent
        / "datasets"
        / "samples"
        / "sysmon"
    )

    filenames = [
        "sysmon_create_remote_thread.json",
        "sysmon_process_access.json",
        "sysmon_file_create_stream_hash.json",
        "sysmon_file_delete.json",
    ]

    events = []
    for fn in filenames:
        p = samples_dir / fn
        assert p.exists()
        with open(p, "r", encoding="utf-8") as f:
            events.append(json.load(f))

    assert len(events) == 4

    request = IngestRequest(
        source_type="sysmon",
        source_identifier="CORP-FIN-WS01",
        events=events,
    )

    service = IngestionService()
    response = await service.ingest_batch(db_session, request)

    assert response.total_received == 4
    assert response.total_normalized == 4
    assert response.total_skipped_duplicates == 0
    assert len(response.errors) == 0
    assert response.total_entities_extracted > 0

    # Second pass: ensure exact duplicate batch is deduplicated idempotently
    response2 = await service.ingest_batch(db_session, request)
    assert response2.total_received == 4
    assert response2.total_normalized == 0
    assert response2.total_skipped_duplicates == 4
    assert len(response2.errors) == 0
