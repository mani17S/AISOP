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
    dataset_path = Path(__file__).resolve().parent.parent.parent.parent / "datasets" / "samples" / "sysmon" / "sysmon_attack_chain.json"
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
