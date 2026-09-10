"""
AISOP Evidence Ingestion & Query Endpoints.
"""

from __future__ import annotations

from typing import Any
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select

from app.db.session import get_db_session
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.schemas.ingest import IngestRequest, IngestResponse
from app.services.ingestion_service import IngestionService

router = APIRouter(prefix="/evidence", tags=["Evidence & Telemetry"])


@router.post("/ingest", response_model=IngestResponse, summary="Ingest raw telemetry batch")
async def ingest_telemetry(
    request: IngestRequest,
    session: Any = Depends(get_db_session),
) -> IngestResponse:
    """
    Ingest a batch of raw telemetry events (e.g. Sysmon JSON).
    Cryptographically hashes raw payloads, normalizes into canonical schemas,
    extracts atomic entities, and stores atomically.
    """
    service = IngestionService()
    response = await service.ingest_batch(session, request)
    return response


@router.get("/events", summary="Query normalized events")
async def list_events(
    event_type: str | None = Query(default=None, description="Filter by canonical event_type"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: Any = Depends(get_db_session),
) -> list[dict[str, Any]]:
    """
    Retrieve normalized events with optional filtering and pagination.
    """
    stmt = select(NormalizedEventModel).order_by(NormalizedEventModel.event_timestamp.desc())
    if event_type:
        stmt = stmt.where(NormalizedEventModel.event_type == event_type)
    stmt = stmt.limit(limit).offset(offset)

    result = await session.execute(stmt)
    events = result.scalars().all()

    return [
        {
            "id": str(e.id),
            "raw_evidence_id": str(e.raw_evidence_id),
            "event_id": e.event_id,
            "event_type": e.event_type,
            "event_timestamp": e.event_timestamp.isoformat(),
            "provider": e.provider,
            "action": e.action,
            "outcome": e.outcome,
            "severity": e.severity,
            "normalized_payload": e.normalized_payload,
        }
        for e in events
    ]


@router.get("/{evidence_id}", summary="Get raw evidence and normalized events")
async def get_evidence(
    evidence_id: uuid.UUID,
    session: Any = Depends(get_db_session),
) -> dict[str, Any]:
    """
    Fetch a raw evidence record and its associated normalized events by UUID.
    """
    stmt = select(RawEvidence).where(RawEvidence.id == evidence_id)
    result = await session.execute(stmt)
    raw = result.scalars().first()
    if not raw:
        raise HTTPException(status_code=404, detail="Evidence not found")

    events_stmt = select(NormalizedEventModel).where(NormalizedEventModel.raw_evidence_id == evidence_id)
    events_res = await session.execute(events_stmt)
    events = events_res.scalars().all()

    return {
        "id": str(raw.id),
        "source_type": raw.source_type,
        "source_identifier": raw.source_identifier,
        "sha256_hash": raw.sha256_hash,
        "ingested_at": raw.ingested_at.isoformat(),
        "raw_payload": raw.raw_payload,
        "normalized_events": [
            {
                "id": str(e.id),
                "event_id": e.event_id,
                "event_type": e.event_type,
                "event_timestamp": e.event_timestamp.isoformat(),
            }
            for e in events
        ],
    }
