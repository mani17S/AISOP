"""
AISOP Evidence Ingestion & Investigation Query Endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.db.session import get_db_session
from app.schemas.ingest import IngestRequest, IngestResponse
from app.schemas.query import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    ExtractedEntityItem,
    NormalizedEventDetail,
    NormalizedEventSummary,
    PaginatedResponse,
    RawEvidenceDetailResponse,
)
from app.services.ingestion_service import IngestionService
from app.services.query_service import InvestigationQueryService
from fastapi import APIRouter, Depends, HTTPException, Path, Query

router = APIRouter(prefix="/evidence", tags=["Evidence & Telemetry"])


@router.post(
    "/ingest", response_model=IngestResponse, summary="Ingest raw telemetry batch"
)
async def ingest_telemetry(
    request: IngestRequest,
    session: Any = Depends(get_db_session),
) -> IngestResponse:
    """
    Ingest a batch of raw telemetry events (e.g. Sysmon JSON).
    Cryptographically hashes raw payloads, normalizes into canonical schemas,
    extracts atomic entities, and stores atomically with deduplication.
    """
    service = IngestionService()
    return await service.ingest_batch(session, request)


@router.get(
    "/events",
    response_model=PaginatedResponse[NormalizedEventSummary],
    summary="Query normalized events",
)
async def list_events(
    start_time: datetime | None = Query(
        default=None,
        description="Filter events observed on or after this timestamp (ISO 8601 UTC)",
    ),
    end_time: datetime | None = Query(
        default=None,
        description="Filter events observed on or before this timestamp (ISO 8601 UTC)",
    ),
    event_type: str | None = Query(
        default=None,
        max_length=100,
        description="Filter by canonical event_type (e.g. process_creation, network_connection)",
    ),
    source_type: str | None = Query(
        default=None,
        max_length=50,
        description="Filter by raw evidence source type (e.g. sysmon)",
    ),
    source_identifier: str | None = Query(
        default=None,
        max_length=255,
        description="Filter by originating endpoint or sensor hostname",
    ),
    severity: str | None = Query(
        default=None,
        max_length=50,
        description="Filter by severity (informational, low, medium, high, critical)",
    ),
    outcome: str | None = Query(
        default=None,
        max_length=50,
        description="Filter by execution outcome (success, failure, unknown)",
    ),
    entity_type: str | None = Query(
        default=None,
        max_length=50,
        description="Filter events containing an extracted entity of this type (e.g. ip, user, host)",
    ),
    entity_value: str | None = Query(
        default=None,
        max_length=500,
        description="Filter events containing an extracted entity with this value (e.g. 192.168.1.1)",
    ),
    page: int = Query(
        default=1,
        ge=1,
        description="1-indexed page number (must be >= 1)",
    ),
    limit: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description=f"Number of events per page (1 to {MAX_PAGE_SIZE}, default: {DEFAULT_PAGE_SIZE})",
    ),
    session: Any = Depends(get_db_session),
) -> PaginatedResponse[NormalizedEventSummary]:
    """
    Retrieve normalized events with multi-field filtering, time bounding, and deterministic pagination.
    """
    service = InvestigationQueryService()
    try:
        return await service.query_events(
            session=session,
            start_time=start_time,
            end_time=end_time,
            event_type=event_type,
            source_type=source_type,
            source_identifier=source_identifier,
            severity=severity,
            outcome=outcome,
            entity_type=entity_type,
            entity_value=entity_value,
            page=page,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get(
    "/events/{event_id}",
    response_model=NormalizedEventDetail,
    summary="Get single normalized event detail",
)
async def get_event(
    event_id: uuid.UUID = Path(..., description="Normalized event UUID"),
    session: Any = Depends(get_db_session),
) -> NormalizedEventDetail:
    """
    Fetch a single normalized event by UUID, including its extracted entities and provenance.
    """
    service = InvestigationQueryService()
    event = await service.get_event_by_id(session, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Normalized event not found")
    return event


@router.get(
    "/entities",
    response_model=PaginatedResponse[ExtractedEntityItem],
    summary="Query extracted entities / IOCs",
)
async def list_entities(
    entity_type: str | None = Query(
        default=None,
        max_length=50,
        description="Filter by entity type (ip, host, user, process, file_hash, domain)",
    ),
    entity_value: str | None = Query(
        default=None,
        max_length=500,
        description="Filter by normalized entity value",
    ),
    role: str | None = Query(
        default=None,
        max_length=50,
        description="Filter by entity role (source, destination, actor, etc.)",
    ),
    page: int = Query(
        default=1,
        ge=1,
        description="1-indexed page number (must be >= 1)",
    ),
    limit: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description=f"Number of items per page (1 to {MAX_PAGE_SIZE}, default: {DEFAULT_PAGE_SIZE})",
    ),
    session: Any = Depends(get_db_session),
) -> PaginatedResponse[ExtractedEntityItem]:
    """
    Retrieve extracted atomic entities with filtering and deterministic pagination.
    """
    service = InvestigationQueryService()
    try:
        return await service.query_entities(
            session=session,
            entity_type=entity_type,
            entity_value=entity_value,
            role=role,
            page=page,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get(
    "/by-hash/{sha256_hash}",
    response_model=RawEvidenceDetailResponse,
    summary="Get raw evidence by SHA-256 hash",
)
async def get_evidence_by_hash(
    sha256_hash: str = Path(
        ...,
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]{64}$",
        description="64-character hexadecimal SHA-256 integrity hash",
    ),
    session: Any = Depends(get_db_session),
) -> RawEvidenceDetailResponse:
    """
    Fetch a raw evidence record and its child normalized events by cryptographic SHA-256 digest.
    """
    service = InvestigationQueryService()
    evidence = await service.get_evidence_by_hash(session, sha256_hash)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found for hash")
    return evidence


@router.get(
    "/{evidence_id}",
    response_model=RawEvidenceDetailResponse,
    summary="Get raw evidence and normalized events by UUID",
)
async def get_evidence(
    evidence_id: uuid.UUID = Path(..., description="Raw evidence UUID"),
    session: Any = Depends(get_db_session),
) -> RawEvidenceDetailResponse:
    """
    Fetch a raw evidence record and its child normalized events by UUID.
    """
    service = InvestigationQueryService()
    evidence = await service.get_evidence_by_id(session, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence
