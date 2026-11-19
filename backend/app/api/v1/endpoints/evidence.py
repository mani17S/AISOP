"""
AISOP Evidence Ingestion & Investigation Query Endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.core.auth import AuthenticatedClient, verify_api_key
from app.core.errors import CodedHTTPException, QUERY_PARAMETER_INVALID, ApiError, safe_exception_text
from app.core.rbac import (
    can_access_global_entity_search,
    can_access_global_event_triage,
    can_ingest_telemetry,
)
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
    SanitizedExtractedEntityItem,
    SanitizedNormalizedEventSummary,
)
from app.services.ingestion_service import IngestionService
from app.services.query_service import InvestigationQueryService
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

router = APIRouter(prefix="/evidence", tags=["Evidence & Telemetry"])


@router.post(
    "/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest raw telemetry batch",
)
async def ingest_telemetry(
    request: IngestRequest,
    session: Any = Depends(get_db_session),
    client: AuthenticatedClient = Depends(verify_api_key),
) -> IngestResponse:
    """
    Ingest a batch of raw telemetry events (e.g. Sysmon JSON).
    Cryptographically hashes raw payloads, normalizes into canonical schemas,
    extracts atomic entities, and stores atomically with deduplication.
    """
    if client.analyst is not None and not can_ingest_telemetry(client.analyst.global_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient global role to ingest telemetry. Ingest identity required.",
        )
    service = IngestionService()
    return await service.ingest_batch(session, request)


@router.get(
    "/events",
    response_model=PaginatedResponse[SanitizedNormalizedEventSummary],
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
    client: AuthenticatedClient = Depends(verify_api_key),
    session: Any = Depends(get_db_session),
) -> PaginatedResponse[SanitizedNormalizedEventSummary]:
    """
    Retrieve normalized events with multi-field filtering, time bounding, and deterministic pagination.
    Decision 1A & Gate D.2.3.2: Triage receives sanitized summaries only (excludes raw_evidence_id and normalized_payload).
    Machine clients without human analyst identity are strictly rejected with 403.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access evidence query endpoints.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    if not can_access_global_event_triage(client.analyst.global_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient global role to access global event triage.",
        )

    service = InvestigationQueryService()
    try:
        paginated = await service.query_events(
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
        raise ApiError(400, QUERY_PARAMETER_INVALID, safe_exception_text(exc, "A query parameter is invalid."))

    # Apply Decision 1A sanitization (excludes raw_evidence_id and normalized_payload)
    sanitized_items = [
        SanitizedNormalizedEventSummary.from_event_summary(item)
        for item in paginated.items
    ]
    return PaginatedResponse[SanitizedNormalizedEventSummary](
        items=sanitized_items,
        total=paginated.total,
        page=paginated.page,
        limit=paginated.limit,
        total_pages=paginated.total_pages,
        has_next=paginated.has_next,
        has_previous=paginated.has_previous,
    )


@router.get(
    "/events/{event_id}",
    response_model=NormalizedEventDetail,
    summary="Get single normalized event detail",
)
async def get_event(
    event_id: uuid.UUID = Path(..., description="Normalized event UUID"),
    client: AuthenticatedClient = Depends(verify_api_key),
    session: Any = Depends(get_db_session),
) -> NormalizedEventDetail:
    """
    Unscoped event detail retrieval is deprecated and disabled (Gate D.2.3.2).
    Evidence must be linked to a case and retrieved through case-scoped authorization path.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access evidence query endpoints.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    raise CodedHTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Direct unscoped evidence retrieval is disabled. Case-scoped evidence retrieval via /api/v1/cases/{case_id}/evidence is required.",
        code="UNSCOPED_ENDPOINT_DISABLED",
    )


@router.get(
    "/entities",
    response_model=PaginatedResponse[SanitizedExtractedEntityItem],
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
    client: AuthenticatedClient = Depends(verify_api_key),
    session: Any = Depends(get_db_session),
) -> PaginatedResponse[SanitizedExtractedEntityItem]:
    """
    Retrieve extracted atomic entities with filtering and deterministic pagination.
    Decision 1A & Gate D.2.3.2: Triage receives sanitized entities only (excludes event_id, raw_evidence_id, and attributes).
    Machine clients without human analyst identity are strictly rejected with 403.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access evidence query endpoints.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    if not can_access_global_entity_search(client.analyst.global_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient global role to access global entity search.",
        )

    service = InvestigationQueryService()
    try:
        paginated = await service.query_entities(
            session=session,
            entity_type=entity_type,
            entity_value=entity_value,
            role=role,
            page=page,
            limit=limit,
        )
    except ValueError as exc:
        raise ApiError(400, QUERY_PARAMETER_INVALID, safe_exception_text(exc, "A query parameter is invalid."))

    # Apply Decision 1A sanitization (excludes event_id, raw_evidence_id, and attributes)
    sanitized_items = [
        SanitizedExtractedEntityItem.from_entity_item(item)
        for item in paginated.items
    ]
    return PaginatedResponse[SanitizedExtractedEntityItem](
        items=sanitized_items,
        total=paginated.total,
        page=paginated.page,
        limit=paginated.limit,
        total_pages=paginated.total_pages,
        has_next=paginated.has_next,
        has_previous=paginated.has_previous,
    )


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
    client: AuthenticatedClient = Depends(verify_api_key),
    session: Any = Depends(get_db_session),
) -> RawEvidenceDetailResponse:
    """
    Unscoped raw evidence retrieval by hash is deprecated and disabled (Gate D.2.3.2).
    Evidence must be linked to a case and retrieved through case-scoped authorization path.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access evidence query endpoints.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    raise CodedHTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Direct unscoped raw evidence retrieval is disabled. Case-scoped evidence retrieval via /api/v1/cases/{case_id}/evidence is required.",
        code="UNSCOPED_ENDPOINT_DISABLED",
    )


@router.get(
    "/{evidence_id}",
    response_model=RawEvidenceDetailResponse,
    summary="Get raw evidence and normalized events by UUID",
)
async def get_evidence(
    evidence_id: uuid.UUID = Path(..., description="Raw evidence UUID"),
    client: AuthenticatedClient = Depends(verify_api_key),
    session: Any = Depends(get_db_session),
) -> RawEvidenceDetailResponse:
    """
    Unscoped raw evidence retrieval by UUID is deprecated and disabled (Gate D.2.3.2).
    Evidence must be linked to a case and retrieved through case-scoped authorization path.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access evidence query endpoints.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    raise CodedHTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Direct unscoped raw evidence retrieval is disabled. Case-scoped evidence retrieval via /api/v1/cases/{case_id}/evidence is required.",
        code="UNSCOPED_ENDPOINT_DISABLED",
    )
