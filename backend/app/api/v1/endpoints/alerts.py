"""
AISOP Multi-Source Alert Ingestion, Retrieval & Adapter Registry Endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.core.auth import AuthenticatedClient, verify_api_key
from app.core.errors import CodedHTTPException, QUERY_PARAMETER_INVALID, ApiError, safe_exception_text
from app.core.rbac import can_access_global_event_triage, can_ingest_telemetry
from app.db.session import get_db_session
from app.modules.alerts.adapter_protocol import get_default_registry
from app.schemas.alert_ingest import AlertIngestRequest, AlertIngestResponse
from app.schemas.alert_query import AlertDetailResponse, AlertSummaryItem
from app.schemas.query import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, PaginatedResponse
from app.services.alert_query_service import AlertQueryService
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

router = APIRouter(prefix="/alerts", tags=["Alerts & Multi-Source Ingestion"])


@router.post(
    "/ingest",
    response_model=AlertIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest heterogeneous vendor alerts",
)
async def ingest_alerts(
    request: AlertIngestRequest,
    session: Any = Depends(get_db_session),
    client: AuthenticatedClient = Depends(verify_api_key),
) -> AlertIngestResponse:
    """
    Ingest a batch of raw security alerts from multi-source vendors
    (Sysmon, Windows Security Events, Linux Auth, EDR, Network IDS, Cloud Audit,
    Email Gateways, Generic SIEM correlation).

    Cryptographically hashes raw payloads, normalizes via registered adapters,
    extracts graph entities & IOC observables, and persists atomically with deduplication.
    """
    if client.analyst is not None and not can_ingest_telemetry(client.analyst.global_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient global role to ingest alerts. Ingestion role required.",
        )

    from app.services.alert_ingestion_service import AlertIngestionService

    service = AlertIngestionService()
    return await service.ingest_batch(session, request)


@router.get(
    "/adapters",
    summary="List available vendor alert adapters and supported taxonomies",
)
async def list_adapters(
    client: AuthenticatedClient = Depends(verify_api_key),
) -> dict[str, Any]:
    """
    Return all registered alert adapters and taxonomy taxonomies supported by AISOP.
    """
    registry = get_default_registry()
    adapters = registry.list_adapters()
    return {
        "adapters": adapters,
        "count": len(adapters),
        "supported_severities": [
            "informational",
            "low",
            "medium",
            "high",
            "critical",
            "unknown",
        ],
        "supported_categories": [
            "malware",
            "initial_access",
            "execution",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "exfiltration",
            "command_and_control",
            "impact",
            "suspicious_activity",
            "policy_violation",
            "system_anomaly",
            "other",
        ],
    }


@router.get(
    "",
    response_model=PaginatedResponse[AlertSummaryItem],
    summary="Query paginated security alerts for SOC triage queue",
)
async def list_alerts(
    page: int = Query(
        default=1,
        ge=1,
        description="1-indexed page number (must be >= 1)",
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=MAX_PAGE_SIZE,
        description=f"Items per page (1 to {MAX_PAGE_SIZE}, default: 20)",
    ),
    source_type: str | None = Query(
        default=None,
        max_length=50,
        description="Filter by source adapter (e.g. sysmon, edr_malware, windows_security)",
    ),
    severity: str | None = Query(
        default=None,
        max_length=50,
        description="Filter by canonical severity (critical, high, medium, low, informational)",
    ),
    category: str | None = Query(
        default=None,
        max_length=50,
        description="Filter by canonical category (e.g. malware, credential_access, execution)",
    ),
    provider: str | None = Query(
        default=None,
        max_length=100,
        description="Filter by vendor provider name (e.g. microsoft_defender, crowdstrike)",
    ),
    source_identifier: str | None = Query(
        default=None,
        max_length=255,
        description="Filter by source hostname or sensor identifier",
    ),
    start_time: datetime | None = Query(
        default=None,
        description="Filter alerts observed on or after timestamp (ISO 8601 UTC)",
    ),
    end_time: datetime | None = Query(
        default=None,
        description="Filter alerts observed on or before timestamp (ISO 8601 UTC)",
    ),
    search: str | None = Query(
        default=None,
        max_length=200,
        description="Search keyword in title, description, or alert ID",
    ),
    client: AuthenticatedClient = Depends(verify_api_key),
    session: Any = Depends(get_db_session),
) -> PaginatedResponse[AlertSummaryItem]:
    """
    Retrieve paginated security alerts with multi-dimensional filtering for SOC triage.
    Enforces RBAC: requires analyst identity holding tier_1, tier_2, or security_admin.
    Machine-only or ingest tokens are strictly rejected with 403.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access alert triage endpoints.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    if not can_access_global_event_triage(client.analyst.global_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient global role permissions to access alert triage.",
        )

    service = AlertQueryService()
    try:
        return await service.list_alerts(
            session=session,
            page=page,
            limit=limit,
            source_type=source_type,
            severity=severity,
            category=category,
            provider=provider,
            source_identifier=source_identifier,
            start_time=start_time,
            end_time=end_time,
            search=search,
        )
    except ValueError as exc:
        raise ApiError(status.HTTP_400_BAD_REQUEST, QUERY_PARAMETER_INVALID, safe_exception_text(exc, "A query parameter is invalid."))


@router.get(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    summary="Retrieve canonical alert detail for triage inspection",
)
async def get_alert(
    alert_id: uuid.UUID = Path(..., description="Alert UUID (NormalizedEvent UUID)"),
    client: AuthenticatedClient = Depends(verify_api_key),
    session: Any = Depends(get_db_session),
) -> AlertDetailResponse:
    """
    Retrieve complete canonical alert detail for triage modal inspection prior to case creation.
    Enforces RBAC: requires analyst identity holding tier_1, tier_2, or security_admin.
    Raw evidence payload is strictly excluded to preserve least privilege.
    If record does not exist or represents non-alert evidence, returns HTTP 404.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access alert triage endpoints.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    if not can_access_global_event_triage(client.analyst.global_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient global role permissions to access alert triage.",
        )

    service = AlertQueryService()
    detail = await service.get_alert_detail(session=session, alert_id=alert_id)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found or access denied.",
        )

    return detail
