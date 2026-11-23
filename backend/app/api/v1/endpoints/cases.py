"""
AISOP Case Management and Scoping Endpoints.

Milestone: Phase 3 — P3-H2 / Gate D.2.2
Endpoints:
- POST /api/v1/cases — Create case and designate creator as initial lead
- GET /api/v1/cases — Paginated list of cases where caller has active assignment
- GET /api/v1/cases/{case_id} — Case detail view (anti-enumeration enforced)
- PATCH /api/v1/cases/{case_id} — Update mutable metadata (requires Lead)
- POST /api/v1/cases/{case_id}/assignments — Staff investigator/viewer (Tier-2/Admin Lead)
- POST /api/v1/cases/{case_id}/lead — Atomic lead transfer (target Tier-2/Admin)
- POST /api/v1/cases/{case_id}/close — Transition to closed/archived (Tier-2/Admin Lead)
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    AuthenticatedAnalyst,
    AuthenticatedCaseContext,
    get_case_assignment_context,
    get_current_analyst,
    get_knowledge_retriever,
    get_threat_intel_engine,
    require_case_role,
)
from app.core.errors import (
    CONTEXT_BUDGET_EXCEEDED,
    EVIDENCE_PERSISTENCE_FAILED,
    ApiError,
    CodedHTTPException,
    safe_exception_text,
)
from app.core.rbac import (
    CaseRole,
    GlobalRole,
    can_close_or_archive_case,
    can_execute_case_synthesis,
    can_create_case,
    can_link_case_evidence,
    can_manage_case_assignments,
    can_update_case_metadata,
)
from app.core.config import Settings, get_settings
from app.db.session import get_db_session, get_db_session_factory
from app.models.case import CaseAuditEventModel
from app.modules.ai.context_builder import IncompleteContextOverflowError
from app.modules.ai.guardrails import InvestigationValidationResult
from app.modules.ai.knowledge.retriever import KnowledgeRetriever
from app.modules.ai.llm.manager import get_llm_provider_or_inert
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.threatintel.local_engine import LocalThreatIntelEngine


def get_case_llm_provider() -> LLMProvider:
    """Dependency provider for the local LLM provider (inert when AI is disabled or misconfigured; never a different provider)."""
    return get_llm_provider_or_inert()

from app.schemas.case import (
    CaseAssignmentRequest,
    CaseAssignmentResponse,
    CaseAuditEventItem,
    CaseCreateRequest,
    CaseEvidenceLinkRequest,
    CaseEvidenceLinkResponse,
    CaseInvestigationSynthesizeRequest,
    CaseLifecycleUpdateRequest,
    CaseMetadataUpdateRequest,
    CaseResponse,
    CaseScopedEvidenceItem,
    CaseStatus,
    LeadTransferRequest,
)
from app.schemas.query import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    PaginatedResponse,
    SanitizedNormalizedEventSummary,
)
from app.schemas.report import InvestigationReportBundle, ReportExportResponse
from app.schemas.multisource import DomainEvidenceImportRequest, MultiSourceInvestigationRequest, MultiSourceReviewRequest, MultiSourceSection
from app.services.domain_evidence_service import DomainEvidenceService, ImportTooLarge
from app.services.case_service import CaseService
from app.services.multisource_investigation_service import (
    CaseClosed,
    CaseNotFound,
    EvidenceChanged,
    EvidenceTooLarge,
    ExportNotApproved,
    InvestigationMismatch,
    MultiSourceError,
    MultiSourceInvestigationService,
    NoInvestigation,
    PersistenceFailed,
)

router = APIRouter(prefix="/cases", tags=["Case Management"])


@router.post(
    "",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new security case",
)
async def create_case(
    request: CaseCreateRequest,
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> CaseResponse:
    """
    Create a new incident case, automatically assign creator as the initial Lead,
    and persist an attributable audit trail record in a single atomic transaction.
    Permitted for Tier-1, Tier-2, and Security Admin analysts.
    """
    if not can_create_case(analyst.global_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient global role permissions to create cases.",
        )

    # A stolen key must not be able to flood the case list: one account may create a limited number of cases per hour.
    recent = (
        await session.execute(
            select(func.count())
            .select_from(CaseAuditEventModel)
            .where(
                CaseAuditEventModel.action == "case_created",
                CaseAuditEventModel.actor_analyst_id == analyst.analyst_id,
                CaseAuditEventModel.created_at >= datetime.now(timezone.utc) - timedelta(hours=1),
            )
        )
    ).scalar_one()
    if recent >= settings.CASE_CREATE_MAX_PER_HOUR:
        raise CodedHTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many cases were created by this account in the last hour. Try again later or ask a security admin.",
            headers={"Retry-After": "600"},
            code="CASE_CREATION_LIMIT_REACHED",
        )

    service = CaseService()
    return await service.create_case(session=session, request=request, creator=analyst)


@router.get(
    "",
    response_model=PaginatedResponse[CaseResponse],
    summary="List cases assigned to caller",
)
async def list_cases(
    page: int = Query(default=1, ge=1, description="1-indexed page number"),
    limit: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description=f"Items per page (max: {MAX_PAGE_SIZE})",
    ),
    case_status: CaseStatus | None = Query(
        default=None,
        alias="status",
        description="Filter by lifecycle status",
    ),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[CaseResponse]:
    """
    Retrieve a paginated list of security cases for which the authenticated analyst
    holds an active case assignment.
    """
    service = CaseService()
    items, total = await service.list_cases_for_analyst(
        session=session,
        analyst_id=analyst.analyst_id,
        status_filter=case_status,
        page=page,
        limit=limit,
    )

    total_pages = math.ceil(total / limit) if total > 0 else 0
    has_next = (page * limit) < total
    has_previous = (page > 1) and ((page - 1) * limit < total)

    return PaginatedResponse[CaseResponse](
        items=items,
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
        has_next=has_next,
        has_previous=has_previous,
    )


@router.get(
    "/{case_id}",
    response_model=CaseResponse,
    summary="Get case details by ID",
)
async def get_case(
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(get_case_assignment_context),
    session: AsyncSession = Depends(get_db_session),
) -> CaseResponse:
    """
    Fetch full case details for an authorized analyst holding an active assignment.
    Employs anti-enumeration: non-existent cases and unassigned access return identical HTTP 404.
    """
    service = CaseService()
    return await service.get_case_detail(session=session, case_id=case_id)


@router.patch(
    "/{case_id}",
    response_model=CaseResponse,
    summary="Update case metadata",
)
async def update_case_metadata(
    request: CaseMetadataUpdateRequest,
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(require_case_role(CaseRole.LEAD)),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> CaseResponse:
    """
    Update mutable case metadata (title, description, severity).
    Strictly requires caller to hold active Lead role on the case.
    """
    if not can_update_case_metadata(analyst.global_role, context.case_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to update case metadata.",
        )

    service = CaseService()
    return await service.update_case_metadata(
        session=session,
        case_id=case_id,
        request=request,
        actor=analyst,
    )


@router.post(
    "/{case_id}/assignments",
    response_model=CaseAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Assign an investigator or viewer to a case",
)
async def assign_analyst(
    request: CaseAssignmentRequest,
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(require_case_role(CaseRole.LEAD)),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> CaseAssignmentResponse:
    """
    Staff an active analyst to a case as an investigator or viewer.
    Decision 3A Rule: Tier-1 case leads CANNOT manage staffing.
    Only Tier-2 or Security Admin leads may manage assignments.
    """
    if not can_manage_case_assignments(analyst.global_role, context.case_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient global role to manage case assignments. Tier-2 or Security Admin required.",
        )

    service = CaseService()
    return await service.assign_analyst(
        session=session,
        case_id=case_id,
        request=request,
        actor=analyst,
    )


@router.post(
    "/{case_id}/lead",
    response_model=CaseResponse,
    summary="Transfer active case leadership",
)
async def transfer_lead(
    request: LeadTransferRequest,
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(require_case_role(CaseRole.LEAD)),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> CaseResponse:
    """
    Atomically transfer active case leadership from the current Lead to an eligible target.
    Decision 3A Rule: Target analyst must hold global role Tier-2 or Security Admin.
    Outgoing lead is automatically demoted to Investigator.
    """
    service = CaseService()
    return await service.transfer_lead(
        session=session,
        case_id=case_id,
        request=request,
        current_lead=analyst,
    )


@router.post(
    "/{case_id}/close",
    response_model=CaseResponse,
    summary="Close or archive case",
)
async def close_case(
    request: CaseLifecycleUpdateRequest,
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(require_case_role(CaseRole.LEAD)),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> CaseResponse:
    """
    Formally transition case to terminal status (closed or archived).
    Decision 3A Rule: Tier-1 case leads CANNOT close cases.
    Only Tier-2 or Security Admin leads may close or archive cases.
    """
    if not can_close_or_archive_case(analyst.global_role, context.case_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient global role to close or archive cases. Tier-2 or Security Admin required.",
        )

    service = CaseService()
    return await service.close_case(
        session=session,
        case_id=case_id,
        request=request,
        actor=analyst,
    )


@router.post(
    "/{case_id}/evidence",
    response_model=CaseEvidenceLinkResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Associate normalized evidence with a case",
)
async def link_case_evidence(
    request: CaseEvidenceLinkRequest,
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(require_case_role(CaseRole.INVESTIGATOR, CaseRole.LEAD)),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> CaseEvidenceLinkResponse:
    """
    Associate a normalized evidence record with a security case and generate an audit record.
    Requires caller to be an active investigator or lead on the case.
    Viewers are prohibited.
    """
    if not can_link_case_evidence(analyst.global_role, context.case_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to link evidence to this case. Investigator or Lead required.",
        )

    service = CaseService()
    return await service.link_evidence_to_case(
        session=session,
        case_id=case_id,
        request=request,
        actor=analyst,
    )


@router.get(
    "/{case_id}/evidence",
    response_model=PaginatedResponse[CaseScopedEvidenceItem | SanitizedNormalizedEventSummary],
    summary="Retrieve paginated evidence associated with a case",
)
async def list_case_evidence(
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    page: int = Query(default=1, ge=1, description="1-indexed page number"),
    limit: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description=f"Items per page (max: {MAX_PAGE_SIZE})",
    ),
    severity: str | None = Query(default=None, description="Filter by event severity"),
    event_type: str | None = Query(default=None, description="Filter by event type"),
    context: AuthenticatedCaseContext = Depends(
        require_case_role(CaseRole.VIEWER, CaseRole.INVESTIGATOR, CaseRole.LEAD)
    ),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[CaseScopedEvidenceItem | SanitizedNormalizedEventSummary]:
    """
    Retrieve evidence records associated with a security case with role-based field sanitization.
    - Viewers: Sanitized event summaries (excludes raw_evidence_id and normalized_payload).
    - Investigators and Leads: Case investigation fields (includes normalized_payload, excludes raw_payload).
    Employs anti-enumeration: unassigned analysts receive HTTP 404.
    """
    service = CaseService()
    items, total = await service.list_case_evidence(
        session=session,
        case_id=case_id,
        case_role=context.case_role,
        page=page,
        limit=limit,
        severity=severity,
        event_type=event_type,
    )

    total_pages = math.ceil(total / limit) if total > 0 else 0
    has_next = (page * limit) < total
    has_previous = (page > 1) and ((page - 1) * limit < total)

    return PaginatedResponse[CaseScopedEvidenceItem | SanitizedNormalizedEventSummary](
        items=items,
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
        has_next=has_next,
        has_previous=has_previous,
    )


@router.get(
    "/{case_id}/activity",
    response_model=list[CaseAuditEventItem],
    summary="Retrieve immutable audit trail for a case",
)
async def list_case_activity(
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(
        require_case_role(CaseRole.VIEWER, CaseRole.INVESTIGATOR, CaseRole.LEAD)
    ),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> list[CaseAuditEventItem]:
    """
    Retrieve chronological audit trail of all security actions associated with a case.
    Requires active case assignment (anti-enumeration 404 for unassigned callers).
    """
    service = CaseService()
    return await service.list_case_activity(session=session, case_id=case_id)


_MULTISOURCE_HTTP = {
    ImportTooLarge: (status.HTTP_413_CONTENT_TOO_LARGE, "Too many records in one request."),
    CaseNotFound: (status.HTTP_404_NOT_FOUND, "Case not found or access denied."),
    CaseClosed: (status.HTTP_409_CONFLICT, "The case is closed or archived; a new investigation cannot be started."),
    EvidenceTooLarge: (status.HTTP_413_CONTENT_TOO_LARGE, "The case has too much evidence for a single investigation; narrow the linked evidence."),
    EvidenceChanged: (status.HTTP_409_CONFLICT, "Case evidence changed while the investigation was running; the result was discarded."),
    PersistenceFailed: (status.HTTP_500_INTERNAL_SERVER_ERROR, "Audit logging failed; the investigation result was not stored."),
    NoInvestigation: (status.HTTP_404_NOT_FOUND, "No multi-source investigation has been started for this case."),
    InvestigationMismatch: (status.HTTP_409_CONFLICT, "The investigation or its evidence changed; reload it and review the current result."),
    ExportNotApproved: (status.HTTP_409_CONFLICT, "Export refused: the case lead has not approved the current result."),
}


def _multisource_http_error(exc: MultiSourceError) -> HTTPException:
    code, detail = _MULTISOURCE_HTTP.get(type(exc), (status.HTTP_500_INTERNAL_SERVER_ERROR, "Investigation could not be completed."))
    return HTTPException(status_code=code, detail=detail)


@router.post(
    "/{case_id}/evidence/domain",
    status_code=status.HTTP_201_CREATED,
    summary="Import source-agnostic evidence (aisop.evidence/1 envelopes) into a case",
)
async def import_domain_evidence(
    request: DomainEvidenceImportRequest,
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(require_case_role(CaseRole.INVESTIGATOR, CaseRole.LEAD)),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """
    Validate each envelope with the evidence-domain adapters; malformed records are quarantined (reported, not stored),
    valid and unrecognised-but-well-formed records are preserved unchanged, deduplicated by SHA-256, and linked to this
    case, all in one transaction with one audit record. Same permission as linking evidence.
    """
    if not can_link_case_evidence(analyst.global_role, context.case_role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions to add evidence to this case. Investigator or Lead required.")
    try:
        return await DomainEvidenceService().import_records(session=session, case_id=case_id, actor=analyst, records=request.records)
    except PersistenceFailed as exc:  # the investigation mapper's wording ("audit logging failed") would be wrong here
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, EVIDENCE_PERSISTENCE_FAILED, "The evidence could not be stored; nothing was imported.")
    except MultiSourceError as exc:
        raise _multisource_http_error(exc)


@router.post(
    "/{case_id}/investigations/multisource",
    status_code=status.HTTP_201_CREATED,
    summary="Start (or reuse) a deterministic multi-source investigation of the case evidence",
)
async def start_multisource_investigation(
    response: Response,
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    request: MultiSourceInvestigationRequest = Body(default_factory=MultiSourceInvestigationRequest),
    context: AuthenticatedCaseContext = Depends(require_case_role(CaseRole.INVESTIGATOR, CaseRole.LEAD)),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
    llm: LLMProvider = Depends(get_case_llm_provider),
) -> dict[str, Any]:
    """
    Human-initiated investigation of the evidence linked to this case: normalization of the preserved raw
    records, cross-source correlation, timeline, deterministic ATT&CK mapping, evidence-sufficiency verdict
    and an analyst report. The deterministic workflow needs no LLM. ``use_llm=true`` additionally runs the
    gated, claim-verified LLM investigation and requires the same role as case synthesis. Repeating the
    request for identical evidence returns the stored result (200) and writes nothing; ``force=true``
    appends a new audit record. Responds 201 when a new investigation was stored.
    """
    if request.use_llm and not can_execute_case_synthesis(analyst.global_role, context.case_role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role to run the AI-assisted investigation.")
    try:
        created, payload = await MultiSourceInvestigationService().start(
            session=session, case_id=case_id, actor=analyst, use_llm=request.use_llm, force=request.force, llm_provider=llm,
        )
    except MultiSourceError as exc:
        raise _multisource_http_error(exc)
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return payload


@router.post(
    "/{case_id}/investigations/multisource/review",
    summary="Record the case lead's review (approve or reject) of the latest multi-source investigation",
)
async def review_multisource_investigation(
    request: MultiSourceReviewRequest,
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(require_case_role(CaseRole.LEAD)),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """
    Human review record. Only the case lead can write it. It is bound to the evidence fingerprint the reviewer saw, appended to the
    audit trail, and becomes 'stale' automatically if the case evidence changes afterwards. It does not change the investigation.
    """
    try:
        return await MultiSourceInvestigationService().review(
            session=session, case_id=case_id, actor=analyst, decision=request.decision,
            evidence_fingerprint=request.evidence_fingerprint, note=request.note,
        )
    except MultiSourceError as exc:
        raise _multisource_http_error(exc)


@router.get(
    "/{case_id}/investigations/multisource/export",
    summary="Release the approved multi-source report (case lead approval of the current result required)",
)
async def export_multisource_report(
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    context: AuthenticatedCaseContext = Depends(require_case_role(CaseRole.INVESTIGATOR, CaseRole.LEAD)),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Outward-facing release: refused (409) unless the lead approved this exact result and the evidence is unchanged. Audited."""
    try:
        return await MultiSourceInvestigationService().export_report(session=session, case_id=case_id, actor=analyst)
    except MultiSourceError as exc:
        raise _multisource_http_error(exc)


@router.get(
    "/{case_id}/investigations/multisource/{section}",
    summary="Retrieve a section of the latest multi-source investigation",
)
async def get_multisource_investigation_section(
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    section: MultiSourceSection = Path(..., description="status | timeline | correlation | attack | sufficiency | report | graph | evidence"),
    context: AuthenticatedCaseContext = Depends(
        require_case_role(CaseRole.VIEWER, CaseRole.INVESTIGATOR, CaseRole.LEAD)
    ),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Read-only view of the latest stored investigation; ``stale_evidence`` is true when the case evidence changed since the run."""
    try:
        return await MultiSourceInvestigationService().get_section(session=session, case_id=case_id, section=section)
    except MultiSourceError as exc:
        raise _multisource_http_error(exc)


@router.post(
    "/{case_id}/investigations/synthesize",
    response_model=InvestigationValidationResult,
    summary="Synthesize grounded case investigation via local LLM",
)
@router.post(
    "/{case_id}/synthesize",
    response_model=InvestigationValidationResult,
    summary="Synthesize grounded case investigation via local LLM (alias)",
)
async def synthesize_case_investigation_endpoint(
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    request: CaseInvestigationSynthesizeRequest = Body(default_factory=CaseInvestigationSynthesizeRequest),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session_factory: Any = Depends(get_db_session_factory),
    llm: LLMProvider = Depends(get_case_llm_provider),
    ti_engine: LocalThreatIntelEngine | None = Depends(get_threat_intel_engine),
    knowledge_retriever: KnowledgeRetriever | None = Depends(get_knowledge_retriever),
) -> InvestigationValidationResult:
    """
    Synthesize an AI-assisted security investigation report from telemetry strictly linked to this case.
    Enforces active analyst validation, investigator/lead case role, anti-enumeration,
    connection release before inference, fresh session revalidation, and transactional audit logging.
    """
    service = CaseService()
    try:
        result, _ = await service.synthesize_case_investigation(
            case_id=case_id,
            actor=analyst,
            request=request,
            session_factory=session_factory,
            llm_provider=llm,
            threat_intel_engine=ti_engine,
            knowledge_retriever=knowledge_retriever,
        )
        return result
    except IncompleteContextOverflowError as exc:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_ENTITY, CONTEXT_BUDGET_EXCEEDED, "Mandatory investigation context exceeds maximum evidence budget: " + safe_exception_text(exc, "see service limits."))


@router.post(
    "/{case_id}/reports/synthesize",
    response_model=InvestigationReportBundle,
    summary="Synthesize grounded case report bundle via local LLM",
)
async def synthesize_case_reports_endpoint(
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    request: CaseInvestigationSynthesizeRequest = Body(default_factory=CaseInvestigationSynthesizeRequest),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session_factory: Any = Depends(get_db_session_factory),
    llm: LLMProvider = Depends(get_case_llm_provider),
    ti_engine: LocalThreatIntelEngine | None = Depends(get_threat_intel_engine),
    knowledge_retriever: KnowledgeRetriever | None = Depends(get_knowledge_retriever),
) -> InvestigationReportBundle:
    """
    Synthesize role-tailored report bundle (Executive, Technical, Detection Engineering)
    from telemetry strictly linked to this case.
    """
    service = CaseService()
    try:
        return await service.synthesize_case_reports(
            case_id=case_id,
            actor=analyst,
            request=request,
            session_factory=session_factory,
            llm_provider=llm,
            threat_intel_engine=ti_engine,
            knowledge_retriever=knowledge_retriever,
        )
    except IncompleteContextOverflowError as exc:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_ENTITY, CONTEXT_BUDGET_EXCEEDED, "Mandatory investigation context exceeds maximum evidence budget: " + safe_exception_text(exc, "see service limits."))


@router.get(
    "/{case_id}/reports/export",
    response_model=ReportExportResponse,
    summary="Export role-tailored report bundle in Markdown or JSON format",
)
async def export_case_report_endpoint(
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    format: str = Query(default="markdown", pattern="^(markdown|json)$", description="Export serialization format"),
    view: str = Query(
        default="bundle",
        pattern="^(bundle|executive|technical|detection)$",
        description="Target report view",
    ),
    context: AuthenticatedCaseContext = Depends(
        require_case_role(CaseRole.VIEWER, CaseRole.INVESTIGATOR, CaseRole.LEAD)
    ),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session_factory: Any = Depends(get_db_session_factory),
    llm: LLMProvider = Depends(get_case_llm_provider),
    ti_engine: LocalThreatIntelEngine | None = Depends(get_threat_intel_engine),
    knowledge_retriever: KnowledgeRetriever | None = Depends(get_knowledge_retriever),
) -> ReportExportResponse:
    """
    Export role-tailored report bundle or specific views in Markdown or JSON format.
    Requires active case role (anti-enumeration 404 for unassigned callers).
    Records append-only audit event with cryptographic context hash.
    """
    service = CaseService()
    try:
        return await service.export_case_report(
            case_id=case_id,
            actor=analyst,
            export_format=format,
            view=view,
            session_factory=session_factory,
            llm_provider=llm,
            threat_intel_engine=ti_engine,
            knowledge_retriever=knowledge_retriever,
        )
    except IncompleteContextOverflowError as exc:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_ENTITY, CONTEXT_BUDGET_EXCEEDED, "Mandatory investigation context exceeds maximum evidence budget: " + safe_exception_text(exc, "see service limits."))



