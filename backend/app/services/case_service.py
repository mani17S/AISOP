"""
AISOP Case Management Service Foundation.

Milestone: Phase 3 — P3-H2 / Gate D.2.2
Provides core, authorization-sensitive case and assignment queries and mutations.

Security & Architectural Invariants:
1. Strict anti-enumeration: queries join CaseModel and CaseAssignmentModel so that
   non-existent cases and unassigned access return identical None / 404 results.
2. Zero DetachedInstanceError: uses column projections or eager loading with selectinload
   to avoid lazy-loading crashes across async boundaries.
3. Fail-closed defaults: database errors and corrupt roles are logged safely and fail closed.
4. Decision 3A Enforcement:
   - Tier-1 analysts can create cases and become initial lead.
   - Tier-1 leads cannot manage investigator assignments or close/archive cases.
   - Lead transfer target must hold GlobalRole.ANALYST_TIER_2 or GlobalRole.SECURITY_ADMIN.
5. Atomic operations: State changes, assignment staffing, and audit trail records
   are committed together in a single transaction.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, status
from app.core.errors import CodedHTTPException
from loguru import logger
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from app.db.session import get_session_factory, isolated_session
from app.modules.ai.context_builder.hasher import (
    canonicalize_payload,
    compute_validation_output_sha256,
)

from app.core.rbac import (
    AuthenticatedAnalyst,
    AuthenticatedCaseContext,
    CaseRole,
    GlobalRole,
    can_close_or_archive_case,
    can_execute_case_synthesis,
    can_link_case_evidence,
    can_manage_case_assignments,
    can_transfer_case_lead,
    can_update_case_metadata,
    parse_case_role,
    parse_global_role,
)
from app.models.analyst import Analyst
from app.models.case import (
    CaseAssignmentModel,
    CaseAuditEventModel,
    CaseEvidenceModel,
    CaseModel,
)
from app.models.evidence import NormalizedEventModel
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
    CaseSeverity,
    CaseStatus,
    LeadTransferRequest,
)
from app.schemas.query import ExtractedEntityItem, SanitizedNormalizedEventSummary
from app.schemas.investigation import (
    ContextEntityItem,
    ContextEventItem,
    ContextKnowledgeChunkItem,
    InvestigationContext,
    InvestigationScopeType,
)
from app.schemas.knowledge import RetrievalRequest
from app.schemas.report import InvestigationReportBundle, ReportExportResponse
from app.modules.ai.context_builder import (
    IncompleteContextOverflowError,
    InvestigationContextBuilder,
)
from app.modules.ai.guardrails import (
    GuardrailDecision,
    InvestigationOutputValidator,
    InvestigationValidationResult,
)
from app.modules.ai.knowledge.retriever import KnowledgeRetriever
from app.modules.ai.llm.exceptions import (
    LLMConnectionError,
    LLMError,
    LLMTimeoutError,
)
from app.modules.ai.guardrails.gated_generation import GatedGenerator
from app.services.attack_reference_service import resolve_attack_reference
from app.modules.ai.guardrails.sufficiency_gate import apply_sufficiency_disclosure, evaluate_sufficiency
from app.modules.evidence_domains.model import stored_event_time_unknown
from app.modules.evidence_domains.contradictions import detect_contradictions, observations_from_stored
from app.modules.ai.llm.manager import get_llm_provider
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.ai.prompt_builder import InvestigationPromptBuilder
from app.modules.ai.reporting import (
    ContextIntegrityError,
    DeterministicReportSynthesizer,
)
from app.modules.ai.response_parser import (
    InvestigationResponseParser,
    ResponseParsingError,
)
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.services.multisource_investigation_service import MULTISOURCE_ACTION, activity_summary, case_sufficiency_summaries
from app.services.query_service import InvestigationQueryService

svc_logger = logger.bind(component="case_service")


def _is_unlinked_or_missing_hash(sha256_str: str | None) -> bool:
    """Predicate to check if sha256 is unlinked, missing, empty, or 64-zero sentinel."""
    if not sha256_str:
        return True
    clean = sha256_str.strip().lower()
    if clean == ("0" * 64) or clean == "":
        return True
    return len(clean) != 64 or not all(c in "0123456789abcdef" for c in clean)


def generate_case_number() -> str:
    """Generate canonical case number matching ^CASE-\\d{8}-[A-Z0-9]{4}$."""
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_part = uuid.uuid4().hex[:4].upper()
    return f"CASE-{date_part}-{random_part}"


def _apply_for_update(stmt: Any, session: AsyncSession) -> Any:
    """Safely apply with_for_update() on PostgreSQL while skipping on SQLite."""
    try:
        bind = getattr(session, "bind", None) or getattr(getattr(session, "_sync", None), "bind", None)
        if bind is not None and getattr(bind.dialect, "name", "") == "postgresql":
            return stmt.with_for_update()
    except Exception:
        pass
    return stmt


class CaseSummary(BaseModel):
    """
    Immutable typed summary of a security case.
    Prevents raw ORM detachment and unnecessary lazy-loading.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: uuid.UUID = Field(description="Case UUID")
    case_number: str = Field(description="Human-readable case identifier")
    title: str = Field(description="Case title")
    description: str | None = Field(default=None, description="Case briefing")
    severity: str = Field(description="Case severity")
    status: str = Field(description="Current lifecycle status")
    created_at: datetime = Field(description="Creation timestamp (UTC)")
    updated_at: datetime = Field(description="Last update timestamp (UTC)")
    closed_at: datetime | None = Field(default=None, description="Closure timestamp if terminal")


_DOMAIN_CONTEXT_ATTRIBUTES = (
    "classification", "trust_class", "source_system", "time_status", "event_time", "event_timestamp_is_ingestion_time", "upstream_id",
)


def _context_attributes(ev: Any, is_domain: bool) -> dict[str, Any]:
    payload = dict(ev.normalized_payload or {})
    if not is_domain:
        return payload
    return {k: payload[k] for k in _DOMAIN_CONTEXT_ATTRIBUTES if k in payload}


def _context_entities(ev: Any, observation: Any) -> list[ExtractedEntityItem]:
    """
    Context entities of one stored event. Domain evidence (an ``Observation`` re-derived by the approved adapter from the preserved raw
    payload): exactly ``observation.entities``, the incident path's source, with deterministic ids. Legacy evidence: its stored entity rows.
    """
    if observation is not None:
        return [
            ExtractedEntityItem(
                id=uuid.uuid5(ev.id, f"{etype}|{value}"),
                event_id=ev.id,
                raw_evidence_id=ev.raw_evidence_id,
                entity_type=etype,
                entity_value=value,
                role="associated",
                attributes={},
            )
            for etype, value in observation.entities
        ]
    return [
        ExtractedEntityItem(
            id=ent.id,
            event_id=ent.event_id,
            raw_evidence_id=ent.raw_evidence_id,
            entity_type=ent.entity_type,
            entity_value=ent.entity_value,
            role=ent.role or "associated",
            attributes=dict(ent.attributes or {}),
        )
        for ent in (ev.entities or [])
    ]


class CaseService:
    """Service providing case lookups, lifecycle mutations, and authorized assignment resolution."""

    async def get_case_by_id(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
    ) -> CaseSummary | None:
        """Fetch a case by UUID, returning an immutable CaseSummary."""
        stmt = select(CaseModel).where(CaseModel.id == case_id)
        result = await session.execute(stmt)
        case_record = result.scalars().first()
        if case_record is None:
            return None

        created = (
            case_record.created_at
            if case_record.created_at.tzinfo is not None
            else case_record.created_at.replace(tzinfo=timezone.utc)
        )
        updated = (
            case_record.updated_at
            if case_record.updated_at.tzinfo is not None
            else case_record.updated_at.replace(tzinfo=timezone.utc)
        )
        closed = None
        if case_record.closed_at is not None:
            closed = (
                case_record.closed_at
                if case_record.closed_at.tzinfo is not None
                else case_record.closed_at.replace(tzinfo=timezone.utc)
            )

        return CaseSummary(
            id=case_record.id,
            case_number=case_record.case_number,
            title=case_record.title,
            description=case_record.description,
            severity=case_record.severity,
            status=case_record.status,
            created_at=created,
            updated_at=updated,
            closed_at=closed,
        )

    async def get_assignment_context(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
        analyst_id: uuid.UUID,
    ) -> AuthenticatedCaseContext | None:
        """
        Resolve an analyst's active assignment on a case into an AuthenticatedCaseContext.
        Enforces anti-enumeration at the query boundary via inner join.
        """
        stmt = (
            select(
                CaseAssignmentModel.case_id,
                CaseAssignmentModel.analyst_id,
                CaseAssignmentModel.case_role,
                CaseAssignmentModel.assigned_at,
            )
            .join(CaseModel, CaseAssignmentModel.case_id == CaseModel.id)
            .where(
                CaseAssignmentModel.case_id == case_id,
                CaseAssignmentModel.analyst_id == analyst_id,
            )
        )
        result = await session.execute(stmt)
        row = result.first()
        if row is None:
            return None

        c_id, a_id, role_str, assigned_at = row
        try:
            case_role = parse_case_role(role_str)
        except ValueError:
            svc_logger.warning(
                "Encountered unrecognized case role in assignment record",
                case_id=str(c_id),
                analyst_id=str(a_id),
                raw_role=role_str,
            )
            return None

        if assigned_at.tzinfo is None:
            assigned_at = assigned_at.replace(tzinfo=timezone.utc)
        else:
            assigned_at = assigned_at.astimezone(timezone.utc)

        return AuthenticatedCaseContext(
            case_id=c_id,
            analyst_id=a_id,
            case_role=case_role,
            assigned_at=assigned_at,
        )

    async def is_analyst_assigned(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
        analyst_id: uuid.UUID,
    ) -> bool:
        """Predicate checking whether an analyst has an active assignment on a case."""
        ctx = await self.get_assignment_context(session, case_id, analyst_id)
        return ctx is not None

    async def create_case(
        self,
        session: AsyncSession,
        request: CaseCreateRequest,
        creator: AuthenticatedAnalyst,
    ) -> CaseResponse:
        """
        Create a new security case, assign creator as initial lead, atomically associate
        any requested initial evidence records, and persist audit records.
        """
        # 1. Validate initial_evidence_ids before performing mutations
        evidence_records: list[NormalizedEventModel] = []
        if request.initial_evidence_ids:
            # Check for duplicate IDs in the request
            seen_evidence_ids: set[uuid.UUID] = set()
            duplicates: list[uuid.UUID] = []
            for eid in request.initial_evidence_ids:
                if eid in seen_evidence_ids:
                    duplicates.append(eid)
                seen_evidence_ids.add(eid)
            if duplicates:
                raise CodedHTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Duplicate evidence IDs in initial_evidence_ids: {sorted(str(d) for d in set(duplicates))}",
                    code="DUPLICATE_EVIDENCE_IDS",
                )

            # Query database for all specified evidence IDs
            ev_stmt = (
                select(NormalizedEventModel)
                .options(joinedload(NormalizedEventModel.raw_evidence))
                .where(NormalizedEventModel.id.in_(request.initial_evidence_ids))
            )
            ev_res = await session.execute(ev_stmt)
            evidence_records = list(ev_res.scalars().all())

            found_ids = {e.id for e in evidence_records}
            missing_ids = set(request.initial_evidence_ids) - found_ids
            if missing_ids:
                raise CodedHTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Initial evidence record(s) not found: {sorted(str(m) for m in missing_ids)}",
                    code="EVIDENCE_NOT_FOUND",
                )

        case_id = uuid.uuid4()
        case_number = generate_case_number()
        now = datetime.now(timezone.utc)

        case = CaseModel(
            id=case_id,
            case_number=case_number,
            title=request.title,
            description=request.description,
            severity=request.severity.value,
            status=CaseStatus.OPEN.value,
            created_at=now,
            updated_at=now,
        )
        session.add(case)
        await session.flush()

        lead_assignment = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case_id,
            analyst_id=creator.analyst_id,
            case_role=CaseRole.LEAD.value,
            assigned_at=now,
        )
        session.add(lead_assignment)

        # Insert initial CaseEvidenceModel records and attributable audit events
        for ev_record in evidence_records:
            link = CaseEvidenceModel(
                id=uuid.uuid4(),
                case_id=case_id,
                evidence_id=ev_record.id,
                linked_by_analyst_id=creator.analyst_id,
                linked_at=now,
            )
            session.add(link)

            link_audit = CaseAuditEventModel(
                id=uuid.uuid4(),
                case_id=case_id,
                actor_analyst_id=creator.analyst_id,
                actor_username=creator.username,
                action="evidence_linked",
                context_sha256=None,
                details={
                    "evidence_id": str(ev_record.id),
                    "event_id": ev_record.event_id,
                    "event_type": ev_record.event_type,
                    "severity": ev_record.severity,
                    "source_type": (
                        ev_record.raw_evidence.source_type
                        if ev_record.raw_evidence
                        else None
                    ),
                    "context": "initial_case_creation",
                },
                created_at=now,
            )
            session.add(link_audit)

        case_audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=case_id,
            actor_analyst_id=creator.analyst_id,
            actor_username=creator.username,
            action="case_created",
            context_sha256=None,
            details={
                "severity": request.severity.value,
                "title": request.title,
                "initial_evidence_count": len(evidence_records),
                "initial_evidence_ids": [str(e.id) for e in evidence_records],
            },
            created_at=now,
        )
        session.add(case_audit)
        await session.flush()

        return CaseResponse(
            id=case.id,
            case_number=case.case_number,
            title=case.title,
            description=case.description,
            severity=request.severity,
            status=CaseStatus.OPEN,
            lead_analyst_id=creator.analyst_id,
            created_at=now,
            updated_at=now,
            closed_at=None,
        )

    async def list_cases_for_analyst(
        self,
        session: AsyncSession,
        analyst_id: uuid.UUID,
        status_filter: CaseStatus | None = None,
        page: int = 1,
        limit: int = 50,
    ) -> tuple[list[CaseResponse], int]:
        """
        Retrieve paginated cases where the analyst holds an active assignment.
        Avoids N+1 queries by eager-loading assignments with selectinload.
        """
        count_stmt = (
            select(func.count(distinct(CaseModel.id)))
            .join(CaseAssignmentModel, CaseModel.id == CaseAssignmentModel.case_id)
            .where(CaseAssignmentModel.analyst_id == analyst_id)
        )
        if status_filter is not None:
            count_stmt = count_stmt.where(CaseModel.status == status_filter.value)

        count_res = await session.execute(count_stmt)
        total = count_res.scalar() or 0

        if total == 0:
            return [], 0

        offset = (page - 1) * limit
        data_stmt = (
            select(CaseModel)
            .join(CaseAssignmentModel, CaseModel.id == CaseAssignmentModel.case_id)
            .options(selectinload(CaseModel.assignments))
            .where(CaseAssignmentModel.analyst_id == analyst_id)
        )
        if status_filter is not None:
            data_stmt = data_stmt.where(CaseModel.status == status_filter.value)

        data_stmt = (
            data_stmt.order_by(CaseModel.created_at.desc(), CaseModel.id.desc())
            .offset(offset)
            .limit(limit)
        )
        res = await session.execute(data_stmt)
        cases = res.scalars().unique().all()
        sufficiency = await case_sufficiency_summaries(session, [c.id for c in cases])

        items = []
        for c in cases:
            lead_id = c.lead_analyst_id
            if lead_id is None:
                # Fallback to current analyst if lead is not found (defensive)
                lead_id = analyst_id

            created = c.created_at if c.created_at.tzinfo else c.created_at.replace(tzinfo=timezone.utc)
            updated = c.updated_at if c.updated_at.tzinfo else c.updated_at.replace(tzinfo=timezone.utc)
            closed = (
                c.closed_at
                if (c.closed_at is None or c.closed_at.tzinfo)
                else c.closed_at.replace(tzinfo=timezone.utc)
            )

            items.append(
                CaseResponse(
                    id=c.id,
                    case_number=c.case_number,
                    title=c.title,
                    description=c.description,
                    severity=CaseSeverity(c.severity),
                    status=CaseStatus(c.status),
                    lead_analyst_id=lead_id,
                    created_at=created,
                    updated_at=updated,
                    closed_at=closed,
                    **sufficiency.get(c.id, {}),
                )
            )

        return items, total

    async def get_case_detail(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
    ) -> CaseResponse:
        """
        Fetch full case details for an authorized caller.
        """
        stmt = (
            select(CaseModel)
            .options(selectinload(CaseModel.assignments))
            .where(CaseModel.id == case_id)
        )
        res = await session.execute(stmt)
        case = res.scalars().first()
        if case is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Case not found or access denied.",
            )

        lead_id = case.lead_analyst_id
        if lead_id is None:
            svc_logger.error("Data integrity defect: Case lacks active lead", case_id=str(case_id))
            raise CodedHTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authorization service unavailable.",
                code="AUTHORIZATION_SERVICE_UNAVAILABLE",
            )

        created = case.created_at if case.created_at.tzinfo else case.created_at.replace(tzinfo=timezone.utc)
        updated = case.updated_at if case.updated_at.tzinfo else case.updated_at.replace(tzinfo=timezone.utc)
        closed = (
            case.closed_at
            if (case.closed_at is None or case.closed_at.tzinfo)
            else case.closed_at.replace(tzinfo=timezone.utc)
        )
        lead_row = (await session.execute(select(Analyst.username).where(Analyst.id == lead_id))).scalars().first()

        return CaseResponse(
            id=case.id,
            case_number=case.case_number,
            title=case.title,
            description=case.description,
            severity=CaseSeverity(case.severity),
            status=CaseStatus(case.status),
            lead_analyst_id=lead_id,
            lead_analyst_username=lead_row,
            created_at=created,
            updated_at=updated,
            closed_at=closed,
            **(await case_sufficiency_summaries(session, [case.id])).get(case.id, {}),
        )

    async def update_case_metadata(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
        request: CaseMetadataUpdateRequest,
        actor: AuthenticatedAnalyst,
    ) -> CaseResponse:
        """
        Modify mutable case metadata (title, description, severity) and record audit event atomically.
        """
        stmt = _apply_for_update(
            select(CaseModel).options(selectinload(CaseModel.assignments)).where(CaseModel.id == case_id),
            session,
        )
        res = await session.execute(stmt)
        case = res.scalars().first()
        if case is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Case not found or access denied.",
            )

        if case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
            raise CodedHTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot update metadata on terminal case with status '{case.status}'.",
                code="CASE_TERMINAL_STATE",
            )

        changes: dict[str, Any] = {}
        if request.title is not None and request.title != case.title:
            changes["title"] = {"old": case.title, "new": request.title}
            case.title = request.title
        if request.description is not None and request.description != case.description:
            changes["description"] = {"old": case.description, "new": request.description}
            case.description = request.description
        if request.severity is not None and request.severity.value != case.severity:
            changes["severity"] = {"old": case.severity, "new": request.severity.value}
            case.severity = request.severity.value

        now = datetime.now(timezone.utc)
        case.updated_at = now

        audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=case_id,
            actor_analyst_id=actor.analyst_id,
            actor_username=actor.username,
            action="case_metadata_updated",
            context_sha256=None,
            details={"updated_fields": list(changes.keys()), "changes": changes},
            created_at=now,
        )
        session.add(audit)
        await session.flush()

        lead_id = case.lead_analyst_id or actor.analyst_id
        created = case.created_at if case.created_at.tzinfo else case.created_at.replace(tzinfo=timezone.utc)
        closed = (
            case.closed_at
            if (case.closed_at is None or case.closed_at.tzinfo)
            else case.closed_at.replace(tzinfo=timezone.utc)
        )

        return CaseResponse(
            id=case.id,
            case_number=case.case_number,
            title=case.title,
            description=case.description,
            severity=CaseSeverity(case.severity),
            status=CaseStatus(case.status),
            lead_analyst_id=lead_id,
            created_at=created,
            updated_at=now,
            closed_at=closed,
            **(await case_sufficiency_summaries(session, [case.id])).get(case.id, {}),
        )

    async def assign_analyst(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
        request: CaseAssignmentRequest,
        actor: AuthenticatedAnalyst,
    ) -> CaseAssignmentResponse:
        """
        Staff an investigator or viewer to a case, updating existing assignment if needed.
        """
        # 1. Target analyst validation
        target_stmt = select(Analyst).where(Analyst.id == request.analyst_id)
        target_res = await session.execute(target_stmt)
        target = target_res.scalars().first()
        if target is None or not target.is_active:
            raise CodedHTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target analyst does not exist or is deactivated.",
                code="ASSIGNMENT_TARGET_INVALID",
            )

        # 2. Case state validation
        case_stmt = _apply_for_update(select(CaseModel).where(CaseModel.id == case_id), session)
        case_res = await session.execute(case_stmt)
        case = case_res.scalars().first()
        if case is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Case not found or access denied.",
            )
        if case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
            raise CodedHTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot modify assignments on terminal case with status '{case.status}'.",
                code="CASE_TERMINAL_STATE",
            )

        # 3. Check existing assignment
        assign_stmt = _apply_for_update(
            select(CaseAssignmentModel).where(
                CaseAssignmentModel.case_id == case_id,
                CaseAssignmentModel.analyst_id == target.id,
            ),
            session,
        )
        assign_res = await session.execute(assign_stmt)
        existing_assign = assign_res.scalars().first()

        now = datetime.now(timezone.utc)

        if existing_assign is not None:
            if existing_assign.case_role == CaseRole.LEAD.value:
                raise CodedHTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot alter lead assignment via staffing endpoint. Use lead-transfer.",
                    code="LEADERSHIP_RULE_VIOLATION",
                )
            if existing_assign.case_role == request.case_role.value:
                raise CodedHTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Analyst already has active assignment with role '{request.case_role.value}'.",
                    code="ASSIGNMENT_ALREADY_EXISTS",
                )
            old_role = existing_assign.case_role
            existing_assign.case_role = request.case_role.value
            existing_assign.assigned_at = now
            action_type = "assignment_updated"
            audit_details = {
                "target_analyst_id": str(target.id),
                "target_username": target.username,
                "old_role": old_role,
                "new_role": request.case_role.value,
            }
        else:
            assignment_obj = CaseAssignmentModel(
                id=uuid.uuid4(),
                case_id=case_id,
                analyst_id=target.id,
                case_role=request.case_role.value,
                assigned_at=now,
            )
            session.add(assignment_obj)
            action_type = "assignment_created"
            audit_details = {
                "target_analyst_id": str(target.id),
                "target_username": target.username,
                "assigned_role": request.case_role.value,
            }

        audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=case_id,
            actor_analyst_id=actor.analyst_id,
            actor_username=actor.username,
            action=action_type,
            context_sha256=None,
            details=audit_details,
            created_at=now,
        )
        session.add(audit)
        await session.flush()

        return CaseAssignmentResponse(
            case_id=case_id,
            analyst_id=target.id,
            username=target.username,
            case_role=request.case_role,
            assigned_at=now,
        )

    async def transfer_lead(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
        request: LeadTransferRequest,
        current_lead: AuthenticatedAnalyst,
    ) -> CaseResponse:
        """
        Atomically transfer active case leadership to an eligible Tier-2 or Security Admin analyst.
        """
        if request.target_analyst_id == current_lead.analyst_id:
            raise CodedHTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot transfer leadership to yourself.",
                code="LEADERSHIP_RULE_VIOLATION",
            )

        # 1. Target analyst validation
        target_stmt = select(Analyst).where(Analyst.id == request.target_analyst_id)
        target_res = await session.execute(target_stmt)
        target = target_res.scalars().first()
        if target is None or not target.is_active:
            raise CodedHTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target analyst does not exist or is deactivated.",
                code="ASSIGNMENT_TARGET_INVALID",
            )

        try:
            target_role = parse_global_role(target.global_role)
        except ValueError:
            raise CodedHTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target analyst has invalid global role.",
                code="ASSIGNMENT_TARGET_INVALID",
            )

        if not can_transfer_case_lead(
            current_global_role=current_lead.global_role,
            current_case_role=CaseRole.LEAD,
            target_global_role=target_role,
        ):
            raise CodedHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Leadership can only be transferred to Tier-2 analysts or Security Administrators.",
                code="LEADERSHIP_RULE_VIOLATION",
            )

        # 2. Case state validation
        case_stmt = _apply_for_update(
            select(CaseModel).options(selectinload(CaseModel.assignments)).where(CaseModel.id == case_id),
            session,
        )
        case_res = await session.execute(case_stmt)
        case = case_res.scalars().first()
        if case is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Case not found or access denied.",
            )
        if case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
            raise CodedHTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot transfer leadership on terminal case with status '{case.status}'.",
                code="CASE_TERMINAL_STATE",
            )

        # 3. Fetch assignments with consistent ordering to prevent deadlocks
        analyst_ids = sorted([current_lead.analyst_id, target.id])
        assign_stmt = _apply_for_update(
            select(CaseAssignmentModel)
            .where(
                CaseAssignmentModel.case_id == case_id,
                CaseAssignmentModel.analyst_id.in_(analyst_ids),
            )
            .order_by(CaseAssignmentModel.analyst_id.asc()),
            session,
        )
        assign_res = await session.execute(assign_stmt)
        assignments = {a.analyst_id: a for a in assign_res.scalars().all()}

        outgoing_assign = assignments.get(current_lead.analyst_id)
        if outgoing_assign is None or outgoing_assign.case_role != CaseRole.LEAD.value:
            raise CodedHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Current caller is not the active lead on this case.",
                code="NOT_CASE_LEAD",
            )

        now = datetime.now(timezone.utc)

        # 4. Atomic role transition: demote current lead, promote target lead
        outgoing_assign.case_role = CaseRole.INVESTIGATOR.value
        outgoing_assign.assigned_at = now
        await session.flush()

        target_assign = assignments.get(target.id)
        if target_assign is not None:
            target_assign.case_role = CaseRole.LEAD.value
            target_assign.assigned_at = now
        else:
            new_lead_assign = CaseAssignmentModel(
                id=uuid.uuid4(),
                case_id=case_id,
                analyst_id=target.id,
                case_role=CaseRole.LEAD.value,
                assigned_at=now,
            )
            session.add(new_lead_assign)
        await session.flush()

        case.updated_at = now

        audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=case_id,
            actor_analyst_id=current_lead.analyst_id,
            actor_username=current_lead.username,
            action="lead_transferred",
            context_sha256=None,
            details={
                "previous_lead_id": str(current_lead.analyst_id),
                "previous_lead_username": current_lead.username,
                "new_lead_id": str(target.id),
                "new_lead_username": target.username,
                "reason": request.reason,
            },
            created_at=now,
        )
        session.add(audit)
        await session.flush()

        created = case.created_at if case.created_at.tzinfo else case.created_at.replace(tzinfo=timezone.utc)
        closed = (
            case.closed_at
            if (case.closed_at is None or case.closed_at.tzinfo)
            else case.closed_at.replace(tzinfo=timezone.utc)
        )

        return CaseResponse(
            id=case.id,
            case_number=case.case_number,
            title=case.title,
            description=case.description,
            severity=CaseSeverity(case.severity),
            status=CaseStatus(case.status),
            lead_analyst_id=target.id,
            created_at=created,
            updated_at=now,
            closed_at=closed,
            **(await case_sufficiency_summaries(session, [case.id])).get(case.id, {}),
        )

    async def close_case(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
        request: CaseLifecycleUpdateRequest,
        actor: AuthenticatedAnalyst,
    ) -> CaseResponse:
        """
        Transition case to terminal lifecycle status (closed or archived) with mandatory audit justification.
        """
        stmt = _apply_for_update(
            select(CaseModel).options(selectinload(CaseModel.assignments)).where(CaseModel.id == case_id),
            session,
        )
        res = await session.execute(stmt)
        case = res.scalars().first()
        if case is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Case not found or access denied.",
            )

        if case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
            raise CodedHTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Case is already in terminal state '{case.status}'.",
                code="CASE_TERMINAL_STATE",
            )

        now = datetime.now(timezone.utc)
        old_status = case.status
        case.status = request.status.value
        case.closed_at = now
        case.updated_at = now

        audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=case_id,
            actor_analyst_id=actor.analyst_id,
            actor_username=actor.username,
            action=f"case_{request.status.value}",
            context_sha256=None,
            details={
                "previous_status": old_status,
                "new_status": request.status.value,
                "closure_reason": request.closure_reason,
            },
            created_at=now,
        )
        session.add(audit)
        await session.flush()

        lead_id = case.lead_analyst_id or actor.analyst_id
        created = case.created_at if case.created_at.tzinfo else case.created_at.replace(tzinfo=timezone.utc)

        return CaseResponse(
            id=case.id,
            case_number=case.case_number,
            title=case.title,
            description=case.description,
            severity=CaseSeverity(case.severity),
            status=request.status,
            lead_analyst_id=lead_id,
            created_at=created,
            updated_at=now,
            closed_at=now,
            **(await case_sufficiency_summaries(session, [case.id])).get(case.id, {}),
        )

    async def link_evidence_to_case(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
        request: CaseEvidenceLinkRequest,
        actor: AuthenticatedAnalyst,
    ) -> CaseEvidenceLinkResponse:
        """
        Associate a normalized evidence event with a security case and record audit log atomically.
        """
        # 1. Validate case existence and lifecycle status
        case_stmt = _apply_for_update(select(CaseModel).where(CaseModel.id == case_id), session)
        case_res = await session.execute(case_stmt)
        case = case_res.scalars().first()
        if case is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Case not found or access denied.",
            )
        if case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
            raise CodedHTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot link evidence to terminal case with status '{case.status}'.",
                code="CASE_TERMINAL_STATE",
            )

        # 2. Validate normalized evidence existence
        ev_stmt = (
            select(NormalizedEventModel)
            .options(joinedload(NormalizedEventModel.raw_evidence))
            .where(NormalizedEventModel.id == request.evidence_id)
        )
        ev_res = await session.execute(ev_stmt)
        event = ev_res.scalars().first()
        if event is None:
            raise CodedHTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Normalized evidence event not found.",
                code="EVIDENCE_NOT_FOUND",
            )

        # 3. Check for duplicate association
        dup_stmt = select(CaseEvidenceModel).where(
            CaseEvidenceModel.case_id == case_id,
            CaseEvidenceModel.evidence_id == request.evidence_id,
        )
        dup_res = await session.execute(dup_stmt)
        existing_link = dup_res.scalars().first()
        if existing_link is not None:
            raise CodedHTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Evidence is already linked to this case.",
                code="EVIDENCE_ALREADY_LINKED",
            )

        # 4. Create association and audit event atomically
        now = datetime.now(timezone.utc)
        link = CaseEvidenceModel(
            id=uuid.uuid4(),
            case_id=case_id,
            evidence_id=request.evidence_id,
            linked_by_analyst_id=actor.analyst_id,
            linked_at=now,
        )
        session.add(link)

        audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=case_id,
            actor_analyst_id=actor.analyst_id,
            actor_username=actor.username,
            action="evidence_linked",
            context_sha256=None,
            details={
                "evidence_id": str(request.evidence_id),
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": event.severity,
                "source_type": event.raw_evidence.source_type if event.raw_evidence else None,
            },
            created_at=now,
        )
        session.add(audit)
        await session.flush()

        return CaseEvidenceLinkResponse(
            id=link.id,
            case_id=case_id,
            evidence_id=request.evidence_id,
            linked_by_analyst_id=actor.analyst_id,
            linked_at=now,
        )

    async def list_case_evidence(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
        case_role: CaseRole,
        page: int = 1,
        limit: int = 50,
        severity: str | None = None,
        event_type: str | None = None,
    ) -> tuple[list[CaseScopedEvidenceItem | SanitizedNormalizedEventSummary], int]:
        """
        Retrieve paginated evidence associated with a case, enforcing role-based projections.
        Viewers receive sanitized summaries (no raw_evidence_id or normalized_payload).
        Investigators and Leads receive case-scoped investigation fields (with normalized_payload).
        """
        # Count query strictly joined to case_evidence junction table
        count_stmt = (
            select(func.count(NormalizedEventModel.id))
            .join(CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id)
            .where(CaseEvidenceModel.case_id == case_id)
        )
        if severity is not None:
            count_stmt = count_stmt.where(NormalizedEventModel.severity == severity)
        if event_type is not None:
            count_stmt = count_stmt.where(NormalizedEventModel.event_type == event_type)

        count_res = await session.execute(count_stmt)
        total = count_res.scalar() or 0

        if total == 0:
            return [], 0

        offset = (page - 1) * limit
        data_stmt = (
            select(NormalizedEventModel, CaseEvidenceModel)
            .join(CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id)
            .options(joinedload(NormalizedEventModel.raw_evidence))
            .where(CaseEvidenceModel.case_id == case_id)
        )
        if severity is not None:
            data_stmt = data_stmt.where(NormalizedEventModel.severity == severity)
        if event_type is not None:
            data_stmt = data_stmt.where(NormalizedEventModel.event_type == event_type)

        data_stmt = (
            data_stmt.order_by(
                NormalizedEventModel.event_timestamp.desc(),
                NormalizedEventModel.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        res = await session.execute(data_stmt)
        rows = res.unique().all()

        items: list[CaseScopedEvidenceItem | SanitizedNormalizedEventSummary] = []
        is_viewer = (case_role == CaseRole.VIEWER)

        for event, link in rows:
            event_ts = (
                event.event_timestamp
                if event.event_timestamp.tzinfo
                else event.event_timestamp.replace(tzinfo=timezone.utc)
            )
            src_type = event.raw_evidence.source_type if event.raw_evidence else None
            src_id = event.raw_evidence.source_identifier if event.raw_evidence else None

            if is_viewer:
                items.append(
                    SanitizedNormalizedEventSummary(
                        id=event.id,
                        event_id=event.event_id,
                        event_type=event.event_type,
                        event_timestamp=event_ts,
                        provider=event.provider,
                        action=event.action,
                        outcome=event.outcome,
                        severity=event.severity,
                        source_type=src_type,
                        source_identifier=src_id,
                    )
                )
            else:
                linked_at = (
                    link.linked_at
                    if link.linked_at.tzinfo
                    else link.linked_at.replace(tzinfo=timezone.utc)
                )
                items.append(
                    CaseScopedEvidenceItem(
                        id=event.id,
                        event_id=event.event_id,
                        event_type=event.event_type,
                        event_timestamp=event_ts,
                        provider=event.provider,
                        action=event.action,
                        outcome=event.outcome,
                        severity=event.severity,
                        source_type=src_type,
                        source_identifier=src_id,
                        normalized_payload=event.normalized_payload,
                        linked_at=linked_at,
                        linked_by_analyst_id=link.linked_by_analyst_id,
                    )
                )

        return items, total

    async def list_case_activity(
        self,
        session: AsyncSession,
        case_id: uuid.UUID,
    ) -> list[CaseAuditEventItem]:
        """
        Retrieve chronological audit trail of all security actions associated with a case.
        """
        stmt = (
            select(CaseAuditEventModel)
            .where(CaseAuditEventModel.case_id == case_id)
            .order_by(CaseAuditEventModel.created_at.asc())
        )
        res = await session.execute(stmt)
        records = res.scalars().all()
        return [
            CaseAuditEventItem(
                id=r.id,
                case_id=r.case_id,
                actor_analyst_id=r.actor_analyst_id,
                actor_username=r.actor_username,
                action=r.action,
                context_sha256=r.context_sha256,
                details=(activity_summary(r.details or {}) if r.action == MULTISOURCE_ACTION else (r.details or {})),
                created_at=(
                    r.created_at
                    if r.created_at.tzinfo
                    else r.created_at.replace(tzinfo=timezone.utc)
                ),
            )
            for r in records
        ]

    async def synthesize_case_investigation(
        self,
        case_id: Any = None,
        actor: AuthenticatedAnalyst | None = None,
        request: CaseInvestigationSynthesizeRequest | None = None,
        session_factory: Any | None = None,
        session: AsyncSession | None = None,
        *args: Any,
        llm_provider: LLMProvider | None = None,
        threat_intel_engine: LocalThreatIntelEngine | None = None,
        knowledge_retriever: KnowledgeRetriever | None = None,
        validator: InvestigationOutputValidator | None = None,
        context_builder: InvestigationContextBuilder | None = None,
        response_parser: InvestigationResponseParser | None = None,
        prompt_builder: InvestigationPromptBuilder | None = None,
        audit_action: str = "case_investigation_synthesized",
        session_release_callback: Any | None = None,
        **kwargs: Any,
    ) -> tuple[InvestigationValidationResult, InvestigationContext]:
        """
        Execute the case-scoped 3-phase AI investigation synthesis lifecycle:
        Phase A: Authenticate analyst, validate case status and assignment role,
                 query linked evidence, build canonical InvestigationContext and evidence snapshot,
                 and commit & release database session before LLM inference.
        Phase B: Local inference with untrusted data isolation, prompt injection defenses,
                 response parsing, and 3-tier epistemic guardrail validation (0 DB connections held).
        Phase C: Acquire fresh database session, revalidate analyst active status, case eligibility,
                 assignment role, exact evidence set equality, and content/attribute fingerprint;
                 write transactional audit event and fail closed if audit fails.
        """
        # Handle backwards-compatible positional call: (session, case_id, actor, request)
        if isinstance(case_id, (AsyncSession, object)) and hasattr(case_id, "execute") and actor is not None and isinstance(actor, uuid.UUID):
            session = case_id
            case_id = actor
            actor = request  # type: ignore
            request = kwargs.get("request") or (args[0] if args else CaseInvestigationSynthesizeRequest())

        if request is None:
            request = CaseInvestigationSynthesizeRequest()

        if actor is None or not actor.is_active:
            raise CodedHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Analyst account is deactivated.",
                code="ACCOUNT_DEACTIVATED",
            )

        # ── PHASE A — AUTHORIZE AND BUILD CONTEXT ───────────────────────────
        async with isolated_session(session_factory=session_factory, fallback_session=session) as phase_a_session:
            # 1. Validate case existence and anti-enumeration
            case_stmt = select(CaseModel).where(CaseModel.id == case_id)
            case_res = await phase_a_session.execute(case_stmt)
            case = case_res.scalars().first()
            if case is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Case not found or access denied.",
                )

            # 2. Validate active case assignment and role
            assign_stmt = select(CaseAssignmentModel).where(
                CaseAssignmentModel.case_id == case_id,
                CaseAssignmentModel.analyst_id == actor.analyst_id,
            )

            assign_res = await phase_a_session.execute(assign_stmt)
            assignment = assign_res.scalars().first()
            if assignment is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Case not found or access denied.",
                )

            if not can_execute_case_synthesis(actor.global_role, assignment.case_role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient case role to synthesize investigations. Investigator or Lead required.",
                )

            if case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
                raise CodedHTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Cannot synthesize investigation for terminal case with status '{case.status}'.",
                    code="CASE_TERMINAL_STATE",
                )

            # 3. Query ONLY evidence linked to this case
            ev_stmt = (
                select(NormalizedEventModel, CaseEvidenceModel)
                .join(CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id)
                .options(
                    joinedload(NormalizedEventModel.entities),
                    joinedload(NormalizedEventModel.raw_evidence),
                )
                .where(CaseEvidenceModel.case_id == case_id)
                .order_by(NormalizedEventModel.event_timestamp.asc())
            )
            if request.time_window_start is not None:
                ev_stmt = ev_stmt.where(NormalizedEventModel.event_timestamp >= request.time_window_start)
            if request.time_window_end is not None:
                ev_stmt = ev_stmt.where(NormalizedEventModel.event_timestamp < request.time_window_end)

            ev_res = await phase_a_session.execute(ev_stmt)
            orm_rows = ev_res.unique().all()

            # ADR-013 Revision 2 (suff-v4): the SAME pure detector as the incident path, over observations re-derived from the PRESERVED raw
            # payloads of this case's evidence only (the rows above were selected through case_evidence for this case). Findings are facts;
            # the single gate below decides the verdict. Nothing here changes authorization, case scoping or the evidence snapshot.
            domain_observations = observations_from_stored(
                (ev.id, ev.raw_evidence.raw_payload, ev.raw_evidence.sha256_hash) for ev, _link in orm_rows if ev.raw_evidence is not None
            )
            contradiction_candidates = detect_contradictions(domain_observations)
            # Stage 7B (D1): for domain evidence the canonical context entities are the SAME ones the incident path uses: the entities the
            # approved adapter derives from the PRESERVED raw payload. The stored ``normalized_payload["entities"]`` and any client field
            # are never read for this, so nothing client-supplied becomes a trusted canonical entity.
            observation_by_event = {o.key: o for o in domain_observations}

            # Compute Evidence Snapshot & Content Fingerprint (SEC-D24-002 & SEC-D24-004)
            snapshot_items = []
            phase_a_evidence_ids_set = set()
            for ev, link in orm_rows:
                phase_a_evidence_ids_set.add(ev.id)
                raw_hash = (
                    ev.raw_evidence.sha256_hash
                    if ev.raw_evidence and ev.raw_evidence.sha256_hash
                    else ("0" * 64)
                )
                source_id = (
                    ev.raw_evidence.source_identifier
                    if ev.raw_evidence and ev.raw_evidence.source_identifier
                    else (getattr(ev, "source_identifier", None) or ev.provider or "unknown")
                )
                ts = ev.event_timestamp
                ts_iso = ts.isoformat() if ts else ""
                snapshot_items.append({
                    "evidence_id": str(ev.id),
                    "link_id": str(link.id),
                    "event_id": str(ev.event_id),
                    "event_type": str(ev.event_type),
                    "action": str(ev.action),
                    "outcome": str(ev.outcome or "unknown"),
                    "severity": str(ev.severity or "informational"),
                    "timestamp": ts_iso,
                    "source_identifier": str(source_id),
                    "raw_hash": str(raw_hash),
                    "normalized_payload": dict(ev.normalized_payload or {}),
                })

            snapshot_items.sort(key=lambda x: x["evidence_id"])
            canonical_evidence_json = canonicalize_payload(snapshot_items)
            phase_a_evidence_fingerprint = hashlib.sha256(canonical_evidence_json.encode("utf-8")).hexdigest().lower()
            phase_a_evidence_ids = frozenset(phase_a_evidence_ids_set)

            # Build context_events and extracted_entities_for_ti
            context_events: list[ContextEventItem] = []
            extracted_entities_for_ti: list[ExtractedEntityItem] = []
            target_hosts_set: set[str] = set()
            undated_count = 0

            for ev, link in orm_rows:
                # Stage 7A (D1): a record with no usable event time carries its INGESTION time in event_timestamp. That is never an
                # event time, so it is kept out of the time-ordered context (as in the incident path); it stays preserved, in the
                # snapshot and the case, and is disclosed below. Its entities still feed non-temporal enrichment.
                is_undated = stored_event_time_unknown(ev.normalized_payload)
                if is_undated:
                    undated_count += 1
                raw_hash = (
                    ev.raw_evidence.sha256_hash
                    if ev.raw_evidence and ev.raw_evidence.sha256_hash
                    else ("0" * 64)
                )
                source_id = (
                    ev.raw_evidence.source_identifier
                    if ev.raw_evidence and ev.raw_evidence.source_identifier
                    else (getattr(ev, "source_identifier", None) or ev.provider or "unknown")
                )
                target_hosts_set.add(source_id)
                summary = f"{ev.event_type} {ev.action} on {source_id}"

                if is_undated:
                    extracted_entities_for_ti.extend(_context_entities(ev, observation_by_event.get(ev.id)))
                    continue

                ts = ev.event_timestamp
                if ts is not None and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                elif ts is not None:
                    ts = ts.astimezone(timezone.utc)

                c_ev = ContextEventItem(
                    event_uuid=ev.id,
                    raw_evidence_sha256=raw_hash,
                    event_id=str(ev.event_id),
                    event_type=ev.event_type,
                    timestamp_utc=ts,
                    action=ev.action,
                    outcome=ev.outcome or "unknown",
                    severity=ev.severity or "informational",
                    source_identifier=source_id,
                    summary=summary,
                    # Domain evidence: the entities are carried by the context entities (derived from the preserved payload above) and
                    # storage metadata (adapter, schema, model version, ...) is provenance kept in the record, not analytical evidence; only
                    # the source-stated facts and the time/trust semantics the analyst must see are put in the bounded prompt context.
                    attributes=_context_attributes(ev, ev.id in observation_by_event),
                )
                context_events.append(c_ev)

                extracted_entities_for_ti.extend(_context_entities(ev, observation_by_event.get(ev.id)))

            # 4. Enrich with Local Threat Intelligence
            ti_findings: list[Any] = []
            if threat_intel_engine and extracted_entities_for_ti:
                try:
                    query_svc = InvestigationQueryService(threat_intel_engine=threat_intel_engine)
                    ti_findings = await query_svc.enrich_entities_with_threat_intel(extracted_entities_for_ti)
                except Exception as exc:
                    svc_logger.warning("Local threat intelligence enrichment failed", error=str(exc))

            # 5. Semantic Knowledge Retrieval (RAG)
            knowledge_chunks: list[ContextKnowledgeChunkItem] = []
            retrieval_uncertainty: str | None = None
            if knowledge_retriever is None:
                retrieval_uncertainty = (
                    "RETRIEVER_UNAVAILABLE: Semantic knowledge retrieval component is not initialized."
                )
            elif not request.query_filter or len(request.query_filter.strip()) < 3:
                retrieval_uncertainty = (
                    "SKIPPED_SHORT_OR_MISSING_QUERY: Semantic knowledge retrieval skipped due to absent or short query filter (<3 chars)."
                )
            else:
                try:
                    retrieval_res = await knowledge_retriever.retrieve(
                        session=phase_a_session,
                        request=RetrievalRequest(query=request.query_filter.strip(), top_k=5),
                    )
                    if retrieval_res:
                        for chunk in retrieval_res:
                            knowledge_chunks.append(
                                ContextKnowledgeChunkItem(
                                    chunk_id=chunk.id,
                                    source_document=chunk.source_document,
                                    section_title=chunk.section_title or "General",
                                    chunk_index=chunk.chunk_index,
                                    similarity_score=round(chunk.similarity_score, 4),
                                    content=chunk.content,
                                )
                            )
                    else:
                        retrieval_uncertainty = (
                            "RETRIEVED_NO_MATCH: Semantic knowledge retrieval executed but returned zero matching chunks."
                        )
                except Exception as exc:
                    svc_logger.warning("Semantic knowledge retrieval encountered operational failure", error=str(exc))
                    retrieval_uncertainty = (
                        "RETRIEVAL_FAILED: Semantic knowledge retrieval encountered operational failure during query execution."
                    )

            # 6. Assemble Canonical InvestigationContext
            uncertainty_flags: list[str] = []
            if not context_events and not undated_count:
                uncertainty_flags.append("NO_TELEMETRY_IN_SCOPE: No case evidence recorded in the specified scope")
            if undated_count:
                # Same wording as the incident path (workflow.py UNDATED_OBSERVATIONS).
                uncertainty_flags.append(
                    f"UNDATED_OBSERVATIONS: {undated_count} observation(s) have no usable event time and were not placed on the timeline"
                )
            if retrieval_uncertainty:
                uncertainty_flags.append(retrieval_uncertainty)

            has_unlinked = any(_is_unlinked_or_missing_hash(e.raw_evidence_sha256) for e in context_events)
            if has_unlinked:
                uncertainty_flags.append(
                    "PROVENANCE_LIMITATION: One or more telemetry events lack cryptographic raw-evidence bindings; raw source integrity unverified."
                )
            if request.root_event_id and not any(e.event_uuid == request.root_event_id for e in context_events):
                uncertainty_flags.append(
                    "ROOT_ANCHOR_FALLBACK_APPLIED: Caller-specified root_event_id was absent from queried telemetry; context anchor designated via chronological/severity fallback."
                )
            elif request.root_event_id and any(
                e.event_uuid == request.root_event_id and _is_unlinked_or_missing_hash(e.raw_evidence_sha256)
                for e in context_events
            ):
                uncertainty_flags.append(
                    "ROOT_PROVENANCE_MISSING: Root anchor event lacks cryptographic raw-evidence binding."
                )

            if request.time_window_start is not None and request.time_window_end is not None:
                start_time = request.time_window_start
                end_time = request.time_window_end
            elif context_events:
                start_time = min(e.timestamp_utc for e in context_events)
                end_time = max(e.timestamp_utc for e in context_events) + timedelta(seconds=1)
            else:
                now_utc = datetime.now(timezone.utc)
                start_time = now_utc - timedelta(hours=1)
                end_time = now_utc

            scope_type = (
                InvestigationScopeType.SINGLE_EVENT
                if len(context_events) == 1
                else InvestigationScopeType.INCIDENT_TIMELINE
            )

            active_llm = llm_provider or get_llm_provider()
            default_model = getattr(active_llm, "model_name", "llama3.1:8b")
            target_model = request.model_override or default_model

            builder = context_builder or InvestigationContextBuilder()
            context = builder.build_structured_context(
                events=context_events,
                investigation_id=uuid.uuid4(),
                root_event_id=request.root_event_id,
                scope_type=scope_type,
                time_window_start=start_time,
                time_window_end=end_time,
                target_hosts=sorted(target_hosts_set) if target_hosts_set else None,
                entities=extracted_entities_for_ti if extracted_entities_for_ti else None,
                threat_intel=ti_findings,
                knowledge_chunks=knowledge_chunks,
                query_filter=request.query_filter,
                llm_provider="ollama",
                model_name=target_model,
                uncertainty_flags=uncertainty_flags,
            )

        # ── EXIT PHASE A: phase_a_session is CLOSED. Connection is released! ──
        if session_release_callback:
            if asyncio.iscoroutinefunction(session_release_callback):
                await session_release_callback()
            else:
                session_release_callback()

        # ── PHASE B — LOCAL INFERENCE (Zero active DB connections held) ──────
        parser = response_parser or InvestigationResponseParser()
        val = validator or InvestigationOutputValidator(attack_reference=resolve_attack_reference())

        def _build_fallback_result(reason: str, sufficiency: Any = None) -> InvestigationValidationResult:
            fallback = parser.build_deterministic_fallback(context, reason, sufficiency)
            validated = val.validate(fallback, context)
            return InvestigationValidationResult(
                decision=GuardrailDecision.REJECT_TO_FALLBACK,
                is_valid=False,
                output=validated.output,
                violations=validated.violations,
                context_sha256=context.reproducibility.context_sha256,
                validated_at_utc=datetime.now(timezone.utc),
            )

        # ── DETERMINISTIC EVIDENCE-SUFFICIENCY GATE (Stage 3C, ADR-008) ──────
        # Runs before ANY model invocation, with no DB connection held. Fails closed:
        # an exception inside the gate yields INSUFFICIENT, which forbids the model call.
        assessment = evaluate_sufficiency(context, contradiction_candidates)
        svc_logger.info(
            "Evidence sufficiency assessed",
            investigation_id=str(context.investigation_id),
            verdict=assessment.verdict.value,
            reason_codes=assessment.reason_codes,
            assessment_sha256=assessment.assessment_sha256,
        )
        sufficiency_note = assessment.limitation_note()

        fallback_reason = ""
        if assessment.abstain:
            fallback_reason = "Evidence assessed INSUFFICIENT: " + ", ".join(assessment.reason_codes)
            validation_result = _build_fallback_result(fallback_reason, assessment)
        else:
            pb = prompt_builder or InvestigationPromptBuilder(default_model=default_model, structured_assertions=True)
            max_attempts = 2
            raw_response = None
            validation_result = None

            for attempt in range(max_attempts):
                if attempt == 0:
                    llm_request = pb.build_request(
                        context,
                        model_override=request.model_override,
                        sufficiency_note=sufficiency_note,
                    )
                else:
                    svc_logger.info(
                        "Executing bounded retry for truncated investigation synthesis",
                        attempt=attempt,
                        investigation_id=str(context.investigation_id),
                    )
                    llm_request = pb.build_retry_request(
                        context,
                        model_override=request.model_override,
                        sufficiency_note=sufficiency_note,
                    )

                raw_response = None
                try:
                    raw_response = await GatedGenerator.generate(active_llm, llm_request, assessment, context)
                except LLMTimeoutError as exc:
                    svc_logger.warning("Case synthesis LLM timeout", error=str(exc))
                    fallback_reason = f"LLM inference timed out: {exc}"
                    break
                except LLMConnectionError as exc:
                    svc_logger.warning("Case synthesis LLM connection failed", error=str(exc))
                    fallback_reason = f"LLM provider unavailable: {exc}"
                    break
                except LLMError as exc:
                    svc_logger.warning("Case synthesis LLM provider error", error=str(exc))
                    fallback_reason = f"LLM provider failure: {exc}"
                    break
                except Exception as exc:
                    svc_logger.error("Case synthesis unexpected inference error", error=str(exc))
                    fallback_reason = f"Internal inference execution failure: {exc}"
                    break

                if raw_response is None:
                    break

                is_length_truncated = getattr(raw_response, "finish_reason", None) == "length"

                try:
                    parsed_output = parser.parse(raw_response, context)
                    validation_result = val.validate(parsed_output, context, assessment)
                    if validation_result.decision == GuardrailDecision.REJECT_TO_FALLBACK:
                        fallback_reason = f"Guardrail validation rejected output: {len(validation_result.violations)} violation(s)"
                    break
                except ResponseParsingError as exc:
                    err_msg = str(exc).lower()
                    is_truncated_parse = (
                        is_length_truncated
                        or "truncated" in err_msg
                        or "length" in err_msg
                        or "unterminated" in err_msg
                    )
                    if attempt == 0 and is_truncated_parse:
                        svc_logger.warning(
                            "Case synthesis output was truncated, triggering bounded retry",
                            error=str(exc),
                            attempt=attempt,
                        )
                        continue
                    svc_logger.warning("Case synthesis parsing failed", error=str(exc))
                    fallback_reason = f"Response parsing failure: {exc}"
                    validation_result = _build_fallback_result(fallback_reason)
                    break

            if validation_result is None:
                validation_result = _build_fallback_result(fallback_reason or "Inference failed without producing valid output")

        # 3C-R: the sufficiency verdict must reach the analyst-facing output, not only the prompt.
        validation_result = apply_sufficiency_disclosure(validation_result, assessment)

        # Stage 7A (D1): "event time unknown" must reach the analyst-facing output whatever the model produced (deterministic, same
        # fixed wording as the incident path). The record's ingestion time is kept separately in the stored record, never shown as an event time.
        undated_flags = [f for f in context.uncertainty_flags if f.startswith("UNDATED_OBSERVATIONS")]
        if undated_flags:
            _gaps = list(validation_result.output.uncertainty_and_data_gaps)
            _add = [f for f in undated_flags if f not in _gaps]
            if _add:
                validation_result = validation_result.model_copy(
                    update={"output": validation_result.output.model_copy(update={"uncertainty_and_data_gaps": _gaps + _add})}
                )

        # ── PHASE C — REVALIDATE, AUDIT, AND RETURN (Acquire fresh session) ───
        async with isolated_session(session_factory=session_factory, fallback_session=session) as phase_c_session:
            # 1. Analyst check
            analyst_stmt = select(Analyst).where(Analyst.id == actor.analyst_id)
            analyst_res = await phase_c_session.execute(analyst_stmt)
            current_analyst = analyst_res.scalars().first()
            if current_analyst is None or not current_analyst.is_active:
                svc_logger.warning("Synthesis discarded: analyst account deactivated during inference", analyst_id=str(actor.analyst_id))
                raise CodedHTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Analyst authorization revoked: account was deactivated during synthesis.",
                    code="AUTHORIZATION_REVOKED",
                )

            # 2. Case check
            case_stmt = select(CaseModel).where(CaseModel.id == case_id)
            case_res = await phase_c_session.execute(case_stmt)
            current_case = case_res.scalars().first()
            if current_case is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Case not found or access denied.",
                )
            if current_case.status in (CaseStatus.CLOSED.value, CaseStatus.ARCHIVED.value):
                svc_logger.warning("Synthesis discarded: case closed/archived during inference", case_id=str(case_id))
                raise CodedHTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Case status invalidated: case was closed or archived during synthesis.",
                    code="SYNTHESIS_INPUT_CHANGED",
                )

            # 3. Assignment check
            assign_stmt = select(CaseAssignmentModel).where(
                CaseAssignmentModel.case_id == case_id,
                CaseAssignmentModel.analyst_id == actor.analyst_id,
            )

            assign_res = await phase_c_session.execute(assign_stmt)
            current_assign = assign_res.scalars().first()
            if current_assign is None or not can_execute_case_synthesis(current_analyst.global_role, current_assign.case_role):
                svc_logger.warning("Synthesis discarded: assignment revoked or role downgraded during inference", case_id=str(case_id))
                raise CodedHTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Analyst case assignment was revoked or downgraded during synthesis.",
                    code="AUTHORIZATION_REVOKED",
                )

            # 4. Evidence consistency & mutation check (SEC-D24-002 & SEC-D24-004)
            c_ev_stmt = (
                select(NormalizedEventModel, CaseEvidenceModel)
                .join(CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id)
                .options(
                    joinedload(NormalizedEventModel.entities),
                    joinedload(NormalizedEventModel.raw_evidence),
                )
                .where(CaseEvidenceModel.case_id == case_id)
                .order_by(NormalizedEventModel.event_timestamp.asc())
            )
            if request.time_window_start is not None:
                c_ev_stmt = c_ev_stmt.where(NormalizedEventModel.event_timestamp >= request.time_window_start)
            if request.time_window_end is not None:
                c_ev_stmt = c_ev_stmt.where(NormalizedEventModel.event_timestamp < request.time_window_end)

            c_ev_res = await phase_c_session.execute(c_ev_stmt)
            c_orm_rows = c_ev_res.unique().all()
            current_ev_ids = frozenset(ev.id for ev, _ in c_orm_rows)

            # Exact set equality check (SEC-D24-002)
            if current_ev_ids != phase_a_evidence_ids:
                if not phase_a_evidence_ids.issubset(current_ev_ids):
                    svc_logger.warning("Synthesis discarded: evidence unlinked during inference", case_id=str(case_id))
                    detail = "Case evidence invalidated: one or more evidence records were unlinked during synthesis."
                else:
                    svc_logger.warning("Synthesis discarded: new evidence linked during inference", case_id=str(case_id))
                    detail = "Case evidence invalidated: new evidence was linked to the case during synthesis."
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=detail,
                )

            # Re-compute evidence content & mutation fingerprint (SEC-D24-004)
            c_snapshot_items = []
            for ev, link in c_orm_rows:
                raw_hash = (
                    ev.raw_evidence.sha256_hash
                    if ev.raw_evidence and ev.raw_evidence.sha256_hash
                    else ("0" * 64)
                )
                source_id = (
                    ev.raw_evidence.source_identifier
                    if ev.raw_evidence and ev.raw_evidence.source_identifier
                    else (getattr(ev, "source_identifier", None) or ev.provider or "unknown")
                )
                ts = ev.event_timestamp
                ts_iso = ts.isoformat() if ts else ""
                c_snapshot_items.append({
                    "evidence_id": str(ev.id),
                    "link_id": str(link.id),
                    "event_id": str(ev.event_id),
                    "event_type": str(ev.event_type),
                    "action": str(ev.action),
                    "outcome": str(ev.outcome or "unknown"),
                    "severity": str(ev.severity or "informational"),
                    "timestamp": ts_iso,
                    "source_identifier": str(source_id),
                    "raw_hash": str(raw_hash),
                    "normalized_payload": dict(ev.normalized_payload or {}),
                })

            c_snapshot_items.sort(key=lambda x: x["evidence_id"])
            c_canonical_json = canonicalize_payload(c_snapshot_items)
            current_evidence_fingerprint = hashlib.sha256(c_canonical_json.encode("utf-8")).hexdigest().lower()

            if current_evidence_fingerprint != phase_a_evidence_fingerprint:
                svc_logger.warning("Synthesis discarded: evidence content or link attributes mutated during inference", case_id=str(case_id))
                raise CodedHTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Case evidence invalidated: normalized event content, severity, attributes, or associations were modified during synthesis.",
                    code="SYNTHESIS_INPUT_CHANGED",
                )

            # 5. Transactional Audit Write
            now_c = datetime.now(timezone.utc)
            output_sha256 = compute_validation_output_sha256(validation_result)
            actual_model = validation_result.output.model_identifier
            target_model = context.reproducibility.model_name

            audit_details: dict[str, Any] = {
                "investigation_id": str(context.investigation_id),
                "decision": validation_result.decision.value,
                "is_valid": validation_result.is_valid,
                "evidence_count": len(context.events),
                "grounding_score": validation_result.output.overall_grounding_score,
                "model_name": actual_model,
                "target_model": target_model,
                "output_sha256": output_sha256,
            }
            audit_details.update(assessment.audit_details())
            if fallback_reason:
                audit_details["fallback_reason"] = fallback_reason[:200]
            elif actual_model == "deterministic_fallback" and validation_result.violations:
                audit_details["fallback_reason"] = (
                    f"Guardrail validation rejected output: {len(validation_result.violations)} violation(s)"
                )

            audit = CaseAuditEventModel(
                id=uuid.uuid4(),
                case_id=case_id,
                actor_analyst_id=actor.analyst_id,
                actor_username=actor.username,
                action=audit_action,
                context_sha256=context.reproducibility.context_sha256,
                details=audit_details,
                created_at=now_c,
            )
            phase_c_session.add(audit)
            try:
                await phase_c_session.commit()
            except Exception as exc:
                await phase_c_session.rollback()
                svc_logger.error("Audit write failure: result suppressed", error=str(exc))
                raise CodedHTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Audit logging failed; investigation result suppressed.",
                    code="AUDIT_LOGGING_FAILED",
                )

        return validation_result, context

    async def synthesize_case_reports(
        self,
        case_id: Any = None,
        actor: AuthenticatedAnalyst | None = None,
        request: CaseInvestigationSynthesizeRequest | None = None,
        session_factory: Any | None = None,
        session: AsyncSession | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> InvestigationReportBundle:
        """
        Execute case-scoped investigation synthesis and generate deterministic role-tailored report bundle.
        """
        if isinstance(case_id, (AsyncSession, object)) and hasattr(case_id, "execute") and actor is not None and isinstance(actor, uuid.UUID):
            session = case_id
            case_id = actor
            actor = request  # type: ignore
            request = kwargs.get("request") or (args[0] if args else CaseInvestigationSynthesizeRequest())

        if request is None:
            request = CaseInvestigationSynthesizeRequest()

        validation_result, context = await self.synthesize_case_investigation(
            case_id=case_id,
            actor=actor,
            request=request,
            session_factory=session_factory,
            session=session,
            audit_action="case_report_synthesized",
            **kwargs,
        )
        synthesizer = DeterministicReportSynthesizer()
        return synthesizer.synthesize_bundle(
            validation_result=validation_result,
            context=context,
            is_server_verified=True,
        )

    async def export_case_report(
        self,
        case_id: uuid.UUID,
        actor: AuthenticatedAnalyst,
        export_format: str = "markdown",
        view: str = "bundle",
        session_factory: Any | None = None,
        session: AsyncSession | None = None,
        **kwargs: Any,
    ) -> ReportExportResponse:
        """
        Export a deterministic role-tailored report or consolidated bundle in Markdown or JSON format,
        anchored in the case audit log.
        """
        bundle = await self.synthesize_case_reports(
            case_id=case_id,
            actor=actor,
            session_factory=session_factory,
            session=session,
            **kwargs,
        )

        format_norm = export_format.strip().lower()
        view_norm = view.strip().lower()

        if format_norm == "json":
            content = bundle.model_dump_json(indent=2)
            filename = f"aisop-case-{str(case_id)[:8]}-report-{view_norm}.json"
        else:
            format_norm = "markdown"
            if view_norm == "executive":
                content = bundle.markdown_executive
            elif view_norm == "technical":
                content = bundle.markdown_technical
            elif view_norm == "detection":
                content = bundle.markdown_detection
            else:
                view_norm = "bundle"
                content = (
                    f"# AISOP Consolidated Incident Investigation Report\n\n"
                    f"- **Case ID:** `{case_id}`\n"
                    f"- **Investigation ID:** `{bundle.investigation_id}`\n"
                    f"- **Context SHA-256:** `{bundle.context_sha256}`\n"
                    f"- **Generated At:** {bundle.generated_at_utc.isoformat()} (UTC)\n"
                    f"- **Integrity Verification:** Cryptographically Anchored in Server Audit Log\n\n"
                    f"---\n\n"
                    f"## Part 1 — Executive Brief\n\n"
                    f"{bundle.markdown_executive}\n\n"
                    f"---\n\n"
                    f"## Part 2 — Technical Incident Response Report\n\n"
                    f"{bundle.markdown_technical}\n\n"
                    f"---\n\n"
                    f"## Part 3 — Detection Engineering Report\n\n"
                    f"{bundle.markdown_detection}\n"
                )
            filename = f"aisop-case-{str(case_id)[:8]}-report-{view_norm}.md"

        # Record append-only audit event for export
        actor_id = getattr(actor, "analyst_id", getattr(actor, "id", None)) if actor else None
        audit_details = {
            "format": format_norm,
            "view": view_norm,
            "filename": filename,
            "investigation_id": str(bundle.investigation_id),
        }
        if session is not None:
            audit_event = CaseAuditEventModel(
                case_id=case_id,
                actor_analyst_id=actor_id,
                actor_username=actor.username if actor else "system",
                action="case_report_exported",
                context_sha256=bundle.context_sha256,
                details=audit_details,
            )
            session.add(audit_event)
            await session.flush()
        elif session_factory is not None:
            async with isolated_session(session_factory=session_factory) as db_sess:
                audit_event = CaseAuditEventModel(
                    case_id=case_id,
                    actor_analyst_id=actor_id,
                    actor_username=actor.username if actor else "system",
                    action="case_report_exported",
                    context_sha256=bundle.context_sha256,
                    details=audit_details,
                )
                db_sess.add(audit_event)
                await db_sess.commit()

        return ReportExportResponse(
            case_id=case_id,
            investigation_id=bundle.investigation_id,
            format=format_norm,
            view=view_norm,
            filename=filename,
            content=content,
            context_sha256=bundle.context_sha256,
            exported_at_utc=datetime.now(timezone.utc),
            is_server_verified=True,
        )


