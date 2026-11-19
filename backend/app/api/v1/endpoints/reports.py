from __future__ import annotations

import secrets
from datetime import timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.investigations import get_investigation_service
from app.core.auth import AuthenticatedClient, verify_api_key
from app.core.errors import (
    CodedHTTPException,
    CONTEXT_INTEGRITY_FAILED,
    REPORT_PARAMETER_INVALID,
    ApiError,
    safe_exception_text,
)
from app.db.session import get_db_session, get_db_session_factory, isolated_session
from app.models.case import CaseAuditEventModel
from app.modules.ai.context_builder import IncompleteContextOverflowError
from app.modules.ai.context_builder.hasher import compute_validation_output_sha256
from app.modules.ai.guardrails.validator import GuardrailDecision
from app.modules.ai.reporting import (
    ContextIntegrityError,
    DeterministicReportSynthesizer,
    verify_context_binding,
)
from app.schemas.investigation import InvestigationSynthesizeRequest
from app.schemas.report import InvestigationReportBundle, ReportFormatRequest
from app.services.case_service import CaseService
from app.services.investigation_service import InvestigationPipelineService

report_logger = logger.bind(component="reporting_api")

router = APIRouter(prefix="/reports", tags=["Reporting"])


@router.post(
    "/synthesize",
    response_model=InvestigationReportBundle,
    summary="Synthesize grounded incident investigation report bundle",
)
async def synthesize_reports(
    request: InvestigationSynthesizeRequest,
    client: AuthenticatedClient = Depends(verify_api_key),
    session: AsyncSession = Depends(get_db_session),
    service: InvestigationPipelineService = Depends(get_investigation_service),
) -> InvestigationReportBundle:
    """
    Direct unscoped report synthesis is deprecated and disabled (Gate D.2.4).
    Report bundles must be generated within an authorized case boundary via
    /api/v1/cases/{case_id}/reports/synthesize.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access report synthesis.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    raise CodedHTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Direct unscoped report synthesis is disabled. Case-scoped report synthesis via /api/v1/cases/{case_id}/reports/synthesize is required.",
        code="UNSCOPED_ENDPOINT_DISABLED",
    )


@router.post(
    "/format",
    response_model=InvestigationReportBundle,
    summary="Format investigation validation result into report bundle",
)
async def format_reports(
    request: ReportFormatRequest,
    client: AuthenticatedClient = Depends(verify_api_key),
    session_factory: Any = Depends(get_db_session_factory),
) -> InvestigationReportBundle:
    """
    Format an existing InvestigationValidationResult into role-tailored report views.
    Requires an active authenticated human analyst (Gate D.2.4).
    Enforces server-side audit binding and case authorization:
    - If case_id is provided, verifies active case assignment (anti-enumeration 404 for unassigned)
      and validates cryptographic provenance against server-side CaseAuditEvent records.
    - If unverified or detached, demotes claims to unverified inferences and strips confirmed status.
    - If context is provided, verifies canonical SHA-256 context hash consistency.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access report formatting.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    if not client.analyst.is_active:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive analyst cannot access report formatting.",
            code="ACCOUNT_DEACTIVATED",
        )

    try:
        if request.context is not None:
            verify_context_binding(request.validation_result, request.context)

        is_server_verified = False
        if request.case_id is not None:
            case_svc = CaseService()
            async with isolated_session(session_factory=session_factory) as db:
                assignment_ctx = await case_svc.get_assignment_context(
                    session=db,
                    case_id=request.case_id,
                    analyst_id=client.analyst.analyst_id,
                )
                if assignment_ctx is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Case not found or access denied.",
                    )

                submitted_output_sha256 = compute_validation_output_sha256(request.validation_result)

                audit_stmt = (
                    select(CaseAuditEventModel)
                    .where(
                        CaseAuditEventModel.case_id == request.case_id,
                        CaseAuditEventModel.context_sha256 == request.validation_result.context_sha256,
                        CaseAuditEventModel.action.in_([
                            "case_investigation_synthesized",
                            "case_report_synthesized",
                        ]),
                    )
                    .order_by(CaseAuditEventModel.created_at.desc())
                )
                audit_res = await db.execute(audit_stmt)
                audit_events = audit_res.scalars().all()
                for audit_event in audit_events:
                    details = audit_event.details or {}
                    stored_output_sha256 = details.get("output_sha256")
                    if not stored_output_sha256:
                        # Legacy or unverified audit record lacking output digest binding
                        continue

                    # Exact output digest match (SEC-D243-001 trust boundary)
                    if not secrets.compare_digest(str(stored_output_sha256), str(submitted_output_sha256)):
                        continue

                    # Exact investigation ID match
                    if str(details.get("investigation_id", "")) != str(request.validation_result.output.investigation_id):
                        continue

                    # Decision match and must be valid non-fallback
                    if details.get("decision") != request.validation_result.decision.value:
                        continue
                    if details.get("decision") == GuardrailDecision.REJECT_TO_FALLBACK.value:
                        continue
                    if request.validation_result.decision == GuardrailDecision.REJECT_TO_FALLBACK:
                        continue

                    # Validity match: both server audit and submitted result must be valid
                    if details.get("is_valid") is not True or request.validation_result.is_valid is not True:
                        continue

                    # All trust-boundary checks satisfied
                    is_server_verified = True
                    break

        synthesizer = DeterministicReportSynthesizer()
        return synthesizer.synthesize_bundle(
            validation_result=request.validation_result,
            context=request.context,
            is_server_verified=is_server_verified,
        )

    except ContextIntegrityError as exc:
        report_logger.warning("Context integrity verification failed", error=str(exc))
        raise ApiError(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            CONTEXT_INTEGRITY_FAILED,
            "Context integrity verification failed.",
        )
    except ValueError as exc:
        report_logger.warning("Report format rejected: invalid parameter", error=str(exc))
        raise ApiError(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            REPORT_PARAMETER_INVALID,
            safe_exception_text(exc, "A report parameter is invalid."),
        )
    except HTTPException:
        raise
    except Exception as exc:
        report_logger.error("Unhandled exception in report formatting", error=str(exc))
        raise CodedHTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred during report formatting.",
            code="REPORT_FORMATTING_FAILED",
        )

