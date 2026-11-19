"""
AISOP Investigation Synthesis Endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from app.core.errors import CodedHTTPException
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_knowledge_retriever, get_threat_intel_engine
from app.core.auth import AuthenticatedClient, verify_api_key
from app.db.session import get_db_session
from app.modules.ai.context_builder import IncompleteContextOverflowError
from app.modules.ai.guardrails import InvestigationValidationResult
from app.modules.ai.knowledge.retriever import KnowledgeRetriever
from app.modules.ai.llm.manager import get_llm_provider_or_inert
from app.modules.ai.llm.protocol import LLMProvider
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.schemas.investigation import InvestigationSynthesizeRequest
from app.services.investigation_service import InvestigationPipelineService

router = APIRouter(prefix="/investigations", tags=["Investigations"])


def get_investigation_service(
    ti_engine: LocalThreatIntelEngine | None = Depends(get_threat_intel_engine),
    knowledge_retriever: KnowledgeRetriever | None = Depends(get_knowledge_retriever),
) -> InvestigationPipelineService:
    """Dependency provider for InvestigationPipelineService."""
    return InvestigationPipelineService(
        llm_provider=get_llm_provider_or_inert(),
        threat_intel_engine=ti_engine,
        knowledge_retriever=knowledge_retriever,
    )


@router.post(
    "/synthesize",
    response_model=InvestigationValidationResult,
    summary="Synthesize grounded incident investigation report",
)
async def synthesize_investigation(
    request: InvestigationSynthesizeRequest,
    client: AuthenticatedClient = Depends(verify_api_key),
    session: AsyncSession = Depends(get_db_session),
    service: InvestigationPipelineService = Depends(get_investigation_service),
) -> InvestigationValidationResult:
    """
    Direct unscoped investigation synthesis is deprecated and disabled (Gate D.2.4).
    Investigations must be executed within an authorized case boundary via
    /api/v1/cases/{case_id}/investigations/synthesize.
    """
    if client.analyst is None:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Machine credentials without analyst identity cannot access investigation synthesis.",
            code="MACHINE_CREDENTIAL_NOT_PERMITTED",
        )

    raise CodedHTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Direct unscoped investigation synthesis is disabled. Case-scoped synthesis via /api/v1/cases/{case_id}/investigations/synthesize is required.",
        code="UNSCOPED_ENDPOINT_DISABLED",
    )

