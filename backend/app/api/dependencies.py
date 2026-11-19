"""
AISOP FastAPI Request Dependencies.
"""

from __future__ import annotations

import uuid
from typing import Callable, Sequence

from fastapi import Depends, HTTPException, Path, Request, status
from app.core.errors import CodedHTTPException
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.auth import AuthenticatedClient, verify_api_key
from app.core.config import get_settings
from app.core.rbac import (
    AuthenticatedAnalyst,
    AuthenticatedCaseContext,
    CaseRole,
    GlobalRole,
    parse_case_role,
    parse_global_role,
)
from app.db.session import get_db_session
from app.modules.ai.knowledge.retriever import KnowledgeRetriever
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.services.case_service import CaseService

__all__ = [
    "AuthenticatedClient",
    "verify_api_key",
    "get_threat_intel_engine",
    "get_knowledge_retriever",
    "AuthenticatedAnalyst",
    "AuthenticatedCaseContext",
    "get_current_analyst",
    "get_case_assignment_context",
    "require_global_role",
    "require_case_role",
]


def get_threat_intel_engine(request: Request) -> LocalThreatIntelEngine | None:
    """
    Retrieve application-scoped LocalThreatIntelEngine from FastAPI app.state.
    Returns None if uninitialized or unavailable, allowing conservative failure handling.
    """
    return getattr(request.app.state, "threat_intel_engine", None)


def get_knowledge_retriever(request: Request) -> KnowledgeRetriever | None:
    """
    Retrieve application-scoped KnowledgeRetriever from FastAPI app.state.
    Returns None if uninitialized or unavailable, allowing conservative failure handling.
    Returns None when AI assistance is disabled: retrieval embeds the query through the local model endpoint, which must not be called.
    """
    if not get_settings().LLM_ENABLED:
        return None
    return getattr(request.app.state, "knowledge_retriever", None)


# ── RBAC & Case Scoping Authorization Dependencies (Gate B Contracts) ────────


async def get_current_analyst(
    client: AuthenticatedClient = Depends(verify_api_key),
) -> AuthenticatedAnalyst:
    """
    Resolve and return the authenticated human analyst or principal identity.

    Security Invariants:
    - Reuses the identity verified during ingress authentication.
    - Fails closed with HTTP 401 if credentials do not resolve to an analyst.
    - Fails closed with HTTP 403 if the analyst account is deactivated.
    """
    if not isinstance(client, AuthenticatedClient) or client.analyst is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated credentials do not resolve to an analyst identity.",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    if not client.analyst.is_active:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst account is deactivated.",
            code="ACCOUNT_DEACTIVATED",
        )
    return client.analyst


def get_case_service() -> CaseService:
    """Dependency provider for CaseService."""
    return CaseService()


async def get_case_assignment_context(
    case_id: uuid.UUID = Path(..., description="Case UUID"),
    analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    session: AsyncSession = Depends(get_db_session),
    case_service: CaseService = Depends(get_case_service),
) -> AuthenticatedCaseContext:
    """
    Resolve and verify an analyst's active assignment on a specific security case.

    Security Invariants:
    - Reuses the verified analyst identity from ingress token authentication.
    - Validates path parameter `case_id` as a UUID.
    - Rejects inactive analyst accounts with HTTP 403 Forbidden.
    - Anti-enumeration: Missing cases and unassigned access return generic HTTP 404 Not Found.
    - Decision 2A (Strict Administrator Parity): security_admin receives no implicit bypass
      and must possess an active case assignment.
    - Fails closed on database errors with HTTP 500 without leaking SQL or internal details.
    """
    if analyst is None or not isinstance(analyst, AuthenticatedAnalyst):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated credentials do not resolve to an analyst identity.",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    if not analyst.is_active:
        raise CodedHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst account is deactivated.",
            code="ACCOUNT_DEACTIVATED",
        )

    if case_id is None or not isinstance(case_id, uuid.UUID):
        raise CodedHTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid case identifier. Must be a valid UUID.",
            code="INVALID_CASE_IDENTIFIER",
        )

    if session is None:
        logger.error("Case assignment resolution failed: database session is unavailable")
        raise CodedHTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authorization service unavailable.",
            code="AUTHORIZATION_SERVICE_UNAVAILABLE",
        )

    svc = case_service or CaseService()
    try:
        context = await svc.get_assignment_context(
            session=session,
            case_id=case_id,
            analyst_id=analyst.analyst_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Database error during case assignment lookup",
            error_type=type(exc).__name__,
        )
        raise CodedHTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authorization service unavailable.",
            code="AUTHORIZATION_SERVICE_UNAVAILABLE",
        ) from None

    if context is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found or access denied.",
        )

    return context


def require_global_role(
    *allowed_roles: GlobalRole | str,
) -> Callable[..., AuthenticatedAnalyst]:
    """
    Construct a FastAPI dependency that verifies the caller holds one of the allowed global roles.

    Enforces:
    - Inactive analyst rejection (HTTP 403 Forbidden).
    - Strict role validation against canonical GlobalRole enum.
    - Deny-by-default for missing or unauthorized roles (HTTP 403 Forbidden).
    """
    parsed_targets: set[GlobalRole] = {parse_global_role(r) for r in allowed_roles}

    async def _dependency(
        analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    ) -> AuthenticatedAnalyst:
        if not analyst.is_active:
            raise CodedHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Analyst account is deactivated.",
                code="ACCOUNT_DEACTIVATED",
            )
        if analyst.global_role not in parsed_targets:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient global role permissions.",
            )
        return analyst

    return _dependency


def require_case_role(
    *allowed_roles: CaseRole | str,
) -> Callable[..., AuthenticatedCaseContext]:
    """
    Construct a FastAPI dependency that verifies the analyst has an active case assignment
    matching one of the required case roles.

    Enforces:
    - Decision 2A (Strict Administrator Parity): security_admin receives no implicit
      bypass and must possess an active case assignment.
    - Anti-enumeration: Unassigned analysts receive HTTP 404 Not Found rather than 403,
      preventing case UUID probing.
    - Inactive analyst rejection (HTTP 403 Forbidden).
    """
    parsed_targets: set[CaseRole] = {parse_case_role(r) for r in allowed_roles}

    async def _dependency(
        context: AuthenticatedCaseContext | None = Depends(get_case_assignment_context),
        analyst: AuthenticatedAnalyst = Depends(get_current_analyst),
    ) -> AuthenticatedCaseContext:
        if not analyst.is_active:
            raise CodedHTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Analyst account is deactivated.",
                code="ACCOUNT_DEACTIVATED",
            )
        if context is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Case not found or access denied.",
            )
        if context.case_role not in parsed_targets:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient case role permissions.",
            )
        return context

    return _dependency

