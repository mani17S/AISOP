"""
Unit tests for AISOP RBAC and Case-Scoping FastAPI Authorization Dependencies.

Provably offline tests verifying:
- Unimplemented interfaces fail closed with HTTP 501 (pending database migration)
- require_global_role dependency enforces:
  - Canonical role matching
  - Role mismatch rejection with HTTP 403 Forbidden
  - Deactivated analyst rejection with HTTP 403 Forbidden
- require_case_role dependency enforces:
  - Decision 2A (Strict Administrator Parity): security_admin receives no bypass
  - Anti-enumeration behavior: unassigned access returns HTTP 404 Not Found
  - Insufficient case role returns HTTP 403 Forbidden
  - Deactivated analyst returns HTTP 403 Forbidden
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock
import pytest
from fastapi import HTTPException, status

from app.api.dependencies import (
    AuthenticatedAnalyst,
    AuthenticatedCaseContext,
    AuthenticatedClient,
    CaseRole,
    GlobalRole,
    get_case_assignment_context,
    get_current_analyst,
    require_case_role,
    require_global_role,
)


class TestDefaultDependencyFailClosed:
    @pytest.mark.anyio
    async def test_get_current_analyst_fails_closed_without_valid_analyst(self):
        with pytest.raises(HTTPException) as exc_info:
            await get_current_analyst()
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "do not resolve to an analyst identity" in exc_info.value.detail

    @pytest.mark.anyio
    async def test_get_current_analyst_resolves_valid_analyst(self):
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="analyst_alice",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        client = AuthenticatedClient(
            client_id="analyst-client-1",
            authenticated=True,
            analyst=analyst,
        )
        resolved = await get_current_analyst(client=client)
        assert resolved == analyst

    @pytest.mark.anyio
    async def test_get_current_analyst_rejects_inactive_analyst(self):
        inactive_analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="deactivated_bob",
            global_role=GlobalRole.ANALYST_TIER_2,
            is_active=False,
        )
        client = AuthenticatedClient(
            client_id="analyst-client-2",
            authenticated=True,
            analyst=inactive_analyst,
        )
        with pytest.raises(HTTPException) as exc_info:
            await get_current_analyst(client=client)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "deactivated" in exc_info.value.detail.lower()

class TestGetCaseAssignmentContext:
    """Offline unit tests for database-backed get_case_assignment_context."""

    @pytest.mark.anyio
    async def test_active_analyst_active_assignment_resolves_role(self):
        case_id = uuid.uuid4()
        analyst_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        analyst = AuthenticatedAnalyst(
            analyst_id=analyst_id,
            username="investigator_dave",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        mock_service = AsyncMock()
        mock_service.get_assignment_context.return_value = AuthenticatedCaseContext(
            case_id=case_id,
            analyst_id=analyst_id,
            case_role=CaseRole.INVESTIGATOR,
            assigned_at=now,
        )
        mock_session = AsyncMock()

        ctx = await get_case_assignment_context(
            case_id=case_id,
            analyst=analyst,
            session=mock_session,
            case_service=mock_service,
        )
        assert ctx.case_id == case_id
        assert ctx.analyst_id == analyst_id
        assert ctx.case_role == CaseRole.INVESTIGATOR
        assert ctx.assigned_at == now

    @pytest.mark.anyio
    async def test_missing_assignment_returns_404_anti_enumeration(self):
        case_id = uuid.uuid4()
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="unassigned_analyst",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        mock_service = AsyncMock()
        mock_service.get_assignment_context.return_value = None
        mock_session = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await get_case_assignment_context(
                case_id=case_id,
                analyst=analyst,
                session=mock_session,
                case_service=mock_service,
            )
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == "Case not found or access denied."

    @pytest.mark.anyio
    async def test_unknown_case_id_returns_404_anti_enumeration(self):
        unknown_case_id = uuid.uuid4()
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="analyst_test",
            global_role=GlobalRole.ANALYST_TIER_2,
            is_active=True,
        )
        mock_service = AsyncMock()
        mock_service.get_assignment_context.return_value = None
        mock_session = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await get_case_assignment_context(
                case_id=unknown_case_id,
                analyst=analyst,
                session=mock_session,
                case_service=mock_service,
            )
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == "Case not found or access denied."

    @pytest.mark.anyio
    async def test_deactivated_analyst_fails_closed_403(self):
        case_id = uuid.uuid4()
        deactivated = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="deactivated_alice",
            global_role=GlobalRole.SECURITY_ADMIN,
            is_active=False,
        )
        mock_service = AsyncMock()
        mock_session = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await get_case_assignment_context(
                case_id=case_id,
                analyst=deactivated,
                session=mock_session,
                case_service=mock_service,
            )
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "deactivated" in exc_info.value.detail.lower()
        mock_service.get_assignment_context.assert_not_called()

    @pytest.mark.anyio
    async def test_invalid_or_missing_analyst_fails_401(self):
        case_id = uuid.uuid4()
        mock_session = AsyncMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_case_assignment_context(
                case_id=case_id,
                analyst=None,
                session=mock_session,
            )
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.anyio
    async def test_invalid_case_id_type_fails_422(self):
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="analyst_bob",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        mock_session = AsyncMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_case_assignment_context(
                case_id="not-a-uuid",
                analyst=analyst,
                session=mock_session,
            )
        assert exc_info.value.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.anyio
    async def test_database_error_fails_closed_500(self):
        case_id = uuid.uuid4()
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="analyst_charlie",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        mock_service = AsyncMock()
        mock_service.get_assignment_context.side_effect = Exception("psycopg OperationalError: connection refused")
        mock_session = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await get_case_assignment_context(
                case_id=case_id,
                analyst=analyst,
                session=mock_session,
                case_service=mock_service,
            )
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc_info.value.detail == "Authorization service unavailable."
        assert "connection refused" not in exc_info.value.detail
        assert "psycopg" not in exc_info.value.detail

    @pytest.mark.anyio
    async def test_session_none_fails_closed_500(self):
        case_id = uuid.uuid4()
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="analyst_dan",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        with pytest.raises(HTTPException) as exc_info:
            await get_case_assignment_context(
                case_id=case_id,
                analyst=analyst,
                session=None,
            )
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc_info.value.detail == "Authorization service unavailable."

    @pytest.mark.anyio
    @pytest.mark.parametrize("role", [
        GlobalRole.SECURITY_ADMIN,
        GlobalRole.ANALYST_TIER_2,
        GlobalRole.ANALYST_TIER_1,
        GlobalRole.INGEST,
    ])
    async def test_all_global_roles_enforce_case_assignment_no_bypass(self, role):
        """
        Decision 2A: security_admin receives no implicit bypass; all roles must
        possess an active case assignment.
        """
        case_id = uuid.uuid4()
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username=f"user_{role.value}",
            global_role=role,
            is_active=True,
        )
        mock_service = AsyncMock()
        mock_service.get_assignment_context.return_value = None
        mock_session = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await get_case_assignment_context(
                case_id=case_id,
                analyst=analyst,
                session=mock_session,
                case_service=mock_service,
            )
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == "Case not found or access denied."


class TestRequireGlobalRoleDependency:
    @pytest.mark.anyio
    async def test_permits_authorized_role(self):
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="tier2_alice",
            global_role=GlobalRole.ANALYST_TIER_2,
            is_active=True,
        )
        dep = require_global_role(GlobalRole.ANALYST_TIER_2, GlobalRole.SECURITY_ADMIN)
        result = await dep(analyst=analyst)
        assert result.username == "tier2_alice"
        assert result.global_role == GlobalRole.ANALYST_TIER_2

    @pytest.mark.anyio
    async def test_rejects_unauthorized_role(self):
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="tier1_bob",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        # Endpoint requires Tier-2 or Security Admin
        dep = require_global_role(GlobalRole.ANALYST_TIER_2, GlobalRole.SECURITY_ADMIN)
        with pytest.raises(HTTPException) as exc_info:
            await dep(analyst=analyst)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Insufficient global role" in exc_info.value.detail

    @pytest.mark.anyio
    async def test_rejects_inactive_analyst(self):
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="deactivated_admin",
            global_role=GlobalRole.SECURITY_ADMIN,
            is_active=False,  # Inactive account
        )
        dep = require_global_role(GlobalRole.SECURITY_ADMIN)
        with pytest.raises(HTTPException) as exc_info:
            await dep(analyst=analyst)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "deactivated" in exc_info.value.detail.lower()


class TestRequireCaseRoleDependency:
    @pytest.mark.anyio
    async def test_permits_assigned_investigator(self):
        analyst_id = uuid.uuid4()
        case_id = uuid.uuid4()
        analyst = AuthenticatedAnalyst(
            analyst_id=analyst_id,
            username="investigator_charlie",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        context = AuthenticatedCaseContext(
            case_id=case_id,
            analyst_id=analyst_id,
            case_role=CaseRole.INVESTIGATOR,
            assigned_at=datetime.now(timezone.utc),
        )
        dep = require_case_role(CaseRole.INVESTIGATOR, CaseRole.LEAD)
        result = await dep(context=context, analyst=analyst)
        assert result.case_id == case_id
        assert result.case_role == CaseRole.INVESTIGATOR

    @pytest.mark.anyio
    async def test_rejects_lower_case_role(self):
        analyst_id = uuid.uuid4()
        case_id = uuid.uuid4()
        analyst = AuthenticatedAnalyst(
            analyst_id=analyst_id,
            username="viewer_dave",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        context = AuthenticatedCaseContext(
            case_id=case_id,
            analyst_id=analyst_id,
            case_role=CaseRole.VIEWER,  # Only viewer
            assigned_at=datetime.now(timezone.utc),
        )
        # Action requires investigator or lead (e.g. AI synthesis)
        dep = require_case_role(CaseRole.INVESTIGATOR, CaseRole.LEAD)
        with pytest.raises(HTTPException) as exc_info:
            await dep(context=context, analyst=analyst)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Insufficient case role" in exc_info.value.detail

    @pytest.mark.anyio
    async def test_decision_2a_administrator_parity_enforced(self):
        """
        Decision 2A: security_admin receives no implicit bypass and is subject
        to strict case assignment checks.
        """
        admin_id = uuid.uuid4()
        case_id = uuid.uuid4()
        admin = AuthenticatedAnalyst(
            analyst_id=admin_id,
            username="security_admin_eve",
            global_role=GlobalRole.SECURITY_ADMIN,
            is_active=True,
        )
        # Admin is only assigned as viewer
        context = AuthenticatedCaseContext(
            case_id=case_id,
            analyst_id=admin_id,
            case_role=CaseRole.VIEWER,
            assigned_at=datetime.now(timezone.utc),
        )
        # Endpoint requires Lead
        dep = require_case_role(CaseRole.LEAD)
        with pytest.raises(HTTPException) as exc_info:
            await dep(context=context, analyst=admin)
        # Must fail with 403 - no admin bypass!
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.anyio
    async def test_rejects_none_context_with_404_anti_enumeration(self):
        """
        Anti-enumeration invariant: When context is None (unassigned case),
        the dependency returns HTTP 404 Not Found with generic detail.
        """
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="unassigned_analyst",
            global_role=GlobalRole.ANALYST_TIER_1,
            is_active=True,
        )
        dep = require_case_role(CaseRole.INVESTIGATOR, CaseRole.LEAD)
        with pytest.raises(HTTPException) as exc_info:
            await dep(context=None, analyst=analyst)
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == "Case not found or access denied."

    @pytest.mark.anyio
    async def test_none_context_with_security_admin_returns_404(self):
        """
        Decision 2A Parity: Even security_admin receives HTTP 404 on unassigned case.
        """
        admin = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="security_admin_eve",
            global_role=GlobalRole.SECURITY_ADMIN,
            is_active=True,
        )
        dep = require_case_role(CaseRole.INVESTIGATOR, CaseRole.LEAD)
        with pytest.raises(HTTPException) as exc_info:
            await dep(context=None, analyst=admin)
        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert exc_info.value.detail == "Case not found or access denied."

    @pytest.mark.anyio
    async def test_deactivated_analyst_with_none_context_returns_403(self):
        """
        Deactivated analyst check takes precedence over case lookup.
        """
        analyst = AuthenticatedAnalyst(
            analyst_id=uuid.uuid4(),
            username="deactivated_analyst",
            global_role=GlobalRole.ANALYST_TIER_2,
            is_active=False,
        )
        dep = require_case_role(CaseRole.INVESTIGATOR, CaseRole.LEAD)
        with pytest.raises(HTTPException) as exc_info:
            await dep(context=None, analyst=analyst)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "deactivated" in exc_info.value.detail.lower()
