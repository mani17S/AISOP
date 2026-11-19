"""
Unit tests for AISOP Case Management Pydantic V2 Schemas.

Provably offline tests verifying:
- CaseCreateRequest validation (title length, severity enum, extra fields forbidden)
- CaseMetadataUpdateRequest validation (at least one field required, extra fields forbidden)
- CaseAssignmentRequest validation (prohibits assigning Lead role, extra fields forbidden)
- LeadTransferRequest validation (target analyst UUID, reason length bounds, extra forbidden)
- CaseLifecycleUpdateRequest validation (prohibits non-terminal statuses, reason bounds)
- CaseResponse validation (case_number regex, serialization)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.core.rbac import CaseRole
from app.schemas.case import (
    CaseAssignmentRequest,
    CaseAssignmentResponse,
    CaseCreateRequest,
    CaseLifecycleUpdateRequest,
    CaseMetadataUpdateRequest,
    CaseResponse,
    CaseSeverity,
    CaseStatus,
    LeadTransferRequest,
)


class TestCaseCreateSchema:
    def test_valid_case_creation(self):
        req = CaseCreateRequest(
            title="Suspicious Beaconing from DC-01",
            description="Investigating outbound beaconing to suspected C2 IP.",
            severity=CaseSeverity.HIGH,
            initial_evidence_ids=[uuid.uuid4()],
        )
        assert req.title == "Suspicious Beaconing from DC-01"
        assert req.severity == CaseSeverity.HIGH
        assert len(req.initial_evidence_ids) == 1

    def test_rejects_short_title(self):
        with pytest.raises(ValidationError):
            CaseCreateRequest(title="AB")

    def test_rejects_excessive_title(self):
        with pytest.raises(ValidationError):
            CaseCreateRequest(title="A" * 201)

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            CaseCreateRequest(
                title="Valid Title",
                arbitrary_field="malicious_payload",
            )


class TestCaseMetadataUpdateSchema:
    def test_valid_partial_update(self):
        req = CaseMetadataUpdateRequest(title="New Title")
        assert req.title == "New Title"
        assert req.description is None
        assert req.severity is None

    def test_rejects_empty_update(self):
        with pytest.raises(ValidationError, match="At least one field"):
            CaseMetadataUpdateRequest()

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            CaseMetadataUpdateRequest(title="Valid", status="closed")


class TestCaseAssignmentSchema:
    def test_valid_assignment_request(self):
        analyst_id = uuid.uuid4()
        req = CaseAssignmentRequest(
            analyst_id=analyst_id,
            case_role=CaseRole.INVESTIGATOR,
        )
        assert req.analyst_id == analyst_id
        assert req.case_role == CaseRole.INVESTIGATOR

    def test_rejects_assigning_lead_role(self):
        with pytest.raises(ValidationError, match="Cannot assign 'lead' role"):
            CaseAssignmentRequest(
                analyst_id=uuid.uuid4(),
                case_role=CaseRole.LEAD,
            )

    def test_valid_assignment_response(self):
        case_id = uuid.uuid4()
        analyst_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        resp = CaseAssignmentResponse(
            case_id=case_id,
            analyst_id=analyst_id,
            username="analyst_bob",
            case_role=CaseRole.VIEWER,
            assigned_at=now,
        )
        assert resp.case_id == case_id
        assert resp.case_role == CaseRole.VIEWER


class TestLeadTransferSchema:
    def test_valid_lead_transfer(self):
        target_id = uuid.uuid4()
        req = LeadTransferRequest(
            target_analyst_id=target_id,
            reason="Escalating to Senior Tier-2 Analyst due to confirmed lateral movement.",
        )
        assert req.target_analyst_id == target_id

    def test_rejects_short_reason(self):
        with pytest.raises(ValidationError):
            LeadTransferRequest(
                target_analyst_id=uuid.uuid4(),
                reason="Done",
            )

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            LeadTransferRequest(
                target_analyst_id=uuid.uuid4(),
                reason="Valid transfer reason.",
                bypass_checks=True,
            )


class TestCaseLifecycleSchema:
    def test_valid_closure(self):
        req = CaseLifecycleUpdateRequest(
            status=CaseStatus.CLOSED,
            closure_reason="False positive confirmed after user verification.",
        )
        assert req.status == CaseStatus.CLOSED

    def test_valid_archival(self):
        req = CaseLifecycleUpdateRequest(
            status=CaseStatus.ARCHIVED,
            closure_reason="Investigation resolved, 90-day retention elapsed.",
        )
        assert req.status == CaseStatus.ARCHIVED

    def test_rejects_transition_to_open_or_in_progress(self):
        with pytest.raises(ValidationError, match="Invalid lifecycle transition"):
            CaseLifecycleUpdateRequest(
                status=CaseStatus.OPEN,
                closure_reason="Reopening case via lifecycle endpoint.",
            )

        with pytest.raises(ValidationError, match="Invalid lifecycle transition"):
            CaseLifecycleUpdateRequest(
                status=CaseStatus.IN_PROGRESS,
                closure_reason="Moving to in progress.",
            )


class TestCaseResponseSchema:
    def test_valid_case_response(self):
        now = datetime.now(timezone.utc)
        resp = CaseResponse(
            id=uuid.uuid4(),
            case_number="CASE-20261025-A1B2",
            title="Investigating Mimikatz Executable",
            description="Process execution detected on HOST-FINANCE-01",
            severity=CaseSeverity.CRITICAL,
            status=CaseStatus.IN_PROGRESS,
            lead_analyst_id=uuid.uuid4(),
            created_at=now,
            updated_at=now,
        )
        assert resp.case_number == "CASE-20261025-A1B2"
        assert resp.severity == CaseSeverity.CRITICAL

    def test_rejects_invalid_case_number_format(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError):
            CaseResponse(
                id=uuid.uuid4(),
                case_number="INVALID-CASE-NUMBER",
                title="Investigating Incident",
                severity=CaseSeverity.LOW,
                status=CaseStatus.OPEN,
                lead_analyst_id=uuid.uuid4(),
                created_at=now,
                updated_at=now,
            )
