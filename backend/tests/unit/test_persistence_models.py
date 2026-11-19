"""
Unit tests for AISOP RBAC and Case Scoping Persistence Models (Phase 3 — Gate C.3).

Provably offline tests verifying:
- Model metadata definitions: table names, column types, nullability, and primary keys.
- Normalized case lead representation: cases contains NO persisted lead_analyst_id.
- CaseModel derives lead_analyst_id from loaded case_assignments.
- Canonical check constraints matching RBAC GlobalRole, CaseRole, CaseSeverity, and CaseStatus enums.
- Foreign key definitions and ondelete behaviors:
  - RESTRICT on analyst_api_clients.analyst_id (token issuance lineage retention)
  - RESTRICT on case_evidence.evidence_id (evidence lineage protection)
  - RESTRICT on case_assignments.analyst_id (staffed analyst protection)
  - RESTRICT on case_audit_events.case_id & actor_analyst_id (audit log preservation)
  - CASCADE on case_assignments.case_id & case_evidence.case_id
- Unique constraints on username, email, token_prefix, case_number, and junction tables.
- Partial unique index uq_case_lead_active enforcing at most one lead per case.
- In-memory database operations:
  - Case creation and initial lead assignment in a single unit of work.
  - Derived lead_analyst_id for CaseResponse API serialization.
  - Multiple cases referencing the same normalized evidence without raw data duplication or mutation.
  - One-active-lead invariant: duplicate lead assignment on the same case fails with IntegrityError.
  - Permitted multiple investigator/viewer assignments on the same case.
  - Atomic lead transfer: outgoing lead demoted, target promoted, and audit logged in one transaction.
  - Credential lineage: ON DELETE RESTRICT prevents deleting analyst with issued API clients.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.rbac import VALID_CASE_ROLES, VALID_GLOBAL_ROLES, CaseRole, GlobalRole
from app.db.base import Base
from app.models.analyst import Analyst, AnalystApiClient
from app.models.case import (
    VALID_CASE_SEVERITIES,
    VALID_CASE_STATUSES,
    CaseAssignmentModel,
    CaseAuditEventModel,
    CaseEvidenceModel,
    CaseModel,
)
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.schemas.case import CaseResponse, CaseSeverity, CaseStatus


class TestModelMetadataDefinitions:
    """Verify table structure, column mappings, and constraints on Base.metadata."""

    def test_analysts_table_metadata(self):
        tbl = Base.metadata.tables["analysts"]
        assert "id" in tbl.c
        assert tbl.c.id.primary_key
        assert "username" in tbl.c
        assert not tbl.c.username.nullable
        assert "email" in tbl.c
        assert not tbl.c.email.nullable
        assert "global_role" in tbl.c
        assert not tbl.c.global_role.nullable
        assert "is_active" in tbl.c
        assert not tbl.c.is_active.nullable
        assert "created_at" in tbl.c
        assert "updated_at" in tbl.c

        # Unique indexes
        idx_names = {idx.name: idx for idx in tbl.indexes}
        assert "ix_analysts_username" in idx_names
        assert idx_names["ix_analysts_username"].unique
        assert "ix_analysts_email" in idx_names
        assert idx_names["ix_analysts_email"].unique

        # Check constraint on canonical global roles
        check_constraints = [c for c in tbl.constraints if isinstance(c, sa.CheckConstraint)]
        assert any("global_role IN" in str(c.sqltext) for c in check_constraints)

    def test_analyst_api_clients_table_metadata(self):
        tbl = Base.metadata.tables["analyst_api_clients"]
        assert "id" in tbl.c
        assert "analyst_id" in tbl.c
        assert "client_name" in tbl.c
        assert "token_prefix" in tbl.c
        assert "hashed_secret" in tbl.c
        assert "is_active" in tbl.c
        assert "expires_at" in tbl.c
        assert "created_at" in tbl.c
        assert "last_used_at" in tbl.c

        # Foreign key to analysts.id with RESTRICT (Decision 4: lineage retention)
        fks = list(tbl.foreign_keys)
        assert len(fks) == 1
        fk = fks[0]
        assert fk.target_fullname == "analysts.id"
        assert fk.ondelete.upper() == "RESTRICT"

        # Unique token_prefix
        idx_names = {idx.name: idx for idx in tbl.indexes}
        assert "ix_analyst_api_clients_token_prefix" in idx_names
        assert idx_names["ix_analyst_api_clients_token_prefix"].unique

    def test_cases_table_metadata_normalized(self):
        """Verify cases metadata contains NO persisted lead_analyst_id (Decision 1: Normalized design)."""
        tbl = Base.metadata.tables["cases"]
        assert "id" in tbl.c
        assert "case_number" in tbl.c
        assert "title" in tbl.c
        assert "description" in tbl.c
        assert "severity" in tbl.c
        assert "status" in tbl.c
        assert "created_at" in tbl.c
        assert "updated_at" in tbl.c
        assert "closed_at" in tbl.c

        # CRITICAL: lead_analyst_id must NOT be a column on table cases
        assert "lead_analyst_id" not in tbl.c

        # No direct foreign keys on cases (lead tracked in case_assignments)
        assert len(list(tbl.foreign_keys)) == 0

        # Unique case_number
        idx_names = {idx.name: idx for idx in tbl.indexes}
        assert "ix_cases_case_number" in idx_names
        assert idx_names["ix_cases_case_number"].unique
        assert "ix_cases_lead_analyst_id" not in idx_names

        # Check constraints for status and severity
        check_constraints = [c for c in tbl.constraints if isinstance(c, sa.CheckConstraint)]
        assert any("severity IN" in str(c.sqltext) for c in check_constraints)
        assert any("status IN" in str(c.sqltext) for c in check_constraints)

    def test_case_evidence_table_metadata(self):
        tbl = Base.metadata.tables["case_evidence"]
        assert "id" in tbl.c
        assert "case_id" in tbl.c
        assert "evidence_id" in tbl.c
        assert "linked_by_analyst_id" in tbl.c
        assert "linked_at" in tbl.c

        # Foreign keys
        fk_map = {fk.parent.name: fk for fk in tbl.foreign_keys}
        assert fk_map["case_id"].target_fullname == "cases.id"
        assert fk_map["case_id"].ondelete.upper() == "CASCADE"
        assert fk_map["evidence_id"].target_fullname == "normalized_events.id"
        assert fk_map["evidence_id"].ondelete.upper() == "RESTRICT"
        assert fk_map["linked_by_analyst_id"].target_fullname == "analysts.id"
        assert fk_map["linked_by_analyst_id"].ondelete.upper() == "SET NULL"

        # Composite unique constraint on (case_id, evidence_id)
        uqs = [c for c in tbl.constraints if isinstance(c, sa.UniqueConstraint)]
        assert any(
            set(col.name for col in uq.columns) == {"case_id", "evidence_id"}
            for uq in uqs
        )

    def test_case_assignments_table_metadata(self):
        tbl = Base.metadata.tables["case_assignments"]
        assert "id" in tbl.c
        assert "case_id" in tbl.c
        assert "analyst_id" in tbl.c
        assert "case_role" in tbl.c
        assert "assigned_at" in tbl.c

        # Foreign keys
        fk_map = {fk.parent.name: fk for fk in tbl.foreign_keys}
        assert fk_map["case_id"].target_fullname == "cases.id"
        assert fk_map["case_id"].ondelete.upper() == "CASCADE"
        assert fk_map["analyst_id"].target_fullname == "analysts.id"
        assert fk_map["analyst_id"].ondelete.upper() == "RESTRICT"

        # Composite unique constraint on (case_id, analyst_id)
        uqs = [c for c in tbl.constraints if isinstance(c, sa.UniqueConstraint)]
        assert any(
            set(col.name for col in uq.columns) == {"case_id", "analyst_id"}
            for uq in uqs
        )

        # Check constraint on case_role
        check_constraints = [c for c in tbl.constraints if isinstance(c, sa.CheckConstraint)]
        assert any("case_role IN" in str(c.sqltext) for c in check_constraints)

        # One-active-lead partial unique index
        idx_names = {idx.name: idx for idx in tbl.indexes}
        assert "uq_case_lead_active" in idx_names
        lead_idx = idx_names["uq_case_lead_active"]
        assert lead_idx.unique
        assert "case_id" in [c.name for c in lead_idx.columns]

    def test_case_audit_events_table_metadata(self):
        tbl = Base.metadata.tables["case_audit_events"]
        assert "id" in tbl.c
        assert "case_id" in tbl.c
        assert "actor_analyst_id" in tbl.c
        assert "actor_username" in tbl.c
        assert "action" in tbl.c
        assert "context_sha256" in tbl.c
        assert "details" in tbl.c
        assert "created_at" in tbl.c

        # Foreign keys with RESTRICT
        fk_map = {fk.parent.name: fk for fk in tbl.foreign_keys}
        assert fk_map["case_id"].target_fullname == "cases.id"
        assert fk_map["case_id"].ondelete.upper() == "RESTRICT"
        assert fk_map["actor_analyst_id"].target_fullname == "analysts.id"
        assert fk_map["actor_analyst_id"].ondelete.upper() == "RESTRICT"

        # Composite index for timeline
        idx_names = {idx.name: idx for idx in tbl.indexes}
        assert "ix_case_audit_events_case_time" in idx_names


class TestInMemoryPersistenceOperations:
    """Verify operations, associations, and constraints using isolated in-memory SQLite engine."""

    @pytest.fixture
    def test_session(self, sqlite_engine):
        conn = sqlite_engine.connect()
        # Enable SQLite foreign key enforcement for testing referential integrity
        conn.execute(sa.text("PRAGMA foreign_keys = ON;"))
        session = Session(bind=conn)
        try:
            yield session
        finally:
            session.rollback()
            session.close()
            conn.close()

    def _create_analyst(self, session: Session, username: str, role: GlobalRole = GlobalRole.ANALYST_TIER_1) -> Analyst:
        analyst = Analyst(
            id=uuid.uuid4(),
            username=username,
            email=f"{username}@soc.aisop.local",
            global_role=role.value,
            is_active=True,
        )
        session.add(analyst)
        session.flush()
        return analyst

    def _create_raw_and_normalized_evidence(self, session: Session, event_id: str) -> NormalizedEventModel:
        raw = RawEvidence(
            id=uuid.uuid4(),
            source_type="sysmon",
            source_identifier=f"test-host-{event_id}",
            sha256_hash=f"{event_id:0>64}",
            raw_payload={"EventID": 1},
            ingested_at=datetime.now(timezone.utc),
        )
        session.add(raw)
        session.flush()

        norm = NormalizedEventModel(
            id=uuid.uuid4(),
            raw_evidence_id=raw.id,
            event_id=event_id,
            event_type="process_creation",
            event_timestamp=datetime.now(timezone.utc),
            provider="Microsoft-Windows-Sysmon",
            action="process_create",
            outcome="success",
            severity="medium",
            normalized_payload={"process_name": "cmd.exe"},
        )
        session.add(norm)
        session.flush()
        return norm

    def test_create_analyst_and_api_client(self, test_session: Session):
        analyst = self._create_analyst(test_session, "alice", GlobalRole.ANALYST_TIER_2)
        client = AnalystApiClient(
            id=uuid.uuid4(),
            analyst_id=analyst.id,
            client_name="alice-terminal",
            token_prefix="0123456789abcdef",
            hashed_secret="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            is_active=True,
        )
        test_session.add(client)
        test_session.commit()

        queried = test_session.query(Analyst).filter_by(username="alice").first()
        assert queried is not None
        assert len(queried.api_clients) == 1
        assert queried.api_clients[0].client_name == "alice-terminal"
        assert queried.api_clients[0].token_prefix == "0123456789abcdef"

    def test_deleting_analyst_with_api_client_fails_with_restrict(self, test_session: Session):
        """Decision 4: ON DELETE RESTRICT on analyst_api_clients prevents accidental hard-deletion."""
        analyst = self._create_analyst(test_session, "dave_retention", GlobalRole.ANALYST_TIER_1)
        client = AnalystApiClient(
            id=uuid.uuid4(),
            analyst_id=analyst.id,
            client_name="dave-cli",
            token_prefix="fedcba9876543210",
            hashed_secret="secret_hash_value",
            is_active=True,
        )
        test_session.add(client)
        test_session.commit()

        # Attempt to delete analyst -> must raise IntegrityError because client exists
        test_session.delete(analyst)
        with pytest.raises(IntegrityError):
            test_session.commit()
        test_session.rollback()

    def test_case_creation_and_derived_lead_analyst_id(self, test_session: Session):
        """Decision 1: Case creation establishes lead in single transaction; lead_analyst_id derived from assignment."""
        lead = self._create_analyst(test_session, "creator_t1", GlobalRole.ANALYST_TIER_1)

        # Create case and assign creator as initial lead in one atomic unit of work
        case = CaseModel(
            id=uuid.uuid4(),
            case_number="CASE-20261025-0101",
            title="Initial Triage Incident",
            severity=CaseSeverity.MEDIUM.value,
            status=CaseStatus.OPEN.value,
        )
        test_session.add(case)
        test_session.flush()

        lead_assignment = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case.id,
            analyst_id=lead.id,
            case_role=CaseRole.LEAD.value,
        )
        test_session.add(lead_assignment)
        test_session.commit()

        # Query back case with assignments
        queried = test_session.query(CaseModel).filter_by(case_number="CASE-20261025-0101").first()
        assert queried is not None
        assert queried.lead_analyst_id == lead.id
        assert queried.lead_assignment is not None
        assert queried.lead_assignment.analyst_id == lead.id

        # Verify CaseResponse serialization derives lead_analyst_id seamlessly
        resp = CaseResponse(
            id=queried.id,
            case_number=queried.case_number,
            title=queried.title,
            description=queried.description,
            severity=CaseSeverity(queried.severity),
            status=CaseStatus(queried.status),
            lead_analyst_id=queried.lead_analyst_id,
            created_at=queried.created_at,
            updated_at=queried.updated_at,
        )
        assert resp.lead_analyst_id == lead.id

    def test_multiple_cases_reference_same_evidence(self, test_session: Session):
        """Verify many-to-many case evidence association: same evidence linked to two cases without duplication."""
        lead = self._create_analyst(test_session, "lead_bob", GlobalRole.ANALYST_TIER_2)
        evidence = self._create_raw_and_normalized_evidence(test_session, "EVT-1001")

        case_1 = CaseModel(
            id=uuid.uuid4(),
            case_number="CASE-20261025-0001",
            title="Lateral Movement Investigation",
            severity=CaseSeverity.HIGH.value,
            status=CaseStatus.OPEN.value,
        )
        case_2 = CaseModel(
            id=uuid.uuid4(),
            case_number="CASE-20261025-0002",
            title="Malware Outbreak Investigation",
            severity=CaseSeverity.CRITICAL.value,
            status=CaseStatus.IN_PROGRESS.value,
        )
        test_session.add_all([case_1, case_2])
        test_session.flush()

        # Assign lead to each case in same unit of work
        test_session.add_all([
            CaseAssignmentModel(id=uuid.uuid4(), case_id=case_1.id, analyst_id=lead.id, case_role=CaseRole.LEAD.value),
            CaseAssignmentModel(id=uuid.uuid4(), case_id=case_2.id, analyst_id=lead.id, case_role=CaseRole.LEAD.value),
        ])

        link_1 = CaseEvidenceModel(
            id=uuid.uuid4(),
            case_id=case_1.id,
            evidence_id=evidence.id,
            linked_by_analyst_id=lead.id,
        )
        link_2 = CaseEvidenceModel(
            id=uuid.uuid4(),
            case_id=case_2.id,
            evidence_id=evidence.id,
            linked_by_analyst_id=lead.id,
        )
        test_session.add_all([link_1, link_2])
        test_session.commit()

        # Both cases reference the identical normalized evidence ID
        links = test_session.query(CaseEvidenceModel).filter_by(evidence_id=evidence.id).all()
        assert len(links) == 2
        case_ids = {l.case_id for l in links}
        assert case_ids == {case_1.id, case_2.id}

        # Original evidence payload was not mutated
        ev_record = test_session.query(NormalizedEventModel).filter_by(id=evidence.id).first()
        assert ev_record.event_id == "EVT-1001"

    def test_one_active_lead_invariant_enforced(self, test_session: Session):
        """Enforces at most one active lead per case; adding a second lead raises IntegrityError."""
        lead_1 = self._create_analyst(test_session, "lead_one", GlobalRole.ANALYST_TIER_1)
        lead_2 = self._create_analyst(test_session, "lead_two", GlobalRole.ANALYST_TIER_2)

        case = CaseModel(
            id=uuid.uuid4(),
            case_number="CASE-20261025-0003",
            title="Active Lead Test Case",
            severity=CaseSeverity.MEDIUM.value,
            status=CaseStatus.OPEN.value,
        )
        test_session.add(case)
        test_session.flush()

        # Assign initial lead
        assign_1 = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case.id,
            analyst_id=lead_1.id,
            case_role=CaseRole.LEAD.value,
        )
        test_session.add(assign_1)
        test_session.commit()

        # Attempt to add a second assignment with role='lead' to the same case
        assign_2 = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case.id,
            analyst_id=lead_2.id,
            case_role=CaseRole.LEAD.value,
        )
        test_session.add(assign_2)
        with pytest.raises(IntegrityError):
            test_session.commit()
        test_session.rollback()

    def test_atomic_lead_transfer_demotes_and_promotes(self, test_session: Session):
        """Lead-transfer invariant: demoting outgoing lead and promoting target in one transaction succeeds."""
        initial_lead = self._create_analyst(test_session, "lead_init", GlobalRole.ANALYST_TIER_1)
        new_lead = self._create_analyst(test_session, "lead_target", GlobalRole.ANALYST_TIER_2)

        case = CaseModel(
            id=uuid.uuid4(),
            case_number="CASE-20261025-0102",
            title="Escalated Case",
            severity=CaseSeverity.HIGH.value,
            status=CaseStatus.OPEN.value,
        )
        test_session.add(case)
        test_session.flush()

        init_assign = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case.id,
            analyst_id=initial_lead.id,
            case_role=CaseRole.LEAD.value,
        )
        test_session.add(init_assign)
        test_session.commit()

        # Execute atomic lead transfer within a single transaction:
        # 1. Demote outgoing lead
        init_assign.case_role = CaseRole.INVESTIGATOR.value
        test_session.flush()

        # 2. Promote target analyst to lead
        new_assign = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case.id,
            analyst_id=new_lead.id,
            case_role=CaseRole.LEAD.value,
        )
        test_session.add(new_assign)

        # 3. Log audit event
        audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=case.id,
            actor_analyst_id=initial_lead.id,
            actor_username="lead_init",
            action="lead_transferred",
            context_sha256="transfer_hash_123",
            details={"previous_lead": str(initial_lead.id), "new_lead": str(new_lead.id), "reason": "Tier-2 escalation"},
            created_at=datetime.now(timezone.utc),
        )
        test_session.add(audit)
        test_session.commit()

        # Verify case now has exactly one lead and it matches target
        refreshed = test_session.query(CaseModel).filter_by(id=case.id).first()
        leads = [a for a in refreshed.assignments if a.case_role == CaseRole.LEAD.value]
        assert len(leads) == 1
        assert leads[0].analyst_id == new_lead.id
        assert refreshed.lead_analyst_id == new_lead.id

    def test_multiple_investigators_allowed_on_same_case(self, test_session: Session):
        """Verify non-lead roles (investigator, viewer) permit multiple distinct analysts."""
        lead = self._create_analyst(test_session, "case_lead", GlobalRole.ANALYST_TIER_2)
        inv_1 = self._create_analyst(test_session, "inv_1", GlobalRole.ANALYST_TIER_1)
        inv_2 = self._create_analyst(test_session, "inv_2", GlobalRole.ANALYST_TIER_1)

        case = CaseModel(
            id=uuid.uuid4(),
            case_number="CASE-20261025-0004",
            title="Multi-Staffing Test Case",
            severity=CaseSeverity.LOW.value,
            status=CaseStatus.OPEN.value,
        )
        test_session.add(case)
        test_session.flush()

        a_lead = CaseAssignmentModel(
            id=uuid.uuid4(), case_id=case.id, analyst_id=lead.id, case_role=CaseRole.LEAD.value
        )
        a_inv1 = CaseAssignmentModel(
            id=uuid.uuid4(), case_id=case.id, analyst_id=inv_1.id, case_role=CaseRole.INVESTIGATOR.value
        )
        a_inv2 = CaseAssignmentModel(
            id=uuid.uuid4(), case_id=case.id, analyst_id=inv_2.id, case_role=CaseRole.INVESTIGATOR.value
        )
        test_session.add_all([a_lead, a_inv1, a_inv2])
        test_session.commit()

        assignments = test_session.query(CaseAssignmentModel).filter_by(case_id=case.id).all()
        assert len(assignments) == 3

    def test_case_audit_events_persisted(self, test_session: Session):
        """Verify audit events are persisted and associated with cases and actors."""
        lead = self._create_analyst(test_session, "audit_lead", GlobalRole.ANALYST_TIER_2)
        case = CaseModel(
            id=uuid.uuid4(),
            case_number="CASE-20261025-0005",
            title="Audit Test Case",
            severity=CaseSeverity.MEDIUM.value,
            status=CaseStatus.OPEN.value,
        )
        test_session.add(case)
        test_session.flush()

        audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=case.id,
            actor_analyst_id=lead.id,
            actor_username="audit_lead",
            action="case_created",
            context_sha256="abc123hash",
            details={"initial_severity": "medium", "reason": "Triage alert escalation"},
            created_at=datetime.now(timezone.utc),
        )
        test_session.add(audit)
        test_session.commit()

        saved = test_session.query(CaseAuditEventModel).filter_by(case_id=case.id).first()
        assert saved is not None
        assert saved.action == "case_created"
        assert saved.actor_username == "audit_lead"
        assert saved.details["initial_severity"] == "medium"
