"""
AISOP Case Management, Scoping & Audit Persistence Models.

Milestone: Phase 3 — P3-H2 (RBAC and Analyst Case Scoping)
Entities:
- CaseModel: Security incident case identity, status, severity, lead analyst reference.
- CaseEvidenceModel: Junction table associating immutable normalized evidence with cases.
- CaseAssignmentModel: Analyst-to-case assignment with canonical case roles and one-active-lead invariant.
- CaseAuditEventModel: Attributable, append-only security and administrative case audit trail.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from app.core.rbac import VALID_CASE_ROLES, CaseRole
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.schemas.case import CaseSeverity, CaseStatus
import sqlalchemy as sa
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.models.analyst import Analyst
    from app.models.evidence import NormalizedEventModel

VALID_CASE_STATUSES = frozenset(s.value for s in CaseStatus)
VALID_CASE_SEVERITIES = frozenset(s.value for s in CaseSeverity)


class CaseModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Security investigation case in PostgreSQL.

    Invariants:
    - Case leadership is authoritatively tracked via `case_assignments` where `case_role = 'lead'`.
    - Partial unique index `uq_case_lead_active` guarantees at most one lead per case at database level.
    - Initial case creation and lead assignment must be committed within a single atomic transaction.
    - Lifecycle status strictly validated against canonical CaseStatus values.
    - Case severity strictly validated against canonical CaseSeverity values.
    """

    __tablename__ = "cases"

    case_number: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        unique=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=CaseSeverity.MEDIUM.value,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=CaseStatus.OPEN.value,
        index=True,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        CheckConstraint(
            f"severity IN ({', '.join(repr(s) for s in sorted(VALID_CASE_SEVERITIES))})",
            name="ck_cases_severity",
        ),
        CheckConstraint(
            f"status IN ({', '.join(repr(s) for s in sorted(VALID_CASE_STATUSES))})",
            name="ck_cases_status",
        ),
    )

    # Relationships
    assignments: Mapped[list[CaseAssignmentModel]] = relationship(
        "CaseAssignmentModel",
        back_populates="case",
        cascade="all, delete-orphan",
    )

    @property
    def lead_analyst_id(self) -> uuid.UUID | None:
        """
        Derive lead analyst UUID from case assignments.

        Note: Service and query layers should prefer explicit joins or eager loading
        (e.g., joinedload/selectinload) when querying cases to avoid lazy loading.
        """
        for assignment in self.assignments:
            if assignment.case_role == CaseRole.LEAD.value:
                return assignment.analyst_id
        return None

    @property
    def lead_assignment(self) -> CaseAssignmentModel | None:
        """Derive active lead assignment object from case assignments."""
        for assignment in self.assignments:
            if assignment.case_role == CaseRole.LEAD.value:
                return assignment
        return None
    evidence_links: Mapped[list[CaseEvidenceModel]] = relationship(
        "CaseEvidenceModel",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    audit_events: Mapped[list[CaseAuditEventModel]] = relationship(
        "CaseAuditEventModel",
        back_populates="case",
    )


class CaseEvidenceModel(Base, UUIDPrimaryKeyMixin):
    """
    Junction table linking normalized evidence records to cases.

    Invariants:
    - Many-to-many relationship: An evidence record can be associated with multiple cases.
    - Evidence records are NOT duplicated or mutated; referential integrity is preserved.
    - ON DELETE RESTRICT on evidence_id prevents deleting evidence records linked to any case.
    """

    __tablename__ = "case_evidence"

    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("normalized_events.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    linked_by_analyst_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("analysts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint(
            "case_id",
            "evidence_id",
            name="uq_case_evidence_case_evidence",
        ),
    )

    # Relationships
    case: Mapped[CaseModel] = relationship(
        "CaseModel",
        back_populates="evidence_links",
    )
    evidence: Mapped[NormalizedEventModel] = relationship(
        "NormalizedEventModel",
    )
    linked_by: Mapped[Analyst | None] = relationship(
        "Analyst",
    )


class CaseAssignmentModel(Base, UUIDPrimaryKeyMixin):
    """
    Analyst assignment to a security case with a canonical case role.

    Invariants:
    - At most one assignment per analyst per case.
    - At most ONE active 'lead' per case enforced at database level via partial unique index.
    - ON DELETE RESTRICT on analyst_id prevents deleting analysts with active case staffing.
    """

    __tablename__ = "case_assignments"

    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("analysts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    case_role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        UniqueConstraint(
            "case_id",
            "analyst_id",
            name="uq_case_assignments_case_analyst",
        ),
        CheckConstraint(
            f"case_role IN ({', '.join(repr(r) for r in sorted(VALID_CASE_ROLES))})",
            name="ck_case_assignments_role",
        ),
        # Partial unique index enforcing exactly at most one active lead per case
        Index(
            "uq_case_lead_active",
            "case_id",
            unique=True,
            postgresql_where=sa.text("case_role = 'lead'"),
            sqlite_where=sa.text("case_role = 'lead'"),
        ),
    )

    # Relationships
    case: Mapped[CaseModel] = relationship(
        "CaseModel",
        back_populates="assignments",
    )
    analyst: Mapped[Analyst] = relationship(
        "Analyst",
        back_populates="case_assignments",
    )


class CaseAuditEventModel(Base, UUIDPrimaryKeyMixin):
    """
    Append-only security and administrative audit event for case operations.

    Invariants:
    - ON DELETE RESTRICT on case_id and actor_analyst_id prevents silent audit trail loss.
    - Immutable: Never modified or deleted after creation.
    - Excludes secrets, passwords, or raw tokens from metadata.
    """

    __tablename__ = "case_audit_events"

    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("cases.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    actor_analyst_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("analysts.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    actor_username: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    context_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB().with_variant(JSON, "sqlite"),
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    __table_args__ = (
        Index(
            "ix_case_audit_events_case_time",
            "case_id",
            "created_at",
        ),
    )

    # Relationships
    case: Mapped[CaseModel] = relationship(
        "CaseModel",
        back_populates="audit_events",
    )
    actor: Mapped[Analyst | None] = relationship(
        "Analyst",
    )
