"""
AISOP Analyst Identity & API Client Persistence Models.

Milestone: Phase 3 — P3-H2 (RBAC and Analyst Case Scoping)
Entities:
- Analyst: Human analyst identity, canonical global role, activation state, and audit timestamps.
- AnalystApiClient: Machine API client credential association, token prefix lookup, and hashed secret storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from app.core.rbac import VALID_GLOBAL_ROLES, GlobalRole
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from app.models.case import CaseAssignmentModel, CaseModel


class Analyst(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Human analyst identity in PostgreSQL.

    Invariants:
    - Canonical global role strictly enforced at validation and database boundaries.
    - Machine API clients are distinguished from human analysts.
    - Deactivated analysts fail-closed in authorization dependencies.
    """

    __tablename__ = "analysts"

    username: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )
    global_role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    __table_args__ = (
        CheckConstraint(
            f"global_role IN ({', '.join(repr(r) for r in sorted(VALID_GLOBAL_ROLES))})",
            name="ck_analysts_global_role",
        ),
    )

    # Relationships
    api_clients: Mapped[list[AnalystApiClient]] = relationship(
        "AnalystApiClient",
        back_populates="analyst",
    )
    case_assignments: Mapped[list[CaseAssignmentModel]] = relationship(
        "CaseAssignmentModel",
        back_populates="analyst",
    )


class AnalystApiClient(Base, UUIDPrimaryKeyMixin):
    """
    Machine API client credential record associated with an analyst or ingestion principal.

    Invariants:
    - Plaintext secrets are NEVER stored or returned; only cryptographic digests (SHA-256).
    - Lookup is performed via non-secret 16-hex token_prefix.
    - Constant-time secret comparison at verification boundary.
    - ON DELETE RESTRICT preserves credential issuance lineage against accidental hard-delete.
    """

    __tablename__ = "analyst_api_clients"

    analyst_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("analysts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    client_name: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    token_prefix: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        unique=True,
        index=True,
    )
    hashed_secret: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    analyst: Mapped[Analyst] = relationship(
        "Analyst",
        back_populates="api_clients",
    )
