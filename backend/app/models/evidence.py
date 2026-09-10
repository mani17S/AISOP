"""
AISOP Evidence & Telemetry ORM Models.

Implements the Evidence-First Principle:
- RawEvidence: Immutable store of raw telemetry records with cryptographic SHA-256 hashes.
- NormalizedEventModel: Structured, canonical representation of observed events.
- ExtractedEntityModel: Atomic, queryable entities (IP, Host, User, Process, Hash, Domain).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKeyMixin


class RawEvidence(Base, UUIDPrimaryKeyMixin):
    """
    Immutable raw telemetry record.
    """
    __tablename__ = "raw_evidence"

    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_identifier: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    normalized_events: Mapped[list[NormalizedEventModel]] = relationship(
        "NormalizedEventModel",
        back_populates="raw_evidence",
        cascade="all, delete-orphan",
    )


class NormalizedEventModel(Base, UUIDPrimaryKeyMixin):
    """
    Canonical normalized security event.
    """
    __tablename__ = "normalized_events"

    raw_evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("raw_evidence.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=False, default="unknown")
    action: Mapped[str] = mapped_column(String(50), nullable=False, default="observed")
    outcome: Mapped[str] = mapped_column(String(50), nullable=False, default="success")
    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="informational")
    normalized_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Relationships
    raw_evidence: Mapped[RawEvidence] = relationship("RawEvidence", back_populates="normalized_events")
    entities: Mapped[list[ExtractedEntityModel]] = relationship(
        "ExtractedEntityModel",
        back_populates="event",
        cascade="all, delete-orphan",
    )


class ExtractedEntityModel(Base, UUIDPrimaryKeyMixin):
    """
    Atomic entity extracted from an event for rapid graph correlation.
    """
    __tablename__ = "extracted_entities"

    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("normalized_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    raw_evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("raw_evidence.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    entity_value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="observed")
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Relationships
    event: Mapped[NormalizedEventModel] = relationship("NormalizedEventModel", back_populates="entities")


# Composite indexes for fast timeline & entity correlation queries
Index("ix_normalized_events_type_time", NormalizedEventModel.event_type, NormalizedEventModel.event_timestamp)
Index("ix_extracted_entities_type_value", ExtractedEntityModel.entity_type, ExtractedEntityModel.entity_value)
