"""
AISOP Database Declarative Base & Common Mixins.

SQLAlchemy 2.0 modern declarative mapping.
Designed to be multi-engine compatible:
- PostgreSQL with psycopg binary driver in production
- SQLite in-memory for lightning-fast, isolated unit testing (Option A decision)
"""

from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any

from sqlalchemy import DateTime, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base declarative class for all AISOP models."""
    pass


class UUIDPrimaryKeyMixin:
    """Provides a UUID primary key compatible with PostgreSQL UUID and SQLite."""
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )


class TimestampMixin:
    """Provides UTC created_at and updated_at tracking."""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
