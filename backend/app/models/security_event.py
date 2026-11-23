"""
Security events: suspicious responses the server observed, aggregated per minute, source address and kind.

One row is a count, not a request. No credential, body or header value is stored (see app/core/security_events.py).
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.db.base import Base, UUIDPrimaryKeyMixin
from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column


class SecurityEventModel(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "security_events"

    bucket_minute: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    path_sample: Mapped[str] = mapped_column(String(160), nullable=False)
    user_agent_sample: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
