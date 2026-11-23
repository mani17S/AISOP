"""Security events: attacks the server observed, aggregated per minute, source and kind.

Revision ID: 0005_security_events
Revises: 0004_p3h2_rbac_case_scoping
Create Date: 2026-11-22 21:00:00.000000

Table Created:
- security_events: one row is a count of suspicious responses (failed login, lockout, rate limit, probe of an unknown path,
  oversized body, ...) for one minute, one source address and one kind. No credential, body or header value is stored.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_security_events"
down_revision: Union[str, None] = "0004_p3h2_rbac_case_scoping"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("bucket_minute", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("method", sa.String(length=8), nullable=False),
        sa.Column("path_sample", sa.String(length=160), nullable=False),
        sa.Column("user_agent_sample", sa.String(length=160), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_events")),
    )
    op.create_index(op.f("ix_security_events_id"), "security_events", ["id"], unique=False)
    op.create_index(op.f("ix_security_events_bucket_minute"), "security_events", ["bucket_minute"], unique=False)
    op.create_index(op.f("ix_security_events_kind"), "security_events", ["kind"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_security_events_kind"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_bucket_minute"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_id"), table_name="security_events")
    op.drop_table("security_events")
