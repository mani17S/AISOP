"""API key sightings: where each valid key has been used from.

Revision ID: 0006_api_key_sightings
Revises: 0005_security_events
Create Date: 2026-11-23 09:00:00.000000

Table Created:
- api_key_sightings: one row per (key identifier, source address): the first and last time a valid key was used from that address
  and how many times. Holds a non-secret 16 hex identifier, the account name and the address; never the key. Lets the Security page
  notice a valid key used from a new address.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_api_key_sightings"
down_revision: Union[str, None] = "0005_security_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "api_key_sightings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_prefix", sa.String(length=16), nullable=False),
        sa.Column("client_name", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_key_sightings")),
        sa.UniqueConstraint("token_prefix", "source_ip", name="uq_api_key_sightings_prefix_ip"),
    )
    op.create_index(op.f("ix_api_key_sightings_id"), "api_key_sightings", ["id"], unique=False)
    op.create_index(op.f("ix_api_key_sightings_token_prefix"), "api_key_sightings", ["token_prefix"], unique=False)
    op.create_index(op.f("ix_api_key_sightings_first_seen"), "api_key_sightings", ["first_seen"], unique=False)
    op.create_index(op.f("ix_api_key_sightings_last_seen"), "api_key_sightings", ["last_seen"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_api_key_sightings_last_seen"), table_name="api_key_sightings")
    op.drop_index(op.f("ix_api_key_sightings_first_seen"), table_name="api_key_sightings")
    op.drop_index(op.f("ix_api_key_sightings_token_prefix"), table_name="api_key_sightings")
    op.drop_index(op.f("ix_api_key_sightings_id"), table_name="api_key_sightings")
    op.drop_table("api_key_sightings")
