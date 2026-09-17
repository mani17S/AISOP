"""Initial schema for AISOP evidence and telemetry tables.

Revision ID: 0001_initial_evidence_schema
Revises: None
Create Date: 2026-09-17 09:30:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_initial_evidence_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -- 1. Table: raw_evidence ----------------------------------
    op.create_table(
        "raw_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("source_identifier", sa.String(length=255), nullable=False),
        sa.Column("sha256_hash", sa.String(length=64), nullable=False),
        sa.Column("raw_payload", sa.JSON(), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_raw_evidence")),
    )
    op.create_index(op.f("ix_raw_evidence_id"), "raw_evidence", ["id"], unique=False)
    op.create_index(
        op.f("ix_raw_evidence_source_type"),
        "raw_evidence",
        ["source_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_evidence_source_identifier"),
        "raw_evidence",
        ["source_identifier"],
        unique=False,
    )
    op.create_index(
        op.f("ix_raw_evidence_sha256_hash"),
        "raw_evidence",
        ["sha256_hash"],
        unique=True,
    )

    # -- 2. Table: normalized_events ------------------------------
    op.create_table(
        "normalized_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("raw_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.String(length=50), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("outcome", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column("normalized_payload", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["raw_evidence_id"],
            ["raw_evidence.id"],
            name=op.f("fk_normalized_events_raw_evidence_id_raw_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_normalized_events")),
    )
    op.create_index(
        op.f("ix_normalized_events_id"), "normalized_events", ["id"], unique=False
    )
    op.create_index(
        op.f("ix_normalized_events_raw_evidence_id"),
        "normalized_events",
        ["raw_evidence_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_normalized_events_event_id"),
        "normalized_events",
        ["event_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_normalized_events_event_type"),
        "normalized_events",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_normalized_events_event_timestamp"),
        "normalized_events",
        ["event_timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_normalized_events_type_time",
        "normalized_events",
        ["event_type", "event_timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_normalized_events_time_id",
        "normalized_events",
        [sa.text("event_timestamp DESC"), sa.text("id DESC")],
        unique=False,
    )

    # -- 3. Table: extracted_entities ----------------------------
    op.create_table(
        "extracted_entities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("raw_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=False),
        sa.Column("entity_value", sa.String(length=500), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["normalized_events.id"],
            name=op.f("fk_extracted_entities_event_id_normalized_events"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["raw_evidence_id"],
            ["raw_evidence.id"],
            name=op.f("fk_extracted_entities_raw_evidence_id_raw_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_extracted_entities")),
    )
    op.create_index(
        op.f("ix_extracted_entities_id"), "extracted_entities", ["id"], unique=False
    )
    op.create_index(
        op.f("ix_extracted_entities_event_id"),
        "extracted_entities",
        ["event_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_extracted_entities_raw_evidence_id"),
        "extracted_entities",
        ["raw_evidence_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_extracted_entities_entity_type"),
        "extracted_entities",
        ["entity_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_extracted_entities_entity_value"),
        "extracted_entities",
        ["entity_value"],
        unique=False,
    )
    op.create_index(
        "ix_extracted_entities_type_value",
        "extracted_entities",
        ["entity_type", "entity_value"],
        unique=False,
    )


def downgrade() -> None:
    # -- 3. Drop: extracted_entities ------------------------------
    op.drop_index("ix_extracted_entities_type_value", table_name="extracted_entities")
    op.drop_index(
        op.f("ix_extracted_entities_entity_value"), table_name="extracted_entities"
    )
    op.drop_index(
        op.f("ix_extracted_entities_entity_type"), table_name="extracted_entities"
    )
    op.drop_index(
        op.f("ix_extracted_entities_raw_evidence_id"),
        table_name="extracted_entities",
    )
    op.drop_index(
        op.f("ix_extracted_entities_event_id"), table_name="extracted_entities"
    )
    op.drop_index(op.f("ix_extracted_entities_id"), table_name="extracted_entities")
    op.drop_table("extracted_entities")

    # -- 2. Drop: normalized_events ------------------------------
    op.drop_index("ix_normalized_events_time_id", table_name="normalized_events")
    op.drop_index("ix_normalized_events_type_time", table_name="normalized_events")
    op.drop_index(
        op.f("ix_normalized_events_event_timestamp"), table_name="normalized_events"
    )
    op.drop_index(
        op.f("ix_normalized_events_event_type"), table_name="normalized_events"
    )
    op.drop_index(op.f("ix_normalized_events_event_id"), table_name="normalized_events")
    op.drop_index(
        op.f("ix_normalized_events_raw_evidence_id"), table_name="normalized_events"
    )
    op.drop_index(op.f("ix_normalized_events_id"), table_name="normalized_events")
    op.drop_table("normalized_events")

    # -- 1. Drop: raw_evidence -----------------------------------
    op.drop_index(op.f("ix_raw_evidence_sha256_hash"), table_name="raw_evidence")
    op.drop_index(op.f("ix_raw_evidence_source_identifier"), table_name="raw_evidence")
    op.drop_index(op.f("ix_raw_evidence_source_type"), table_name="raw_evidence")
    op.drop_index(op.f("ix_raw_evidence_id"), table_name="raw_evidence")
    op.drop_table("raw_evidence")
