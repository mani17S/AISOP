"""RBAC persistence, analyst API clients, cases, and case-scoping schema.

Revision ID: 0004_p3h2_rbac_case_scoping
Revises: 0003_source_scoped_chunks
Create Date: 2026-10-25 12:00:00.000000

Milestone: Phase 3 — P3-H2 (RBAC and Analyst Case Scoping)
Tables Created:
- analysts: Human analyst identities, canonical global roles, and activation status.
- analyst_api_clients: Machine API client associations with cryptographic hashed secrets and token prefixes.
- cases: Security investigation cases with canonical statuses, severities, and lead references.
- case_evidence: Junction table associating immutable normalized evidence with cases.
- case_assignments: Analyst-to-case staffing with canonical case roles and one-active-lead partial unique index.
- case_audit_events: Append-only security and administrative audit event trail.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0004_p3h2_rbac_case_scoping"
down_revision: Union[str, None] = "0003_source_scoped_chunks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # ── 1. Table: analysts ───────────────────────────────────────
    op.create_table(
        "analysts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("global_role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "global_role IN ('analyst_tier_1', 'analyst_tier_2', 'ingest', 'security_admin')",
            name=op.f("ck_analysts_global_role"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_analysts")),
    )
    op.create_index(op.f("ix_analysts_id"), "analysts", ["id"], unique=False)
    op.create_index(op.f("ix_analysts_username"), "analysts", ["username"], unique=True)
    op.create_index(op.f("ix_analysts_email"), "analysts", ["email"], unique=True)
    op.create_index(op.f("ix_analysts_global_role"), "analysts", ["global_role"], unique=False)

    # ── 2. Table: analyst_api_clients ────────────────────────────
    op.create_table(
        "analyst_api_clients",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analyst_id", sa.Uuid(), nullable=False),
        sa.Column("client_name", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.String(length=16), nullable=False),
        sa.Column("hashed_secret", sa.String(length=128), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["analyst_id"],
            ["analysts.id"],
            name=op.f("fk_analyst_api_clients_analyst_id_analysts"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_analyst_api_clients")),
    )
    op.create_index(op.f("ix_analyst_api_clients_id"), "analyst_api_clients", ["id"], unique=False)
    op.create_index(op.f("ix_analyst_api_clients_analyst_id"), "analyst_api_clients", ["analyst_id"], unique=False)
    op.create_index(op.f("ix_analyst_api_clients_token_prefix"), "analyst_api_clients", ["token_prefix"], unique=True)

    # ── 3. Table: cases ──────────────────────────────────────────
    op.create_table(
        "cases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_number", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'informational', 'low', 'medium')",
            name=op.f("ck_cases_severity"),
        ),
        sa.CheckConstraint(
            "status IN ('archived', 'closed', 'in_progress', 'open')",
            name=op.f("ck_cases_status"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cases")),
    )
    op.create_index(op.f("ix_cases_id"), "cases", ["id"], unique=False)
    op.create_index(op.f("ix_cases_case_number"), "cases", ["case_number"], unique=True)
    op.create_index(op.f("ix_cases_severity"), "cases", ["severity"], unique=False)
    op.create_index(op.f("ix_cases_status"), "cases", ["status"], unique=False)

    # ── 4. Table: case_evidence ──────────────────────────────────
    op.create_table(
        "case_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("linked_by_analyst_id", sa.Uuid(), nullable=True),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_case_evidence_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["normalized_events.id"],
            name=op.f("fk_case_evidence_evidence_id_normalized_events"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["linked_by_analyst_id"],
            ["analysts.id"],
            name=op.f("fk_case_evidence_linked_by_analyst_id_analysts"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_evidence")),
        sa.UniqueConstraint("case_id", "evidence_id", name=op.f("uq_case_evidence_case_evidence")),
    )
    op.create_index(op.f("ix_case_evidence_id"), "case_evidence", ["id"], unique=False)
    op.create_index(op.f("ix_case_evidence_case_id"), "case_evidence", ["case_id"], unique=False)
    op.create_index(op.f("ix_case_evidence_evidence_id"), "case_evidence", ["evidence_id"], unique=False)
    op.create_index(op.f("ix_case_evidence_linked_by_analyst_id"), "case_evidence", ["linked_by_analyst_id"], unique=False)

    # ── 5. Table: case_assignments ───────────────────────────────
    op.create_table(
        "case_assignments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("analyst_id", sa.Uuid(), nullable=False),
        sa.Column("case_role", sa.String(length=32), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "case_role IN ('investigator', 'lead', 'viewer')",
            name=op.f("ck_case_assignments_role"),
        ),
        sa.ForeignKeyConstraint(
            ["analyst_id"],
            ["analysts.id"],
            name=op.f("fk_case_assignments_analyst_id_analysts"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_case_assignments_case_id_cases"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_assignments")),
        sa.UniqueConstraint("case_id", "analyst_id", name=op.f("uq_case_assignments_case_analyst")),
    )
    op.create_index(op.f("ix_case_assignments_id"), "case_assignments", ["id"], unique=False)
    op.create_index(op.f("ix_case_assignments_case_id"), "case_assignments", ["case_id"], unique=False)
    op.create_index(op.f("ix_case_assignments_analyst_id"), "case_assignments", ["analyst_id"], unique=False)
    op.create_index(op.f("ix_case_assignments_case_role"), "case_assignments", ["case_role"], unique=False)

    # Partial unique index enforcing at most one active lead per case
    op.create_index(
        "uq_case_lead_active",
        "case_assignments",
        ["case_id"],
        unique=True,
        postgresql_where=sa.text("case_role = 'lead'"),
        sqlite_where=sa.text("case_role = 'lead'"),
    )

    # ── 6. Table: case_audit_events ──────────────────────────────
    details_col = (
        postgresql.JSONB(astext_type=sa.Text())
        if is_postgres
        else sa.JSON()
    )
    op.create_table(
        "case_audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("actor_analyst_id", sa.Uuid(), nullable=True),
        sa.Column("actor_username", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("context_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "details",
            details_col,
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["actor_analyst_id"],
            ["analysts.id"],
            name=op.f("fk_case_audit_events_actor_analyst_id_analysts"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            name=op.f("fk_case_audit_events_case_id_cases"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_audit_events")),
    )
    op.create_index(op.f("ix_case_audit_events_id"), "case_audit_events", ["id"], unique=False)
    op.create_index(op.f("ix_case_audit_events_case_id"), "case_audit_events", ["case_id"], unique=False)
    op.create_index(op.f("ix_case_audit_events_actor_analyst_id"), "case_audit_events", ["actor_analyst_id"], unique=False)
    op.create_index(op.f("ix_case_audit_events_actor_username"), "case_audit_events", ["actor_username"], unique=False)
    op.create_index(op.f("ix_case_audit_events_action"), "case_audit_events", ["action"], unique=False)
    op.create_index(op.f("ix_case_audit_events_created_at"), "case_audit_events", ["created_at"], unique=False)
    op.create_index(
        "ix_case_audit_events_case_time",
        "case_audit_events",
        ["case_id", "created_at"],
        unique=False,
    )

    # ── 7. PostgreSQL Immutability Triggers for Audit Events ─────
    # Security Policy: Append-only audit integrity
    # - Row-level trigger blocks UPDATE and DELETE operations.
    # - Statement-level trigger blocks TRUNCATE operations.
    # Least-privilege production recommendation:
    #   GRANT SELECT, INSERT ON case_audit_events TO aisop_app;
    #   REVOKE UPDATE, DELETE, TRUNCATE ON case_audit_events FROM aisop_app;
    # Note: Does not protect against table owner / superuser overrides or trigger disabling.
    if is_postgres:
        op.execute("""
            CREATE OR REPLACE FUNCTION fn_prevent_case_audit_events_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'case_audit_events records are append-only and immutable; UPDATE, DELETE, or TRUNCATE is prohibited.';
            END;
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER trg_case_audit_events_immutable
            BEFORE UPDATE OR DELETE ON case_audit_events
            FOR EACH ROW EXECUTE FUNCTION fn_prevent_case_audit_events_mutation();

            CREATE TRIGGER trg_case_audit_events_prevent_truncate
            BEFORE TRUNCATE ON case_audit_events
            FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_case_audit_events_mutation();
        """)


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # 1. Drop triggers and function if PostgreSQL
    if is_postgres:
        op.execute("""
            DROP TRIGGER IF EXISTS trg_case_audit_events_prevent_truncate ON case_audit_events;
            DROP TRIGGER IF EXISTS trg_case_audit_events_immutable ON case_audit_events;
            DROP FUNCTION IF EXISTS fn_prevent_case_audit_events_mutation();
        """)

    # 2. Drop case_audit_events
    op.drop_index("ix_case_audit_events_case_time", table_name="case_audit_events")
    op.drop_index(op.f("ix_case_audit_events_created_at"), table_name="case_audit_events")
    op.drop_index(op.f("ix_case_audit_events_action"), table_name="case_audit_events")
    op.drop_index(op.f("ix_case_audit_events_actor_username"), table_name="case_audit_events")
    op.drop_index(op.f("ix_case_audit_events_actor_analyst_id"), table_name="case_audit_events")
    op.drop_index(op.f("ix_case_audit_events_case_id"), table_name="case_audit_events")
    op.drop_index(op.f("ix_case_audit_events_id"), table_name="case_audit_events")
    op.drop_table("case_audit_events")

    # 3. Drop case_assignments
    op.drop_index("uq_case_lead_active", table_name="case_assignments")
    op.drop_index(op.f("ix_case_assignments_case_role"), table_name="case_assignments")
    op.drop_index(op.f("ix_case_assignments_analyst_id"), table_name="case_assignments")
    op.drop_index(op.f("ix_case_assignments_case_id"), table_name="case_assignments")
    op.drop_index(op.f("ix_case_assignments_id"), table_name="case_assignments")
    op.drop_table("case_assignments")

    # 4. Drop case_evidence
    op.drop_index(op.f("ix_case_evidence_linked_by_analyst_id"), table_name="case_evidence")
    op.drop_index(op.f("ix_case_evidence_evidence_id"), table_name="case_evidence")
    op.drop_index(op.f("ix_case_evidence_case_id"), table_name="case_evidence")
    op.drop_index(op.f("ix_case_evidence_id"), table_name="case_evidence")
    op.drop_table("case_evidence")

    # 5. Drop cases
    op.drop_index(op.f("ix_cases_status"), table_name="cases")
    op.drop_index(op.f("ix_cases_severity"), table_name="cases")
    op.drop_index(op.f("ix_cases_case_number"), table_name="cases")
    op.drop_index(op.f("ix_cases_id"), table_name="cases")
    op.drop_table("cases")

    # 6. Drop analyst_api_clients
    op.drop_index(op.f("ix_analyst_api_clients_token_prefix"), table_name="analyst_api_clients")
    op.drop_index(op.f("ix_analyst_api_clients_analyst_id"), table_name="analyst_api_clients")
    op.drop_index(op.f("ix_analyst_api_clients_id"), table_name="analyst_api_clients")
    op.drop_table("analyst_api_clients")

    # 7. Drop analysts
    op.drop_index(op.f("ix_analysts_global_role"), table_name="analysts")
    op.drop_index(op.f("ix_analysts_email"), table_name="analysts")
    op.drop_index(op.f("ix_analysts_username"), table_name="analysts")
    op.drop_index(op.f("ix_analysts_id"), table_name="analysts")
    op.drop_table("analysts")
