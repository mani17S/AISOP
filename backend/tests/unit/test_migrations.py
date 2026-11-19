"""
Unit tests for AISOP Database Migrations & Schema Lifecycle (Milestone P1-H7 & P2-H2).

Tests:
- Alembic configuration discovery and loading.
- Target metadata table and constraint verification.
- Migration revision discovery (0002_pgvector_knowledge_schema as head).
- Offline SQL DDL generation for both upgrade and downgrade.
- Full upgrade and downgrade migration lifecycle execution on an isolated engine.
- Schema parity: zero unmigrated differences between Base.metadata and migration.

Testing note:
SQLite migration tests validate Alembic execution flow, table creation, and DDL syntax.
PostgreSQL + pgvector remains the authoritative production and verification environment.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from app.db.base import Base
from app.models.evidence import (  # noqa: F401
    ExtractedEntityModel,
    NormalizedEventModel,
    RawEvidence,
)
from app.models.knowledge import KnowledgeEmbedding  # noqa: F401
from pgvector.sqlalchemy import Vector
import sqlalchemy as sa
from sqlalchemy import create_engine, inspect


@pytest.fixture
def alembic_config() -> Config:
    """Load the root alembic.ini configuration."""
    backend_dir = Path(__file__).resolve().parents[2]
    alembic_ini_path = backend_dir / "alembic.ini"
    if not alembic_ini_path.exists():
        alembic_ini_path = backend_dir.parent / "alembic.ini"
    cfg = Config(str(alembic_ini_path))
    return cfg


def test_alembic_config_discovery(alembic_config: Config):
    """Verify Alembic configuration discovers migration scripts and version directory."""
    script_dir = ScriptDirectory.from_config(alembic_config)
    assert script_dir is not None

    heads = script_dir.get_heads()
    assert len(heads) == 1
    assert heads[0] == "0004_p3h2_rbac_case_scoping"


def test_target_metadata_tables():
    """Verify Base.metadata contains the complete canonical set of models."""
    expected_tables = {
        "raw_evidence",
        "normalized_events",
        "extracted_entities",
        "knowledge_embeddings",
        "analysts",
        "analyst_api_clients",
        "cases",
        "case_evidence",
        "case_assignments",
        "case_audit_events",
    }
    actual_tables = set(Base.metadata.tables.keys())
    assert expected_tables.issubset(actual_tables)

    # Check raw_evidence
    raw_tbl = Base.metadata.tables["raw_evidence"]
    assert "id" in raw_tbl.c
    assert "source_type" in raw_tbl.c
    assert "source_identifier" in raw_tbl.c
    assert "sha256_hash" in raw_tbl.c
    assert "raw_payload" in raw_tbl.c
    assert "ingested_at" in raw_tbl.c

    # Check normalized_events
    norm_tbl = Base.metadata.tables["normalized_events"]
    assert "id" in norm_tbl.c
    assert "raw_evidence_id" in norm_tbl.c
    assert "event_id" in norm_tbl.c
    assert "event_type" in norm_tbl.c
    assert "event_timestamp" in norm_tbl.c
    assert "provider" in norm_tbl.c
    assert "action" in norm_tbl.c
    assert "outcome" in norm_tbl.c
    assert "severity" in norm_tbl.c
    assert "normalized_payload" in norm_tbl.c

    # Check extracted_entities
    ent_tbl = Base.metadata.tables["extracted_entities"]
    assert "id" in ent_tbl.c
    assert "event_id" in ent_tbl.c
    assert "raw_evidence_id" in ent_tbl.c
    assert "entity_type" in ent_tbl.c
    assert "entity_value" in ent_tbl.c
    assert "role" in ent_tbl.c
    assert "attributes" in ent_tbl.c

    # Check knowledge_embeddings (Milestone P2-H3 Phase A additions)
    know_tbl = Base.metadata.tables["knowledge_embeddings"]
    assert "id" in know_tbl.c
    assert "source_document" in know_tbl.c
    assert "section_title" in know_tbl.c
    assert "chunk_index" in know_tbl.c
    assert "content" in know_tbl.c
    assert "content_hash" in know_tbl.c
    assert "embedding" in know_tbl.c
    assert "chunk_metadata" in know_tbl.c
    assert "created_at" in know_tbl.c
    assert "updated_at" in know_tbl.c
    assert not know_tbl.c.content_hash.unique

    # Verify composite unique index on (source_document, chunk_index) exists
    idx_names = {idx.name for idx in know_tbl.indexes}
    assert "ix_knowledge_embeddings_source_document_chunk_index" in idx_names

    # Check cases (Gate C.3 Decision 1: Normalized lead representation)
    case_tbl = Base.metadata.tables["cases"]
    assert "id" in case_tbl.c
    assert "case_number" in case_tbl.c
    assert "title" in case_tbl.c
    assert "severity" in case_tbl.c
    assert "status" in case_tbl.c
    assert "lead_analyst_id" not in case_tbl.c  # No persisted column on cases
    case_idx_names = {idx.name for idx in case_tbl.indexes}
    assert "ix_cases_lead_analyst_id" not in case_idx_names

    # Check analyst_api_clients (Gate C.3 Decision 3: Credential lineage retention)
    client_tbl = Base.metadata.tables["analyst_api_clients"]
    client_fks = [fk for fk in client_tbl.foreign_keys if fk.parent.name == "analyst_id"]
    assert len(client_fks) == 1
    assert client_fks[0].ondelete == "RESTRICT"

    # Check case_assignments partial unique index
    assign_tbl = Base.metadata.tables["case_assignments"]
    assign_idx_names = {idx.name for idx in assign_tbl.indexes}
    assert "uq_case_lead_active" in assign_idx_names


def test_offline_sql_upgrade(alembic_config: Config, capsys: pytest.CaptureFixture):
    """Verify offline SQL generation (--sql) produces valid DDL for all tables and indices."""
    command.upgrade(alembic_config, "head", sql=True)
    captured = capsys.readouterr()
    sql = captured.out

    assert "CREATE TABLE raw_evidence" in sql
    assert "CREATE TABLE normalized_events" in sql
    assert "CREATE TABLE extracted_entities" in sql
    assert "CREATE TABLE knowledge_embeddings" in sql
    assert "CREATE TABLE analysts" in sql
    assert "CREATE TABLE analyst_api_clients" in sql
    assert "CREATE TABLE cases" in sql
    assert "CREATE TABLE case_evidence" in sql
    assert "CREATE TABLE case_assignments" in sql
    assert "CREATE TABLE case_audit_events" in sql
    assert "CREATE TABLE alembic_version" in sql
    assert "ix_raw_evidence_sha256_hash" in sql
    assert "ix_normalized_events_type_time" in sql
    assert "ix_extracted_entities_type_value" in sql
    assert "ix_knowledge_embeddings_source_document" in sql
    assert "ix_knowledge_embeddings_content_hash" in sql
    assert "ix_knowledge_embeddings_source_document_chunk_index" in sql
    assert "chunk_index" in sql
    assert "ix_cases_case_number" in sql
    assert "uq_case_lead_active" in sql
    assert "COMMIT;" in sql

    # Gate C.3 Decision 1: lead_analyst_id must NOT be emitted in CREATE TABLE cases
    assert "lead_analyst_id" not in sql

    # Gate C.3 Decision 2: PostgreSQL immutability triggers emitted in SQL
    assert "trg_case_audit_events_prevent_truncate" in sql
    assert "trg_case_audit_events_immutable" in sql
    assert "fn_prevent_case_audit_events_mutation" in sql


def test_offline_sql_downgrade(alembic_config: Config, capsys: pytest.CaptureFixture):
    """Verify offline SQL downgrade produces reverse-order drop statements."""
    command.downgrade(
        alembic_config, "0004_p3h2_rbac_case_scoping:base", sql=True
    )
    captured = capsys.readouterr()
    sql = captured.out

    # Gate C.3 Decision 2: PostgreSQL triggers and function dropped in reverse order
    assert "DROP TRIGGER IF EXISTS trg_case_audit_events_prevent_truncate" in sql
    assert "DROP TRIGGER IF EXISTS trg_case_audit_events_immutable" in sql
    assert "DROP FUNCTION IF EXISTS fn_prevent_case_audit_events_mutation" in sql

    assert "DROP TABLE case_audit_events;" in sql
    assert "DROP TABLE case_assignments;" in sql
    assert "DROP TABLE case_evidence;" in sql
    assert "DROP TABLE cases;" in sql
    assert "DROP TABLE analyst_api_clients;" in sql
    assert "DROP TABLE analysts;" in sql
    assert "DROP TABLE knowledge_embeddings;" in sql
    assert "DROP TABLE extracted_entities;" in sql
    assert "DROP TABLE normalized_events;" in sql
    assert "DROP TABLE raw_evidence;" in sql
    assert "DELETE FROM alembic_version" in sql


def test_migration_0002_unchanged(alembic_config: Config):
    """Verify migration 0002 remains immutable with expected revision IDs and down_revision."""
    script_dir = ScriptDirectory.from_config(alembic_config)
    rev_0002 = script_dir.get_revision("0002_pgvector_knowledge_schema")
    assert rev_0002 is not None
    assert rev_0002.revision == "0002_pgvector_knowledge_schema"
    assert rev_0002.down_revision == "0001_initial_evidence_schema"
    assert rev_0002.nextrev == {"0003_source_scoped_chunks"}


def test_migration_0003_unchanged(alembic_config: Config):
    """Verify migration 0003 remains immutable with expected revision IDs and down_revision."""
    script_dir = ScriptDirectory.from_config(alembic_config)
    rev_0003 = script_dir.get_revision("0003_source_scoped_chunks")
    assert rev_0003 is not None
    assert rev_0003.revision == "0003_source_scoped_chunks"
    assert rev_0003.down_revision == "0002_pgvector_knowledge_schema"
    assert rev_0003.nextrev == {"0004_p3h2_rbac_case_scoping"}


def test_migration_0004_metadata(alembic_config: Config):
    """Verify migration 0004 has correct revision and down_revision."""
    script_dir = ScriptDirectory.from_config(alembic_config)
    rev_0004 = script_dir.get_revision("0004_p3h2_rbac_case_scoping")
    assert rev_0004 is not None
    assert rev_0004.revision == "0004_p3h2_rbac_case_scoping"
    assert rev_0004.down_revision == "0003_source_scoped_chunks"
    assert rev_0004.nextrev == set()


def test_migration_0004_immutability_triggers_and_downgrade_source(alembic_config: Config):
    """
    Verify migration 0004 source specifies PostgreSQL statement-level TRUNCATE trigger,
    row-level UPDATE/DELETE trigger, RESTRICT on analyst_api_clients, correct downgrade
    ordering, and contains no persisted lead_analyst_id.
    """
    script_dir = ScriptDirectory.from_config(alembic_config)
    rev_0004 = script_dir.get_revision("0004_p3h2_rbac_case_scoping")
    assert rev_0004 is not None
    assert rev_0004.path is not None

    source = Path(rev_0004.path).read_text(encoding="utf-8")

    # Decision 1: Normalized case lead (no persisted column in migration)
    assert "lead_analyst_id" not in source

    # Decision 2: PostgreSQL Audit Immutability Triggers
    assert "trg_case_audit_events_prevent_truncate" in source
    assert "BEFORE TRUNCATE ON case_audit_events" in source
    assert "FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_case_audit_events_mutation()" in source
    assert "trg_case_audit_events_immutable" in source
    assert "BEFORE UPDATE OR DELETE ON case_audit_events" in source
    assert "FOR EACH ROW EXECUTE FUNCTION fn_prevent_case_audit_events_mutation()" in source
    assert "fn_prevent_case_audit_events_mutation" in source

    # Verify least-privilege documentation and superuser caveat
    assert "REVOKE UPDATE, DELETE, TRUNCATE ON case_audit_events" in source
    assert "Does not protect against table owner / superuser overrides" in source

    # Decision 3: Credential lineage retention (RESTRICT foreign key)
    assert 'ondelete="RESTRICT"' in source
    assert "fk_analyst_api_clients_analyst_id_analysts" in source

    # Downgrade cleanup ordering: truncate trigger -> row trigger -> function
    pos_drop_trunc = source.find("DROP TRIGGER IF EXISTS trg_case_audit_events_prevent_truncate")
    pos_drop_immut = source.find("DROP TRIGGER IF EXISTS trg_case_audit_events_immutable")
    pos_drop_func = source.find("DROP FUNCTION IF EXISTS fn_prevent_case_audit_events_mutation")

    assert pos_drop_trunc != -1
    assert pos_drop_immut != -1
    assert pos_drop_func != -1
    assert pos_drop_trunc < pos_drop_immut < pos_drop_func



def test_migration_0003_guarded_downgrade_prevents_silent_deletion(alembic_config: Config):
    """
    Verify that Migration 0003 guarded downgrade aborts with RuntimeError when
    duplicate content_hash values exist, refusing to silently delete records.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    with engine.connect() as connection:
        alembic_config.attributes["connection"] = connection
        command.upgrade(alembic_config, "head")

        # Insert two rows with identical content_hash and distinct chunk_index
        now = "2026-10-21 10:00:00"
        connection.execute(
            sa.text(
                "INSERT INTO knowledge_embeddings "
                "(id, source_document, section_title, chunk_index, content, content_hash, embedding, chunk_metadata, created_at, updated_at) "
                "VALUES (:id, :doc, :sec, :idx, :content, :hash, :emb, :meta, :created, :updated)"
            ),
            [
                {"id": "00000000-0000-0000-0000-000000000001", "doc": "doc1.md", "sec": "s1", "idx": 0, "content": "dup", "hash": "dup_hash_123", "emb": "[0.0]*768", "meta": "{}", "created": now, "updated": now},
                {"id": "00000000-0000-0000-0000-000000000002", "doc": "doc2.md", "sec": "s2", "idx": 0, "content": "dup", "hash": "dup_hash_123", "emb": "[0.0]*768", "meta": "{}", "created": now, "updated": now},
            ],
        )
        connection.commit()

        # Attempt downgrade to 0002 -> must raise RuntimeError and NOT delete rows
        with pytest.raises(RuntimeError) as exc_info:
            command.downgrade(alembic_config, "0002_pgvector_knowledge_schema")

        assert "Downgrade aborted: 1 duplicate content_hash values exist" in str(exc_info.value)
        assert "Downgrade is lossy" in str(exc_info.value)

        # Verify both rows remain intact (zero rows silently deleted)
        count = connection.execute(sa.text("SELECT count(*) FROM knowledge_embeddings")).scalar()
        assert count == 2

    engine.dispose()


def test_isolated_migration_lifecycle(alembic_config: Config):
    """
    Execute full online migration upgrade and downgrade cycle on an isolated
    in-memory database engine via injected connection.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    with engine.connect() as connection:
        alembic_config.attributes["connection"] = connection

        # 1. Upgrade to head
        command.upgrade(alembic_config, "head")

        inspector = inspect(connection)
        tables = inspector.get_table_names()
        assert "raw_evidence" in tables
        assert "normalized_events" in tables
        assert "extracted_entities" in tables
        assert "knowledge_embeddings" in tables
        assert "analysts" in tables
        assert "analyst_api_clients" in tables
        assert "cases" in tables
        assert "case_evidence" in tables
        assert "case_assignments" in tables
        assert "case_audit_events" in tables
        assert "alembic_version" in tables

        # 2. Check foreign keys
        fks_events = inspector.get_foreign_keys("normalized_events")
        assert any(fk["referred_table"] == "raw_evidence" for fk in fks_events)

        fks_entities = inspector.get_foreign_keys("extracted_entities")
        assert any(fk["referred_table"] == "normalized_events" for fk in fks_entities)
        assert any(fk["referred_table"] == "raw_evidence" for fk in fks_entities)

        fks_api_clients = inspector.get_foreign_keys("analyst_api_clients")
        assert any(fk["referred_table"] == "analysts" for fk in fks_api_clients)

        fks_cases = inspector.get_foreign_keys("cases")
        assert len(fks_cases) == 0  # Normalized: cases has no direct FK; lead is in case_assignments

        fks_case_evidence = inspector.get_foreign_keys("case_evidence")
        assert any(fk["referred_table"] == "cases" for fk in fks_case_evidence)
        assert any(fk["referred_table"] == "normalized_events" for fk in fks_case_evidence)

        fks_case_assignments = inspector.get_foreign_keys("case_assignments")
        assert any(fk["referred_table"] == "cases" for fk in fks_case_assignments)
        assert any(fk["referred_table"] == "analysts" for fk in fks_case_assignments)

        fks_case_audit = inspector.get_foreign_keys("case_audit_events")
        assert any(fk["referred_table"] == "cases" for fk in fks_case_audit)

        # 3. Check schema parity with Base.metadata (zero unexpected diffs)
        def sqlite_compare_type(
            context,
            inspected_column,
            metadata_column,
            inspected_type,
            metadata_type,
        ):
            # SQLite reflects Vector columns as NUMERIC because SQLite lacks native vector types
            if (
                isinstance(metadata_type, Vector)
                and inspected_type.__class__.__name__ == "NUMERIC"
            ):
                return False
            return None

        def sqlite_include_object(object, name, type_, reflected, compare_to):
            # Exclude PostgreSQL-specific HNSW index from SQLite schema parity check
            if type_ == "index" and getattr(object, "dialect_options", {}).get("postgresql", {}).get("using") == "hnsw":
                return False
            return True

        ctx = MigrationContext.configure(
            connection,
            opts={
                "compare_type": sqlite_compare_type,
                "compare_server_default": True,
                "include_object": sqlite_include_object,
            },
        )
        diffs = compare_metadata(ctx, Base.metadata)
        assert diffs == []

        # 4. Downgrade to base
        command.downgrade(alembic_config, "base")

        inspector = inspect(connection)
        remaining_tables = inspector.get_table_names()
        assert "case_audit_events" not in remaining_tables
        assert "case_assignments" not in remaining_tables
        assert "case_evidence" not in remaining_tables
        assert "cases" not in remaining_tables
        assert "analyst_api_clients" not in remaining_tables
        assert "analysts" not in remaining_tables
        assert "knowledge_embeddings" not in remaining_tables
        assert "raw_evidence" not in remaining_tables
        assert "normalized_events" not in remaining_tables
        assert "extracted_entities" not in remaining_tables

    engine.dispose()
