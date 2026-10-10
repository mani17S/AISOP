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
    assert heads[0] == "0002_pgvector_knowledge_schema"


def test_target_metadata_tables():
    """Verify Base.metadata contains the complete canonical set of models."""
    expected_tables = {
        "raw_evidence",
        "normalized_events",
        "extracted_entities",
        "knowledge_embeddings",
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

    # Check knowledge_embeddings
    know_tbl = Base.metadata.tables["knowledge_embeddings"]
    assert "id" in know_tbl.c
    assert "source_document" in know_tbl.c
    assert "section_title" in know_tbl.c
    assert "content" in know_tbl.c
    assert "content_hash" in know_tbl.c
    assert "embedding" in know_tbl.c
    assert "chunk_metadata" in know_tbl.c
    assert "created_at" in know_tbl.c
    assert "updated_at" in know_tbl.c


def test_offline_sql_upgrade(alembic_config: Config, capsys: pytest.CaptureFixture):
    """Verify offline SQL generation (--sql) produces valid DDL for all tables."""
    command.upgrade(alembic_config, "head", sql=True)
    captured = capsys.readouterr()
    sql = captured.out

    assert "CREATE TABLE raw_evidence" in sql
    assert "CREATE TABLE normalized_events" in sql
    assert "CREATE TABLE extracted_entities" in sql
    assert "CREATE TABLE knowledge_embeddings" in sql
    assert "CREATE TABLE alembic_version" in sql
    assert "ix_raw_evidence_sha256_hash" in sql
    assert "ix_normalized_events_type_time" in sql
    assert "ix_extracted_entities_type_value" in sql
    assert "ix_knowledge_embeddings_source_document" in sql
    assert "ix_knowledge_embeddings_content_hash" in sql
    assert "COMMIT;" in sql


def test_offline_sql_downgrade(alembic_config: Config, capsys: pytest.CaptureFixture):
    """Verify offline SQL downgrade produces reverse-order drop statements."""
    command.downgrade(
        alembic_config, "0002_pgvector_knowledge_schema:base", sql=True
    )
    captured = capsys.readouterr()
    sql = captured.out

    assert "DROP TABLE knowledge_embeddings;" in sql
    assert "DROP TABLE extracted_entities;" in sql
    assert "DROP TABLE normalized_events;" in sql
    assert "DROP TABLE raw_evidence;" in sql
    assert "DELETE FROM alembic_version" in sql


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
        assert "alembic_version" in tables

        # 2. Check foreign keys
        fks_events = inspector.get_foreign_keys("normalized_events")
        assert any(fk["referred_table"] == "raw_evidence" for fk in fks_events)

        fks_entities = inspector.get_foreign_keys("extracted_entities")
        assert any(fk["referred_table"] == "normalized_events" for fk in fks_entities)
        assert any(fk["referred_table"] == "raw_evidence" for fk in fks_entities)

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
        assert "knowledge_embeddings" not in remaining_tables
        assert "raw_evidence" not in remaining_tables
        assert "normalized_events" not in remaining_tables
        assert "extracted_entities" not in remaining_tables

    engine.dispose()
