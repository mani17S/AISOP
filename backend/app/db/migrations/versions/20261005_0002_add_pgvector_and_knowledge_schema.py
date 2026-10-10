"""Add pgvector extension and knowledge_embeddings schema.

Revision ID: 0002_pgvector_knowledge_schema
Revises: 0001_initial_evidence_schema
Create Date: 2026-10-05 01:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
from pgvector.sqlalchemy import Vector
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002_pgvector_knowledge_schema"
down_revision: Union[str, None] = "0001_initial_evidence_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # 1. Enable pgvector extension (PostgreSQL only)
    if is_postgres:
        op.execute("CREATE EXTENSION IF NOT EXISTS vector;")

    # 2. Create knowledge_embeddings table
    op.create_table(
        "knowledge_embeddings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source_document", sa.String(length=255), nullable=False),
        sa.Column("section_title", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("embedding", Vector(768), nullable=False),
        sa.Column(
            "chunk_metadata",
            postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_embeddings")),
    )

    # 3. Standard B-Tree Indexes (NO redundant index on id)
    op.create_index(
        op.f("ix_knowledge_embeddings_source_document"),
        "knowledge_embeddings",
        ["source_document"],
        unique=False,
    )
    op.create_index(
        op.f("ix_knowledge_embeddings_content_hash"),
        "knowledge_embeddings",
        ["content_hash"],
        unique=True,
    )

    # 4. HNSW Vector Index (PostgreSQL only)
    # Parameters m=16, ef_construction=64 represent an initial recall/latency trade-off
    # to be empirically evaluated.
    if is_postgres:
        op.create_index(
            "ix_knowledge_embeddings_embedding_hnsw",
            "knowledge_embeddings",
            ["embedding"],
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
            postgresql_with={"m": 16, "ef_construction": 64},
        )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # 1. Drop HNSW index if on PostgreSQL
    if is_postgres:
        op.drop_index(
            "ix_knowledge_embeddings_embedding_hnsw",
            table_name="knowledge_embeddings",
        )

    # 2. Drop standard B-Tree indexes
    op.drop_index(
        op.f("ix_knowledge_embeddings_content_hash"),
        table_name="knowledge_embeddings",
    )
    op.drop_index(
        op.f("ix_knowledge_embeddings_source_document"),
        table_name="knowledge_embeddings",
    )

    # 3. Drop table
    op.drop_table("knowledge_embeddings")

    # Note: pgvector extension is NOT dropped during downgrade to preserve
    # database-level extensions and permissions for subsequent operations.
