"""Source-scoped positional knowledge chunk schema and indices.

Revision ID: 0003_source_scoped_chunks
Revises: 0002_pgvector_knowledge_schema
Create Date: 2026-10-21 10:00:00.000000

Milestone: P2-H3 (Knowledge Base Ingestion Pipeline & Semantic Retrieval)
Key Changes:
- Add top-level integer column `chunk_index` to `knowledge_embeddings`.
- Drop global uniqueness constraint on `content_hash` and replace with non-unique B-tree lookup index.
- Execute deterministic structural window-function backfill for legacy surviving rows.
- Enforce NOT NULL on `chunk_index`.
- Create composite unique index on `(source_document, chunk_index)`.
- Guarded non-destructive downgrade policy: aborts if duplicate content_hash values exist.
"""

from typing import Sequence, Union

from alembic import context, op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0003_source_scoped_chunks"
down_revision: Union[str, None] = "0002_pgvector_knowledge_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # 1. Add chunk_index column (nullable initially for structural backfill)
    with op.batch_alter_table("knowledge_embeddings") as batch_op:
        batch_op.add_column(sa.Column("chunk_index", sa.Integer(), nullable=True))

    # 2. Drop global uniqueness from content_hash and recreate as non-unique B-tree index
    op.drop_index(
        op.f("ix_knowledge_embeddings_content_hash"),
        table_name="knowledge_embeddings",
    )
    op.create_index(
        op.f("ix_knowledge_embeddings_content_hash"),
        "knowledge_embeddings",
        ["content_hash"],
        unique=False,
    )

    # 3. Deterministic structural backfill for surviving legacy rows
    # NOTE: This backfill is purely a structural bridge to satisfy NOT NULL and
    # UNIQUE(source_document, chunk_index) constraints on surviving rows.
    # It does NOT reconstruct true physical source-document order. True document order
    # must be restored via post-migration re-ingestion from source files.
    if is_postgres:
        op.execute(sa.text("""
            UPDATE knowledge_embeddings SET chunk_index = seq.new_idx
            FROM (
                SELECT id, ROW_NUMBER() OVER (
                    PARTITION BY source_document 
                    ORDER BY 
                        CASE 
                            WHEN (chunk_metadata->>'chunk_index') ~ '^[0-9]+$' 
                            THEN (chunk_metadata->>'chunk_index')::int 
                            ELSE 0 
                        END, 
                        section_title, 
                        created_at, 
                        id
                ) - 1 AS new_idx
                FROM knowledge_embeddings
            ) seq WHERE knowledge_embeddings.id = seq.id;
        """))
    else:
        op.execute(sa.text("""
            WITH seq AS (
                SELECT id, ROW_NUMBER() OVER (
                    PARTITION BY source_document 
                    ORDER BY 
                        COALESCE(json_extract(chunk_metadata, '$.chunk_index'), 0),
                        section_title, 
                        created_at, 
                        id
                ) - 1 AS new_idx
                FROM knowledge_embeddings
            )
            UPDATE knowledge_embeddings 
            SET chunk_index = (SELECT new_idx FROM seq WHERE seq.id = knowledge_embeddings.id)
            WHERE id IN (SELECT id FROM seq);
        """))

    # 4. Enforce NOT NULL on chunk_index
    with op.batch_alter_table("knowledge_embeddings") as batch_op:
        batch_op.alter_column("chunk_index", nullable=False)

    # 5. Create composite unique index on (source_document, chunk_index)
    op.create_index(
        op.f("ix_knowledge_embeddings_source_document_chunk_index"),
        "knowledge_embeddings",
        ["source_document", "chunk_index"],
        unique=True,
    )


def downgrade() -> None:
    bind = op.get_bind()

    # 1. Guard against lossy downgrade: abort if duplicate content_hash values exist (online mode only)
    if not context.is_offline_mode():
        dup_query = sa.text("""
            SELECT count(*) FROM (
                SELECT content_hash 
                FROM knowledge_embeddings 
                GROUP BY content_hash 
                HAVING count(*) > 1
            ) d;
        """)
        result = bind.execute(dup_query)
        dup_count = result.scalar() if result is not None else 0
        if dup_count and dup_count > 0:
            raise RuntimeError(
                f"Downgrade aborted: {dup_count} duplicate content_hash values exist in 'knowledge_embeddings'. "
                "Reverting to revision 0002_pgvector_knowledge_schema would require restoring global UNIQUE(content_hash), "
                "which would cause destructive data deletion of valid knowledge chunks. "
                "Downgrade is lossy and strictly blocked. To revert to revision 0002 without data loss, "
                "restore from a pre-migration database backup."
            )

    # 2. Drop composite unique index on (source_document, chunk_index)
    op.drop_index(
        op.f("ix_knowledge_embeddings_source_document_chunk_index"),
        table_name="knowledge_embeddings",
    )

    # 3. Drop non-unique content_hash index and restore global unique index
    op.drop_index(
        op.f("ix_knowledge_embeddings_content_hash"),
        table_name="knowledge_embeddings",
    )
    op.create_index(
        op.f("ix_knowledge_embeddings_content_hash"),
        "knowledge_embeddings",
        ["content_hash"],
        unique=True,
    )

    # 4. Drop chunk_index column
    with op.batch_alter_table("knowledge_embeddings") as batch_op:
        batch_op.drop_column("chunk_index")
