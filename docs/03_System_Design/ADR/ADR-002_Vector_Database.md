# ADR-002: Vector Database Selection

| Field | Value |
|-------|-------|
| **ID** | ADR-002 |
| **Status** | APPROVED |
| **Date Proposed** | 2026-09-09 |
| **Date Approved** | 2026-09-09 |
| **Decision Maker** | Project Owner |

---

## Question

Where and how should AISOP store vector embeddings for semantic similarity
search (Retrieval-Augmented Generation)?

## Context

AISOP needs to store and retrieve semantically similar unstructured knowledge
to augment LLM prompts. The primary knowledge sources include:

- MITRE ATT&CK technique descriptions (~600 techniques with tactics,
  procedures, detection guidance, mitigations)
- Detection playbooks (step-by-step investigation procedures)
- Sigma rule documentation (detection rule descriptions and rationale)
- Historical investigation case summaries
- Organizational security policies and SOPs

When an analyst investigates an alert, AISOP must rapidly find the most
relevant MITRE techniques, playbooks, and historical cases to include in the
LLM prompt context window.

This decision affects:

- How many separate database services must be running locally.
- Whether vector search results can be JOIN'd with relational investigation
  data in a single query.
- Backup, migration, and disaster recovery complexity.
- The contributor's mental model of the data layer.

AISOP Master Prompt references:

- §4: *"A user should eventually be able to deploy AISOP locally."*
- §9: Security-first design — unified access control.
- §27: Reproducible setup, easy extension by contributors.

## Options Considered

### Option A: PostgreSQL with `pgvector` Extension (Unified Database)

Add the `pgvector` extension to the existing PostgreSQL 17 instance. Vector
embeddings stored in regular Postgres tables with a `vector(N)` column.
Similarity search uses Postgres operators (`<=>` cosine, `<->` L2) with HNSW
or IVFFlat indexes.

Removes `chromadb` and its transitive dependencies (`onnxruntime`,
`flatbuffers`, `ormsgpack`, `overrides`, `pypika`, `mmh3`, etc.) from
`requirements.txt`.

### Option B: Embedded ChromaDB (In-Process)

ChromaDB runs inside the FastAPI process as a Python library. Data persisted
to a local `vector_db/` directory using SQLite + parquet files. No separate
server process.

### Option C: Standalone ChromaDB Server

ChromaDB runs as a separate HTTP service on `localhost:8000`. The FastAPI
backend connects via `chromadb.HttpClient`. In production, ChromaDB would be
a separate Docker container.

## Trade-Off Analysis

| Criterion | Option A: pgvector | Option B: Embedded ChromaDB | Option C: Standalone ChromaDB |
|-----------|-------------------|---------------------------|------------------------------|
| Local-First Deployment | Strong | Strong | Weak |
| Open-Source Extensibility | Strong | Adequate | Adequate |
| Modularity | Strong | Adequate | Adequate |
| Security | Strong | Adequate | Weak |
| Maintainability | Strong | Adequate | Weak |
| Scalability | Strong | Adequate | Adequate |
| Developer Experience | Strong | Adequate | Weak |
| Testing | Strong | Adequate | Weak |
| Operational Complexity | Strong | Adequate | Weak |
| Future LLM Flexibility | Adequate | Adequate | Adequate |

Key differentiator: pgvector unifies all data under PostgreSQL's
authentication, encryption, access control, backup, and migration systems.
AISOP's expected knowledge base size (~10K–50K embeddings) is well within
pgvector's comfortable operating range with HNSW indexes.

## Recommendation

Option A (PostgreSQL with `pgvector`) was recommended. Unifies all data in
one database service. Superior security, operational simplicity, and developer
experience. Option B (Embedded ChromaDB) was identified as an acceptable
fallback if `pgvector` Windows installation proves problematic.

## Decision (Project Owner — 2026-09-09)

**APPROVED: PostgreSQL + pgvector (Option A).**

PostgreSQL will be the primary persistent data store and pgvector will provide
vector/embedding capabilities.

A separate vector database shall not be introduced into the core architecture
unless a future requirement justifies it and the Project Owner approves it.

## Architectural Consequences

1. `requirements.txt` will drop `chromadb` and its transitive dependencies,
   reducing install size by ~200–400MB.
2. All data (relational + vector) lives in PostgreSQL. Alembic manages all
   schema migrations. `pg_dump` backs up everything.
3. The RAG retriever service internally runs SQL queries with vector
   operators — same developer experience as any other database query.
4. `sentence-transformers` or a lighter embedding library remains for
   computing embeddings before insertion.
5. Contributors need PostgreSQL with the `vector` extension installed. On
   Docker, this is trivial (`ankane/pgvector` image). On bare metal, it
   requires the extension binary for the target platform.
6. The `CHROMA_HOST`, `CHROMA_PORT`, and `CHROMA_COLLECTION_NAME` settings in
   `config.py` and `.env.example` become obsolete and should be removed.
7. New settings for `pgvector` (embedding dimensions, index type) should be
   added to the configuration.

## Risks

1. **Risk (Medium): `pgvector` Windows Installation.** The `pgvector`
   extension requires compilation on some platforms. On Windows without Visual
   Studio Build Tools, this can be challenging. **Mitigation:** Use Docker for
   PostgreSQL with `pgvector` pre-installed (`ankane/pgvector:v0.7.0-pg17`),
   or fall back to Embedded ChromaDB (Option B) if native installation proves
   difficult. This fallback does NOT require a new ADR — it was pre-evaluated.
2. **Risk (Low): Embedding Model Dimension Changes.** Switching embedding
   models with different vector dimensions requires a one-time migration.
   **Mitigation:** Store the embedding model name in metadata; build
   re-embedding as a management command.
