# AISOP — Milestone P2-H3 Implementation Readiness Gate & Architecture Audit

**Document ID:** `AISOP-GATE-P2H3-004`  
**Task ID:** `AISOP-P2-H3-DESIGN-GATE-004`  
**Date:** 2026-10-21  
**Project:** AISOP — AI-Assisted Security Operations Platform  
**Authoritative Workspace:** `C:\Users\sarik\Documents\GO\02_COLLEGE\SEM_Projects\MINOR\SEM7\AISOP`  
**Audit Mode:** READ-ONLY REPOSITORY AUDIT + DESIGN VALIDATION + GOVERNANCE  
**Implementation Authorization:** NOT GRANTED — AWAITING EXPLICIT PROJECT OWNER APPROVAL  

---

## 1. Executive Verdict

### Verdict: CONDITIONAL GO

The architectural strategy for Milestone **P2-H3** (Knowledge Base Ingestion Pipeline & Semantic Retrieval) — transitioning from flawed text-content uniqueness to **Positional Uniqueness (`Option A-Prime`)** — is hereby certified as technically sound, mathematically consistent, and architecturally superior.

This design permanently resolves the critical defects in the current implementation:
1. Cross-document chunk suppression where distinct documents sharing common procedural text (e.g., standard disclaimers, MITRE definitions, SOP steps) silently drop chunks from subsequent documents.
2. Intra-document chunk suppression where identical text occurring across distinct sections of the same document is discarded.
3. Lack of document-wide sequential chunk ordering required for contextual reconstruction.
4. Non-atomic cross-document deletions where re-indexing one document can delete chunks belonging to other documents.

However, implementation authorization is **STRICTLY CONDITIONAL** upon Project Owner resolution of four governance and safety prerequisites:

1. **Rejection of Destructive Downgrade:** The previously proposed downgrade strategy (deleting duplicate content rows in `downgrade()` to restore `UNIQUE(content_hash)`) is **REJECTED**. The Project Owner must approve a guarded, non-destructive downgrade policy that aborts if duplicates exist and directs restoration from backup.
2. **Backfill Reality Acknowledgment:** The Project Owner must formally recognize that SQL window functions can only assign an arbitrary deterministic integer sequence to existing database rows to satisfy schema constraints; true document order can only be recovered via post-migration re-ingestion from authoritative source files.
3. **Exact-Search Protocol Hardening:** The exact-search benchmark protocol must implement dual scan disabling (`SET LOCAL enable_indexscan = off; SET LOCAL enable_bitmapscan = off;`) and use the corrected recall denominator when candidate filtering yields fewer than $k$ eligible chunks.
4. **Implementation Authorization Gate:** Antigravity remains strictly in read-only audit mode until the Project Owner explicitly authorizes Phase A implementation.

---

## 2. Verified Repository Identity and Git State

Preflight inspection of the host environment and Git metadata confirms:

* **Authoritative Workspace Path:** `C:\Users\sarik\Documents\GO\02_COLLEGE\SEM_Projects\MINOR\SEM7\AISOP`
* **Secondary Workspace / Mirror:** `D:\AISOP` (present, verified at identical commit `c4e877c`).
* **Active Working Directory:** Operating exclusively within `C:\Users\sarik\Documents\GO\02_COLLEGE\SEM_Projects\MINOR\SEM7\AISOP`.
* **Git Repository Verified:** Yes (`.git` valid).
* **Current Branch:** `main`
* **HEAD Commit:** `c4e877cf06056bce32f5a3f893a82261b850ff85`
  * *Commit Subject:* `docs(milestones): record P2-H1 and P2-H2 completion baselines`
  * *Commit Date:* Wed Oct 21 02:44:06 2026 +0530
* **Upstream Relationship:** Ahead of `origin/main` by 12 commits (local commits unpushed; clean upstream tracking).
* **Tracked Modifications (12 files):**
  * `backend/README.md`
  * `backend/app/core/config.py` (RAG settings: chunk size, overlap, top-k, similarity threshold)
  * `backend/app/db/migrations/env.py`
  * `backend/app/db/session.py`
  * `backend/app/main.py`
  * `backend/app/modules/ai/knowledge/embedder.py`
  * `backend/pyproject.toml`
  * `docs/00_Project_Management/ADR_Tracker.md`
  * `docs/00_Project_Management/Milestones.md`
  * `docs/01_System_Architecture/System_Architecture_Document.md`
  * `docs/03_System_Design/ADR/ADR-004_Vector_Database_Selection.md`
  * `docs/04_Security_and_Compliance/Threat_Model.md`
* **Untracked Items (35 items):** Includes P2-H3 implementation draft modules (`backend/app/modules/ai/knowledge/` chunker, loader, ingestion_service, retriever), schemas, unit/integration test files, and governance records (`AISOP_Historical_Handover.md`, `P2-H3_Readiness_Audit.md`).
* **Secret & Environment Safety:** Inspected `.env` existence without reading, logging, or printing secret values, passwords, or connection strings.
* **Preservation Rule Adherence:** Zero destructive commands executed (`git add`, `git commit`, `git reset`, `git clean`, `git stash`, branch changes, or checkout).

---

## 3. Current P2-H3 Implementation Inventory

An exhaustive inspection of the existing codebase, schema definitions, and migration revisions was conducted:

| # | Inspection Item | Exact File & Symbol / Line | Observed Current Behavior | Evidence Source | Severity & Consequence | Required Remediation |
|:---:|:---|:---|:---|:---:|:---|:---|
| **1** | **Global Hash Uniqueness** | `backend/app/models/knowledge.py:L50`<br>Migration `0002:L58` | `content_hash` has `unique=True` on table column and index. | Code inspection | **Critical (P0):** Multi-document knowledge base cannot store identical text across documents. | Drop global uniqueness in Migration 0003; replace with non-unique B-tree index. |
| **2** | **Chunk Index Location & Meaning** | `backend/app/schemas/knowledge.py:L62`<br>`chunker.py:L117` | `chunk_index` exists only inside `chunk_metadata` JSONB dict; 0-based per section. | Code inspection | **High (P1):** Relational queries cannot filter, order, or constrain by chunk position. | Add first-class `chunk_index` integer column to table. |
| **3** | **Chunk Index Scope** | `backend/app/modules/ai/knowledge/chunker.py:L117` | Index resets to `0` at the start of each Markdown section (`## Heading`). | Code inspection | **High (P1):** Document-wide sequence does not exist; multiple chunks share index `0`. | Introduce `document_chunk_index` running continuously $0, \dots, N-1$ across document. |
| **4** | **Intra-Doc Duplicate Dropping** | `ingestion_service.py:L168-178` | Skips chunk if `chunk.content_hash in seen_chunk_hashes`. | Code inspection | **High (P1):** Repeated disclaimers, SOP steps, or MITRE definitions within a file are erased. | Remove intra-doc hash deduplication filter; preserve all occurrences. |
| **5** | **Cross-Doc Duplicate Dropping** | `ingestion_service.py:L180-196` | Queries DB for hashes existing in other docs and filters them out. | Code inspection | **Critical (P0):** If Doc B has text identical to Doc A, Doc B receives 0 database records. | Remove cross-doc database hash exclusion check completely. |
| **6** | **In-Memory Embedding Dedup** | `ingestion_service.py:L201-203` | No in-memory mapping. Calls `embed_batch` directly on surviving chunk list. | Code inspection | **Medium (P2):** Repeated texts are either dropped (current) or cause redundant Ollama calls (if unhandled). | Deduplicate strings before calling Ollama; map returned vectors back to all chunk occurrences. |
| **7** | **Retrieval Contract & Tie-Breaking** | `backend/app/modules/ai/knowledge/retriever.py:L181-190` | Returns `RetrievalResult`. `chunk_index` buried in metadata. No secondary tie-breaker in `ORDER BY`. | Code inspection | **Medium (P2):** Retrieval cannot guarantee stable pagination or deterministic ordering for identical scores. | Expose top-level `chunk_index`; order by `distance ASC, source_document ASC, chunk_index ASC`. |
| **8** | **Document Replacement Atomicity** | `ingestion_service.py:L235-258` | Uses `session.begin_nested()` savepoint: deletes existing rows and bulk inserts new ones. | Code inspection | **Verified (Good):** Savepoint rollback restores prior chunks if insert fails. | Retain savepoint pattern; verify session flush behavior. |
| **9** | **Document Deletion & Pruning** | `ingestion_service.py` | Lacks `delete_document()` or directory pruning method. | Code inspection | **Medium (P2):** Deleted or renamed markdown files leave orphaned rows permanently in DB. | Implement `delete_document(source_document)` and `prune_orphaned_documents()`. |
| **10** | **Failure-Safe Re-Indexing** | `ingestion_service.py:L260-265` | Savepoint rollbacks on exception, leaving previous document rows intact. | Code & test inspection | **Verified (Good):** Tested in `test_ingest_document_failure_rollback`. | Preserve savepoint isolation during Migration 0003 updates. |
| **11** | **Migration HEAD & Revision State** | `backend/app/db/migrations/versions/` | Revision `0002_pgvector_knowledge_schema` is at HEAD. `0001` created initial core schema. | Alembic check | **Verified (Good):** `0002` is committed and immutable. New changes must go into `0003`. | Create `20261021_0003_source_scoped_knowledge_chunks.py`. |
| **12** | **Existing Tests & Verification Scope** | `backend/tests/unit/` & `integration/` | 180 total tests collected. 167 Tier 1 unit/mock tests PASS (100%). 13 Tier 2 tests require port 5433. | Pytest collection & run | **Verified (Good):** Unit suite passes offline in 14.73s. Tier 2 requires Docker start. | Keep all 167 passing tests green; author Tier 1 & Tier 2 tests for Option A-Prime. |

---

## 4. Option A-Prime Decision Matrix

Option A-Prime models chunk identity by its **physical position in a source document**, completely decoupling relational uniqueness from semantic text content.

* **Relational Identity:** `(source_document, chunk_index)`
* **Relational Constraint:** `UNIQUE (source_document, chunk_index)`
* **Text Indexing:** `content_hash` becomes a non-unique lookup index (`ix_knowledge_embeddings_content_hash`).
* **Core Invariant:**
  $$\text{Number of Persisted Rows} = \text{Number of Physical Chunk Occurrences}$$

### 4.1 Detailed Architectural Evaluation Table

| Element ID | Architecture Element | Proposed Rule / Design | Decision | Technical Rationale & Trade-Off |
|:---:|:---|:---|:---:|:---|
| **A.1** | **Source Document Identity** | Store `source_document` as relative POSIX path from `knowledge_base/` root (e.g., `mitre/T1059.md`). | **ACCEPT** | Avoids machine-dependent absolute paths; eliminates the complexity of a separate document registry table while fully satisfying project requirements. |
| **A.2** | **Path Normalization** | Loader applies `Path(p).resolve().relative_to(kb_root).as_posix()`. | **ACCEPT** | Neutralizes Windows `\` vs POSIX `/` differences, prevents path-traversal vulnerabilities, and ensures cross-platform consistency. |
| **A.3** | **Document Versioning** | Compute whole-file SHA-256 at load time; store in `chunk_metadata["doc_version"]`. | **ACCEPT** | Enables efficient change detection (`force_reindex=False` skips unmodified files) without adding redundant schema columns. |
| **A.4** | **Document-Wide Chunk Index** | Assign continuous $0, \dots, N-1$ index across entire document. | **REVISE** | The chunker currently resets `chunk_index` to 0 per section. Must refactor `DocumentChunker` to sequence across all sections. |
| **A.5** | **Repeated Content Intra-Doc** | Duplicate text within a document persists at every distinct `chunk_index`. | **ACCEPT** | Essential for cybersecurity playbooks where common warnings, commands, or disclaimers appear in multiple sections with distinct context. |
| **A.6** | **Cross-Doc Text Sharing** | Identical text in multiple documents persists independently in each document's rows. | **ACCEPT** | Prevents cross-document cascading deletion and guarantees document attribution integrity. |
| **A.7** | **In-Memory Embedding Dedup** | Map unique text hashes to embedding vectors in memory before calling Ollama; assign vector to all occurrence rows. | **ACCEPT** | Eliminates redundant Ollama embedding inference while maintaining 100% database row fidelity. |
| **A.8** | **Retrieval Contract Schema** | Expose top-level `chunk_index`, `source_document`, `section_title`, `content`, `similarity_score`. | **ACCEPT** | Consumers receive structured provenance without parsing JSONB metadata. |
| **A.9** | **Deterministic Tie-Breaking** | `ORDER BY (embedding <=> :query) ASC, source_document ASC, chunk_index ASC`. | **ACCEPT** | Guarantees stable ordering and reproducible pagination when cosine distances are identical. |
| **A.10** | **Distance vs Similarity** | `cosine_similarity = 1.0 - cosine_distance`. | **ACCEPT** | pgvector `<=>` operator computes cosine distance $[0, 2]$. Transforming to similarity $[ -1, 1 ]$ is mathematically consistent. |

---

## 5. Migration 0003 — Safety Review

### 5.1 Proposed Schema DDL (`20261021_0003_source_scoped_knowledge_chunks.py`)

Migration `0003` must transition the database schema safely without dropping valid rows:

1. **Add Column:** `op.add_column("knowledge_embeddings", sa.Column("chunk_index", sa.Integer(), nullable=True))`
2. **Drop Unique Hash Index:** `op.drop_index("ix_knowledge_embeddings_content_hash", table_name="knowledge_embeddings")`
3. **Create Non-Unique Hash Index:** `op.create_index("ix_knowledge_embeddings_content_hash", "knowledge_embeddings", ["content_hash"], unique=False)`
4. **Structural Backfill (Window Function):**
   ```sql
   UPDATE knowledge_embeddings SET chunk_index = seq.new_idx
   FROM (
     SELECT id, ROW_NUMBER() OVER (
       PARTITION BY source_document 
       ORDER BY (chunk_metadata->>'chunk_index')::int, section_title, created_at, id
     ) - 1 AS new_idx
     FROM knowledge_embeddings
   ) seq WHERE knowledge_embeddings.id = seq.id;
   ```
5. **Enforce Nullability:** `op.alter_column("knowledge_embeddings", "chunk_index", nullable=False)`
6. **Create Composite Unique Index:**
   `op.create_index("ix_knowledge_embeddings_source_chunk_idx", "knowledge_embeddings", ["source_document", "chunk_index"], unique=True)`

### 5.2 Migration Verification Matrix

| Scenario | Database State Prior to Migration | Expected Migration Outcome | Verification Test / Evidence Required |
|:---|:---|:---|:---|
| **1. Empty Database** | Zero rows in `knowledge_embeddings`. | Upgrade succeeds cleanly; DDL applies; column is `NOT NULL`. | `test_postgres_0003_upgrade_lifecycle` on clean schema. |
| **2. Existing Single-Section Rows** | Rows exist with distinct `content_hash` and section-local chunk indices. | Backfill assigns `0, 1, 2...`; column set to NOT NULL; unique constraint applied. | Test with populated database; verify `SELECT count(*) WHERE chunk_index IS NULL` is 0. |
| **3. Multiple Sections / Duplicate Local Indices** | Multiple sections in a document each had local index `0, 1, 2`. | `ROW_NUMBER()` partitions by `source_document` and assigns unique sequential integers. | Assert no unique constraint violation on composite index creation. |
| **4. Duplicate Hashes Intra-Doc** | Data artificially inserted with identical `content_hash` in same document. | Upgrade succeeds because `content_hash` uniqueness is dropped before index creation. | Migration applies without error; both rows retain distinct `chunk_index`. |
| **5. Duplicate Hashes Across Docs** | Data inserted with identical `content_hash` across distinct `source_document`s. | Upgrade succeeds; non-unique hash index allows identical hashes. | Assert index creation succeeds and both rows are preserved. |
| **6. Failure During Migration** | Process interrupted or syntax failure before commit. | Whole migration is in a single DDL transaction; rollback leaves schema at revision `0002`. | Assert PostgreSQL transaction rolls back cleanly; revision remains `0002`. |
| **7. Failure During Re-Ingestion** | Post-migration re-ingestion encounters Ollama timeout or parse error. | Application savepoint (`session.begin_nested()`) rolls back affected document; existing rows remain. | Assert `test_ingest_document_failure_rollback` passes. |
| **8. Repeated Execution / Idempotency** | Running migration upgrade again when already at `0003`. | Alembic recognizes head revision `0003` and exits as a no-op. | Assert `alembic upgrade head` produces zero changes when already at head. |
| **9. Guarded Downgrade Behavior** | Attempting `alembic downgrade -1` when database contains duplicate hashes. | Downgrade aborts with informative exception; zero rows deleted. | Assert `test_postgres_0003_guarded_downgrade` raises `RuntimeError`. |

---

## 6. Backfill and Re-Ingestion Plan

### 6.1 Critical Finding: Backfill Cannot Reconstruct Original Document Order
> [!WARNING]
> **Engineering Reality:** The SQL window function `ROW_NUMBER() OVER (...)` is strictly a **structural constraint bridge** to satisfy `NOT NULL` and `UNIQUE(source_document, chunk_index)` constraints on legacy rows.
> 
> It **CANNOT** reconstruct true historical document order because:
> 1. Sorting by `section_title` alphabetically does not reflect heading sequence in the original Markdown file.
> 2. Batched inserts have identical `created_at` timestamps.
> 3. Chunks previously dropped by global deduplication were never inserted and are permanently absent from the database.
>
> True document order and complete chunk coverage can only be restored by re-ingesting authoritative source files from disk.

### 6.2 Strict Separation of Concerns
* **Migration Rule:** Migration `0003` must **NEVER** import application services, read filesystem markdown, or invoke Ollama embedding APIs. Schema migration and content ingestion are strictly separated.
* **Standard Operational Procedure (SOP):**
  1. **Preflight Audit:** Verify source files exist in `knowledge_base/` and record pre-migration row count.
  2. **Backup:** Generate PostgreSQL dump (`pg_dump -Fc aisop > backup_pre_0003.dump`).
  3. **DDL Migration:** Execute `alembic upgrade head` (applies `0003` structural changes and backfill).
  4. **Schema Verification:** Assert `chunk_index` column exists, is `NOT NULL`, and composite index is active.
  5. **Application Re-Ingestion:** Execute CLI / service ingestion with `force_reindex=True`.
  6. **Reconciliation:** Verify that `SELECT count(*) FROM knowledge_embeddings` matches expected chunk count.
  7. **Smoke Tests:** Execute semantic retrieval queries to verify vector search and tie-breaker sorting.

---

## 7. Recovery and Rollback Decision

### 7.1 Rejection of Destructive Downgrade
The earlier design proposal suggested that `downgrade()` in Migration `0003` could restore `UNIQUE(content_hash)` by executing:
```sql
DELETE FROM knowledge_embeddings 
WHERE id NOT IN (SELECT DISTINCT ON (content_hash) id FROM knowledge_embeddings);
```
**This strategy is STRICTLY REJECTED.** Automatically and silently deleting valid security intelligence chunks, SOP steps, or MITRE playbooks to satisfy an obsolete constraint violates data integrity and DevSecOps standards.

### 7.2 Guarded Downgrade Policy
Downgrade logic must inspect the data before attempting constraint creation:
```python
def downgrade() -> None:
    bind = op.get_bind()
    dup_count = bind.execute(sa.text(
        "SELECT count(*) FROM ("
        "  SELECT content_hash FROM knowledge_embeddings "
        "  GROUP BY content_hash HAVING count(*) > 1"
        ") d"
    )).scalar()
    
    if dup_count > 0:
        raise RuntimeError(
            f"Downgrade aborted: {dup_count} duplicate content_hash values exist. "
            "Downgrading would require destructive data deletion. "
            "To revert to revision 0002, restore from pre-migration backup."
        )
    
    op.drop_index("ix_knowledge_embeddings_source_chunk_idx", table_name="knowledge_embeddings")
    op.alter_column("knowledge_embeddings", "chunk_index", nullable=True)
    op.drop_column("knowledge_embeddings", "chunk_index")
    op.drop_index("ix_knowledge_embeddings_content_hash", table_name="knowledge_embeddings")
    op.create_index("ix_knowledge_embeddings_content_hash", "knowledge_embeddings", ["content_hash"], unique=True)
```

### 7.3 Primary Operational Recovery: Forward Recovery
In production and staging environments, the primary disaster recovery posture is **forward recovery**:
1. Fix schema or ingestion defects in a forward migration (`0004`).
2. If total rollback is required, drop the test database and restore from `backup_pre_0003.dump`.

---

## 8. Exact-Search Ground-Truth Protocol

### 8.1 Corrected Recall Formulation
In standard information retrieval, Recall@k is computed as:
$$\text{Recall}@k = \frac{|ANN_k \cap ENN_k|}{k}$$
However, when candidate filtering (e.g., filtering by `source_document LIKE 'mitre/%'`) yields fewer than $k$ eligible chunks in the entire database ($|ENN_{eligible}| < k$), dividing by $k$ artificially depresses recall even when the HNSW index retrieved 100% of eligible rows.

**Adopted Mathematical Formula:**
$$\text{Recall}@k = \begin{cases} 
1.0 & \text{if } |ENN_{eligible}| = 0 \\
\frac{|ANN_k \cap ENN_k|}{\min(k, |ENN_{eligible}|)} & \text{if } |ENN_{eligible}| > 0 
\end{cases}$$

### 8.2 Dual Scan Disabling Protocol
In PostgreSQL with `pgvector`, setting `enable_indexscan = off` does **NOT** guarantee a sequential scan; PostgreSQL's query planner may still choose a Bitmap Index Scan on the HNSW index.

To guarantee that the Exact Nearest Neighbor ($ENN$) ground truth is computed via a true Sequential Scan:
```sql
BEGIN;
SET LOCAL enable_indexscan = off;
SET LOCAL enable_bitmapscan = off;

EXPLAIN (ANALYZE, BUFFERS)
SELECT id, source_document, chunk_index, (embedding <=> :query_vector) AS dist
FROM knowledge_embeddings
WHERE (:source_filter IS NULL OR source_document LIKE :source_filter || '%')
ORDER BY (embedding <=> :query_vector) ASC, source_document ASC, chunk_index ASC
LIMIT :top_k;
COMMIT;
```

* **Execution Plan Assertions:**
  - Ground truth ($ENN$): Execution plan must assert `Seq Scan on knowledge_embeddings` (0% index usage).
  - Approximate ($ANN$): Execution plan must assert `Index Scan using ix_knowledge_embeddings_embedding_hnsw`.

### 8.3 Benchmark Dataset & SOC Queries
* **Benchmark Size:** Minimum 60 curated chunks from real AISOP knowledge files (`knowledge_base/mitre/`, `knowledge_base/sop/`).
* **Queries:** 10 realistic SOC analyst queries (e.g., "Powershell download cradle execution", "Pass the hash lateral movement", "Suspicious scheduled task creation").
* **Empirical Acceptance Threshold:** Average $\text{Recall}@5 \ge 95\%$ across the 10 queries. (Treated as an empirical acceptance gate, not an immutable mathematical invariant).

---

## 9. Tier 1 and Tier 2 Acceptance Matrix

### 9.1 Test Baseline History Reconciliation
Historical documents reference various test counts:
* `114 tests`: Phase 1 completion baseline.
* `134 tests`: P2-H1 LLM abstraction baseline.
* `138 tests`: P2-H2 schema addition baseline.
* `167 tests`: Current active offline Tier 1 test suite (passing 100% in 14.73s).
* `177 tests`: P2-H3 draft test suite including live Ollama/Postgres tests.
* `180 tests`: Full current collection including 13 deselected integration tests requiring port 5433 / Ollama.

### 9.2 Acceptance Matrix

| Test ID | Tier | Target File | Setup & Preconditions | Assertion / Invariant Verified | Defect Prevented | Current Status | Required Passing Evidence |
|:---|:---:|:---|:---|:---|:---|:---:|:---|
| `test_migration_0003_offline_ddl` | Tier 1 | `test_migrations.py` | Mock Alembic context (offline mode). | Generates SQL: adds `chunk_index`, drops unique hash, creates composite unique index. | Broken DDL syntax in migration. | Proposed | Offline pytest execution log. |
| `test_chunker_document_wide_indexing` | Tier 1 | `test_knowledge_loader_and_chunker.py` | Multi-section markdown string with repeated headings. | Chunks have continuous `chunk_index` $0, 1, 2, \dots, N-1$ across sections. | Chunker resetting index to 0 per section. | Proposed | Unit test assert passes. |
| `test_ingest_preserves_intra_doc_repeats` | Tier 1 | `test_knowledge_ingestion_and_retrieval.py` | Document with identical text in Section 1 and Section 2. | Both chunks persisted with distinct `chunk_index` and identical `content_hash`. | Silent dropping of repeated SOP steps. | Proposed | SQLite/Mock test assert passes. |
| `test_ingest_preserves_cross_doc_repeats` | Tier 1 | `test_knowledge_ingestion_and_retrieval.py` | Doc A and Doc B containing identical paragraph. | Both documents persist their chunks; `successful_chunks` matches total for both. | Silent dropping of shared chunks across docs. | Proposed | SQLite/Mock test assert passes. |
| `test_in_memory_embedding_dedup` | Tier 1 | `test_knowledge_ingestion_and_retrieval.py` | Batch with 5 chunks, 2 identical texts. | `embedder.embed_batch` called with 4 unique strings; all 5 chunks get vectors. | Redundant Ollama embedding API calls. | Proposed | Mock spy on `embed_batch`. |
| `test_document_deletion_api` | Tier 1 | `test_knowledge_ingestion_and_retrieval.py` | Ingest Doc A and Doc B; call `delete_document("docA.md")`. | Doc A rows deleted; Doc B rows completely intact. | Orphaned rows; collateral document deletion. | Proposed | SQLite/Mock test assert passes. |
| `test_retrieval_tie_breaker_order` | Tier 1 | `test_knowledge_ingestion_and_retrieval.py` | Chunks inserted with identical embedding vector. | Retrieval results ordered deterministically by `source_document ASC, chunk_index ASC`. | Non-deterministic pagination drift. | Proposed | Retrieval assert passes. |
| `test_postgres_0003_upgrade_lifecycle` | Tier 2 | `test_postgres_lifecycle.py` | PostgreSQL 17 on port 5433 at revision `0002`. | `alembic upgrade head` succeeds; `(source_document, chunk_index)` uniqueness active. | Migration failure on live PostgreSQL. | Proposed | Live migration execution log. |
| `test_postgres_0003_guarded_downgrade` | Tier 2 | `test_postgres_lifecycle.py` | Live PostgreSQL at `0003` with duplicate hashes. | `alembic downgrade -1` raises `RuntimeError` and does not delete rows. | Destructive data loss on downgrade. | Proposed | Live downgrade exception assert. |
| `test_postgres_atomic_replacement_shared` | Tier 2 | `test_postgres_vector_retrieval.py` | Ingest Doc A and Doc B sharing chunks; re-ingest Doc A v2. | Doc A updated; Doc B's shared chunks remain untouched. | Collateral cross-doc chunk deletion. | Proposed | Live database query assert. |
| `test_postgres_exact_search_recall_bench` | Tier 2 | `test_postgres_vector_retrieval.py` | 60 curated chunks; 10 SOC queries; port 5433 active. | $ENN$ uses `Seq Scan`; $ANN$ uses `Index Scan`; average $\text{Recall}@5 \ge 95\%$. | HNSW index inaccuracy or silent query scan fallback. | Proposed | Log output with per-query recall table. |

---

## 10. Phase 2 Milestone Reconciliation Recommendation

### 10.1 Roadmap Divergence Analysis
* **Historical Baseline (7 Oct 2026):** P2-H4 MITRE ATT&CK, P2-H5 Threat Intelligence, P2-H6 Investigation Context, P2-H7 Structured Output.
* **Consolidated Baseline (19 Oct 2026):** MITRE ATT&CK was integrated directly into P2-H3 as foundational knowledge base content. The roadmap was streamlined to:
  - `P2-H1`: LLM Provider Abstraction & Multi-Provider Architecture (Completed)
  - `P2-H2`: pgvector Foundation & Schema Layer (Completed)
  - `P2-H3`: Knowledge Base Ingestion Pipeline & Semantic Retrieval (Current Gate)
  - `P2-H4`: Threat-Intelligence Enrichment & External Context Providers
  - `P2-H5`: LLM-Powered Investigation Reasoning & Evidence Grounding
  - `P2-H6`: Structured Investigation Reporting & Actionable SOP Generation
  - `P2-H7`: Phase 2 Capstone Review, Security Hardening & Full Pipeline Consolidation

### 10.2 Architectural Recommendation
Formally ratify the **19 October 7-Milestone Sequence**. Merging MITRE ingestion into P2-H3 avoids redundant pipeline construction and establishes a cohesive knowledge subsystem.

### 10.3 Frontend Architecture Stance
[ADR-005](file:///c:/Users/sarik/Documents/GO/02_COLLEGE/SEM_Projects/MINOR/SEM7/AISOP/docs/03_System_Design/ADR/ADR-005_Frontend_Stack.md) explicitly mandates a **React 19 + Vite SPA with Tailwind CSS** for the analyst console. Proposals to substitute Streamlit are **REJECTED** for the primary web console, as Streamlit cannot meet the security operations workflow, sub-second analyst responsiveness, or interactive visual topology requirements defined in the architecture specification.

---

## 11. Unresolved Questions Requiring Project Owner Decisions

Prior to granting implementation authorization, the Project Owner must decide:

1. **Guarded Downgrade Decision:** Does the Project Owner formally approve the guarded downgrade policy in Migration `0003` (aborting with `RuntimeError` and requiring backup restore if duplicate hashes exist), permanently rejecting silent row deletion?
2. **Backfill Acknowledgement:** Does the Project Owner acknowledge that the SQL window function in Migration `0003` is a structural constraint bridge, and that true document-wide order must be restored via `ingest_directory(force_reindex=True)`?
3. **Roadmap Ratification:** Does the Project Owner formally ratify the 19 October 7-milestone sequence (P2-H1 to P2-H7) as the authoritative project schedule?
4. **Implementation Authorization:** Does the Project Owner authorize Antigravity to proceed with Phase A implementation (authoring Migration `0003`, updating `KnowledgeEmbedding` model, and updating schemas)?

---

## 12. Proposed Implementation Order

Upon receiving explicit Project Owner authorization, implementation will proceed in four strictly bounded phases:

```
┌────────────────────────────────────────────────────────┐
│ Phase A: Schema & Relational Model Layer               │
│ 1. Author migration 20261021_0003_... with guarded     │
│    downgrade and structural window backfill.           │
│ 2. Update KnowledgeEmbedding model (chunk_index column │
│    and composite unique constraint).                   │
│ 3. Update schemas/knowledge.py with chunk_index.       │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Phase B: Chunker & Loader Provenance Layer             │
│ 4. Refactor DocumentChunker to sequence chunk_index    │
│    continuously (0 ... N-1) across all sections.       │
│ 5. Ensure loader resolves relative POSIX paths.        │
│ 6. Add Tier 1 unit tests for continuous indexing.      │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Phase C: Ingestion & Retrieval Service Layer           │
│ 7. Implement in-memory embedding deduplication.        │
│ 8. Remove intra-doc and cross-doc drop filters.        │
│ 9. Add delete_document() and directory pruning API.    │
│ 10. Update retriever SQL with tie-breaker sorting.     │
│ 11. Verify all 167 existing Tier 1 tests remain green. │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ Phase D: Integration & Benchmark Verification          │
│ 12. Start Docker aisop-postgres on port 5433.          │
│ 13. Execute Migration 0003 upgrade lifecycle test.     │
│ 14. Ingest 60 curated cybersecurity chunks.            │
│ 15. Execute 10-query exact-search benchmark test.      │
│ 16. Verify full test suite (180+ tests passing).       │
└────────────────────────────────────────────────────────┘
```

---

## 13. Explicit Scope and Safety Limitations

* **Read-Only Audit Conformance:** No source code, migrations, tests, dependencies, or configurations were modified during this review.
* **No Database DDL or Writes:** Zero database queries, migrations, or writes were executed against persistent databases.
* **No Container / Service Mutation:** Docker container `aisop-postgres` was not started or stopped; host Ollama was not invoked for model generation.
* **Zero Credential Exposure:** Environment configuration files (`.env`) were inspected solely for existence without disclosing tokens or secrets.
* **Stopping Condition:** In accordance with task instructions, Antigravity halts execution upon producing this review and awaits explicit Project Owner authorization.

---

## 14. Final Decision: CONDITIONAL GO

### Certified Status: CONDITIONAL GO

The technical architecture, relational schema, and verification strategy for Milestone **P2-H3** are fully validated. The transition to Positional Uniqueness (`Option A-Prime`) resolves all known data-loss and chunk-suppression defects.

**Stopping Execution:** Antigravity is halted. No code implementation, migration creation, or database mutation will be initiated until the Project Owner provides explicit authorization on the decisions outlined in Section 11.
