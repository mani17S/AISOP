# AISOP — Milestone P2-H3 Readiness & Gap Audit Report

**Document ID:** `AISOP-AUDIT-P2H3-001`  
**Date:** 2026-10-21  
**Project:** AISOP — AI-Assisted Security Operations Platform  
**Target Repository:** `D:\\AISOP`  
**Audit Mode:** READ-ONLY DESIGN & IMPLEMENTATION AUDIT  
**Milestone:** P2-H3 — Knowledge Ingestion Pipeline & Semantic Retrieval  
**Verdict:** BLOCKED — NOT READY FOR COMMIT OR OWNER ACCEPTANCE  

---

## 1. Executive Summary

A comprehensive read-only code audit of the current working tree in `D:\\AISOP` was performed across the Knowledge Base subsystem ([backend/app/modules/ai/knowledge/](file:///D:/AISOP/backend/app/modules/ai/knowledge/)), the ORM models ([models/knowledge.py](file:///D:/AISOP/backend/app/models/knowledge.py)), the Alembic migration history, and the automated test suite.

The audit confirms that while Milestone P2-H3 is functionally advanced and passes in-memory unit tests, it contains **two critical architectural blockers** and several minor implementation gaps that prevent safe production commitment:
1. **Critical Blocker 1 (Provenance & Uniqueness Defect):** The relational schema enforces a global `UNIQUE` constraint on `content_hash`, destroying chunk attribution across documents and within documents.
2. **Critical Blocker 2 (Missing Retrieval Ground-Truth Baseline):** The retrieval test harness lacks an exact sequential-scan cosine distance comparison to measure and verify HNSW index recall.
3. **Infrastructure Blocker:** The PostgreSQL test container on port `5433` is currently stopped, preventing execution of Tier 2 integration tests.

Milestone P2-H3 must remain **BLOCKED** until these findings are resolved and formally certified.

---

## 2. Detailed Findings Register

### Finding P2H3-01: Global Content Hash Uniqueness Destroys Attribution
* **Severity:** CRITICAL (P0)
* **Location:** `backend/app/models/knowledge.py:L50`, `backend/app/db/migrations/versions/20261005_0002_add_pgvector_and_knowledge_schema.py:L58-62`
* **Observed Behavior:**
  Migration `0002` created a global unique index:
  ```python
  op.create_index("ix_knowledge_embeddings_content_hash", "knowledge_embeddings", ["content_hash"], unique=True)
  ```
  In [ingestion_service.py:L184-196](file:///D:/AISOP/backend/app/modules/ai/knowledge/ingestion_service.py#L184-L196), the service queries the database for existing hashes from other documents and drops those chunks from the current document before embedding.
* **Risk / Impact:**
  - *Provenance Erasure:* If two security playbooks quote the same MITRE technique description, the second playbook receives zero chunk records in PostgreSQL. Analysts querying by `source_document = 'playbook_b.md'` will never find the chunk.
  - *Cascading Deletion:* If `playbook_a.md` is deleted or updated, the shared chunk row is deleted, leaving `playbook_b.md` corrupted with missing text.
* **Remediation:** Remove the global unique constraint on `content_hash`. Establish composite uniqueness on `(source_document, chunk_index)`. Retain `content_hash` as a standard non-unique index.
* **Migration Required:** YES — New forward migration `0003_source_scoped_knowledge_chunks.py`. (Migration `0002` must not be altered).
* **Owner Approval Required:** YES.

---

### Finding P2H3-02: `UNIQUE(source_document, content_hash)` Collapses Repeated Internal Chunks
* **Severity:** HIGH (P1)
* **Location:** Proposed fix in `README.md` §2 and [ingestion_service.py:L168-178](file:///D:/AISOP/backend/app/modules/ai/knowledge/ingestion_service.py#L168-L178)
* **Observed Behavior:**
  The previously suggested fix (`UNIQUE(source_document, content_hash)`) assumes that identical text never repeats within a single document. However, security documentation frequently repeats boilerplate, disclaimers, or multi-step commands across distinct sections.
  Currently, `ingestion_service.py` runs intra-document deduplication:
  ```python
  for chunk in chunks:
      if chunk.content_hash in seen_chunk_hashes:
          intra_doc_duplicates += 1
          continue
      seen_chunk_hashes.add(chunk.content_hash)
      unique_chunks.append(chunk)
  ```
* **Risk / Impact:**
  Discarding duplicate chunks within a document destroys positional fidelity. A search intended to match Section 5 will return a citation pointing only to Section 1 where the text first appeared.
* **Remediation:** Enforce uniqueness on **position** rather than content: `UNIQUE(source_document, chunk_index)`. This allows identical text to exist at multiple positions with full section and index provenance.
* **Migration Required:** Addressed in migration `0003`.
* **Owner Approval Required:** YES.

---

### Finding P2H3-03: Chunk Index Is Not a First-Class Column
* **Severity:** MEDIUM (P2)
* **Location:** `backend/app/models/knowledge.py:L35-58`, `backend/app/schemas/knowledge.py:L117`
* **Observed Behavior:**
  `chunk_index` is computed by `DocumentChunker` and packed into `chunk_metadata` (JSONB). It does not exist as a top-level column on `KnowledgeEmbedding`.
* **Risk / Impact:**
  Because `chunk_index` is inside JSONB, PostgreSQL cannot enforce a standard composite primary or unique key on `(source_document, chunk_index)` without creating a functional index on JSON expressions, which is slower and harder to query.
* **Remediation:** Promote `chunk_index` to a top-level column:
  ```python
  chunk_index: Mapped[int] = mapped_column(sa.Integer, nullable=False)
  ```
* **Migration Required:** Included in migration `0003`.
* **Owner Approval Required:** YES.

---

### Finding P2H3-04: Absence of Automated Document Deletion / Pruning API
* **Severity:** MEDIUM (P2)
* **Location:** `backend/app/modules/ai/knowledge/ingestion_service.py`
* **Observed Behavior:**
  `KnowledgeIngestionService` contains `ingest_document()`, but lacks any corresponding `delete_document(source_document)` or `prune_orphans()` method.
* **Risk / Impact:**
  If an operator deletes or renames a source file on disk in `knowledge_base/`, all previously embedded chunks remain in the PostgreSQL database indefinitely, polluting future RAG search results with stale knowledge.
* **Remediation:** Author a deterministic `delete_document(source_document: str, session: AsyncSession)` method in `KnowledgeIngestionService`.
* **Migration Required:** NO.
* **Owner Approval Required:** NO (Standard engineering implementation).

---

### Finding P2H3-05: Missing Exact-Search Cosine Ground-Truth Baseline Test
* **Severity:** HIGH (P1)
* **Location:** `backend/tests/integration/test_postgres_vector_retrieval.py:L35-115`
* **Observed Behavior:**
  The current integration test suite evaluates retrieval using only 3 hand-crafted orthogonal unit vectors. There is no automated test that:
  1. Ingests a realistic evaluation dataset ($\ge 50$ chunks).
  2. Executes queries with index scans disabled (`SET LOCAL enable_indexscan = off;`) to calculate exact cosine nearest neighbors (ENN).
  3. Executes queries with HNSW enabled (ANN).
  4. Formally asserts that recall $R \ge 95\%$ for top-$k$ ($k=5$).
* **Risk / Impact:**
  Retrieval quality and recall degradation under filtering conditions remain unverified against real vector spaces.
* **Remediation:** Author `test_postgres_pgvector_exact_search_recall_baseline` in `test_postgres_vector_retrieval.py`.
* **Migration Required:** NO.
* **Owner Approval Required:** YES (Approval of acceptance threshold $\ge 95\%$).

---

### Finding P2H3-06: Live PostgreSQL Test Harness Is Stopped
* **Severity:** HIGH (P1)
* **Location:** Docker container `aisop-postgres` on host port `5433`
* **Observed Behavior:**
  A read-only network probe confirmed that port `5433` is not listening (`TcpTestSucceeded = False`).
* **Risk / Impact:**
  All 11 Tier 2 PostgreSQL integration tests cannot run until the test container is started.
* **Remediation:** Execute `docker compose up -d postgres` prior to running the Tier 2 test harness.
* **Migration Required:** NO.
* **Owner Approval Required:** NO (Operational prerequisite).

---

## 3. P2-H3 Acceptance Checklist

Milestone P2-H3 shall be deemed ACCEPTED only when all criteria below are verified:

- [ ] **Database Constraint:** Forward migration `0003` applied, establishing `chunk_index` column and `UNIQUE(source_document, chunk_index)`.
- [ ] **Cross-Document Attribution Test:** Two documents sharing identical text both maintain 100% of their chunks in PostgreSQL.
- [ ] **Intra-Document Position Test:** A document repeating identical text across multiple sections persists all chunks with correct `chunk_index`.
- [ ] **Atomic Update Test:** Updating Document A replaces only Document A's chunks; Document B's shared text remains completely undisturbed.
- [ ] **Exact-Search Baseline Test:** Automated test proves $\ge 95\%$ HNSW recall against sequential scan ground truth on $\ge 50$ chunks.
- [ ] **Test Tier Pass Rate:**
  - Tier 1 (Offline Suite): 100% pass rate.
  - Tier 2 (PostgreSQL Suite on port 5433): 100% pass rate.
  - Tier 3 (Ollama Live Suite on port 11434): 100% pass rate.
- [ ] **Formal Acceptance:** Project Owner reviews test dossier and executes Git checkpoint commit.
