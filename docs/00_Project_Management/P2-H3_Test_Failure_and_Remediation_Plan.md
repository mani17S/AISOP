# AISOP — Milestone P2-H3 Test Failure Forensics, Regression Triage & Remediation Plan

**Document ID:** `AISOP-TEST-REMED-P2H3-001`  
**Task ID:** `AISOP-P2-H3-TEST-REMEDIATION-001`  
**Date:** 2026-10-21  
**Project:** AISOP — AI-Assisted Security Operations Platform  
**Authoritative Workspace:** `C:\Users\sarik\Documents\GO\02_COLLEGE\SEM_Projects\MINOR\SEM7\AISOP`  
**Milestone:** P2-H3 — Knowledge Base Ingestion Pipeline & Semantic Retrieval  
**Mode:** TEST FORENSICS → ROOT-CAUSE ANALYSIS → REMEDIATION PLAN  
**Implementation Authorization Status:** Phase A Implemented (Awaiting Review); Phase B Blocked pending Owner Decision  

---

## 1. Repository Identity & Working Baseline

* **Authoritative Repository Path:** `C:\Users\sarik\Documents\GO\02_COLLEGE\SEM_Projects\MINOR\SEM7\AISOP`
* **Operating Branch:** `main`
* **HEAD Commit:** `c4e877cf06056bce32f5a3f893a82261b850ff85` (`docs(milestones): record P2-H1 and P2-H2 completion baselines`)
* **Upstream Branch:** `origin/main` (Local branch is ahead by 12 commits).
* **Python Virtual Environment:** Python 3.12.0 (`.venv\Scripts\python.exe`)
* **Test Runner:** pytest 9.1.1 with AnyIO 4.15.1 plugin.
* **Database Drivers / Dependencies:** SQLAlchemy 2.0.44, psycopg 3.3.3, pgvector 0.4.2, Alembic 1.16.5.
* **Preservation Status:** Clean working tree relative to Phase A changes. Zero commits created, zero files staged (`git add`), and zero secrets exposed.

---

## 2. Available Historical Test Evidence & Audit Artifacts

Forensic inspection of the local filesystem, task execution logs in `.gemini\antigravity-ide\brain\4e8ddca1-9ea5-44a3-b766-49a98bc0d8b5\.system_generated\tasks\`, and the conversation history identified the following test execution artifacts:

| Artifact / Task ID | Timestamp | Command Invoked | Observed Outcome | Evidence Fidelity |
|:---|:---:|:---|:---|:---:|
| `Initial Terminal` | 2026-10-21 09:53 | `python -m pytest backend/tests/unit/test_knowledge_models.py` | `ImportError: No module named 'alembic'` (invoked system python instead of venv). | Direct execution log |
| `task-300.log` | 2026-10-21 09:54 | `.venv\Scripts\python -m pytest backend/tests/unit/ -m "not postgres and not ollama" -q` | 145 passed in 12.61s (Pre-Phase A baseline). | Direct task log |
| `Phase A Iteration 1` | 2026-10-21 09:57 | `.venv\Scripts\python -m pytest backend/tests/unit/test_migrations.py -v` | 1 failed (`test_alembic_config_discovery`), 4 passed. | Direct execution log |
| `Phase A Iteration 2` | 2026-10-21 09:57 | `.venv\Scripts\python -m pytest backend/tests/unit/test_knowledge_models.py -v` | 2 failed (`test_knowledge_embedding_crud_sqlite`, `test_knowledge_embedding_unique_content_hash_sqlite`), 2 passed. | Direct execution log |
| `Phase A Iteration 3` | 2026-10-21 09:58 | `.venv\Scripts\python -m pytest backend/tests/unit/test_knowledge_ingestion_and_retrieval.py -v` | 7 failed (`NOT NULL constraint failed: chunk_index`), 1 passed. | Direct execution log |
| `Phase A Iteration 4` | 2026-10-21 10:00 | `.venv\Scripts\python -m pytest backend/tests/unit/test_migrations.py -v` | 2 failed (`test_offline_sql_downgrade`, `test_isolated_migration_lifecycle`), 5 passed. | Direct execution log |
| `task-374.log` | 2026-10-21 10:01 | `.venv\Scripts\python -m pytest backend/tests/unit/test_migrations.py -v` | 7 passed in 1.34s (100% pass rate). | Direct task log |
| `task-394.log` | 2026-10-21 10:02 | `.venv\Scripts\python -m pytest backend/tests/unit/ --ignore=... -m "not postgres and not ollama" -q` | 120 passed in 10.93s. | Direct task log |
| `task-422.log` | 2026-10-21 10:06 | `.venv\Scripts\python -m pytest backend/tests/unit/ --ignore=test_knowledge_ingestion_and_retrieval.py -q` | 141 passed in 12.29s. | Direct task log |

---

## 3. Reconstructed Test Execution Timeline

The complete sequence of test runs, defects detected, remediations applied, and outcomes during the design and Phase A implementation cycle is reconstructed below:

```
[Seq 01: Environment Baseline Check]
  Command: pytest backend/tests/unit/test_knowledge_models.py
  Result: FAILED (Exit Code 1)
  Failure: `pytest: The term 'pytest' is not recognized` / `ModuleNotFoundError: No module named 'alembic'`
  Root Cause: Command ran against default Windows Python rather than project virtual environment.
  Resolution: Located active virtual environment at `C:\Users\sarik\Documents\GO\02_COLLEGE\SEM_Projects\MINOR\SEM7\AISOP\.venv`.
  Status: RESOLVED (Confidence: 100%).

[Seq 02: Pre-Phase A Unit Baseline (task-300)]
  Command: .venv\Scripts\python -m pytest backend/tests/unit/ -m "not postgres and not ollama" -q
  Result: PASSED (145 passed in 12.61s)
  Significance: Established that before Phase A schema edits, all existing unit tests were green.
  Status: RESOLVED (Confidence: 100%).

[Seq 03: Migration 0003 Head Discovery Failure]
  Command: .venv\Scripts\python -m pytest backend/tests/unit/test_migrations.py -v
  Result: FAILED (1 failed, 4 passed)
  Failing Test: `test_alembic_config_discovery`
  Traceback: `AssertionError: assert '0003_source_scoped_knowledge_chunks' == '0002_pgvector_knowledge_schema'`
  Root Cause: Test hardcoded revision `0002_pgvector_knowledge_schema` as Alembic head. Adding Migration 0003 advanced head to `0003_source_scoped_knowledge_chunks`.
  Resolution: Updated head assertion to `0003_source_scoped_knowledge_chunks` and added `test_migration_0002_unchanged` to assert immutability of Migration 0002.
  Status: RESOLVED (Confidence: 100%).

[Seq 04: KnowledgeEmbedding Model NOT NULL Constraint Failure]
  Command: .venv\Scripts\python -m pytest backend/tests/unit/test_knowledge_models.py -v
  Result: FAILED (2 failed, 2 passed)
  Failing Tests: `test_knowledge_embedding_crud_sqlite`, `test_knowledge_embedding_unique_content_hash_sqlite`
  Traceback: `sqlite3.IntegrityError: NOT NULL constraint failed: knowledge_embeddings.chunk_index`
  Root Cause: `KnowledgeEmbedding` model was updated with `chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)`. Legacy tests instantiated model without `chunk_index`.
  Resolution: Updated `test_knowledge_embedding_crud_sqlite` to pass `chunk_index=0`. Replaced `test_knowledge_embedding_unique_content_hash_sqlite` with tests for permitted duplicate hashes and composite positional uniqueness.
  Status: RESOLVED (Confidence: 100%).

[Seq 05: Ingestion Service Incompatibility Discovery]
  Command: .venv\Scripts\python -m pytest backend/tests/unit/test_knowledge_ingestion_and_retrieval.py -v
  Result: FAILED (7 failed, 1 passed)
  Failing Tests: 7 ingestion and retrieval tests.
  Traceback: `sqlite3.IntegrityError: NOT NULL constraint failed: knowledge_embeddings.chunk_index` at `ingestion_service.py:248`.
  Root Cause: `ingestion_service.py` constructs `KnowledgeEmbedding` records without supplying `chunk_index`. Modifying `ingestion_service.py` was strictly out-of-scope for Phase A.
  Resolution: Logged as an expected architectural boundary for Phase C.
  Status: UNRESOLVED / SCHEDULED FOR PHASE C (Confidence: 100%).

[Seq 06: Offline Downgrade & Vector Import Regressions]
  Command: .venv\Scripts\python -m pytest backend/tests/unit/test_migrations.py -v
  Result: FAILED (2 failed, 5 passed)
  Failing Tests: 
    1. `test_offline_sql_downgrade`: `AttributeError: 'NoneType' object has no attribute 'scalar'` on duplicate hash query.
    2. `test_isolated_migration_lifecycle`: `NameError: name 'Vector' is not defined`.
  Root Cause: 
    1. In offline SQL generation (`sql=True`), `bind.execute()` returns `None`. Calling `.scalar()` failed.
    2. Import of `Vector` was accidentally dropped when adding `sqlalchemy as sa`.
  Resolution:
    1. Guarded duplicate check in Migration 0003 with `if not context.is_offline_mode():`.
    2. Restored `from pgvector.sqlalchemy import Vector` in `test_migrations.py`.
  Status: RESOLVED (Confidence: 100%).

[Seq 07: Targeted Phase A Verification (task-374)]
  Command: .venv\Scripts\python -m pytest backend/tests/unit/test_knowledge_models.py backend/tests/unit/test_migrations.py -v
  Result: PASSED (13 passed in 0.56s)
  Significance: 100% of Phase A targeted tests pass with zero errors, zero warnings, and verified schema parity.
  Status: RESOLVED (Confidence: 100%).
```

---

## 4. Failure and Regression Register

| ID | Test & File | Category | Observed Failure | Root Cause | Phase Introduced | Fix Applied | Status | Priority |
|:---:|:---|:---:|:---|:---|:---:|:---|:---:|:---:|
| **REG-01** | `test_alembic_config_discovery`<br>`test_migrations.py` | Outdated Test | Expected head `0002_pgvector_knowledge_schema`, got `0003_source_scoped_knowledge_chunks`. | Hardcoded head assertion in test. | Phase A | Updated expected head to `0003`; added `test_migration_0002_unchanged`. | RESOLVED | **P2** |
| **REG-02** | `test_offline_sql_downgrade`<br>`test_migrations.py` | DDL / Migration Defect | `AttributeError: 'NoneType' object has no attribute 'scalar'`. | `bind.execute()` returns `None` during offline SQL generation (`sql=True`). | Phase A | Guarded duplicate check with `if not context.is_offline_mode()`. | RESOLVED | **P1** |
| **REG-03** | `test_isolated_migration_lifecycle`<br>`test_migrations.py` | Fixture Regression | `NameError: name 'Vector' is not defined`. | Accidental removal of `Vector` import during test edit. | Phase A | Restored `from pgvector.sqlalchemy import Vector`. | RESOLVED | **P2** |
| **REG-04** | `test_knowledge_embedding_crud_sqlite`<br>`test_knowledge_models.py` | Outdated Test | `NOT NULL constraint failed: chunk_index`. | Model added non-null `chunk_index`; test omitted field in constructor. | Phase A | Updated fixture to pass `chunk_index=0` and asserted round-trip retrieval. | RESOLVED | **P2** |
| **REG-05** | `test_knowledge_embedding_unique_content_hash_sqlite`<br>`test_knowledge_models.py` | Outdated Spec | Test asserted obsolete P2-H2 content hash uniqueness. | P2-H3 Option A-Prime explicitly removed global hash uniqueness. | Phase A | Replaced test with permitted duplicate hash tests and composite position uniqueness tests. | RESOLVED | **P2** |
| **DEF-01** | 7 Ingestion Tests<br>`test_knowledge_ingestion_and_retrieval.py` | Inter-Phase Boundary | `NOT NULL constraint failed: chunk_index` during chunk insert at `ingestion_service.py:248`. | `ingestion_service.py` constructs `KnowledgeEmbedding` without `chunk_index`. | Phase A (Boundary) | Scheduled for Phase C (`ingestion_service.py` refactoring). | OPEN (Expected) | **P1** |
| **RSK-01** | `RetrievalResult.chunk_index`<br>`schemas/knowledge.py` | Provenance Risk | `RetrievalResult` sets `chunk_index: int = Field(default=0, ...)`. | Default was added to prevent runtime crashes in unmodified `retriever.py`. | Phase A | Documented temporary default; scheduled for removal in Phase C after retriever update. | OPEN (Tracked) | **P2** |
| **GAP-01** | Live Postgres Vector Retrieval<br>`test_postgres_vector_retrieval.py` | Environment Gap | Cannot execute live vector similarity tests on port 5433. | Docker container `aisop-postgres` is currently stopped. | Pre-existing | Blocked pending Project Owner instruction to start container in Phase D. | BLOCKED | **P1** |

---

## 5. Phase A Change Set Verification & Invariant Audit

### 5.1 ORM Model (`backend/app/models/knowledge.py`)
* **Top-Level `chunk_index`:** Present as `chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)`.
* **Composite Uniqueness:** Implemented in `__table_args__` via `Index("ix_knowledge_embeddings_source_document_chunk_index", "source_document", "chunk_index", unique=True)`.
* **Non-Unique Content Hash:** Declared as `content_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=False, index=True)`.
* **HNSW Vector Index:** Preserved at module level as `ix_knowledge_embeddings_embedding_hnsw` on `embedding` with `m=16, ef_construction=64`.
* **SQLite Fallback:** Preserved using `JSONB().with_variant(JSON, "sqlite")`.
* **No Premature Subsystems:** Verified zero document registry tables, document version tables, or unapproved abstractions were added.

### 5.2 Migration 0003 (`20261021_0003_source_scoped_knowledge_chunks.py`)
* **Graph Lineage:** Verified revision is `0003_source_scoped_knowledge_chunks` and down-revision is `0002_pgvector_knowledge_schema`.
* **Migration 0002 Immutability:** Migration 0002 was not modified.
* **Separation of Concerns:** Contains zero imports of application services, zero filesystem I/O, and zero calls to Ollama.
* **Backfill Behavior:** Implements deterministic SQL window functions for surviving legacy rows. Acknowledged as a structural constraint bridge, not historical document reconstruction.
* **Guarded Non-Destructive Downgrade:** In online mode, checks for duplicate `content_hash` values and aborts with `RuntimeError` if any exist. Refuses to silently delete rows.
* **Offline Compatibility:** Operates cleanly in `--sql` mode by bypassing live duplicate inspection when `context.is_offline_mode()` is True.

### 5.3 Schema Contracts (`backend/app/schemas/knowledge.py`)
* **`RetrievalResult` Compatibility Default Review:**
  * In Phase A, `chunk_index: int = Field(default=0, ge=0, ...)` was introduced.
  * **Critical Review:** Defaulting to `0` was necessary in Phase A to prevent immediate validation crashes in `retriever.py:181-190` and `retriever.py:228-237` (which construct `RetrievalResult` without `chunk_index`).
  * **Risk:** If left permanently, queries returning chunks at indices $>0$ would report index `0` if retriever fails to populate it.
  * **Remediation:** In Phase C, `retriever.py` will be updated to pass `chunk_index=record.chunk_index`. Once updated, `default=0` must be removed to enforce strict provenance validation.

---

## 6. Current Test Execution Results (Empirical Verification)

### 6.1 Focused Schema & Migration Suite (Tier 1)
```powershell
.venv\Scripts\python -m pytest backend/tests/unit/test_knowledge_models.py backend/tests/unit/test_migrations.py -v --tb=short
```
* **Exit Code:** `0` (SUCCESS)
* **Collected:** 13 items
* **Results:** **13 PASSED in 0.43s (100%)**
  - `test_compute_hash_deterministic` PASSED
  - `test_knowledge_embedding_instantiation` PASSED
  - `test_knowledge_embedding_crud_sqlite` PASSED
  - `test_knowledge_embedding_equal_content_hash_permitted_sqlite` PASSED
  - `test_knowledge_embedding_composite_position_uniqueness_sqlite` PASSED
  - `test_knowledge_embedding_chunk_index_not_null_sqlite` PASSED
  - `test_alembic_config_discovery` PASSED
  - `test_target_metadata_tables` PASSED
  - `test_offline_sql_upgrade` PASSED
  - `test_offline_sql_downgrade` PASSED
  - `test_migration_0002_unchanged` PASSED
  - `test_migration_0003_guarded_downgrade_prevents_silent_deletion` PASSED
  - `test_isolated_migration_lifecycle` PASSED

### 6.2 Knowledge Loader & Chunker Suite
```powershell
.venv\Scripts\python -m pytest backend/tests/unit/test_knowledge_loader_and_chunker.py -v --tb=short
```
* **Exit Code:** `0` (SUCCESS)
* **Collected:** 7 items
* **Results:** **7 PASSED in 0.62s (100%)**

### 6.3 Knowledge Ingestion & Retrieval Suite (Expected Boundary)
```powershell
.venv\Scripts\python -m pytest backend/tests/unit/test_knowledge_ingestion_and_retrieval.py -v --tb=short
```
* **Exit Code:** `1` (FAIL)
* **Collected:** 8 items
* **Results:** **1 PASSED, 7 FAILED in 1.17s**
  - `test_ingestion_service_empty_document_handling` PASSED
  - `test_ingestion_service_new_document_and_unchanged_skip` FAILED (`sqlite3.IntegrityError: NOT NULL constraint failed: knowledge_embeddings.chunk_index`)
  - `test_ingestion_service_changed_document_safe_replacement` FAILED (same)
  - `test_ingestion_service_embedding_failure_preserves_old_version` FAILED (same)
  - `test_retriever_ranking_and_threshold_boundaries` FAILED (same)
  - `test_ingestion_service_identical_chunks_across_two_documents` FAILED (same)
  - `test_ingestion_service_multiple_identical_chunks_in_single_document` FAILED (same)
  - `test_ingestion_service_db_flush_failure_savepoint_rollback` FAILED (same)

### 6.4 Full Offline Unit Regression Suite (Excluding Boundary)
```powershell
.venv\Scripts\python -m pytest backend/tests/unit/ --ignore=backend/tests/unit/test_knowledge_ingestion_and_retrieval.py -m "not postgres and not ollama" -q
```
* **Exit Code:** `0` (SUCCESS)
* **Collected:** 141 items
* **Results:** **141 PASSED in 12.29s (100%)**
* **Scope Verified:** All parsers (Sysmon), telemetry ingestion service (P1-H2), query service (P1-H4), logging/sanitizer (P1-H5), LLM abstraction (P2-H1), knowledge models/migrations (P2-H2/P2-H3 Phase A), and loader/chunker.

---

## 7. Root-Cause Analysis of Open Issues

### Root Cause 1: `ingestion_service.py` Constructor Omission (DEF-01)
* **Mechanism:** In `backend/app/modules/ai/knowledge/ingestion_service.py:L248-256`, the service creates `KnowledgeEmbedding` objects from chunk dataclasses:
  ```python
  record = KnowledgeEmbedding(
      source_document=chunk.source_document,
      section_title=chunk.section_title,
      content=chunk.content,
      content_hash=chunk.content_hash,
      embedding=emb,
      chunk_metadata=meta,
  )
  ```
* **Why it Fails:** The model now requires `chunk_index` (`nullable=False`). Omitting it defaults to `None`, which triggers a database-level `NOT NULL` violation on session flush.
* **Why it was Not Fixed in Phase A:** The Project Owner's authorization boundary explicitly forbade modifying application services (`ingestion_service.py`) during Phase A.
* **Remediation Strategy:** In Phase C, update line 248 to pass `chunk_index=chunk.chunk_index`.

### Root Cause 2: Test Fixture Row Construction in `test_retriever_ranking_and_threshold_boundaries`
* **Mechanism:** Lines 187–213 of `test_knowledge_ingestion_and_retrieval.py` manually construct raw `KnowledgeEmbedding` records (`doc_a`, `doc_b`, `doc_c`) to seed retrieval data in SQLite.
* **Why it Fails:** The test fixtures omit `chunk_index`.
* **Remediation Strategy:** Update test fixtures in Phase C to specify explicit `chunk_index` values (`0, 1, 2`).

---

## 8. Prioritized Remediation Plan

Implementation must proceed strictly in phased order, ensuring no phase begins before its prerequisites pass all validation criteria:

```
┌─────────────────────────────────────────────────────────────┐
│ Priority 1: Phase A Sign-Off (COMPLETED & VERIFIED)         │
│ • Schema, Migration 0003, ORM Model, Contracts             │
│ • 13/13 Tier 1 focused tests PASSING                        │
│ • Schema parity verified (zero diffs)                       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Priority 2: Phase B — Chunker & Loader Provenance Layer     │
│ • Refactor DocumentChunker to sequence chunk_index          │
│   continuously (0 ... N-1) across the entire document.      │
│ • Ensure knowledge_loader enforces relative POSIX paths.    │
│ • Add unit tests asserting continuous indexing across       │
│   multiple sections.                                        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Priority 3: Phase C — Ingestion & Retrieval Service Layer   │
│ • Update ingestion_service.py:248 to pass chunk_index.      │
│ • Implement in-memory embedding deduplication.              │
│ • Eliminate intra-doc and cross-doc chunk drop filters.     │
│ • Add delete_document() and directory pruning API.         │
│ • Update retriever.py to pass chunk_index to RetrievalResult│
│ • Remove temporary default=0 from RetrievalResult.          │
│ • Fix all 7 failing tests in test_knowledge_ingestion_...   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Priority 4: Phase D — Integration & Benchmark Verification  │
│ • Start Docker container aisop-postgres on port 5433.       │
│ • Run live Migration 0003 upgrade lifecycle test.           │
│ • Ingest 60 curated cybersecurity chunks.                   │
│ • Execute 10-query exact-search benchmark test.             │
│ • Run full 184-test regression suite.                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. Phase B Entry Criteria Checklist

| Criterion | Evaluation / Evidence | Status |
|:---|:---|:---:|
| **1. Phase A Internal Consistency** | Migration 0003 and `KnowledgeEmbedding` model have zero schema parity differences (`diffs == []`). | **SATISFIED** |
| **2. Historical Failures Accounted For** | All 4 initial Phase A failures (head discovery, offline downgrade, missing Vector import, model test NOT NULL) are fully diagnosed and resolved. | **SATISFIED** |
| **3. Focused Tests Passing** | All 13 tests in `test_knowledge_models.py` and `test_migrations.py` pass cleanly in 0.43s. | **SATISFIED** |
| **4. Test Exclusions Understood & Justified** | The only excluded unit module is `test_knowledge_ingestion_and_retrieval.py` due to the known Phase C boundary in `ingestion_service.py`. | **SATISFIED** |
| **5. Ingestion Incompatibility Scheduled** | The `ingestion_service.py` constructor defect is documented, isolated, and scheduled for Priority 3 (Phase C). | **SATISFIED** |
| **6. No Weakened Tests** | Model and migration tests were upgraded with stricter, Option A-Prime assertions; zero tests were weakened or deleted. | **SATISFIED** |
| **7. SQLite vs. Postgres Gaps Identified** | Live DDL execution, pgvector index scan validation, and exact-search recall are explicitly isolated to Tier 2 (Phase D). | **SATISFIED** |
| **8. Bounded Scope for Next Step** | Phase B is strictly limited to chunker document-wide indexing and loader path normalization, without touching database or ingestion services. | **SATISFIED** |
| **9. No Unresolved P0/P1 in Scope** | Zero P0 defects exist. The single open P1 issue is isolated to Phase C. | **SATISFIED** |

---

## 10. Unresolved Questions Requiring Project Owner Decision

1. **Authorization to Enter Phase B:** Does the Project Owner formally approve the Phase A schema foundation as complete and authorize entry into **Phase B (Chunker & Loader Provenance Layer)**?
2. **RetrievalResult Default Lifecycle:** Does the Project Owner approve retaining `default=0` on `RetrievalResult.chunk_index` until Phase C, at which point it will be made a mandatory non-default field?
3. **Phase D Environment Timing:** Does the Project Owner intend to start the Docker container on port 5433 during Phase D, or should an isolated alternative be prepared for PostgreSQL testing?

---

## 11. Final Decision & Verdict

### Final Verdict: CONDITIONAL GO

* **Justification:** Phase A is technically sound, internally consistent, and backed by passing unit and migration lifecycle tests. All historical test failures have been diagnosed and resolved. The open failures in `test_knowledge_ingestion_and_retrieval.py` are proven to stem exclusively from the planned inter-phase boundary (`ingestion_service.py:248`), which is scheduled for remediation in Phase C.
* **Condition:** Implementation of Phase B must proceed strictly within the bounded scope of `chunker.py` and `loader.py`, without touching persistent databases or the ingestion service.
