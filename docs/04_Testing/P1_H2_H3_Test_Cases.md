# P1-H2 / P1-H3 Test Cases: Ingestion Deduplication & Batch Query Optimization

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H2H3-TC |
| **Milestone** | P1-H2 (Ingestion Deduplication) & P1-H3 (Batch Query Optimization) |
| **Checkpoint Commit** | `e1af0c9` (`e1af0c9673e2a07f049abee7a88365acb27e7d61`) |
| **Governing ADR** | [ADR-004: Ingestion Scope & Deduplication](docs/03_System_Design/ADR/ADR-004_Initial_Ingestion_Scope.md) |
| **Component Scope** | Ingestion Service (`backend/app/services/ingestion_service.py`), Ingest Schemas |
| **Last Updated** | 2026-09-23 |

---

## 1. Purpose & Scope

This document specifies the verification requirements and test cases for milestones **P1-H2** and **P1-H3**, which were merged at commit `e1af0c9`. 

* **P1-H2 (Ingestion Deduplication):** Enforces the "Option A" deduplication contract: when a duplicate raw evidence event (identified by cryptographic SHA-256 canonical hash) is submitted, the ingestion service skips inserting duplicate raw evidence, prevents duplicate normalized events and child entities, returns the existing raw evidence ID, and maintains transaction integrity via nested savepoints.
* **P1-H3 (Batch Query Optimization):** Eliminates $O(N)$ sequential database lookups by executing batched chunked existence queries (`IN (...)` in chunks of `DEFAULT_CHUNK_SIZE=1000`) and performing in-memory set classification.

---

## 2. Test Case Catalogue

### TC-P1H2H3-001 — First Submission Normal Persistence
* **Test ID:** `TC-P1H2H3-001`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_first_submission_persists_normally`
* **Objective:** Verify a newly encountered event persists `RawEvidence`, `NormalizedEventModel`, and extracted entities.
* **Preconditions:** Clean database session.
* **Input:** `IngestRequest` containing single unique process creation event.
* **Expected Result:** `total_received == 1`, `total_normalized == 1`, `total_skipped_duplicates == 0`. One raw row, one normalized event row, and associated entity rows created.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).

---

### TC-P1H2H3-002 — Deduplication Prevents Duplicate Normalized Events
* **Test ID:** `TC-P1H2H3-002`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_exact_duplicate_creates_no_additional_normalized_event`
* **Objective:** Verify that submitting an exact duplicate event does not create additional normalized event rows.
* **Preconditions:** Initial event ingested into database.
* **Input:** Resubmit identical event in a second `IngestRequest`.
* **Expected Result:** Total normalized event count in database remains exactly 1; `total_skipped_duplicates == 1`.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).

---

### TC-P1H2H3-003 — Deduplication Prevents Duplicate Child Entities
* **Test ID:** `TC-P1H2H3-003`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_exact_duplicate_creates_no_additional_entities`
* **Objective:** Verify duplicate submissions do not insert redundant child entity rows in `extracted_entities`.
* **Preconditions:** Initial event ingested with $K$ extracted entities.
* **Input:** Resubmit identical event.
* **Expected Result:** Total entity count in database remains exactly $K$.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).

---

### TC-P1H2H3-004 — Ingest Response Counter & Existing ID Fidelity
* **Test ID:** `TC-P1H2H3-004`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_duplicate_response_counter_and_ids`
* **Objective:** Verify response object reports accurate skipped count and returns existing `evidence_id`.
* **Preconditions:** Event 1 ingested, yielding `evidence_id_1`.
* **Input:** Resubmit Event 1.
* **Expected Result:** `response.total_skipped_duplicates == 1`; `response.evidence_ids[0] == evidence_id_1`.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).

---

### TC-P1H2H3-005 — Mixed Batch Ingestion (New & Duplicate Events)
* **Test ID:** `TC-P1H2H3-005`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_mixed_batch_ingestion_counts`
* **Objective:** Verify batch containing both novel and pre-existing events processes correctly in a single transaction.
* **Preconditions:** Event A already in database; Event B is novel.
* **Input:** `IngestRequest(events=[Event_A, Event_B])`.
* **Expected Result:** `total_received == 2`, `total_normalized == 1`, `total_skipped_duplicates == 1`.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).

---

### TC-P1H2H3-006 — Intra-Batch Duplicate Handling
* **Test ID:** `TC-P1H2H3-006`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_intra_batch_duplicates_a_a_a_b_c_c`
* **Objective:** Verify deduplication within a single batch containing repeated identical payloads `[A, A, A, B, C, C]`.
* **Preconditions:** Empty database.
* **Input:** Batch of 6 events with 3 unique payloads (3xA, 1xB, 2xC).
* **Expected Result:** `total_received == 6`, `total_normalized == 3`, `total_skipped_duplicates == 3`. Exactly 3 records in database.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).

---

### TC-P1H2H3-007 — Concurrent Race Condition Savepoint Rollback
* **Test ID:** `TC-P1H2H3-007`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_concurrent_duplicate_savepoint_handling`
* **Objective:** Verify that an `IntegrityError` (simulating concurrent insert race) is intercepted by a nested savepoint and recovered into a duplicate skip without failing the transaction.
* **Preconditions:** Database session with mock interception simulating concurrent flush collision.
* **Input:** Ingestion of duplicate event.
* **Expected Result:** Savepoint catches collision, rolls back to savepoint, queries existing record, increments duplicate counter, and commits remaining batch.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).

---

### TC-P1H2H3-008 — Batched Existence Query Count Verification ($O(1)$ Queries for $N=20$)
* **Test ID:** `TC-P1H2H3-008`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_batched_query_count_verification_n20`
* **Objective:** Verify that checking existence of 20 hashes executes a single `SELECT ... WHERE sha256_hash IN (...)` query instead of 20 sequential queries.
* **Preconditions:** SQL statement counter attached to engine.
* **Input:** Batch of 20 events.
* **Expected Result:** Exactly 1 `SELECT` existence query executed during lookup phase.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).

---

### TC-P1H2H3-009 — Chunked In-Clause Boundary (1001 Unique Events)
* **Test ID:** `TC-P1H2H3-009`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_chunking_boundary_1001_unique_events`
* **Objective:** Verify that batches exceeding `DEFAULT_CHUNK_SIZE=1000` partition existence queries into chunks of 1000 and 1 items.
* **Preconditions:** Batch of 1001 distinct event hashes.
* **Input:** `service._lookup_existing_hashes(db_session, hashes_1001)`.
* **Expected Result:** Exactly 2 chunk queries executed: Chunk 1 contains 1000 parameters, Chunk 2 contains 1 parameter.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).

---

### TC-P1H2H3-010 — Empty Batch Zero Query Optimization
* **Test ID:** `TC-P1H2H3-010`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_empty_batch_performs_zero_queries_and_returns_zero_counts`
* **Objective:** Verify that submitting an empty batch executes 0 database queries and returns zero counts immediately.
* **Preconditions:** Statement listener attached.
* **Input:** `IngestRequest(events=[])`.
* **Expected Result:** Zero SQL queries executed; `total_received == 0`, `total_normalized == 0`.
* **Status:** PASS (Reconstructed from commit `e1af0c9`).
