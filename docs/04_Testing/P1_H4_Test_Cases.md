# P1-H4 Test Cases: Ingestion Security & Bounds Hardening

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H4-TC |
| **Milestone** | P1-H4: Ingestion Security & Bounds Hardening |
| **Checkpoint Commit** | `2cbe6a8` (`2cbe6a87bc2b3d86519cb6071075a820d0059c38`) |
| **Governing ADR** | [ADR-004: Ingestion Scope & Bounds](docs/03_System_Design/ADR/ADR-004_Initial_Ingestion_Scope.md) |
| **Component Scope** | Ingest Schemas (`app/schemas/ingest.py`), Ingestion Service, API Ingest Endpoint |
| **Last Updated** | 2026-09-23 |

---

## 1. Purpose & Scope

This document specifies the test cases for **Milestone P1-H4**. P1-H4 hardened the ingestion boundary against denial-of-service, memory exhaustion, injection attacks, and partial transaction failures. 

Key capabilities verified:
1. Enforcement of batch size ceilings ($N \le 2000$).
2. Enforcement of single event payload size limits ($\le 64\text{ KB} = 65,536\text{ bytes}$).
3. Sanitization and regex validation of metadata fields (`source_type`, `source_identifier`).
4. Per-event atomic transaction isolation using nested SQL savepoints (`begin_nested()`), guaranteeing that a failure during child model creation rolls back only that event's raw evidence record without creating orphaned rows.
5. HTTP-level rejection via FastAPI endpoints returning HTTP 422 Unprocessable Entity.

---

## 2. Test Case Catalogue

### TC-P1H4-001 — Maximum Batch Size Boundary Validation (2000 vs 2001)
* **Test ID:** `TC-P1H4-001`
* **Module:** `backend/app/schemas/ingest.py`
* **Source Test:** `test_ingestion_service.py::test_batch_size_boundary_validation`
* **Objective:** Verify that a batch of exactly 2000 events is accepted, while 2001 events is rejected by Pydantic schema validation.
* **Preconditions:** None.
* **Input:** `IngestRequest(events=[...2000 items...])` and `IngestRequest(events=[...2001 items...])`.
* **Expected Result:** Batch of 2000 passes validation; batch of 2001 raises `ValidationError` with message `"List should have at most 2000 items"`.
* **Status:** PASS (Reconstructed from commit `2cbe6a8`).

---

### TC-P1H4-002 — Event Payload Byte Limit Enforcement (64 KB Ceiling)
* **Test ID:** `TC-P1H4-002`
* **Module:** `backend/app/schemas/ingest.py`
* **Source Test:** `test_ingestion_service.py::test_event_payload_max_bytes_validation`
* **Objective:** Verify that an individual event payload exceeding 65,536 bytes (64 KB) is rejected during schema parsing.
* **Preconditions:** Raw event containing 70,000 bytes of character data.
* **Input:** `IngestRequest(events=[{"EventID": 1, "LargeData": "A" * 70000}])`.
* **Expected Result:** Raises `ValidationError` with message `"exceeds maximum allowed payload size of 65536 bytes"`.
* **Status:** PASS (Reconstructed from commit `2cbe6a8`).

---

### TC-P1H4-003 — Source Type & Identifier Format Validation
* **Test ID:** `TC-P1H4-003`
* **Module:** `backend/app/schemas/ingest.py`
* **Source Test:** `test_ingestion_service.py::test_source_type_and_identifier_validation`
* **Objective:** Verify regex format constraints and length limits on `source_type` and `source_identifier`.
* **Preconditions:** Test inputs with SQL injection characters (`;`, quotes), empty strings, and strings exceeding max length.
* **Input:** `source_type=""`, `source_type="sysmon; DROP TABLE raw_evidence;"`, `source_type="a" * 51`.
* **Expected Result:** Invalid patterns raise `ValidationError`; valid pattern `"windows_event-2.0"` passes.
* **Status:** PASS (Reconstructed from commit `2cbe6a8`).

---

### TC-P1H4-004 — Atomic Savepoint Rollback on Child Processing Error
* **Test ID:** `TC-P1H4-004`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_atomic_savepoint_rollback_on_child_processing_error`
* **Objective:** Verify that an unexpected failure during child entity extraction on Event 1 rolls back Event 1's `RawEvidence` record via nested savepoint, while allowing Event 0 and Event 2 to commit cleanly.
* **Preconditions:** Mock interception causing `extract_entities()` to crash specifically on Event 1.
* **Input:** Batch of 3 events `[Event_0, Event_1_Bad, Event_2]`.
* **Expected Result:**
  - `response.total_received == 3`, `total_normalized == 2`, `errors` list contains 1 entry for `event_index == 1`.
  - Database contains exactly 2 `RawEvidence` records and 2 `NormalizedEventModel` records (Events 0 and 2).
  - Event 1's `RawEvidence` row is completely absent from database (no orphaned raw evidence).
* **Status:** PASS (Reconstructed from commit `2cbe6a8`).

---

### TC-P1H4-005 — Safe Sample Truncation Utility
* **Test ID:** `TC-P1H4-005`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_safe_sample_truncation`
* **Objective:** Verify `_safe_sample` formats dictionaries, strings, and non-serializable objects without throwing exceptions.
* **Preconditions:** Object raising exception on `__str__` / `__repr__`.
* **Input:** Broken object, large string (>200 chars), nested dictionary.
* **Expected Result:** Large string truncated to max length; broken object safely returns `"<unserializable payload>"`.
* **Status:** PASS (Reconstructed from commit `2cbe6a8`).

---

### TC-P1H4-006 — HTTP Endpoint Rejection of Oversized Payloads (HTTP 422)
* **Test ID:** `TC-P1H4-006`
* **Module:** `backend/app/api/v1/endpoints/evidence.py`
* **Source Test:** `test_ingest_api.py::test_ingest_endpoint_rejects_oversized_payload`
* **Objective:** Verify FastAPI HTTP endpoint returns HTTP 422 when payload contains an event exceeding 64 KB.
* **Preconditions:** In-memory ASGI client.
* **Input:** `POST /api/v1/evidence/ingest` with 70 KB event payload.
* **Expected Result:** HTTP status code 422 Unprocessable Entity.
* **Status:** PASS (Reconstructed from commit `2cbe6a8`).

---

### TC-P1H4-007 — HTTP Endpoint Rejection of Illegal Source Type (HTTP 422)
* **Test ID:** `TC-P1H4-007`
* **Module:** `backend/app/api/v1/endpoints/evidence.py`
* **Source Test:** `test_ingest_api.py::test_ingest_endpoint_rejects_invalid_source_type`
* **Objective:** Verify FastAPI HTTP endpoint returns HTTP 422 on empty or injection-like `source_type`.
* **Preconditions:** In-memory ASGI client.
* **Input:** `POST /api/v1/evidence/ingest` with `source_type="sysmon; DROP TABLE"`.
* **Expected Result:** HTTP status code 422 Unprocessable Entity.
* **Status:** PASS (Reconstructed from commit `2cbe6a8`).

---

### TC-P1H4-008 — HTTP Endpoint Acceptance of Empty Batch (HTTP 200)
* **Test ID:** `TC-P1H4-008`
* **Module:** `backend/app/api/v1/endpoints/evidence.py`
* **Source Test:** `test_ingest_api.py::test_ingest_endpoint_accepts_empty_batch`
* **Objective:** Verify FastAPI HTTP endpoint returns HTTP 200 with zero counters when empty batch is posted.
* **Preconditions:** In-memory ASGI client.
* **Input:** `POST /api/v1/evidence/ingest` with `{"events": []}`.
* **Expected Result:** HTTP status code 200; `total_received == 0`, `total_normalized == 0`.
* **Status:** PASS (Reconstructed from commit `2cbe6a8`).
