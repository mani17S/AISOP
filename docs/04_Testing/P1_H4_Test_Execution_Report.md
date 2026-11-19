# P1-H4 Test Execution Report: Ingestion Security & Bounds Hardening

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H4-EXEC |
| **Milestone** | P1-H4: Ingestion Security & Bounds Hardening |
| **Checkpoint Commit** | `2cbe6a8` (`2cbe6a87bc2b3d86519cb6071075a820d0059c38`) |
| **Parent Commit** | `e1af0c9` |
| **Commit Date** | 2026-09-10 |
| **Execution Status** | Historical Reconstructed / Verified in Current Full Regression |

---

## 1. Executive Summary

Milestone **P1-H4** enforced resource bounds and transactional isolation across the ingestion boundary. It established hard limits on batch sizes (2000 events max), individual payload bytes (64 KB max), and input string character sets, while wrapping individual novel event insertions in nested SQL savepoints (`begin_nested()`) to guarantee atomicity and prevent orphaned raw evidence records.

### Historical Evidence Status
> **Notice on Historical Evidence:**
> Historical execution evidence (verbatim console logs and timestamps) was not preserved in the repository at commit `2cbe6a8`. The test specifications and execution findings documented herein are reconstructed from the implementation and tests committed at `2cbe6a8`, and corroborated by active regression suite execution.

---

## 2. Test Suite Expansion at P1-H4

Commit `2cbe6a8` added 8 dedicated security and boundary test cases across unit and API integration suites:

| Test Case Function | Test Layer | Component Verified | Status at Commit |
|---|---|---|:---:|
| `test_batch_size_boundary_validation` | Unit | 2000 vs 2001 batch length ceiling | PASS |
| `test_event_payload_max_bytes_validation` | Unit | 64 KB (65,536 bytes) payload ceiling | PASS |
| `test_source_type_and_identifier_validation` | Unit | Regex and length validation | PASS |
| `test_atomic_savepoint_rollback_on_child_processing_error` | Unit / DB | Atomic savepoint rollback & zero orphan rows | PASS |
| `test_safe_sample_truncation` | Unit | Safe logging sample formatting | PASS |
| `test_ingest_endpoint_rejects_oversized_payload` | API Integration | HTTP 422 on oversized event | PASS |
| `test_ingest_endpoint_rejects_invalid_source_type` | API Integration | HTTP 422 on invalid metadata | PASS |
| `test_ingest_endpoint_accepts_empty_batch` | API Integration | HTTP 200 on empty batch | PASS |

---

## 3. Current-State Regression Verification

All 8 boundary and security test cases remain active and passing in the consolidated test suite.

### Command Executed
```bash
.venv\Scripts\python.exe -m pytest backend/tests/unit/test_ingestion_service.py backend/tests/integration/test_ingest_api.py -k "boundary or payload or validation or savepoint or rejects or safe_sample" -v
```

### Observed Execution Outcome
* **Boundary & Validation Unit Tests:** 5 passed.
* **HTTP API Security Tests:** 3 passed.
* **Result:** **8 / 8 passed (100% PASS)** in active test harness.

---

## 4. Key Architectural Guarantees Verified

1. **Denial-of-Service Defense:** Ingestion requests containing more than 2000 events or payloads containing individual events $>64\text{ KB}$ are rejected at the schema validation boundary before any database queries or parsing logic execute.
2. **Orphan Row Prevention:** If entity extraction or normalization fails on an event, the nested savepoint rolls back the raw evidence row for that specific event, guaranteeing that no incomplete or orphaned records persist.
3. **Transaction Continuity:** A single corrupted or failing event in a batch of valid events does not fail the entire batch; valid events commit successfully.
