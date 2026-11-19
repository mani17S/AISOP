# P1-H1 Test Execution Report: Initial Ingestion Pipeline & Baseline Data Models

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H1-EXEC |
| **Milestone** | P1-H1: Git Safety Checkpoint & Initial Pipeline Baseline |
| **Checkpoint Commit** | `63bee0b` (`63bee0bd76df3d1c5d9cb8fae1f2ec6ef21f2d`) |
| **Parent Commit** | `fb42fe9` |
| **Commit Date** | 2026-09-09 |
| **Execution Status** | Historical Reconstructed / Verified in Current Full Regression |

---

## 1. Executive Summary

Milestone **P1-H1** established the initial architectural foundation of AISOP, delivering application configuration loading, the cryptographic hashing utility, initial Sysmon parsers (Event IDs 1, 3, 22), canonical Pydantic schemas, and foundational evidence ORM models.

### Historical Evidence Status
> **Notice on Historical Evidence:**
> Historical execution evidence (verbatim terminal runner outputs and timings) was not preserved in the repository at commit `63bee0b`. The test cases and verification results documented herein are reconstructed from the implementation code, test suites, and git history introduced at that checkpoint, and corroborated by current-state regression execution.

---

## 2. Test Suite Composition at P1-H1

At the completion of commit `63bee0b`, the test suite comprised the following automated test files:

| Test File | Test Layer | Component Verified | Test Functions Count |
|---|---|---|:---:|
| `backend/tests/unit/test_config.py` | Unit | Pydantic Settings Defaults, Overrides, Validation | 18 |
| `backend/tests/unit/test_hasher.py` | Unit | SHA-256 Canonical Hasher Determinism | 4 |
| `backend/tests/unit/test_canonical_schema.py` | Unit | Canonical Event Schema Pydantic Models | 2 |
| `backend/tests/unit/test_entity_extractor.py` | Unit | Entity Extraction for Process & Network Events | 2 |
| `backend/tests/unit/test_sysmon_parser.py` | Unit | Sysmon Parser (Event IDs 1, 3, 22) | 5 |
| `backend/tests/unit/test_evidence_models.py` | Unit / DB | SQLAlchemy Evidence ORM Models (Raw & Normalized) | 2 |
| `backend/tests/unit/test_ingestion_service.py` | Unit / DB | Initial Batch Ingestion Flow | 2 |
| `backend/tests/unit/test_sample_dataset_ingestion.py` | Functional | Attack Chain Sample Ingestion | 1 |
| `backend/tests/integration/test_ingest_api.py` | Functional | FastAPI Ingestion Endpoint In-Memory Probe | 1 |
| **Total Automated Tests at P1-H1** | | | **37** |

---

## 3. Current-State Regression Verification

All test capabilities authored in P1-H1 were re-verified in the current repository state to certify that baseline behavior remains functional and un-regressed.

### Command Executed
```bash
.venv\Scripts\python.exe -m pytest backend/tests/unit/test_config.py backend/tests/unit/test_hasher.py backend/tests/unit/test_canonical_schema.py backend/tests/unit/test_evidence_models.py
```

### Observed Execution Outcome
* **Configuration Tests (`test_config.py`):** 18 passed.
* **Hasher Determinism Tests (`test_hasher.py`):** 4 passed.
* **Canonical Schema Tests (`test_canonical_schema.py`):** 2 passed.
* **Evidence Model Tests (`test_evidence_models.py`):** 2 passed.
* **Result:** **100% PASS** in active test harness.

---

## 4. Documented Invariants & Limitations at P1-H1

1. **Test Database Engine:** At P1-H1, unit tests utilized in-memory SQLite (`sqlite+aiosqlite:///:memory:`) for initial fast prototyping. This was identified as a portability limitation and was subsequently replaced in milestone P1-H9 with a strict, containerized PostgreSQL 17 test harness.
2. **Parser Scope:** Telemetry parsing was limited to Sysmon Event IDs 1 (Process Create), 3 (Network Connect), and 22 (DNS Query). File stream hashing, remote thread creation, and process access parsing were deferred to P1-H8.
3. **Deduplication Strategy:** P1-H1 implemented an initial sequential deduplication check. Hardened Option A deduplication with batch chunking and nested savepoint isolation was formalized in P1-H2 and P1-H3.
