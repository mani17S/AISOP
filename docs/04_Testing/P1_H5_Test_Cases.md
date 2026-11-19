# P1-H5 Test Cases: SOC Investigation Query API

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H5-TC |
| **Milestone** | P1-H5: SOC Investigation Query API Expansion |
| **Checkpoint Commit** | `2228764` (`2228764ca95e05e8a65092975d8f1203e1a4788f`) |
| **Governing SRS** | Functional Requirements for Security Investigation Retrieval |
| **Component Scope** | Query Service (`app/services/query_service.py`), Investigation Endpoints (`app/api/v1/endpoints/investigation.py`), Query Schemas |
| **Last Updated** | 2026-09-23 |

---

## 1. Purpose & Scope

This document specifies test cases for **Milestone P1-H5**. P1-H5 introduced the core investigative retrieval interface for Security Operations Center (SOC) analysts. 

Key capabilities verified:
1. Deterministic chronological sorting with tie-breaker ordering (`ORDER BY event_timestamp DESC, id DESC`).
2. Bounded limit/offset pagination with strict upper bounds ($1 \le \text{limit} \le 1000$, $\text{offset} \ge 0$).
3. Inclusive time range filtering (`start_time`, `end_time`).
4. Multi-field filtering (event type, source type, source identifier).
5. Entity/IOC subquery filtering without duplicate event rows.
6. HTTP-level error handling for malformed UUIDs and invalid SHA-256 digests.

---

## 2. Test Case Catalogue

### TC-P1H5-001 — Query Bounds & Parameter Validation
* **Test ID:** `TC-P1H5-001`
* **Module:** `backend/app/services/query_service.py`
* **Source Test:** `test_investigation_query_service.py::test_query_bounds_and_validation`
* **Objective:** Verify that `limit < 1`, `limit > 1000`, and `offset < 0` raise validation errors.
* **Preconditions:** Initialized `InvestigationQueryService`.
* **Input:** Filter parameters with `limit=0`, `limit=1001`, and `offset=-1`.
* **Expected Result:** Raises `ValueError` or Pydantic `ValidationError`.
* **Status:** PASS (Reconstructed from commit `2228764`).

---

### TC-P1H5-002 — Inclusive Time Range Filtering
* **Test ID:** `TC-P1H5-002`
* **Module:** `backend/app/services/query_service.py`
* **Source Test:** `test_investigation_query_service.py::test_time_range_boundaries_inclusive`
* **Objective:** Verify that `start_time` and `end_time` filters are inclusive of boundary timestamps.
* **Preconditions:** Database populated with events at timestamps $T_0$, $T_1$, $T_2$.
* **Input:** Query with `start_time=T_1` and `end_time=T_1`.
* **Expected Result:** Returns exactly the event at $T_1$. Events at $T_0$ and $T_2$ are excluded.
* **Status:** PASS (Reconstructed from commit `2228764`).

---

### TC-P1H5-003 — Deterministic Tie-Breaker Ordering
* **Test ID:** `TC-P1H5-003`
* **Module:** `backend/app/services/query_service.py`
* **Source Test:** `test_investigation_query_service.py::test_deterministic_ordering_with_timestamp_collision`
* **Objective:** Verify that multiple events sharing the exact same microsecond timestamp are sorted deterministically by `id DESC`.
* **Preconditions:** Three events inserted with identical timestamp $T$ and known UUIDs.
* **Input:** `query_service.get_events(db_session, TimelineFilterParams())`.
* **Expected Result:** Events returned in strictly descending UUID order for identical timestamps.
* **Status:** PASS (Reconstructed from commit `2228764`).

---

### TC-P1H5-004 — Pagination State Transitions (Offset Traversal)
* **Test ID:** `TC-P1H5-004`
* **Module:** `backend/app/services/query_service.py`
* **Source Test:** `test_investigation_query_service.py::test_pagination_state_transitions`
* **Objective:** Verify that traversing pages with `limit=2` across 5 events produces disjoint, non-overlapping slices.
* **Preconditions:** 5 events in database.
* **Input:** Page 1 (`limit=2, offset=0`), Page 2 (`limit=2, offset=2`), Page 3 (`limit=2, offset=4`).
* **Expected Result:** Pages contain 2, 2, and 1 items respectively; zero ID overlap across pages; total count reports 5.
* **Status:** PASS (Reconstructed from commit `2228764`).

---

### TC-P1H5-005 — Multi-Field Filter Combinations
* **Test ID:** `TC-P1H5-005`
* **Module:** `backend/app/services/query_service.py`
* **Source Test:** `test_investigation_query_service.py::test_source_and_multi_field_filtering`
* **Objective:** Verify conjunctive filtering across `event_type`, `source_type`, and `source_identifier`.
* **Preconditions:** Database populated with heterogeneous telemetry.
* **Input:** Filter with `event_type="process_creation"`, `source_type="sysmon"`, `source_identifier="HOST-ALPHA"`.
* **Expected Result:** Returns only events satisfying all conditions simultaneously.
* **Status:** PASS (Reconstructed from commit `2228764`).

---

### TC-P1H5-006 — Entity Subquery Without Row Duplication
* **Test ID:** `TC-P1H5-006`
* **Module:** `backend/app/services/query_service.py`
* **Source Test:** `test_investigation_query_service.py::test_entity_ioc_subquery_and_no_duplication`
* **Objective:** Verify that filtering by an entity observable (e.g. IP address) associated with multiple entity roles does not duplicate the parent event row.
* **Preconditions:** Single normalized event linked to 4 extracted entities matching target value.
* **Input:** Query with entity subquery filter.
* **Expected Result:** Returns the event exactly once (no Cartesian product duplication).
* **Status:** PASS (Reconstructed from commit `2228764`).

---

### TC-P1H5-007 — Single Event & Evidence Point Retrieval
* **Test ID:** `TC-P1H5-007`
* **Module:** `backend/app/services/query_service.py`
* **Source Test:** `test_investigation_query_service.py::test_single_event_and_evidence_retrieval`
* **Objective:** Verify point retrieval of normalized event by UUID, raw evidence by UUID, and raw evidence by SHA-256 hash.
* **Preconditions:** Known event and raw evidence records in database.
* **Input:** Query by `event_id`, query by `evidence_id`, query by `sha256_hash`.
* **Expected Result:** Returns corresponding detail models with linked entities and original payloads.
* **Status:** PASS (Reconstructed from commit `2228764`).

---

### TC-P1H5-008 — HTTP Investigation API Pagination & Bounds (HTTP 422)
* **Test ID:** `TC-P1H5-008`
* **Module:** `backend/app/api/v1/endpoints/investigation.py`
* **Source Test:** `test_investigation_api.py::test_investigation_pagination_and_bounds`
* **Objective:** Verify HTTP endpoint returns 422 Unprocessable Entity when `limit=0` or `limit=1001` is supplied.
* **Preconditions:** FastAPI test client.
* **Input:** `GET /api/v1/investigation/events?limit=0` and `GET /api/v1/investigation/events?limit=1001`.
* **Expected Result:** HTTP status code 422.
* **Status:** PASS (Reconstructed from commit `2228764`).

---

### TC-P1H5-009 — HTTP Investigation API Hash Validation (HTTP 422 / 404)
* **Test ID:** `TC-P1H5-009`
* **Module:** `backend/app/api/v1/endpoints/investigation.py`
* **Source Test:** `test_investigation_api.py::test_investigation_hash_validation`
* **Objective:** Verify that an invalid non-hex SHA-256 hash returns 422, while an absent valid hash returns 404.
* **Preconditions:** FastAPI test client.
* **Input:** `GET /api/v1/investigation/evidence/by-hash/not-a-hash` and valid 64-char hex hash not in DB.
* **Expected Result:** Invalid string returns 422; non-existent valid hash returns 404 Not Found.
* **Status:** PASS (Reconstructed from commit `2228764`).

---

### TC-P1H5-010 — HTTP Investigation API Malformed UUID Handling (HTTP 422)
* **Test ID:** `TC-P1H5-010`
* **Module:** `backend/app/api/v1/endpoints/investigation.py`
* **Source Test:** `test_investigation_api.py::test_investigation_malformed_uuid_handling`
* **Objective:** Verify passing a non-UUID string as path parameter returns HTTP 422.
* **Preconditions:** FastAPI test client.
* **Input:** `GET /api/v1/investigation/events/123-invalid-uuid`.
* **Expected Result:** HTTP status code 422 Unprocessable Entity.
* **Status:** PASS (Reconstructed from commit `2228764`).
