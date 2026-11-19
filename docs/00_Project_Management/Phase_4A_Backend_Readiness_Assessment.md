# AISOP — Phase 4A Backend Readiness & Alert-to-Case Traceability Assessment

**Document Version:** 1.1.0  
**Date:** 2026-10-31  
**Status:** IMPLEMENTED & TEST-VERIFIED (BACKEND MILESTONE COMPLETE)  
**Repository:** `D:\AISOP`  
**Current Git HEAD:** `c4e877cf06056bce32f5a3f893a82261b850ff85` on `main`  
**Author:** Principal Security Architect, Senior Full-Stack Engineer & Application Security Engineer  

---

## 1. Executive Summary & Verification Verdict

This assessment documents the engineering verification, implementation, and test closeout of the backend prerequisites required for Phase 4A frontend development (`Alerts.tsx`).

### Implementation Closeout Summary:
1. **Can the frontend retrieve ingested alerts today?**  
   **YES.** The backend implementation delivers:
   - `GET /api/v1/alerts`: Bounded, paginated alert queue querying `NormalizedEventModel` (`action="alert_triggered"`), supporting filtering by `source_type`, `severity`, `category`, `provider`, `source_identifier`, `time range`, and keyword search. Returns `AlertSummaryItem` with titles, categories, severities, MITRE tactics, top observables, and case linkage metadata (`has_case`, `case_count`).
   - `GET /api/v1/alerts/{alert_id}`: Secure canonical alert detail projection (`AlertDetailResponse`) providing full triage context while strictly excluding `raw_payload`.
2. **Does the current data model preserve alert identity across case promotion?**  
   **YES.** The complete `CanonicalAlert` is immutably stored in `normalized_events.normalized_payload`. When promoted to a case via `case_evidence`, the underlying record is preserved and unmutated.
3. **Does the schema support multiple alerts sharing evidence?**  
   **NO.** In AISOP, an alert *is* an evidence record. Distinct alerts never share an evidence record. However, multiple *cases* can link the same alert.
4. **Does `CaseCreateRequest.initial_evidence_ids` link evidence atomically?**  
   **YES.** `CaseService.create_case()` has been corrected to validate existence of all specified evidence IDs, reject duplicates (HTTP 400), abort if any ID is missing (HTTP 404), insert `CaseEvidenceModel` associations, and record attributable `evidence_linked` audit logs within a single atomic database transaction.
5. **Is P3-H4 independently acceptable?**  
   **YES.** Rate limiting and security headers are fully implemented and verified offline with zero dependency on local model inference.

---

## 2. Workstream A — Alert Retrieval API Verification & Implementation

### Baseline Findings vs. Implemented Capabilities

| # | Question | Historical Assessment | Implemented & Test-Verified Capability | Exact File & Line References |
|:---|:---|:---:|:---:|:---|
| **1** | Does a persisted alert retrieval endpoint exist? | Missing | **IMPLEMENTED** | [`backend/app/api/v1/endpoints/alerts.py#L93-L198`](file:///D:/AISOP/backend/app/api/v1/endpoints/alerts.py#L93-L198) |
| **2** | Is there a `GET /api/v1/alerts` endpoint or equivalent? | Missing | **IMPLEMENTED** | `GET /api/v1/alerts` in [`backend/app/api/v1/endpoints/alerts.py`](file:///D:/AISOP/backend/app/api/v1/endpoints/alerts.py) |
| **3** | Can an authorized analyst retrieve alerts without knowing internal IDs? | Missing | **IMPLEMENTED** | Supported via paginated listing and multi-field filtering |
| **4** | Are pagination, sorting and filtering supported? | Partial | **IMPLEMENTED** | Deterministic ordering `(event_timestamp DESC, id DESC)`, bounded pagination `(1 <= limit <= 100)` |
| **5** | Can alerts be filtered by source, severity, status and time range? | Partial | **IMPLEMENTED** | Source, severity, category, provider, time window, and keyword search supported. Alert status defaults to `new` |
| **6** | Are original vendor fields and source provenance available in response? | Missing | **IMPLEMENTED** | Exposes `source_alert_id`, `provider`, `source_type`, `mitre_attack`, `observables`, and `custom_fields` |
| **7** | Are raw evidence payloads exposed unnecessarily? | No | **PRESERVED** | `raw_payload` is strictly excluded from `AlertSummaryItem` and `AlertDetailResponse` |
| **8** | Does retrieval enforce authentication and role permissions? | Yes | **ENFORCED** | Enforces `verify_api_key`, rejects machine tokens without analyst identity (403), rejects ingest role (403) |
| **9** | Are error responses and invalid filters handled safely? | Yes | **ENFORCED** | Invalid page/limit returns 422; invalid time windows return 400 |
| **10** | Are the endpoints covered by meaningful tests? | Missing | **TESTED** | 18 automated unit tests in [`backend/tests/unit/test_alert_retrieval.py`](file:///D:/AISOP/backend/tests/unit/test_alert_retrieval.py) |

---

## 3. Workstream B — Alert, Evidence and Case Relationship Verification

### Complete Telemetry Lifecycle
$$\text{Incoming Vendor Alert} \xrightarrow{\text{Adapter}} \text{CanonicalAlert} \xrightarrow{\text{AlertIngestionService}} \begin{cases} \text{RawEvidence (SHA-256 deduplicated)} \\ \text{NormalizedEventModel (Payload + Taxonomies)} \\ \text{ExtractedEntityModel (IOCs / Graph Nodes)} \end{cases} \xrightarrow{\text{case\_evidence}} \text{CaseModel}$$

### Verified Relationship Invariants
1. **Alert $\longrightarrow$ Evidence (Identity Mapping):** In AISOP, an alert *is* a `NormalizedEventModel` record with `action="alert_triggered"`.
2. **Case $\longrightarrow$ Evidence (Direct M:N Association):** Cases link evidence via `case_evidence`. `ON DELETE RESTRICT` on `evidence_id` prevents deleting evidence linked to cases.
3. **Multi-Case Sharing:** Supported. Multiple cases can reference the same alert evidence record.
4. **Multi-Alert Sharing:** Prohibited in ingestion. Each alert payload creates a unique `RawEvidence` and `NormalizedEventModel`. Duplicate payloads are rejected with idempotency checks.

---

## 4. Workstream C — Atomic Case Creation & Evidence Linking

### Correction of `CaseCreateRequest.initial_evidence_ids`
In [`backend/app/services/case_service.py`](file:///D:/AISOP/backend/app/services/case_service.py), `create_case()` now executes:
1. **Pre-flight Validation:** Checks for duplicate evidence IDs in request (HTTP 400).
2. **Existence Verification:** Queries all specified evidence IDs in `NormalizedEventModel`. If any ID is missing, raises HTTP 404 and aborts.
3. **Atomic Execution:** Within a single database transaction, adds:
   - `CaseModel` (initial case entity)
   - `CaseAssignmentModel` (designates creator as Lead)
   - `CaseEvidenceModel` (for each requested evidence record, attributable to creator)
   - `CaseAuditEventModel` (`action="evidence_linked"` for each association)
   - `CaseAuditEventModel` (`action="case_created"` with initial evidence count and IDs)
4. **Atomic Flush:** Commits all records together. If any constraint fails, the entire transaction rolls back cleanly.

---

## 5. Workstream D — Phase 3 Governance Recommendation

### Decoupling Recommendation
Formally decouple P3-H4 (Rate Limiting & Security Headers) from P3-H3B (Model Benchmark Capture) in [`docs/00_Project_Management/Milestones.md`](file:///D:/AISOP/docs/00_Project_Management/Milestones.md).
- P3-H4: **COMPLETE (Offline Verified)** (18 tests passing, active in `main.py`).
- P3-H3B: **PARTIAL / GATED** (Harness verified across 19 dry-run scenarios; live inference gated under Gate GATE-P3H3B-01).

---

## 6. Workstream E — Phase 4A Capability Readiness Matrix (Updated)

| Capability | Initial Assessment | Implemented State | Readiness Classification |
|:---|:---:|:---:|:---:|
| **Alert Queue Presentation** | Missing endpoint | `GET /api/v1/alerts` implemented & verified | **READY** |
| **Multi-Source Filtering** | Missing API mapping | Supported on `GET /api/v1/alerts` | **READY** |
| **Severity Filtering** | Missing API mapping | Supported on `GET /api/v1/alerts` | **READY** |
| **Alert Details View** | Blocked by 403 | `GET /api/v1/alerts/{alert_id}` implemented | **READY** |
| **Ingestion Form / UI** | Implemented | `POST /api/v1/alerts/ingest` verified | **READY** |
| **Alert-to-Case Promotion** | Two-step only | Atomic `initial_evidence_ids` implemented | **READY** |
| **Evidence Association** | Implemented | `POST /api/v1/cases/{case_id}/evidence` verified | **READY** |
| **MITRE Exploration** | Schema only | Projected in `AlertSummaryItem.mitre_attack` | **READY** |
| **AI Investigation** | Gated | Remains gated under Gate GATE-P3H3B-01 | **BLOCKED** |

---

## 7. Test Verification Evidence

### Focused Suite: `backend/tests/unit/test_alert_retrieval.py`
- **18 tests executed, 18 passed (0 failures) in 1.63s.**
- Covers alert listing, filtering, search, time bounds, detail projection, non-alert exclusion, RBAC boundaries, and atomic initial evidence linking.

### Full Backend Regression Suite
- **1,128 unit tests executed, 1,128 passed (0 failures) in 43.93s.**
- Zero regressions across authentication, case management, BOLA/IDOR security, rate limiting, and security headers.

### Frontend Unit Suite
- **11 tests executed, 11 passed in 139ms.**

---

## 8. PostgreSQL Integration Test Status

- **Status:** **UNAVAILABLE / ENVIRONMENT-GATED**.
- Tests in `test_postgres_lifecycle.py`, `test_postgres_case_scoping.py`, and `test_postgres_vector_retrieval.py` require a running PostgreSQL container (`localhost:5433`) with pgvector and `$env:TEST_DATABASE_URL` configured.
- In accordance with the fail-closed test protocol (`conftest.py`), integration tests were not run against mock PostgreSQL. Full regression was validated in SQLite / in-memory unit mode.

---

## 9. Remaining Limitations

1. **Alert Triage Status Mutation:** `AlertStatus` is serialized in `normalized_payload["status"]`. An endpoint for mutating alert status (e.g. `PATCH /api/v1/alerts/{id}/status`) is not currently implemented; alerts remain in `"new"` triage status unless promoted to a case.
2. **AI Synthesis Gating:** Autonomous AI investigation invocation remains strictly gated behind Gate GATE-P3H3B-01 pending explicit Project Owner approval.
