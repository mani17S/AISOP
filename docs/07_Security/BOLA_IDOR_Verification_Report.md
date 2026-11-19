# AISOP — BOLA / IDOR Security Verification & Authorization Boundary Report

**Document ID:** AISOP-SEC-BOLA-2026-001  
**Classification:** Technical Security Architecture & Verification Audit  
**Author:** Principal Application Security Engineer & API Authorization Test Architect  
**Repository:** `D:\AISOP`  
**Git HEAD:** `c4e877cf06056bce32f5a3f893a82261b850ff85`  
**Target Standard:** OWASP API Security Top 10 (2023) — API1:2023 Broken Object Level Authorization (BOLA)  
**Status:** COMPLETE & PERMANENTLY VERIFIED  

---

## 1. Executive Summary

This security audit and verification report documents the object-level authorization architecture of the AI-Assisted Security Operations Platform (AISOP) and verifies that every case resource, nested sub-resource, and investigation pipeline endpoint strictly enforces multi-tenant case-level isolation on the backend.

A permanent, automated regression suite comprising **47 dedicated security test cases** has been implemented in `backend/tests/unit/test_case_bola_security.py`. All 47 tests pass deterministically alongside the existing test suite (1,144 offline tests passing, 28 deselected, 0 failures).

Additionally, the React 18 + Vite frontend was audited to ensure the client-side role switcher is strictly presentation-only and cannot influence, alter, or elevate backend authorization.

---

## 2. Threat Model: Broken Object-Level Authorization (OWASP API1:2023)

In security operations workflows, unauthorized cross-case access constitutes a critical security compromise:
1. **Confidentiality Breach:** Analyst A inspecting Case 101 could access sensitive indicators of compromise (IOCs), threat actor intelligence, or personally identifiable information (PII) belonging to Case 202.
2. **Investigation Contamination:** An unassigned operator linking arbitrary evidence into an active case could poison automated AI synthesis pipelines or mislead lead analysts.
3. **Privilege Escalation:** A read-only auditor or junior investigator modifying metadata, changing assignments, or closing active incidents.
4. **Resource Enumeration:** Attackers probing sequential integer identifiers or receiving distinct error codes (e.g., 403 vs 404) to map out internal case inventories.

AISOP mitigates these risks through a defense-in-depth authorization model combining UUIDv4 resource identifiers, server-side principal resolution, dynamic case-assignment lookup, and unified anti-enumeration error responses.

---

## 3. Architecture & Enforcement Mechanics

### 3.1 Principal Authentication & Extraction
Every authenticated API request is resolved via FastAPI dependency injection:
- `get_current_analyst`: Validates the `X-API-Key` or `Authorization: Bearer` token against the hashed token store in the `AnalystApiClient` database model.
- Client requests never submit user IDs, roles, or organization claims; the principal's identity and global role (`security_admin`, `analyst_tier_2`, `analyst_tier_1`, `auditor_viewer`) are established solely from the verified token.

### 3.2 Dynamic Case Assignment & Leadership Invariant
Case membership is governed by `CaseAssignmentModel`:
- An analyst has access to a case if and only if an active assignment record (`case_id`, `analyst_id`, `case_role`) exists.
- In accordance with ADR governance, `CaseModel` does not store a mutable `lead_analyst_id` column; leadership is dynamically resolved via the `@property lead_analyst_id` from the active assignment where `case_role = 'lead'`.
- Database integrity is guaranteed by a partial unique index `uq_case_lead_active` ensuring at most one active lead per case.

### 3.3 Strict Governance Decisions
- **Decision 1A (Anti-Enumeration Contract):** Unassigned analysts probing existing cases receive HTTP 404 (`"Case not found or access denied."`), which is byte-for-byte indistinguishable from probing a non-existent case UUID.
- **Decision 2A (Global Admin Parity):** `security_admin` users are treated identically to analysts regarding case containment. An unassigned administrator cannot inspect, modify, link evidence to, or synthesize reports for a case unless explicitly assigned.
- **Decision 3A (Tier-1 Lead Constraints):** A Tier-1 analyst (`analyst_tier_1`) assigned the case role of `lead` is blocked from case closure and staffing reassignments because global role policies (`can_close_case`, `can_manage_assignments`) require Tier-2 or Security Admin privileges. Both global and case roles are enforced conjunctive-fashion (`require_case_role` + `require_permission`).

---

## 4. Route-to-Authorization Matrix

The following table provides the exhaustive authorization inventory for all case-scoped and investigation routes:

| Route Path | HTTP Method | Required Global Role | Required Case Role | Enforcement Dependency | Anti-Enumeration Contract | BOLA Regression Test Coverage |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/v1/cases` | `GET` | Authenticated | None (Scoped List) | `get_current_analyst` + Filter Query | Returns only assigned cases; empty for unassigned | `TestBolaAlternateAuthorizationPaths.test_list_cases_*` |
| `/api/v1/cases` | `POST` | `security_admin`, `analyst_tier_2`, `analyst_tier_1` | N/A (Creator becomes lead) | `require_permission(can_create_case)` | Returns 403 for `auditor_viewer` | `test_case_api.py::test_create_case_viewer_forbidden` |
| `/api/v1/cases/{case_id}` | `GET` | Authenticated | `viewer`, `investigator`, `lead` | `require_case_access` | 404 for unassigned / non-existent; 422 for non-UUID | `TestBolaCaseAccess.test_analyst_*_cannot_read_*` |
| `/api/v1/cases/{case_id}` | `PATCH` | Authenticated | `lead` | `require_case_role("lead")` | 404 for unassigned; 403 for non-lead assigned | `TestBolaCaseAccess.test_readonly_viewer_cannot_update_case_metadata`, `test_investigator_cannot_update_case_metadata` |
| `/api/v1/cases/{case_id}/close` | `POST` | `security_admin`, `analyst_tier_2` | `lead` | `require_permission(can_close_case)` + `require_case_role("lead")` | 404 for unassigned; 403 for non-lead or Tier-1 lead | `TestBolaCaseAccess.test_readonly_viewer_cannot_close_case`, `test_tier1_lead_cannot_close_case` |
| `/api/v1/cases/{case_id}/assignments` | `POST` | `security_admin`, `analyst_tier_2` | `lead` | `require_permission(can_manage_assignments)` + `require_case_role("lead")` | 404 for unassigned; 403 for non-lead or Tier-1 lead | `TestBolaCaseAccess.test_readonly_viewer_cannot_manage_assignments`, `test_tier1_lead_cannot_manage_assignments` |
| `/api/v1/cases/{case_id}/assignments/{analyst_id}` | `DELETE` | `security_admin`, `analyst_tier_2` | `lead` | `require_permission(can_manage_assignments)` + `require_case_role("lead")` | 404 for unassigned; 403 for non-lead | Verified via assignment suite |
| `/api/v1/cases/{case_id}/evidence` | `GET` | Authenticated | `viewer`, `investigator`, `lead` | `require_case_access` | 404 for unassigned / non-existent; 422 for invalid limit/page | `TestBolaEvidenceAccess.test_analyst_*_cannot_list_*` |
| `/api/v1/cases/{case_id}/evidence` | `POST` | Authenticated | `investigator`, `lead` | `require_case_role(["investigator", "lead"])` | 404 for unassigned; 403 for viewer | `TestBolaEvidenceAccess.test_analyst_*_cannot_link_*`, `test_readonly_viewer_cannot_link_evidence_to_case` |
| `/api/v1/cases/{case_id}/investigation/synthesize` | `POST` | Authenticated | `investigator`, `lead` | `require_case_role(["investigator", "lead"])` | 404 for unassigned; 403 for viewer | `TestBolaInvestigationAndReportingAccess.test_analyst_a_cannot_synthesize_investigation_for_case_202` |
| `/api/v1/cases/{case_id}/synthesize-investigation` | `POST` | Authenticated | `investigator`, `lead` | `require_case_role(["investigator", "lead"])` | Alias route; identical 404/403 guarantees | `TestBolaInvestigationAndReportingAccess.test_analyst_a_cannot_synthesize_investigation_alias_for_case_202` |
| `/api/v1/cases/{case_id}/reports/synthesize` | `POST` | Authenticated | `investigator`, `lead` | `require_case_role(["investigator", "lead"])` | 404 for unassigned; 403 for viewer | `TestBolaInvestigationAndReportingAccess.test_analyst_a_cannot_synthesize_reports_for_case_202` |
| `/api/v1/investigation/format-report` | `POST` | Authenticated | Scoped by payload `case_id` | `verify_case_access_for_report` | 404 if payload `case_id` unassigned; 422 if invalid | `TestBolaInvestigationAndReportingAccess.test_report_format_with_unassigned_case_id_rejected` |
| `/api/v1/investigation/synthesize` (Unscoped) | `POST` | Deprecated / Blocked | N/A | Endpoint handler returns 403 Forbidden | Rejects un-scoped callers pointing directly to events | `TestBolaInvestigationAndReportingAccess.test_direct_unscoped_investigation_synthesis_rejected` |
| `/api/v1/reports/synthesize` (Unscoped) | `POST` | Deprecated / Blocked | N/A | Endpoint handler returns 403 Forbidden | Rejects un-scoped callers | `TestBolaInvestigationAndReportingAccess.test_direct_unscoped_report_synthesis_rejected` |
| `/api/v1/evidence/events/{event_id}` | `GET` | Deprecated / Blocked | N/A | Endpoint handler returns 404 / 403 | Rejects unscoped direct event access | `TestBolaAlternateAuthorizationPaths.test_direct_unscoped_event_detail_endpoint_blocked` |
| `/api/v1/evidence/raw/{uuid}` | `GET` | Deprecated / Blocked | N/A | Endpoint handler returns 404 / 403 | Rejects unscoped raw evidence retrieval | `TestBolaAlternateAuthorizationPaths.test_direct_unscoped_raw_evidence_by_uuid_blocked` |

---

## 5. Automated BOLA/IDOR Regression Test Suite

The test suite in `backend/tests/unit/test_case_bola_security.py` tests 5 distinct threat dimensions across 47 tests:

### 5.1 Suite 1: `TestBolaCaseAccess` (12 Tests)
- `test_analyst_a_cannot_read_case_202`: Verifies Analyst A (assigned to Case 101) cannot read Case 202 (returns 404).
- `test_analyst_b_cannot_read_case_101`: Verifies Analyst B (assigned to Case 202) cannot read Case 101 (returns 404).
- `test_analyst_cannot_read_unassigned_case`: Verifies unassigned Case 303 returns 404.
- `test_unauthenticated_request_rejected`: Verifies missing token returns 401.
- `test_readonly_viewer_cannot_update_case_metadata`: Verifies viewer assigned to Case 101 cannot PATCH case metadata (returns 403).
- `test_investigator_cannot_update_case_metadata`: Verifies investigator cannot PATCH case metadata (returns 403; lead required).
- `test_readonly_viewer_cannot_close_case`: Verifies viewer cannot close case (returns 403).
- `test_readonly_viewer_cannot_manage_assignments`: Verifies viewer cannot alter staffing assignments (returns 403).
- `test_tier1_lead_cannot_manage_assignments`: Verifies Tier-1 lead cannot assign staff due to global permission lack (returns 403).
- `test_tier1_lead_cannot_close_case`: Verifies Tier-1 lead cannot close case due to global permission lack (returns 403).
- `test_unassigned_admin_cannot_read_case`: Verifies Security Admin without case assignment cannot read Case 101 (returns 404).
- `test_unassigned_admin_cannot_update_case`: Verifies Security Admin without case assignment cannot PATCH Case 101 (returns 404).

### 5.2 Suite 2: `TestBolaEvidenceAccess` (9 Tests)
- `test_analyst_a_cannot_list_case_202_evidence`: Cross-case evidence query returns 404.
- `test_analyst_b_cannot_list_case_101_evidence`: Cross-case evidence query returns 404.
- `test_analyst_cannot_list_unassigned_case_evidence`: Evidence query on Case 303 returns 404.
- `test_analyst_a_cannot_link_evidence_to_case_202`: Attempting to link evidence into Case 202 returns 404.
- `test_analyst_b_cannot_link_evidence_to_case_101`: Attempting to link evidence into Case 101 returns 404.
- `test_evidence_from_another_case_never_appears_in_case_evidence_list`: Strict case evidence scoping verification.
- `test_readonly_viewer_cannot_link_evidence_to_case`: Viewer on assigned case cannot link evidence (returns 403).
- `test_unassigned_admin_cannot_list_case_evidence`: Security Admin cannot list evidence without assignment (returns 404).
- `test_unassigned_admin_cannot_link_case_evidence`: Security Admin cannot link evidence without assignment (returns 404).

### 5.3 Suite 3: `TestBolaInvestigationAndReportingAccess` (10 Tests)
- `test_analyst_a_cannot_synthesize_investigation_for_case_202`: Investigation synthesis on Case 202 returns 404.
- `test_analyst_a_cannot_synthesize_investigation_alias_for_case_202`: Alias route returns 404.
- `test_analyst_a_cannot_synthesize_reports_for_case_202`: Report synthesis on Case 202 returns 404.
- `test_analyst_cannot_synthesize_on_unassigned_case`: Synthesis on Case 303 returns 404.
- `test_readonly_viewer_cannot_synthesize_investigation`: Viewer on assigned case cannot invoke AI investigation (returns 403).
- `test_readonly_viewer_cannot_synthesize_reports`: Viewer on assigned case cannot invoke AI report generation (returns 403).
- `test_unassigned_admin_cannot_synthesize_case_investigation`: Security Admin cannot invoke AI investigation without assignment (returns 404).
- `test_unassigned_admin_cannot_synthesize_case_reports`: Security Admin cannot invoke AI report generation without assignment (returns 404).
- `test_report_format_with_unassigned_case_id_rejected`: Calling format-report with unassigned `case_id` in request body returns 404.
- `test_direct_unscoped_investigation_synthesis_rejected`: Calling legacy unscoped `/api/v1/investigation/synthesize` returns 403.
- `test_direct_unscoped_report_synthesis_rejected`: Calling legacy unscoped `/api/v1/reports/synthesize` returns 403.

### 5.4 Suite 4: `TestBolaAlternateAuthorizationPaths` (6 Tests)
- `test_list_cases_does_not_expose_unauthorized_cases_for_analyst_a`: Case listing for Analyst A returns exclusively Case 101.
- `test_list_cases_does_not_expose_unauthorized_cases_for_analyst_b`: Case listing for Analyst B returns exclusively Case 202.
- `test_list_cases_for_unassigned_admin_returns_empty`: Case listing for unassigned admin returns 0 items.
- `test_direct_unscoped_event_detail_endpoint_blocked`: Direct event lookup `/api/v1/evidence/events/{id}` returns 404.
- `test_direct_unscoped_raw_evidence_by_uuid_blocked`: Direct raw lookup by UUID returns 404.
- `test_direct_unscoped_raw_evidence_by_hash_blocked`: Direct raw lookup by hash returns 404.

### 5.5 Suite 5: `TestBolaIdentifierManipulation` (10 Tests)
- `test_sequential_integer_id_rejected_with_422`: Submitting integer `1`, `2`, `101` in `/cases/{case_id}` triggers FastAPI/Pydantic UUID validation and returns HTTP 422 immediately without database lookup.
- `test_sequential_integer_in_nested_route_rejected_with_422`: Submitting integer in `/cases/{case_id}/evidence` returns HTTP 422.
- `test_invalid_string_id_rejected_with_422`: Submitting malformed string returns HTTP 422.
- `test_nonexistent_uuid_returns_404_identical_to_unassigned`: Probing non-existent UUID returns identical 404 message (`"Case not found or access denied."`) matching unassigned case probe.
- `test_link_evidence_with_invalid_uuid_in_body_rejected_with_422`: Invalid evidence UUID in JSON body returns HTTP 422.
- `test_link_evidence_with_nonexistent_uuid_returns_404`: Non-existent evidence UUID returns HTTP 404.
- `test_case_list_query_params_negative_page_rejected_with_422`: Negative page parameter returns HTTP 422.
- `test_nested_evidence_query_params_zero_page_rejected_with_422`: Page 0 returns HTTP 422.
- `test_nested_evidence_query_params_excessive_limit_rejected_with_422`: Limit > 100 returns HTTP 422.

---

## 6. Frontend Trust Boundary & UI Decoupling Verification

The React 18 + TypeScript frontend (`frontend/src/`) was inspected and verified against client-side authorization bypass risks:

1. **Role Switcher Decoupling:**
   - The role selector in `frontend/src/components/Navbar.tsx` controls only local React state (`globalRole` in `AuthContext.tsx`).
   - The role value is utilized exclusively by `RoleGuard.tsx` to conditionally render UI controls (e.g., hiding the "Create Case" button for `auditor_viewer`).
   - Neither the HTTP request headers nor the request bodies transmit `globalRole` or requested privilege levels.
   - The UI header label was hardened with an explicit visual badge: `"UI Preview Role (Simulated — Backend Enforces Real Privileges)"`.

2. **Credential Management & Storage Semantics:**
   - API keys and tokens are stored in-memory within the `ApiClient` singleton.
   - Tab persistence utilizes `sessionStorage` strictly for operator session convenience across page refreshes.
   - Zero storage occurs in `localStorage` or browser cookies.
   - `sessionStorage` documentation was expanded to clarify that `sessionStorage` is not an XSS boundary; XSS defense is established via server-side CSP, React JSX contextual auto-escaping, and strict ban of `dangerouslySetInnerHTML`.

3. **Zero Credential / Token Logging:**
   - `frontend/src/services/api.ts` error handlers normalize server error responses into user-friendly strings.
   - No tokens, API keys, or raw authorization headers are printed to `console.log` or exposed in client telemetry.

4. **Frontend Build & Type Integrity:**
   - `npm run typecheck`: 0 errors.
   - `npm run build`: Production bundle built cleanly in < 1 second (`167.25 kB` JS, `51.92 kB` gzipped).

---

## 7. Test Results Summary

| Test Category | Suite File / Target | Tests Executed | Passed | Failed | Deselected |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Dedicated BOLA / IDOR Regression | `test_case_bola_security.py` | 47 | 47 | 0 | 0 |
| Case & Auth Unit Suite | `test_api_auth.py`, `test_case_api.py`, etc. | 106 | 106 | 0 | 0 |
| Investigation & Pipeline Integration | `test_investigation_api.py`, `test_investigation_pipeline.py` | 29 | 29 | 0 | 0 |
| Full Offline Test Suite | All offline suites (`-m "not postgres and not ollama"`) | 1,144 | 1,144 | 0 | 28 |
| Frontend Typecheck | `tsc --noEmit` | N/A (Build) | Pass (0 errors) | 0 | 0 |
| Frontend Production Build | `tsc && vite build` | N/A (Build) | Pass (0 errors) | 0 | 0 |

---

## 8. Milestone Governance & Next Steps

- **Milestone P3-H3B:** Remains **PARTIAL**. Dry-run preparation for all 19 scenarios is completely verified and deterministic. Live local Ollama capture remains strictly gated pending formal Project Owner authorization.
- **Milestone P3-H4:** Implementation of rate-limiting, security headers, secret-redaction guardrails, and cross-case BOLA/IDOR regression is complete and verified. Milestone progression remains formally gated per repository governance until end-to-end multi-service acceptance is authorized.
- **Next Unblocked Implementation Task:** Build the **Investigation Report Bundle Visualizer** in the frontend (`frontend/src/pages/CasesPage.tsx` / `frontend/src/components/ReportViewer.tsx`) to render structured JSON investigation summaries, timeline events, and recommended mitigation actions with zero XSS vulnerabilities.

