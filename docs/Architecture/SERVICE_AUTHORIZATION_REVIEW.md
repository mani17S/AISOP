# Service-Boundary Authorization Review

Date: 2026-11-12. Status: review IMPLEMENTED (code inspected); recommendation **PROPOSED, no authorization semantics were changed**. Question asked: should case authorization also be enforced inside `DomainEvidenceService` (and its sibling `MultiSourceInvestigationService`) rather than only at the router?

## 1. Current pattern (verified)
* Authorization is enforced in the router by dependencies: `require_case_role(...)` (`api/dependencies.py:193`: inactive analyst -> 403; no assignment -> **404** anti-enumeration; wrong case role -> 403) plus capability checks in the handler (`can_link_case_evidence`, `can_execute_case_synthesis`, `can_close_or_archive_case`) taken from `core/rbac.py`.
* Services receive `actor: AuthenticatedAnalyst` **for audit attribution only**. They check that the case exists and is not closed/archived (`CaseNotFound`, `CaseClosed`) but **do not verify that the actor is assigned to the case or holds a sufficient role**. This is true of `DomainEvidenceService._import_once`, `MultiSourceInvestigationService.start/get_section` and `CaseService.link_evidence_to_case`; only the list/get methods of `CaseService` join `CaseAssignmentModel` for anti-enumeration.
* `AuthenticatedCaseContext{case_id, analyst_id, case_role, assigned_at}` (`core/rbac.py:181`) already exists and is produced by the router dependency; it is simply not passed on.

## 2. Callers (grep over `backend/`, 2026-11-12)
| Service method | Production callers | Test callers |
|---|---|---|
| `DomainEvidenceService.import_records` | exactly one: `endpoints/cases.py:454` (`import_domain_evidence`), behind `require_case_role(INVESTIGATOR, LEAD)` and `can_link_case_evidence` | via HTTP in `test_domain_evidence_api.py`, `test_stage6_security.py`, `test_stage6a_hardening.py`, `test_domain_service_regression.py` (monkeypatches `_create`; no direct authorization-sensitive call) |
| `MultiSourceInvestigationService.start` | `endpoints/cases.py:486` (INVESTIGATOR, LEAD) | HTTP; `test_multisource_api.py:446` constructs the service directly (race/mutation test) |
| `MultiSourceInvestigationService.get_section` | `endpoints/cases.py:509` (VIEWER, INVESTIGATOR, LEAD) | HTTP |
No background job, CLI, script or second route calls them.

## 3. Risk assessment
* **Today: no exploitable gap.** Every call passes through the router dependencies; tests prove non-members get 404 and viewers 403 for import and investigation (`test_authorization_and_validation`, `test_new_sections_require_case_membership...`, `test_case_isolation_...`).
* **Latent risk:** a future caller (new route, worker, script, admin tool) that forgets the dependency gets cross-case read/write with the service's full privileges, because the service trusts its caller completely. This is a defence-in-depth gap, not a current vulnerability, and it applies equally to the Stage 4 service and the pre-existing `CaseService` write methods.

## 4. Options
| Option | Pros | Cons |
|---|---|---|
| A. Keep router-only (status quo) | no change | latent risk above |
| B. **Pass the already-verified `AuthenticatedCaseContext` into the service and assert it there** (pure function, no extra query) | cheap; catches a missing dependency and an id mismatch (`ctx.case_id != case_id`); identical conditions to the router so no behaviour change; unit-testable | a caller can still fabricate a context object (it is a plain model), so it defends against omission, not malice |
| C. Re-query `CaseAssignmentModel` inside each service | independent of the caller | extra query per call, duplicates the router logic, can disagree with it (race, different anti-enumeration rules), needs `Analyst` role data the service does not hold |
**Recommendation: B**, and use C only for a future caller that has no router context (a background job), through the existing `CaseService` assignment lookup.

## 5. Regression-safe migration (PROPOSED)
1. Add `core/rbac.py::assert_case_context(ctx, case_id, allowed_roles)` raising a service-level `NotAuthorized` (mapped to 404 for anti-enumeration, 403 for role) with fixed messages.
2. Phase 1: add an **optional** keyword `authorization: AuthenticatedCaseContext | None = None` to `import_records`, `start`, `get_section`. When provided it is enforced; when `None` the current behaviour is kept and a counter or log line records the unauthenticated call. Routers pass the `context` they already hold. Existing tests keep passing unchanged (`test_multisource_api.py:446` passes `None`).
3. Tests: mismatched `case_id`; viewer context on a write; wrong role; `None` still works in Phase 1; router tests unchanged; a test that fails if a router calls a service without passing the context (AST or call-site grep test).
4. Phase 2 (separate approval, after step 3 shows all callers pass it): make the argument required and update the direct-construction test.
Estimated effort 1 to 2 days (planning estimate). Not applied in this task.

## 6. Related observations
* **Existence oracle:** importing a record already stored for another case reports `duplicate: true` (documented, tested, accepted: the caller must already hold the full record).
* **Case row lock:** the import does not lock the case; two concurrent imports are safe because of SHA-256 idempotency and the retry-once path (SQLite-simulated; PostgreSQL race UNVERIFIED).
* **Audit actor:** the audit row records `actor.username` and `analyst_id` from the authenticated analyst; a service-level context check would additionally bind the audit to the verified role.
