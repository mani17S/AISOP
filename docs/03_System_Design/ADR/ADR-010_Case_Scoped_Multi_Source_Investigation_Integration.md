# ADR-010: Case-Scoped Multi-Source Investigation Integration (API, Persistence, Analyst UI)

| Field | Value |
|---|---|
| **ID** | ADR-010 |
| **Status** | PROPOSED (implemented 2026-11-12; offline-tested only; Project Owner approval pending) |
| **Date Proposed** | 2026-11-12 |
| **Decision Maker** | Project Owner |
| **Extends** | ADR-008 (sufficiency gate), ADR-009 (correlation, timeline, ATT&CK mapping), ADR-007 (adapters). Supersedes nothing. |

Labels: IMPLEMENTED (code and passing offline tests), PARTIAL, PROPOSED, BLOCKED, UNVERIFIED.

## 1. Context
After ADR-009 the multi-source engine existed as a library and a demo script. AISOP's application already provided case management with RBAC and anti-enumeration (`require_case_role`), ingestion of heterogeneous alerts with raw-evidence preservation and hash de-duplication (`POST /alerts/ingest`, `RawEvidence.raw_payload`, `sha256_hash`), case evidence links (`case_evidence`), an append-only audit table with database triggers (`case_audit_events`, migration 0004), and a React workspace with human-invoked AI synthesis. The engine was not reachable by an analyst.

## 2. Problem
Make the engine usable inside the product without (a) creating a parallel case or persistence system, (b) weakening case isolation, provenance or the audit semantics, (c) executing migrations or touching protected resources in this milestone, (d) making an LLM a prerequisite, and (e) hiding LIMITED/INSUFFICIENT verdicts from analysts.

## 3. Alternatives considered
| Option | Assessment |
|---|---|
| A. Persist results in a **new table** with a migration | Queryable and sized for large results, but needs a migration, which this milestone may not execute; deferred (PROPOSED; migration text not written because no schema change was necessary). |
| B. **Persist in the existing audit table** (`case_audit_events`, new action value, result in `details` JSON) | No migration, works on SQLite and PostgreSQL (JSON/JSONB variant already in the model), inherits append-only triggers and the "audit failure suppresses the result" rule. Limits: one row per run, size-capped, not queryable by section. **Chosen.** |
| C. Background job queue with polling | Matches "processing" semantics for long LLM runs but adds infrastructure (workers, broker). Deferred; the deterministic path is fast, so the request runs synchronously (PARTIAL: no server-side progress state). |
| D. Extend the existing `/investigations/synthesize` endpoints | They are LLM-centric and return a single validated output; the multi-source result has a different shape. Separate resource chosen, reusing the same dependencies, roles and audit conventions. |
| E. Re-run adapters from preserved raw payloads vs. trust stored normalized fields | Stored normalized rows are alert-shaped (`CanonicalAlert` dump) and lose Sysmon process GUIDs, logon sessions and DNS answers. **Re-normalizing the preserved raw payload** through the ADR-007 adapters was chosen; the stored SHA-256 is kept as provenance and the persisted normalized-event id is the correlated event id. |

## 4. Decision (IMPLEMENTED)
1. **Endpoints** on the existing case router (`backend/app/api/v1/endpoints/cases.py`): `POST /api/v1/cases/{case_id}/investigations/multisource` (start or reuse; 201 stored, 200 reused) and `GET .../multisource/{section}` with `section` in `status, timeline, correlation, attack, sufficiency, report`. Authorization reuses `require_case_role`: start needs investigator or lead; reads allow viewers; `use_llm=true` additionally needs `can_execute_case_synthesis`.
2. **Service** `backend/app/services/multisource_investigation_service.py` (`MultiSourceInvestigationService.start / get_section / build_payload / fingerprint`): reads only evidence linked to the case, re-normalizes preserved raw payloads, runs `run_workflow`, stores one audit row (`action = case_multisource_investigation`, `details` = result document), returns it.
3. **Idempotency** by fingerprint = SHA-256 of (sorted evidence ids with stored raw hashes, `use_llm`, workflow, mapping and rule versions). Same fingerprint and no `force` returns the stored result and writes nothing; `force` appends a new row. Reads report `stale_evidence` when the current fingerprint differs.
4. **Consistency**: the read transaction is ended before any LLM call; after the engine returns, evidence is re-read and a changed fingerprint aborts with 409 (no row written). A closed or archived case returns 409. An audit write failure returns a generic 500 and no result.
5. **LLM remains optional and gated**: default `use_llm=false`; the path is the unchanged `GatedGenerator` after `evaluate_sufficiency`; failures fall back to the deterministic report; claims pass the existing validator; LIMITED is disclosed in the report body and the final output's uncertainty list.
6. **No raw payloads in responses or storage**: the document holds titles, hashes (prefixes), entities in links, rule names and the report text; command lines are never included.
7. **Frontend**: a `Multi-Source Investigation` tab in the existing `InvestigationWorkspace` (`frontend/src/components/MultiSourcePanel.tsx`), human-initiated, with prominent verdict banners and grounding-labelled claims.

## 5. Rationale
Re-using ingestion, case links, RBAC and the audit table keeps provenance and isolation guarantees where they are already tested. Option B was the only persistence route compatible with "no migration executed" and with the SQLite test harness. Fingerprint idempotency prevents silent duplicate state without new constraints. Synchronous execution is honest about its limits instead of simulating a job system.

## 6. Consequences
Positive: analysts can run and read investigations through the application; results are tamper-evident through the audit triggers and ledger hash; deterministic path usable without a model; negative or ambiguous evidence is visible. Negative: audit-row storage is a stopgap (size cap 60 KB of report text per incident, 200 timeline rows, 100 links; one row per run; no section-level queries; large cases will truncate); the request blocks for the duration of an LLM call; the stored document duplicates data derivable from evidence; PostgreSQL behaviour of the JSON document is untested (UNVERIFIED).

## 7. Security implications
Case isolation is enforced twice: the router dependency (anti-enumeration 404) and the evidence query joined on `case_evidence.case_id`. Evidence content is untrusted data: adapters parse it, the engine never follows it, the gate never interprets it, and the model sees it only inside the existing escaped prompt format. Errors returned to callers are fixed strings. The API does not add authentication mechanisms; it inherits those of the application (UNVERIFIED beyond the tested role matrix: unauthenticated 401, unassigned 404, viewer 403 on start, role-gated `use_llm`). The audit row records the actor. Residual: an investigator can fill the audit table with `force` runs (rate limiting is the application's, not added here); stored result size is bounded but not quota-controlled.

## 7a. Evaluation of the claims
Only offline tests with SQLite and a scripted provider exist. No PostgreSQL validation, no real model run, no load test (UNVERIFIED).

## 8. Implementation status and references
IMPLEMENTED: `cases.py: start_multisource_investigation, get_multisource_investigation_section`; `schemas/multisource.py: MultiSourceInvestigationRequest, MultiSourceSection`; `services/multisource_investigation_service.py`; `modules/correlation/normalize.py: normalize_records(digests=, event_keys=)`; `modules/correlation/workflow.py: run_workflow(digests=, event_keys=)`; `frontend/src/components/MultiSourcePanel.tsx`, `services/api.ts: startMultiSourceInvestigation, getMultiSourceSection`; demo `backend/scripts/run_integrated_demo.py`. PARTIAL: persistence in the audit table; synchronous execution. PROPOSED: dedicated table and migration; background jobs; section-level queries. BLOCKED: PostgreSQL validation of the stored document (not authorized in this milestone).

## 8a. Stage 5 amendments (2026-11-12; ADR remains PROPOSED)
Measured and adversarial testing led to these changes within the decision (no change of the persistence choice):
* **Bounds:** at most 1,000 evidence rows per run (413 above; quadratic correlation measured at 2.5 s / 155 MB for 1,000 events in the worst shape); stored result capped at 25 incidents, 200 rejected records, 200 contradictions (with a `truncation` object disclosed to the analyst and in the UI); at most 5 model invocations per run.
* **Activity feed:** the case activity endpoint (all case roles) returns a bounded `summary_only` view for this action instead of the whole document (`activity_summary`); full detail only through the section endpoints.
* **Concurrency:** a per-case in-process lock serialises runs; concurrent identical requests store one result (single worker only; PostgreSQL advisory locking PROPOSED, not validated).
* **Persistence decision re-examined:** audit-row storage remains acceptable for the project demonstration (bounded, no migration, consistent audit semantics). A dedicated table is not justified by the measurements; reasons that would justify it: historical result browsing, section-level queries, results above the caps, multi-worker deployment. Details: `docs/05_Backend/Stage5_Reliability_Report.md`.
* PostgreSQL behaviour of the stored document remains UNVERIFIED; `test_postgres_multisource_persistence.py` is written and not run (`docs/11_Deployment/Stage5_PostgreSQL_Validation_Readiness.md`).

## 9. Relevant tests
`backend/tests/unit/test_multisource_api.py` (23 tests: authentication, anti-enumeration, viewer limits, validation, end-to-end ingestion to persisted report, provenance mapping, idempotency, stale evidence, case isolation, no-evidence abstention, unparseable evidence, duplicates, contradiction, noise, single alert, closed case, evidence race, audit failure, gated LLM, LLM failure, gate failure, role gating, fingerprint), `frontend/tests/multisource_panel.test.tsx` (9 tests), plus the Stage 3C-R suites for the engine.
Stage 5: `backend/tests/unit/test_stage5_adversarial.py` (89 tests: corroboration manipulation, parser limits, ledger, authorization and isolation, lifecycle, LLM hostile input), `backend/tests/integration/test_postgres_multisource_persistence.py` (3, not run).
