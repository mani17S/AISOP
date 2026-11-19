# Stage 5 Reliability Report - Investigation Lifecycle, Persistence and Failure Handling

Date 2026-11-12. Offline evidence only (SQLite, scripted LLM). PostgreSQL behaviour is **UNVERIFIED/BLOCKED**; nothing here is a production-readiness claim. Tests: `backend/tests/unit/test_multisource_api.py` (Stage 4, 23) and `backend/tests/unit/test_stage5_adversarial.py` (Stage 5, 89). Code: `backend/app/services/multisource_investigation_service.py`, `backend/app/api/v1/endpoints/cases.py`, `backend/app/modules/correlation/workflow.py`.

## 1. Lifecycle and observed behaviour
| Situation | Behaviour | Test | Status |
|---|---|---|---|
| New investigation | 201; one `case_audit_events` row | end-to-end test | IMPLEMENTED |
| Identical repeat | 200, `reused: true`, nothing written | idempotency test, round-trip test | IMPLEMENTED |
| `force` | new row appended | idempotency test | IMPLEMENTED |
| Evidence changed since the run | reads show `stale_evidence`; next POST stores a new result | stale test | IMPLEMENTED |
| Evidence changes *during* the run | 409, result discarded, nothing written | race test | IMPLEMENTED |
| Closed/archived case | 409 | closed-case test | IMPLEMENTED |
| Empty case / only unparseable evidence | stored abstention (INSUFFICIENT), model never called | no-evidence, unparseable and invalid-timestamp tests | IMPLEMENTED |
| Missing / unassigned case | 404 identical for both | cross-case test | IMPLEMENTED |
| Invalid case id / section | 422 / 404, no 500 | invalid-input and hostile-section tests | IMPLEMENTED |
| Concurrent identical requests (4 at once) | exactly one stored; the others wait and reuse (one 201, three 200) | `test_d7_*` | IMPLEMENTED (one process only) |
| Engine crash or cancellation mid-run | nothing stored, lock released, retry succeeds | crash test | IMPLEMENTED |
| Provider failure / malformed model output | deterministic result plus `llm_status = fallback:<Type>` | Stage 4 + 8 malformed-output variants | IMPLEMENTED (scripted) |
| Gate failure | fail closed, no model call | Stage 4 test | IMPLEMENTED |
| Audit write failure | generic 500, no result returned or stored | Stage 4 test | IMPLEMENTED |
| Too much evidence (> 1,000 rows) | 413 before any work | `test_d8_*` | IMPLEMENTED |
| Many incidents / many rejected records | stored result capped, `truncation` object and UI notice | `test_d6_*`, panel test | IMPLEMENTED |
| Many incidents with `use_llm` | at most 5 model calls; rest `skipped:llm_incident_limit` | `test_d9_*` | IMPLEMENTED |

## 2. Is synchronous execution a meaningful reliability risk?
Deterministic path: no. Measured (Performance Report): about 3 ms for 10 events, 0.3 to 0.7 s for 500, 1.2 to 2.5 s for 1,000, bounded by the 1,000-event cap. LLM path: yes, but bounded: up to 5 sequential calls, each up to the provider timeout (`ollama` default 120 s, so about 10 minutes worst case) while the request, its database connection-free session and the per-case lock are held. A client or proxy timeout would drop the request; the run may still finish and store its result, and a retry then reuses it (idempotency). Conclusion: acceptable for a single-node demonstration; **no background job system is justified by these measurements** and none was added. If the LLM path is used routinely, a job record plus polling is the next step (PROPOSED, not designed).

## 3. Persistence in `case_audit_events` (ADR-010 option B)
| Aspect | Finding |
|---|---|
| Payload size | before Stage 5 unbounded (100 incidents = 2.3 MB measured). Now at most 25 incidents, 200 rejected, 200 contradictions, 200 timeline rows and 100 links per incident, 60,000 report characters per incident: bounded at roughly 1 to 2 MB worst case; typical 20 to 190 KB. |
| JSON serialization | `json.loads(json.dumps(payload, default=str))` normalises to JSON types before write; round-trip equality test (SQLite). PostgreSQL JSONB round-trip test written, **not run** (`test_postgres_multisource_persistence.py`). |
| Read/write consistency | read transaction ended before the engine runs; fingerprint re-checked before the write; single commit. |
| Idempotency | evidence fingerprint (+ options + engine/rule versions); changing `suff-v3`/mapping version legitimately invalidates reuse. |
| Audit semantics | one append-only row per run; append-only triggers (migration 0004) not exercised on this action in Stage 5 (test written, not run). A write failure suppresses the result. |
| Query cost | `_latest` filters `case_id` + `action`, orders by `created_at`; each column has a single-column index only. Fine for a case with tens of runs; a composite index would be a schema change (PROPOSED). Each section GET re-reads the stored document and the case's evidence rows to compute `stale_evidence`; the UI issues 6 GETs on load (about 6x the read cost; acceptable at the 1,000-event cap, a single combined read would be cheaper: PROPOSED). |
| Case isolation | audit rows are filtered by `case_id`; evidence by `case_evidence.case_id`. |
| Compatibility with audit reporting | the activity feed previously returned the full result to every case member for every run. Fixed (D6): feed rows for this action carry `summary_only` with verdicts, counts and ledger head; full detail only via the section endpoints. |
| Historical retrieval | only the latest row is served; older rows remain in the audit table but have no endpoint (PARTIAL). |

**Is the current design acceptable for the project demonstration?** Yes: bounded size, no migration, consistent audit semantics, tested. It is not a general results store. **A dedicated `investigation_results` table is not justified by the measurements taken**: the size is now bounded, the access pattern is "latest per case", and a migration could not be validated here (no PostgreSQL run is authorized). Reasons that would change this: historical result browsing, section-level queries, results above the caps, or multi-worker deployment. ADR-010 option A remains PROPOSED; no new ADR was needed and no migration was written.

## 4. SQLite and PostgreSQL
Offline suite: SQLite only. PostgreSQL-specific assumptions to be checked (see the readiness document): JSONB equality/round trip of the document (nested arrays, unicode, 0.5 MB), append-only trigger on update/delete of the new rows, `created_at` ordering with timezone-aware values, transaction behaviour of `rollback()` before inference (SQLite adapter is synchronous, PostgreSQL is a real async connection), multi-session concurrency (the in-process lock does not span workers; two workers could both store a result for the same fingerprint, which is harmless duplication, not corruption). **No PostgreSQL validation is claimed.**

## 5. Residual reliability risks
Single-process lock (R5); latest-only retrieval; request blocking during LLM runs; 6 GETs per UI load; no retry logic in the client; the stored document duplicates derivable data and ages with engine versions (reads show the stored versions; staleness only reflects evidence, not engine upgrades).
