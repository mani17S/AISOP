# Stage 7A implementation report: evidence-time consistency, report parity, producer contracts, PostgreSQL readiness

Date: 2026-11-12. Scope: owner decisions D1 to D4 of `AISOP_Stage7A_Evidence_Parity_and_PostgreSQL_Readiness_Master_Prompt.md`. Prior reports are unchanged.

## Status by item
| Item | Status |
|---|---|
| A. Case synthesis keeps event time unknown, ingestion time separate | IMPLEMENTED (offline, SQLite); PostgreSQL persistence UNVERIFIED |
| A. Incident report discloses unknown event time | IMPLEMENTED |
| B. Parity projection and scenarios | IMPLEMENTED for 9 of 10 scenarios; clean-evidence scenario shows a real difference, PINNED not hidden; scenario 10 paired on the case path only |
| C. Producer contract and mapping inventory | IMPLEMENTED (documentation + 73 proving tests); no adapter code changed; legacy per-vendor time rejection UNVERIFIED beyond one fixture |
| D. PostgreSQL verification plan | IMPLEMENTED as a plan; execution NOT RUN (not authorized) |

## Code changes (all traced to D1 to D3)
| File | Change |
|---|---|
| `backend/app/modules/evidence_domains/model.py` | + `stored_event_time_unknown` (single predicate; placed here to avoid the known `bridge` circular import) |
| `backend/app/services/case_service.py` | import; Phase A skips undated stored events from `context_events` (entities still feed enrichment), adds `UNDATED_OBSERVATIONS` flag, deterministic disclosure appended to `uncertainty_and_data_gaps` before the output digest |
| `backend/app/modules/correlation/report.py` | Limitations line "Event time unknown ..." in the incident report |
| tests | `test_stage7a_undated_and_parity.py` (25), `test_stage7a_producer_contract.py` (73) |
| docs | `PRODUCER_FIELD_CONTRACT.md`, `EVIDENCE_TIME_SEMANTICS_AND_REPORT_PARITY.md`, `Stage7A_PostgreSQL_Verification_Plan.md`, this report, an appended section in `CASE_SERVICE_CONTRADICTION_INTEGRATION.md` |

Not touched: schema, migrations, dependencies, configuration, frontend, datasets, ground truth, existing tests.

## Verification (offline, Python 3.12.0, repository root)
| Command | Exit | Result |
|---|---|---|
| `pytest test_stage7a_undated_and_parity.py test_stage7a_producer_contract.py` | 0 | 98 passed |
| ADR-013 family + the two specification files | 0 | 105 passed, 0 expected-fail |
| case synthesis, domain evidence, multi-source API, domain-service regression | 0 | 70 passed |
| `pytest backend/tests/unit` | 0 | 1728 passed, 0 failed, 0 skipped, 0 expected-fail, 13 warnings (1630 + 98) |
| `pytest backend/tests/integration -m "not postgres and not ollama"` | 0 | 85 passed, 33 deselected |
| PostgreSQL / Ollama | not run | 33 collected only (`--collect-only`), 0 executed |
| `py_compile` of the 3 changed production modules | 0 | clean |
| Frontend | not run | no frontend file changed |
Mutation check: forcing `is_undated = False` in `case_service.py` makes 3 of the 25 tests fail (exclusion, verdict-invariance, parity disclosure); the file was restored and re-verified. Logs: `D:\AISOP\logs\stage7a\`.

## Remaining-risk register (additions)
| ID | Risk | Status |
|---|---|---|
| R1 | Clean domain evidence: incident SUFFICIENT vs case LIMITED (entities live only in payload) | OPEN, pinned by a test, owner decision needed |
| R2 | Time-window filters in case synthesis compare the column (ingestion time for undated records); exclusion from context prevents misuse | OPEN, low |
| R3 | Case-path "event time unknown" depends on the payload flag; rows created by other writers without it are treated as dated | OPEN, low (only the domain service writes `aisop_domain` rows) |
| R4 | `case_report_synthesized` not paired with the incident report | OPEN |
| R5 | `canonical_id` is case-folded; may conflate ids in a case-sensitive directory | OPEN, documented |
| R6 | Legacy naive timestamps are assumed UTC without disclosure | OPEN, documented |
| R7 | Per-vendor legacy rejection of invented times proven by one fixture only | OPEN |
| R8 | PostgreSQL behaviour of stored findings, audit size, import race, rollback, stale results | UNVERIFIED (plan ready) |
| R9 | Producers do not yet emit the optional linkage fields; no native vendor adapters | OPEN (contract section 5) |
| R10 | Incident path has no injectable model in the harness, so the unsupported-AI-claim scenario is not a paired run | OPEN, low |

## Protected actions
Not performed: PostgreSQL / Docker / database connection or command, migrations, Ollama, cloud calls, model downloads, dependency changes, reads of `.env`, `.refact`, `viva-credentials.txt`, `opencode.json`, credential or configuration changes, Git staging/commit/stash/reset/clean/rebase/branch/push. Only the presence (set/unset) of two environment variables was checked; values were not printed. Files written only under `D:\AISOP` and `D:\AISOP-Control`.

Git: branch `main`, HEAD `c4e877c`, 0 stashes. Status entries 323 -> 325 (two new untracked test files; the new docs fall under paths that were already untracked or modified). Snapshots: `D:\AISOP-Control\stage7a_git_before.txt` and `stage7a_git_after.txt`.

## Owner authorization request (PostgreSQL)
Nothing runs until you answer. To run the plan in `Stage7A_PostgreSQL_Verification_Plan.md` I need, in one message:
1. Option A (reuse `aisop_p4b_disposable` or `aisop_p2h3_disposable`) or Option B (create `aisop_stage7a_disposable`), and the exact name.
2. Permission to run read-only checks: `docker inspect/port aisop-postgres` and `psql` SELECTs of `pg_database` and `alembic_version` (no writes).
3. Permission to take a fresh logical backup of the cluster to `D:\AISOP-Backups` first (recommended).
4. Permission to set `TEST_DATABASE_URL` / `ALLOW_DESTRUCTIVE_POSTGRES_TESTS=1` for one pytest process against `127.0.0.1:5433` and the chosen name only, with the password supplied by you through a channel I do not read or print.
5. Permission to add `backend/tests/integration/test_postgres_stage7a_verification.py` (proposed tests 1 to 6; skipped when no target is configured).
Writes: rows in the chosen disposable database only, then all its ORM-table rows deleted after each test; no schema, role, extension or volume change under Option A. Excluded: the lifecycle (alembic downgrade) tests, the vector tests and the Ollama tests.
