# Stage 7A PostgreSQL verification plan (READINESS ONLY, NOT EXECUTED)

Date: 2026-11-12. **No PostgreSQL, Docker or database operation was performed to produce this plan.** Nothing here is authorization. Every
"VERIFIED" below is from repository files, compose metadata and the 2026-11-11 reports on D:; every statement about the live server's
current state is **UNVERIFIED** until a separately authorized run.

## 1. Target identity (from safe metadata)

| Item | Value | Source | State |
|---|---|---|---|
| Service / container | `aisop-postgres` | `docker-compose.yml` | VERIFIED in file; running state UNVERIFIED today |
| Image | `pgvector/pgvector:pg17` | same | VERIFIED in file |
| Host port -> container | `5433 -> 5432` (host 5432 is the native Windows PostgreSQL 17, "untouched") | same | VERIFIED in file |
| Volume | `aisop_postgres_data` (named, driver local) | same | VERIFIED in file |
| Databases seen on 2026-11-11 | `aisop_dev`, `aisop_integration_sandbox`, `aisop_p2h3_disposable`, `aisop_p4b_disposable`, `aisop_test`, `postgres` | Stage 3B preflight report (D:\AISOP-Backups) | historical; UNVERIFIED today |
| Environment | `TEST_DATABASE_URL` unset, `ALLOW_DESTRUCTIVE_POSTGRES_TESTS` unset in the shell used for this milestone (presence checked, values never printed) | shell | VERIFIED: **no target is configured** |
| Alembic head in repo | `0004_p3h2_rbac_case_scoping` (0001 -> 0002 -> 0003 -> 0004) | `backend/app/db/migrations/versions` | VERIFIED |
| Migrations needed by ADR-013 / Stage 7A | **none** (findings live in `case_audit_events.details` JSONB; no model change) | git status + code | VERIFIED by inspection |

## 2. Is the target disposable? Findings that decide the answer

1. The guard (`conftest.validate_test_database_target`) accepts only: scheme in {postgresql, +psycopg, +asyncpg}; host in {localhost, 127.0.0.1, ::1}; database name matching `^aisop_[a-z0-9_]+_disposable$`; not in the protected set {aisop, aisop_test, aisop_dev, aisop_prod, postgres}; `ALLOW_DESTRUCTIVE_POSTGRES_TESTS=1`. It does **not** check the port; `test_postgres_case_scoping.py` additionally requires port 5433 for itself only. **The run must be launched with the port pre-checked to 5433**, as the 2026-11-11 launcher did.
2. **The `postgres_session` fixture deletes ALL rows from EVERY ORM table of the target after EACH test** (`case_audit_events` with `DISABLE TRIGGER ALL`). The target must therefore hold nothing that is needed.
3. `postgres_sync_engine` calls `ensure_test_database_exists`, which connects to the `postgres` database and **runs `CREATE DATABASE` if the target is missing**. Using a name that already exists avoids that.
4. `postgres_engine` does **not** create the schema; the target must already be at head (0004). `test_postgres_lifecycle.py` runs `alembic downgrade base` then `upgrade head` and **must be excluded** from this plan.
5. The shared development database `aisop_dev` and `aisop_test` are protected names and cannot be targeted by these tests (guard, tested offline).

Conclusion: a disposable target IS available in principle without altering any non-disposable database, in two ways:
* **Option A (preferred): reuse an existing disposable database** (`aisop_p4b_disposable` or `aisop_p2h3_disposable`, both listed 2026-11-11 and covered by the 2026-11-11 18:13 dumps). No `CREATE DATABASE`. Requires first confirming (read-only query) that it exists and is at `0004`.
* **Option B: create `aisop_stage7a_disposable`.** Changes the cluster (a new database in the persistent volume), makes the 2026-11-11 dumps incomplete for the cluster, and removing it later needs `DROP DATABASE` and a further approval.

Blockers: none that forbid a run; the owner must choose the option and authorize it. The live state of the container, of each candidate database and of its revision is UNVERIFIED.

## 3. Tests (existing and proposed)

"Proposed" tests are NOT written yet; writing them is part of the authorized run milestone. Every test is `@pytest.mark.postgres`.

| # | Purpose / security property | Existing test | Proposed test (location: `backend/tests/integration/test_postgres_stage7a_verification.py`, new file) | Writes | Schema change |
|---|---|---|---|---|---|
| 1 | Typed contradiction findings (`kind`, `materiality`, `independence`, `explanation`, `relation`) survive JSONB round trip; no payload text stored | `test_postgres_multisource_persistence.py::test_multisource_result_round_trips_through_jsonb_and_summary_is_computable` (uses a chain with **no** contradictions, so findings are NOT covered) | `test_contradiction_findings_round_trip_jsonb`: analyze an ADR-013 fixture, store, read back, equality + `activity_summary` | rows in cases, analysts, case_audit_events | none |
| 2 | Audit-row size / serialization boundary | `...::test_large_multisource_result_is_stored_and_read_back_intact` (~560 KB) | `test_audit_row_with_maximum_findings_and_unicode`: findings at the stored caps + multi-byte text | one audit row | none |
| 3 | Unique-hash deduplication race under concurrent import (`raw_evidence.sha256_hash` UNIQUE; `_LostRace` rollback-and-retry-once) | none on PostgreSQL | `test_concurrent_import_of_same_record_yields_one_raw_row`: two connections import the same record simultaneously; assert exactly one `raw_evidence` row, both calls succeed idempotently or the loser retries once, no 5xx | raw_evidence, normalized_events, case_evidence | none |
| 4 | Case/incident transaction integrity and rollback | `test_postgres_case_scoping.py::test_stage_b3_evidence_linkage`, `::test_pol_02_cancellation_and_error_connection_return` | `test_failed_import_rolls_back_all_rows`: force a failure after the raw insert, assert zero orphan rows | transient, rolled back | none |
| 5 | Case isolation and evidence ownership | `test_postgres_case_scoping.py::test_inv_01_duplicate_active_lead_rejected`, `::test_e2e_01_case_synthesis_and_report_trust_boundary`, `::test_e2e_02_postgres_activity_endpoint_anti_enumeration_and_rbac` | `test_contradiction_in_one_case_not_visible_in_another` (PG twin of the SQLite test) | rows | none |
| 6 | Sufficiency-v4 persistence; stale result behaviour | `test_postgres_sufficiency_audit.py::test_abstention_audit_details_round_trip_jsonb_and_are_immutable` (abstention only) | `test_suff_v4_audit_details_round_trip_and_append_only`; stale: assert a synthesis whose evidence changed during inference is discarded with 409 (PG twin of the SEC-D24 SQLite tests) | audit rows | none |
| 7 | Vector / schema compatibility | `test_postgres_vector_retrieval.py` (5 tests) | **Not required**: the Stage 7A persistence path does not use vector retrieval (`knowledge_retriever=None` path). The two `ollama` tests (`test_stage_b4`, `test_stage_b5`) are excluded | n/a | none |

Cleanup for every test: the `postgres_session` teardown deletes all rows of all ORM tables of the target (see section 2, point 2). No test drops
a database, role, schema, extension or volume. Failure handling: stop on the first failure, record the output, do not retry automatically, do not alter the schema.

## 4. Exact commands, to run ONLY after explicit authorization (PowerShell, from `D:\AISOP`)

Pre-checks (read-only, no write):
```
# 1. Docker container and port (read-only)
docker inspect aisop-postgres --format "{{.State.Status}} {{.State.Health.Status}}"
docker port aisop-postgres
# 2. Database list and revision of the chosen target (read-only; credentials come from the owner's secured source, never echoed)
psql ... -c "SELECT datname FROM pg_database ORDER BY 1"
psql ... -d aisop_p4b_disposable -c "SELECT version_num FROM alembic_version"      # expect 0004_p3h2_rbac_case_scoping
```
Run (target name is the owner's choice; URL password supplied by the owner, not by this plan):
```
$env:TEST_DATABASE_URL = "postgresql+psycopg://<user>:<password>@127.0.0.1:5433/aisop_p4b_disposable"
$env:ALLOW_DESTRUCTIVE_POSTGRES_TESTS = "1"
.venv\Scripts\python.exe -m pytest -p no:cacheprovider -m "postgres and not ollama" -q `
  backend/tests/integration/test_postgres_multisource_persistence.py `
  backend/tests/integration/test_postgres_sufficiency_audit.py `
  backend/tests/integration/test_postgres_case_scoping.py `
  backend/tests/integration/test_postgres_stage7a_verification.py
Remove-Item Env:TEST_DATABASE_URL, Env:ALLOW_DESTRUCTIVE_POSTGRES_TESTS
```
Deliberately NOT included: `test_postgres_lifecycle.py` (alembic downgrade to base), `test_postgres_vector_retrieval.py` (not needed), the `ollama` tests.

## 5. Expected writes, backup and restore implications, risk

| Topic | Statement |
|---|---|
| Data touched | only the chosen disposable database inside container `aisop-postgres` / volume `aisop_postgres_data`; rows in `analysts`, `cases`, `case_assignments`, `raw_evidence`, `normalized_events`, `case_evidence`, `case_audit_events` and related tables; all rows of every ORM table in that database are deleted after each test |
| Schema / roles / extensions | no change (Option A). Option B adds one database |
| Backup | latest logical backup: `D:\AISOP-Backups\AISOP_PostgreSQL_Backup_2026-11-11_181339` (cluster dump + per-database dumps; 7 of 7 SHA-256 matched on 2026-11-11 per its report). A restore rehearsal was run 2026-11-11 (`AISOP_Stage3B3_Restore_Run_2026-11-11`); its content was not re-read here. Recommended: take a fresh backup before the run (a write to D: only) because the database state after 2026-11-11 is unknown |
| Restore | the disposable database can be restored from its dump or recreated; non-disposable databases are not touched |
| Risks | (1) env var set to a wrong URL: the guard refuses protected names, non-local hosts and non-disposable names; port is NOT checked by the baseline guard, so the launcher must verify 5433; (2) the all-rows teardown destroys any data a previously used disposable database still holds (acceptable by contract, but it is a loss of the 2026-11-11 test data unless backed up); (3) a failure mid-run leaves test rows until the next teardown; (4) the concurrent-import test needs two real connections and may be timing sensitive |
| Not covered even after this run | browser/UI behaviour, real-model behaviour, performance, and anything on the non-disposable databases |

## 6. Authorization request

See the final section of the Stage 7A implementation report: it states exactly what would be run and touched. Absent an explicit "yes" with the chosen option (A or B) and the target name, nothing here is executed.
