# Stage 7B PostgreSQL verification plan (REVISED, READINESS ONLY, NOT EXECUTED)

Date: 2026-11-12. Supersedes the target and cleanup sections of `Stage7A_PostgreSQL_Verification_Plan.md` (kept unchanged as history).
No PostgreSQL, Docker or database operation was performed. Nothing here is authorization. Statements about the live server are UNVERIFIED.

## 1. Hazards found in the PostgreSQL test code, and what changed (test code only)

| # | Hazard (before) | Location | Remediation (now) | Offline proof |
|---|---|---|---|---|
| 1 | `postgres_session` teardown deleted ALL rows of EVERY table after EVERY test, and ran `ALTER TABLE case_audit_events DISABLE TRIGGER ALL` (DDL) | `conftest.py` | `OwnedRowTracker`: deletes only rows that session inserted, by primary key, one transaction per row; never touches `case_audit_events`; no trigger change, no DDL | `test_owned_row_cleanup_deletes_only_rows_the_session_inserted` (SQLite), source scan |
| 2 | `ensure_test_database_exists` ran `CREATE DATABASE` when the target was missing | `conftest.py` | verifies only (SELECTs): database must exist, carry the disposable marker comment, and be at the single head `0004_p3h2_rbac_case_scoping`; a missing database is an error | `test_ensure_test_database_exists_never_creates`, forbidden-statement scan |
| 3 | `alembic downgrade base` then re-upgrade against the target | `test_postgres_lifecycle.py` | unconditional `@pytest.mark.skip` (needs a separately created ephemeral cluster, a future authorization) | `test_the_alembic_downgrade_lifecycle_test_is_skipped_unconditionally` |
| 4 | Port not checked by the baseline guard | `conftest.py` | `verify_approved_target_identity`: host exactly `127.0.0.1`, port exactly `5433`, database exactly the approved name; applied in `get_test_postgres_url` and in the case-scoping fixture | `test_wrong_host_port_or_database_fails_closed` |
| 5 | No container / volume / disposable-marker identity | n/a | launcher-exported `AISOP_PG_VERIFIED_CONTAINER`, `_IMAGE`, `_VOLUME`, `AISOP_PG_DISPOSABLE_MARKER` must be present and equal to the approved values; DB-side marker comment re-checked | `test_each_identity_variable_is_required_and_must_match` |
| 6 | Several disposable names accepted (`aisop_*_disposable`) | `conftest.py` | exactly one approved name; the old targets (`aisop_p2h3_disposable`, `aisop_p4b_disposable`) are refused | `test_returns_unredacted_url...` (updated) |

Unchanged and acceptable: `test_postgres_case_scoping.py` already used rollback sessions and never deleted committed rows; its `TRUNCATE TABLE` is a single attempt inside a rolled-back savepoint that the append-only trigger must block (asserted by a scan test). `test_postgres_vector_retrieval.py` uses `postgres_session` (now owned-row cleanup). Not verifiable offline: the real PostgreSQL behaviour of the tracker (FK blocks leave rows in place by design).

Residual honesty: rows written through paths other than the test's own session (for example service code on another connection) are not tracked and remain; all carry fresh UUIDs inside the dedicated database. Audit rows are never removed (append-only), so their parent case/analyst rows also remain.

## 2. The ONE proposed target (metadata from `docker-compose.yml`; live state UNVERIFIED)

| Item | Exact value |
|---|---|
| Container | `aisop-postgres` |
| Image | `pgvector/pgvector:pg17` |
| Host and port | `127.0.0.1:5433` (container 5432). Host 5432 is the native Windows PostgreSQL and is refused |
| Volume | `aisop_postgres_data` (driver local) |
| Database | `aisop_stage7b_verify_disposable` (new, unique; matches `^aisop_[a-z0-9_]+_disposable$`; not a protected name; does not exist in the 2026-11-11 inventory) |
| Disposable marker | database comment `aisop-disposable-test-target:aisop_stage7b_verify_disposable` |
| Required schema | Alembic single head `0004_p3h2_rbac_case_scoping` (no new migration exists for ADR-013 or Stage 7A/7B) |
| Environment | `TEST_DATABASE_URL`, `ALLOW_DESTRUCTIVE_POSTGRES_TESTS=1`, `AISOP_PG_VERIFIED_CONTAINER=aisop-postgres`, `AISOP_PG_VERIFIED_IMAGE=pgvector/pgvector:pg17`, `AISOP_PG_VERIFIED_VOLUME=aisop_postgres_data`, `AISOP_PG_DISPOSABLE_MARKER=<marker above>`; process-scoped, removed afterwards; the password is supplied by the owner and never printed |
| Never touched | `aisop_dev`, `aisop_test`, `aisop_integration_sandbox`, `aisop_p2h3_disposable`, `aisop_p4b_disposable`, `postgres`, any role, the native Windows service, the volume's other contents |

## 3. One-time setup (each step needs explicit approval; performed by the owner-approved launcher, NOT by the tests)

| Step | Action | Effect |
|---|---|---|
| S0 | read-only: `docker inspect aisop-postgres` (state, image, port map, mounts); `SELECT datname FROM pg_database` | none; confirms the container is healthy, volume name, and that the target does not exist |
| S1 | `CREATE DATABASE aisop_stage7b_verify_disposable` | the only cluster-level change: one new database in the volume |
| S2 | `COMMENT ON DATABASE aisop_stage7b_verify_disposable IS 'aisop-disposable-test-target:aisop_stage7b_verify_disposable'` | the disposable marker |
| S3 | `alembic upgrade head` against that database only (0001 -> 0004; revision 0002 enables the `vector` extension inside it) | schema and extension inside the new database only |
| S4 | read-only post-check: revision equals `0004_p3h2_rbac_case_scoping`, tables listed, other databases' table lists unchanged | none |

## 4. Tests and exact command (run only after authorization)

Scope (proposed tests are NOT written yet; they are written inside the authorized run milestone, with the same guard):
| # | Test | Status |
|---|---|---|
| 1 | contradiction findings round trip (typed fields, no payload text) | proposed new in `test_postgres_stage7b_verification.py` |
| 2 | audit row size with maximum findings and multi-byte text | proposed new; existing 560 KB test also runs |
| 3 | concurrent import of one record yields one `raw_evidence` row (UNIQUE sha256, rollback-and-retry-once) | proposed new |
| 4 | failed import rolls back every row | proposed new |
| 5 | case isolation of findings | existing case-scoping tests + proposed twin |
| 6 | suff-v4 audit details round trip and append-only; stale-evidence 409 | existing abstention test + proposed new |
| 7 | vector / ollama tests | EXCLUDED (not needed) |
| - | `test_postgres_lifecycle.py` downgrade | SKIPPED unconditionally; the upgrade test is a no-op at head |

Command (PowerShell, from `D:\AISOP`, after the launcher has exported the verified identity):
```
.venv\Scripts\python.exe -m pytest -p no:cacheprovider -m "postgres and not ollama" -q `
  backend/tests/integration/test_postgres_multisource_persistence.py `
  backend/tests/integration/test_postgres_sufficiency_audit.py `
  backend/tests/integration/test_postgres_case_scoping.py
```
(plus `test_postgres_stage7b_verification.py` once written and reviewed).

## 5. Expected writes, cleanup, backup, rollback

| Topic | Statement |
|---|---|
| Writes | rows in `analysts`, `cases`, `case_assignments`, `raw_evidence`, `normalized_events`, `case_evidence`, `case_audit_events` of the new database only; unique UUIDs |
| Cleanup | per test, only rows that test's session inserted (by primary key). Audit rows and their referenced parents remain by design. No truncate, no broad delete, no DDL |
| Backup | none created in this milestone. Recommended before S1: fresh `pg_dumpall` plus per-database dumps to `D:\AISOP-Backups` (the latest is 2026-11-11 18:13; a restore rehearsal was run that day, not re-read here) |
| Restore | non-disposable databases are never written, so no restore is expected; if the cluster is damaged, restore from the dump set |
| Rollback | the new database can be dropped (`DROP DATABASE aisop_stage7b_verify_disposable`) only with a separate explicit approval |
| Failure handling | stop at the first failure, keep the output, no automatic retry, no schema change, report the exact state |
| Fail-closed behaviours | wrong host/port/db, missing or mismatching identity variable, missing database, missing marker, wrong or missing Alembic revision: the run aborts before any write |
| Confirmation | no production, development or shared database is touched; the guard refuses every other name |

## 6. Not covered even after the run
UI/browser behaviour, real-model behaviour, performance, the destructive migration lifecycle (needs a separate ephemeral cluster).

---
## Stage 7C update (2026-11-12)
The six proposed tests now exist in `backend/tests/integration/test_postgres_stage7b_verification.py` (NOT executed). The guard and `OwnedRowTracker` were reviewed and hardened (dependency-ordered cleanup, reported leftovers). The backup plan, the S0 to S4 sequence with an explicit-file test command (the bare marker expression would also select lifecycle and vector tests), and the residual risks are in `Stage7C_PostgreSQL_Test_Review_Report.md`. Still nothing has been run.
