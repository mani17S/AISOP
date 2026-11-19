# Stage 5 PostgreSQL Validation Readiness (prepared, NOT executed)

Date 2026-11-12. Status: **BLOCKED** pending separate owner authorization. Nothing in this stage created a database, ran a migration, touched a role, ran the launcher or connected to PostgreSQL. SQLite results do not validate PostgreSQL behaviour.

## 1. Inspection of the prepared launcher
`D:\AISOP-Backups\AISOP_Stage3C_Run_2026-11-11\pg_validation\Run-AISOP-Stage3C-PostgresTests.ps1` (392 lines, unchanged, never run) was read. Findings:
* Target is hard-coded: `127.0.0.1:5433`, database `aisop_stage3c_disposable`, role `aisop`; refuses other ports and a list of protected database names (`aisop_dev`, `aisop_test`, `aisop_stage3_disposable`, `postgres`, `aisop`, `aisop_prod`, ...).
* Requires the source container to be running/healthy with the approved id, start time, mounts and host port 5433; otherwise stops.
* Password from a hidden prompt, or from the `DATABASE_URL` line of `.env` with `-PasswordFromEnvFile` (read in memory only; refuses an unexpected role/port).
* Pre-verifies that the target database is **absent** and pgvector available; the unmodified test harness (`conftest.ensure_test_database_exists`) then creates the database; tests run with `TEST_DATABASE_URL` and `ALLOW_DESTRUCTIVE_POSTGRES_TESTS` set in process scope only; the launcher never issues DROP and retains the database.
* Groups, in order, stop on first failure: lifecycle (7), vector_retrieval (5), sufficiency_audit (1), case_scoping (13); marker `postgres and not ollama`; expected Alembic revision `0004_p3h2_rbac_case_scoping`.
**Mismatch with the current code:** it does not include the Stage 4/5 persistence tests, and its report folder is the Stage 3C folder (it would refuse to overwrite files but mixes outputs).

## 2. Updated plan and prepared artefacts
* New test module `backend/tests/integration/test_postgres_multisource_persistence.py` (3 tests, `postgres` marker, collected but deselected offline): JSONB round trip of a full multisource-v1 document with unicode; a ~560 KB result; append-only trigger blocks UPDATE and DELETE of the new action's row. Written, **not run**.
* Updated launcher copy `D:\AISOP-Backups\AISOP_Stage5_Validation_2026-11-12\Run-AISOP-Stage5-PostgresTests.NOT_RUN.ps1` (+ `pg_validation\stage3c_db_check.py` helper copy): adds group `multisource_persistence` (expected 3), writes to the Stage 5 `pg_validation` folder. Not executed; the `.NOT_RUN` suffix must be removed by the owner when authorizing.

## 3. Required state and permissions
| Item | Requirement |
|---|---|
| Server | the existing Docker PostgreSQL 17 + pgvector container on host port 5433 (container id/start time as in the launcher baseline; if the container has been recreated the launcher stops and needs renewed approval) |
| Database | `aisop_stage3c_disposable` must not exist beforehand; created by the harness; retained afterwards |
| Role | `aisop` with CREATEDB (the harness issues `CREATE DATABASE`); no role changes needed or allowed |
| Migrations | applied by the existing harness to the disposable database only, expected head `0004_p3h2_rbac_case_scoping`; no new migration was written in Stage 4 or 5 (no schema change) |
| Data safety | the harness' cleanup deletes rows only in the disposable database after protected-name and opt-in checks; the live databases (`aisop`, `aisop_dev`, ...) are never targeted; the launcher compares container state before and after |
| Extensions | pgvector already available (pre-verified) |

## 4. Execution order and expected groups
1. lifecycle (7 tests) - schema/migration lifecycle. 2. vector_retrieval (5). 3. sufficiency_audit (1) - JSONB round trip and append-only trigger for the abstention row; checks `suff-v3` fixtures are not asserted (unit-level change only). 4. **multisource_persistence (3, new)**. 5. case_scoping (13). Total expected 29 passes; a group is VERIFIED only with exit 0, a final pytest summary, at least one pass and no failures, errors or skips. PostgreSQL status for Stage 3C-R and Stage 4 persistence remains UNVERIFIED until all five groups are verified.

## 5. What PostgreSQL validation would and would not establish
Would: JSONB fidelity for the stored result, trigger behaviour on the new action, ordering/timezone semantics used by `_latest`, the existing case-scoping tests against the current code. Would not: multi-worker locking (not implemented), performance on PostgreSQL (not measured), any LLM behaviour, accuracy of the sufficiency gate.

## 6. Exact owner authorization needed (one message)
"Authorize running `Run-AISOP-Stage5-PostgresTests.ps1` (after removing `.NOT_RUN`) against `127.0.0.1:5433`, creating the disposable database `aisop_stage3c_disposable`, applying the existing migrations to it only, running the five listed groups, retaining the database afterwards; password supplied through the hidden prompt (or `-PasswordFromEnvFile`)." Separately: authorize or decline cleanup of the disposable database afterwards.
