# Stage 7C-1 PostgreSQL test review report (preparation only; NOTHING WAS EXECUTED)

Date: 2026-11-12. Scope: owner decisions D1 to D4 of `AISOP_Stage7C_PostgreSQL_Test_Review_Master_Prompt.md`. No Docker, SQL, backup, migration, database creation or PostgreSQL test was run; Docker and PostgreSQL runtime state was not inspected. Every target value below is **proposed metadata copied from the Stage 7B plan and is NOT verified**.

## 1. Proposed PostgreSQL tests (path: `backend/tests/integration/test_postgres_stage7b_verification.py`, the repository convention)
All six carry `@pytest.mark.postgres` and are excluded by the default `-m "not postgres and not ollama"`. Each scenario body is a coroutine over a session-like object; the SAME bodies run offline on SQLite (`tests/unit/test_stage7c_postgres_scenarios.py`) so the assertions are proven correct, not just syntactically valid. Only the PostgreSQL-specific parts (marked `pg=True`, plus S3) are UNVERIFIED.

| # | Test | Assertions (explicit stored values / transaction semantics) | Offline status |
|---|---|---|---|
| S1 | `test_s1_contradiction_findings_round_trip_with_typed_fields` | stored `details` equals the submitted payload; finding has `kind=outcome`, materiality, independence, `affects_verdict` bool, `overlap_seconds` number, two evidence ids and two times; no user name, IP or run id inside any finding; `activity_summary` computable; rule version `suff-v4` | body PASSES on SQLite |
| S2 | `test_s2_audit_row_size_and_serialization_boundary` | payload above 1,000,000 UTF-8 bytes with multi-byte text round-trips byte for byte; PostgreSQL only: `octet_length(details::text)` between 1 MB and 50 MB | body PASSES on SQLite; `octet_length` part UNVERIFIED |
| S3 | `test_s3_concurrent_import_of_one_record_yields_one_raw_row` | two independent connections, one record, one case; an `asyncio.Barrier(2)` inside `_create` (after both existence checks, before either insert; 30 s timeout, no sleeps) forces both to insert; both calls return; duplicates are `[0, 1]`; same evidence id; exactly 1 `raw_evidence`, 1 `normalized_events`, 1 `case_evidence` row | PostgreSQL only; static checks only (barrier present, no sleep, marked) |
| S4 | `test_s4_failed_import_rolls_back_every_row` | a failure injected after the raw and normalized rows are flushed raises `PersistenceFailed`; a second, independent connection sees 0 `raw_evidence`, 0 `case_evidence`, 0 import audit rows; the same record then imports normally (not poisoned) | body PASSES on SQLite (same session); cross-connection visibility UNVERIFIED |
| S5 | `test_s5_case_isolation_and_evidence_ownership` | two cases; B shares one record with A: stored once, linked per case (`duplicates == 1` in B); each case's links equal exactly its own ids; A has `CONTRADICTORY_EVIDENCE:outcome`, B has none; each result's evidence ids belong to its own case; fingerprints differ | body PASSES on SQLite |
| S6 | `test_s6_sufficiency_v4_persistence_and_stale_result` | first run creates and stores a `suff-v4` LIMITED result with the outcome code; stored equals returned; second run is reused (not created) with the same fingerprint; section not stale; after new evidence the section reports `stale_evidence=True`; a new run appends a second record; the first record is unchanged; PostgreSQL only: an UPDATE of the old audit row is blocked by the append-only trigger | body PASSES on SQLite; trigger part UNVERIFIED |

Not included, as required: downgrade/lifecycle, vector, Ollama, database creation or deletion, truncate / broad delete, unrelated data.
Row ownership: each run has a fresh `run` id embedded in usernames, case numbers AND record bodies (digests unique per run). Cleanup is by the session's `OwnedRowTracker` only; audit rows and their RESTRICT-referenced case/analyst parents remain by design and are reported as a warning, never removed by a wider delete. A failed test does not change this.

## 2. Guard review (static; fake-metadata tests, no connection)
Checked and tested (`test_stage7b_postgres_guard.py` 20, `test_stage7c_guard_and_tracker_review.py` 24):
| Requirement | Where | Result |
|---|---|---|
| URL only from the process environment (`TEST_DATABASE_URL`), no other source | `conftest.py`; scan test over all PostgreSQL test files | PASS: no other env name or literal server URL |
| host exactly `127.0.0.1`, port exactly `5433`, database exactly `aisop_stage7b_verify_disposable` | `verify_approved_target_identity` | PASS (a missing port, `localhost`, 5432, other databases refused) |
| container, image, volume, marker env present and equal | same | PASS, fail-closed per variable, values never echoed |
| database comment equals the exact marker; Alembic single head `0004_p3h2_rbac_case_scoping` | `assert_target_is_marked_disposable` (SELECT-only; fake-psycopg tests record the SQL) | PASS in the fake; real behaviour UNVERIFIED |
| no fallback target | every engine fixture (`postgres_sync_engine`, `postgres_engine`, `postgres_alembic_config`, case-scoping engine) builds from the guarded URL | PASS (static) |
| guard does not create/modify | SQL literals are SELECT only; it connects to the target, never to `postgres`; missing database is an error | PASS |
| URL/password never printed | error messages carry variable names or exception TYPE only | PASS (SECRETPW test) |
| not reliant on the `_disposable` suffix | exact-name equality plus marker plus identity | PASS |

Documented limit (as the owner stated): the container, image and volume values are **environment assertions, not proof of runtime identity**. They are only as trustworthy as the launcher; S0 must verify them independently with Docker metadata before anything else.

## 3. OwnedRowTracker review
Defects found and fixed in this milestone: (1) cleanup order depended only on insertion order, now FK dependency order of the metadata first (child tables before parents), then reverse insertion; (2) leftovers were silently ignored, now counted, named (table and reason only, no values) and surfaced as a warning by the fixture; (3) append-only retention was indistinguishable from a problem, now reported separately (`retained_append_only`).
Verified offline (SQLite): registers only rows in `session.new` at flush (not queries); never deletes rows of another session or rows added before `attach`; a rolled-back row has no provable identity and is left (zero statements); a failing delete is reported and nothing else is issued; every statement is `DELETE FROM <table> WHERE <primary key> = ?`; no SELECT/TRUNCATE/DROP/ALTER; children before parents; audit table never touched.
Limitations (not hidden): rows written by Core statements or through another connection are not tracked and remain; deleting an owned parent can cascade to dependents by the schema's `ON DELETE CASCADE` (in a unique-id disposable database those are test-owned by construction, but it is a cascade the tracker does not enumerate); behaviour on real PostgreSQL is UNVERIFIED.

## 4. Native id provenance (D2)
EDR (`detection_id`) and Linux auth (`id`) ids are now on the correlation event as `native_event_id`, scoped by the event's `source_type`, exposed in the incident context attributes next to `source_type`. They are deliberately **not** put in `source_event_id`, because that field feeds duplicate identity and the gate's observation-class logic; using it would have let separate alerts of one source corroborate each other. A fallback id the adapter generated is never presented as native (the id is kept only if the raw record carries that exact value). Tests (`test_stage7c_native_ids_and_entities.py`): preserved and scoped; not in identity, entities, upstream or evidence type; two sources with the same id string create no link and no multi-event incident; duplicate collapsing unchanged by ids; other adapters unaffected.

## 5. Entity normalization (D3): rule per type and component
| Type / component | Rule now | Basis |
|---|---|---|
| domain, URL host | folded; trailing dot removed | DNS names case-insensitive (RFC 4343) |
| file_hash, process_guid | folded | hexadecimal digits |
| ip | folded (IPv6 hex) | IP text |
| email **domain** | folded | RFC 5321 |
| email **local part** | **PRESERVED (changed)** | RFC 5321 section 2.4: case-sensitive |
| message id (`<left@right>`), origin message id | right of last `@` folded, left preserved (changed) | same reasoning; opaque left part |
| logon_session (envelope) id | **PRESERVED (changed)**, issuer folded | opaque token; legacy Windows/Sysmon hex logon ids are folded by their own producer (hexadecimal) |
| cloud_resource, cloud_account | **PRESERVED (changed)** | provider resource names/keys can be case-sensitive |
| principal id, correlation id | preserved; issuer folded; UUID-shaped ids folded | Stage 7B (D4) |
| URL path and query | preserved | already |
| user names, file paths, registry keys, process names | **still folded (unchanged, OPEN)** | case rules depend on the directory or operating system, which the record does not state; pinned by a test; changing them would alter identity matching for every scenario and needs your decision |
Raw values stay in the preserved record; entities are derived views; no stored value or dataset was rewritten.

## 6. Backup plan (D1) - NOT RUN; separate owner authorization required
Existing deployment convention (from the backup records on D: and the Deployment Guide): container-side `pg_dump -Fc` / `pg_dumpall`, files copied out with `docker cp`; the prior set is `D:\AISOP-Backups\AISOP_PostgreSQL_Backup_2026-11-11_181339` (7 files, ~0.35 MB total, 7/7 SHA-256 matched).
| Item | Plan |
|---|---|
| Output directory | `D:\AISOP-Backups\AISOP_PostgreSQL_Backup_<yyyy-MM-dd_HHmmss>\` (new, must not exist) |
| Content | `cluster_pg_dumpall.sql` (roles + all databases) and one `db_<name>.dump` (custom format `-Fc`) for each of the 6 databases seen on 2026-11-11 (`aisop_dev`, `aisop_integration_sandbox`, `aisop_p2h3_disposable`, `aisop_p4b_disposable`, `aisop_test`, `postgres`) |
| Commands (after S0, in the container, as the existing utility does) | `docker exec aisop-postgres pg_dumpall -U aisop --file /tmp/cluster.sql`; `docker exec aisop-postgres pg_dump -U aisop -Fc -d <db> --file /tmp/<db>.dump` for each; `docker cp aisop-postgres:/tmp/<file> <destination>`; then remove `/tmp` files in the container |
| Credentials | never on the command line, never logged: the launcher passes the password through the process environment variable `PGPASSWORD` set from the owner's secured source for that process only, and removes it afterwards; the report records names and sizes only |
| Space | previous set about 0.35 MB; D: has about 99 GB free (checked at `df`, 2026-11-12); require at least 1 GB free and 10x the previous size before starting |
| Integrity | SHA-256 of every file into `backup_manifest.csv`; `pg_restore --list` per archive; footer check of the plain dump; non-empty check |
| Restore test (isolated) | restore each archive into a temporary database with a unique name `aisop_restorecheck_<stamp>_disposable` on the same server ONLY if separately authorized, compare table list and row counts to the source inventory, then drop it with a separate approval; otherwise `pg_restore --list` only is reported as "readability only", never as "recoverable" |
| Retention | keep the new set and the 2026-11-11 set; no deletion of any backup without a separate approval |
| On failure | stop; delete nothing; keep partial files under a `FAILED_` suffix for review; do NOT proceed to S1; report the exact error |
| Gate | the backup must be VERIFIED (all checks above) before S1 is even requested |
This milestone created no backup.

## 7. Proposed execution sequence (each step needs its own explicit approval; none was run)
| Step | Action | Writes |
|---|---|---|
| B | the backup of section 6, verified | files on D: only |
| S0 | read-only identity: `docker inspect aisop-postgres` (state, health, image, port map, mounts/volume), `docker port aisop-postgres`; `SELECT datname FROM pg_database`; compare to the proposed values; ABORT on any mismatch | none |
| S1 | `CREATE DATABASE aisop_stage7b_verify_disposable` only if S0 shows it absent | one new database |
| S2 | `COMMENT ON DATABASE aisop_stage7b_verify_disposable IS 'aisop-disposable-test-target:aisop_stage7b_verify_disposable'` | database comment |
| S3 | `alembic upgrade head` against that database only (0001 to 0004; revision 0002 enables `vector` inside it) | schema and extension in the new database |
| S4 | read-only: revision equals `0004_p3h2_rbac_case_scoping`, table list, other databases' table lists unchanged | none |
| T | the six tests plus the existing persistence/scoping tests (command below); collect exact results | rows in the new database |
| V | confirm no other database changed (table lists and counts equal to S0) | none |
Test command (explicit files; the bare marker expression alone would ALSO select 7 lifecycle and 5 vector tests, so it must never be used without the file list). Selected by this command: 3 + 1 + 13 + 6 = 23 tests; the unconditional lifecycle skip is not involved.
```
$env:TEST_DATABASE_URL = "postgresql+psycopg://<user>:<password from owner>@127.0.0.1:5433/aisop_stage7b_verify_disposable"
$env:ALLOW_DESTRUCTIVE_POSTGRES_TESTS = "1"
$env:AISOP_PG_VERIFIED_CONTAINER = "aisop-postgres"   # exported only after S0 verified it
$env:AISOP_PG_VERIFIED_IMAGE     = "pgvector/pgvector:pg17"
$env:AISOP_PG_VERIFIED_VOLUME    = "aisop_postgres_data"
$env:AISOP_PG_DISPOSABLE_MARKER  = "aisop-disposable-test-target:aisop_stage7b_verify_disposable"
.venv\Scripts\python.exe -m pytest -p no:cacheprovider -m "postgres and not ollama" -q `
  backend/tests/integration/test_postgres_multisource_persistence.py backend/tests/integration/test_postgres_sufficiency_audit.py `
  backend/tests/integration/test_postgres_case_scoping.py backend/tests/integration/test_postgres_stage7b_verification.py
Remove-Item Env:TEST_DATABASE_URL, Env:ALLOW_DESTRUCTIVE_POSTGRES_TESTS, Env:AISOP_PG_VERIFIED_CONTAINER, Env:AISOP_PG_VERIFIED_IMAGE, Env:AISOP_PG_VERIFIED_VOLUME, Env:AISOP_PG_DISPOSABLE_MARKER
```
Failure handling: stop at the first failure, keep output, no automatic retry, no schema change; rollback of the database itself (DROP) only with a separate approval.

## 8. Residual risks
| ID | Risk |
|---|---|
| R8 | everything on PostgreSQL: guard database-side check, tracker, S3 race, S4 cross-connection visibility, trigger, `octet_length` |
| R15 | tracker limits (untracked rows, cascades, FK-blocked leftovers) |
| R17 | the container/image/volume values are environment assertions until S0 independently verifies them |
| R18 | the bare marker expression selects lifecycle and vector tests; the plan relies on the explicit file list |
| R19 | user, file path, registry key and process name case rules remain folded (open decision) |
| R20 | email local-part and session-id preservation can reduce linking for sources that emit inconsistent casing |
| R21 | `native_event_id` is provenance only: EDR/Linux ids cannot be used to detect re-delivered alerts (by design) |
| R22 | an existing test `test_postgres_lifecycle.py` upgrade test still performs an Alembic call (a no-op at head) |

## 9. Verification (offline)
See the chat report for the exact commands and counts. Files written only under `D:\AISOP` and `D:\AISOP-Control`.
