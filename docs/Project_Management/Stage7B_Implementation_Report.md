# Stage 7B implementation report

Date: 2026-11-12. Scope: owner decisions D1 to D6 of `AISOP_Stage7B_Parity_Legacy_Adapters_PostgreSQL_Safety_Master_Prompt.md`. Prior reports are unchanged.

## Status
| Item | Status |
|---|---|
| D1 clean-evidence parity, fixed at the entity/context layer | IMPLEMENTED (offline) |
| D2 unsupported-claim and `case_report_synthesized` parity | IMPLEMENTED (offline) |
| D3 per-adapter legacy coverage | IMPLEMENTED for 8 of 8 adapters, limited to the fixtures' fields; 2 documented gaps |
| D4 canonical identifier case | IMPLEMENTED (issuer folded, identifier preserved, UUID namespace folded) |
| D5 legacy naive timestamps | IMPLEMENTED (flag + disclosure; sysmon/windows UTC by format) |
| D6 PostgreSQL test safety | IMPLEMENTED in test code and verified offline; plan ready; NOT RUN |

## Code changes
| File | Change |
|---|---|
| `services/case_service.py` | `_context_entities` / `_context_attributes`; domain context entities from the adapter-parsed preserved payload; compact domain attributes (also removes a mutated stale `entities` copy from the prompt context) |
| `modules/evidence_domains/adapters.py` | `_issuer_id`: identifier case preserved; UUID-shaped ids folded; issuer lower-cased |
| `modules/correlation/models.py`, `normalize.py` | `time_assumed_utc` field and `_time_assumed_utc` |
| `modules/correlation/workflow.py`, `report.py` | context attribute and `NAIVE_TIMESTAMPS_ASSUMED_UTC` flag; "Time zone assumed" limitation |
| `tests/conftest.py` | approved-target identity guard, read-only marker check, `ensure_test_database_exists` no longer creates, `OwnedRowTracker` replaces table-wide cleanup |
| `tests/integration/test_postgres_lifecycle.py` | downgrade test skipped unconditionally |
| `tests/integration/test_postgres_case_scoping.py` | fixture applies the identity guard and marker check |
| tests | new: `test_stage7b_parity.py` (18), `test_stage7b_legacy_and_identity.py` (57), `test_stage7b_postgres_guard.py` (20). Updated (premise superseded by an owner decision, not weakened): `test_stage7a_undated_and_parity.py` (pinned difference now asserts parity), `test_stage7a_producer_contract.py` (identifier case), `test_postgres_guard.py` (single approved target, old targets refused) |

Not touched: schema, migrations, dependencies, configuration, frontend, datasets, credentials, RBAC.

## Verification (offline, Python 3.12.0, repository root)
| Command | Exit | Result |
|---|---|---|
| `pytest backend/tests/unit` | 0 | 1823 passed, 0 failed, 0 skipped, 0 expected-fail, 13 warnings (1728 + 95) |
| `pytest backend/tests/integration -m "not postgres and not ollama"` | 0 | 85 passed, 33 deselected, 4 warnings |
| PostgreSQL / Ollama | not run | 33 collected only |
| `py_compile` of 6 changed production modules and `conftest.py` | 0 | clean |
| frontend | not run | no frontend file changed |
Mutation checks (all failed as intended, files restored): always-false `_time_assumed_utc` (8 tests fail); global lower-casing of identifiers (4 fail); case path ignoring derived entities (4 fail); an injected `CREATE DATABASE` in the fixtures (1 fails). Logs: `D:\AISOP\logs\stage7b\`.

## Remaining-risk register (additions)
| ID | Risk | Status |
|---|---|---|
| R1, R2 | Stage 7A clean-evidence difference | RESOLVED (R1); R2 (window filter compares the ingestion-time column) OPEN, low |
| R4 | `case_report_synthesized` unpaired | RESOLVED |
| R5, R6 | identifier case, legacy naive times | RESOLVED; see residuals below |
| R10 | unpaired unsupported-claim scenario | RESOLVED |
| R11 | `edr_malware` and `linux_auth` do not carry the native id onto the correlation event | OPEN, documented |
| R12 | `logon_session`, e-mail, domain, hash and IP entity values are still case-folded | OPEN, documented, out of D4 scope |
| R13 | A producer with a case-insensitive directory that emits inconsistent casing now produces a false identity finding | OPEN; mitigated by the contract (emit one form or UUIDs) |
| R14 | Legacy cloud_audit/email/EDR documented time semantics not established; naive stays "assumed" | OPEN, conservative |
| R15 | Owned-row cleanup is unverified on real PostgreSQL; FK-blocked rows remain; untracked rows from service code remain | UNVERIFIED |
| R16 | Case context for domain evidence is smaller than before (storage metadata removed from the prompt); the stored record is unchanged | OPEN, low |
| R8 | Everything on PostgreSQL | UNVERIFIED (plan ready) |

## Protected actions and Git
Not performed: any PostgreSQL/Docker/database connection or command, migration, backup, Ollama, cloud call, model download, dependency or configuration change, credential/secret file read, Git mutation. Writes only under `D:\AISOP` and `D:\AISOP-Control`. Git: `main`, HEAD `c4e877c`, 0 stashes; status entries 325 -> 328 (three new untracked test files). Snapshots: `D:\AISOP-Control\stage7b_git_before.txt`, `stage7b_git_after.txt`.

## Owner authorization request
See the final section of the chat report and `Stage7B_PostgreSQL_Verification_Plan.md`: approve ONE target (`aisop-postgres`, `127.0.0.1:5433`, volume `aisop_postgres_data`, new database `aisop_stage7b_verify_disposable`), steps S0 to S4, and the exact pytest command. Nothing runs without it.
