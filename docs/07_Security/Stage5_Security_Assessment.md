# Stage 5 Security Assessment - Integrated Multi-Source Investigation

Date 2026-11-12. Scope: the integrated product (ingestion -> case evidence -> multi-source investigation -> optional gated LLM -> audit persistence -> API -> analyst UI) of ADR-008, ADR-009 and ADR-010. Method: read the implementation, wrote adversarial tests against it (`backend/tests/unit/test_stage5_adversarial.py`, 89 tests), fixed concrete defects, re-ran the suites. Authorized review of this project only; no destructive testing, no external systems, no real model, no PostgreSQL. Status labels: IMPLEMENTED, PARTIAL, BLOCKED, PROPOSED, UNVERIFIED, FAILED. AISOP is not production-ready.

## 1. Attack surface
| Surface | Entry | Authentication / authorization (existing, tested) |
|---|---|---|
| Evidence ingestion | `POST /api/v1/alerts/ingest` (`api/v1/endpoints/evidence.py`) | machine key or analyst token; raw payload preserved with SHA-256 |
| Case evidence link | case endpoints in `api/v1/endpoints/cases.py` | `require_case_role` (case assignment); anti-enumeration 404 |
| Start investigation | `POST /cases/{id}/investigations/multisource` | investigator/lead; `use_llm` additionally `can_execute_case_synthesis` |
| Read investigation | `GET .../multisource/{section}`, `GET /cases/{id}/activity` | viewer/investigator/lead |
| Model boundary | `GatedGenerator.generate` (only `provider.generate` caller; AST test) | gate verdict; provider is local Ollama by default |
| Persistence | `case_audit_events` rows (append-only DB triggers, migration 0004) | service writes only through the case session |
| Analyst UI | `frontend/src/components/MultiSourcePanel.tsx` | renders server data as text; no `dangerouslySetInnerHTML` |

## 2. Trust boundaries and the trust assumption behind each relationship
1. **Raw telemetry is untrusted data** (content may be attacker-controlled). Adapters parse it; nothing in it is executed, followed or obeyed.
2. **Ingestion authenticity is assumed, not verified.** Any holder of the ingest credential can place records in the evidence pool; they reach an investigation only when an analyst links them to a case. Whether a record really came from the claimed sensor is UNVERIFIED.
3. **Evidence independence (ADR-008 suff-v3)** rests on these assumptions per relationship:
   | Relationship | Treated as | Assumption / weakness |
   |---|---|---|
   | same raw digest | one evidence unit | digest is computed over the stored record; two different records are two units |
   | same host/event id/type/action (even with different digest, any time gap) | one *observation class*; never corroborates (Stage 5, D1) | an attacker who controls one sensor can still emit a *different kind* of event |
   | different observation kinds sharing a file hash, domain, URL, e-mail, public IP, path, registry key | SPECIFIC link = corroboration | the values are producer-supplied; a compromised or spoofing source can fabricate both events (residual R1) |
   | shared process GUID, logon session | STRONG link | GUID/session ids are host-local; SYSTEM-session ids and zero GUIDs are weak (D2) |
   | shared host, user, process name, private/loopback IP | WEAK link: context only | never counts as corroboration |
   | placeholders (`unknown`, `-`, zero hash, `localhost`...) | WEAK regardless of type (D2) | list is finite; novel placeholders are not recognised |
4. **The model is untrusted**: it cannot alter deterministic evidence, the verdict, ATT&CK mapping or the ledger; its claims are verified; failure falls back to the deterministic report.
5. **The stored result is a convenience copy** of derived data; the preserved raw evidence rows remain authoritative.

## 3. Threat scenarios
| # | Scenario | Control | Evidence | Status |
|---|---|---|---|---|
| T1 | Unauthenticated / unassigned access to investigation or sections | 401; anti-enumeration 404 (same body for missing and unassigned) | `test_unauthenticated...`, `test_cross_case_access_with_manipulated_identifiers...` | IMPLEMENTED |
| T2 | Cross-case evidence leakage via ids, case-variant/hyphenless UUIDs, section traversal strings | router dependency + `case_evidence` join; invalid section 422/404 | same | IMPLEMENTED |
| T3 | Evidence of another case investigated because it shares entities | evidence query is joined on this case's links | `test_evidence_of_another_case_is_never_investigated...` | IMPLEMENTED |
| T4 | Viewer starts investigation / unauthorised LLM use | 403; role-gated `use_llm` | Stage 4 + role tests | IMPLEMENTED |
| T5 | Internal detail in errors | fixed strings; audit failure generic 500; engine crash body contains no DSN/exception text | `test_error_responses_do_not_leak...`, Stage 4 test | IMPLEMENTED |
| T6 | Manufactured corroboration: replays, duplicates, near-duplicates, placeholders, weak links | independence rules; see section 4 | 40+ tests | IMPLEMENTED (R1 residual) |
| T7 | Parser abuse: deep nesting, huge records, junk batches, mixed types, invalid timestamps, control/bidi characters, overlong values | bounded, rejected with fixed codes | `test_d3*`, `test_d4*`, others | IMPLEMENTED |
| T8 | Resource exhaustion: huge evidence sets, many incidents, repeated `force` runs, unbounded feed | evidence cap 1000, stored caps, LLM incident cap 5, activity summary | `test_d6*`, `test_d8*`, `test_d9*` | PARTIAL (no per-user rate limit specific to these endpoints) |
| T9 | Prompt injection in evidence; fabricated citations; unsupported escalation by the model; malformed model output | untrusted-data envelope, gate authoritative, claim validator, parser/fallback | `test_prompt_injection...`, `test_hostile_model_output...`, `test_malformed_model_output...` (scripted provider) | IMPLEMENTED against a scripted provider; real model UNVERIFIED |
| T10 | Ledger tampering | hash chain, `expected_head` for tail truncation | `test_ledger_*` | PARTIAL (tamper-evident, not immutable) |
| T11 | Duplicate/concurrent runs, interrupted run | per-case in-process lock; fingerprint reuse; no partial writes | `test_d7*`, crash test | PARTIAL (single worker only) |
| T12 | Activity feed bloat / exposure of full result to every case role | summary only (`activity_summary`) | `test_d6_case_activity_feed...` | IMPLEMENTED |
| T13 | XSS through report or evidence text in the UI | text rendering only; `<pre>` for the report | `multisource_panel.test.tsx` | IMPLEMENTED (render tests; no browser) |

## 4. Defects found and fixed (each with a regression test)
| ID | Defect | Where | Fix |
|---|---|---|---|
| D1 | A replayed/re-emitted observation (same host, event id, type, action; new digest; 0.5 s to 1 h later) counted as independent corroboration: SUFFICIENT from one repeated event. Reproduced before the fix. | `sufficiency_gate.assess_evidence_sufficiency` | `same_observation_class` / `corroborates`; new disclosure code `REPEATED_OBSERVATION_ONLY`; rule version `suff-v3` |
| D2 | Placeholder or invalid shared values (`unknown`, `-`, `null`, `N/A`, `localhost`, zero/uniform hash, malformed hash, dotless domain, SYSTEM logon session `0x3e7`, zero GUID) were SPECIFIC/STRONG links: SUFFICIENT. Case variants did not match. | `evidence/independence.py: entity_link_strength` | `is_informative_value`, `canonical_entity_value`; gate compares canonical values |
| D3 | The ADR-007 adapters replace a missing/unparseable timestamp with the current time; the engine kept it, placing the record on the timeline as if observed "now" and making reports non-reproducible. | `correlation/normalize.py: normalize_records` (adapters: `alerts/adapters/*_adapter.py`) | rejected with `TIMESTAMP_MISSING_OR_INVALID` |
| D4 | Deeply nested records raised `RecursionError` out of the batch; records of any size were parsed; non-string keys raised `TypeError`. | `normalize_records` | `_exceeds_depth` (32), 1 MiB cap, `RECORD_TOO_DEEP`/`RECORD_TOO_LARGE`/`RECORD_NOT_SERIALIZABLE` |
| D5 | `verify_chain` raised on malformed input; a truncated chain verified with no way to detect it. | `correlation/ledger.py: verify_chain` | fails closed; optional `expected_head` |
| D6 | Stored result unbounded (rejected list, incidents; 100 incidents = 2.3 MB measured) and the full document was returned in every case member's activity feed. | `multisource_investigation_service.build_payload`, `case_service.list_case_activity` | caps + `truncation` disclosure; `activity_summary` |
| D7 | Two concurrent identical requests could both run and store duplicates. | `MultiSourceInvestigationService.start` | per-case lock; second request reuses the stored result |
| D8 | No bound on evidence rows (correlation is quadratic: 1,000 events 2.5 s / 155 MB worst case) | `start` | refuse above 1,000 with 413 |
| D9 | One model call per incident, sequential, each up to the provider timeout: unbounded inference | `workflow.run_workflow` | `MAX_LLM_INCIDENTS = 5`, `llm_status = skipped:llm_incident_limit` |
| U1 | UI showed every load failure (403/500/network) as the empty "start" state; skipped AI analysis was labelled "not requested"; truncation invisible. | `MultiSourcePanel.tsx` | errors surfaced; messages added; tests |

Existing tests changed: four sufficiency tests used a second event of the *same* type and host as the "independent" corroborator; they now use a different observation kind (`network_connection`). This is the intended semantic change of D1, not a loosened assertion.

## 5. Tested and held (no defect found)
Anti-enumeration parity; case-id variants; hostile section names; viewer limits; cross-case link isolation; error-body hygiene; audit-write failure and evidence-race handling; Unicode/control characters; 20,000 junk records in bounded time; injection text cannot break the prompt envelope or alter verdict/ATT&CK; fabricated citations are not reported as validated; garbage model output (empty, text, truncated, huge, wrong type) falls back; ledger edit/delete/reorder/insert detection.

## 6. Ledger: what it guarantees
Detects modification of any entry, deletion or insertion before the tail, and reordering. Does not detect a consistently rewritten chain or (without a trusted head) a truncated tail. The head is stored inside the same audit row as the steps, so it protects against accidental or partial change, not against an actor who can rewrite the row; the append-only database triggers (PostgreSQL behaviour UNVERIFIED for this table in Stage 5; test written, not run) are the control against that. It is **not** immutable or tamper-proof, and must not be described so.

## 7. Credential and deployment workstream (separate; nothing changed)
Metadata only; no secret values were opened or printed.
* `.env` is git-ignored; `.refact/` is git-ignored. `.env.example` and `docker-compose.yml` are tracked.
* `.env.example` entered history in local commit `63bee0b` (2026-09-10). Local `main` is 12 commits ahead of `origin/main`; `origin/main` (last fetched state) is the single commit `fb42fe9 Initial AISOP repository structure`, which does not touch `.env.example`; no remote-tracking branch contains `63bee0b` or any later commit. **Conclusion from local refs: the credential-bearing commit has not been pushed as of the last fetch (UNVERIFIED against the live remote: no network call was made).** The owner should confirm on the hosting service (repository visibility, any other remote, forks, CI caches, backups containing the repository).
* `docker-compose.yml:14` publishes PostgreSQL as `"5433:5432"`, which Docker binds on all host interfaces. Firewall state was not inspected.
* Owner actions (not performed): treat the credential in `.env.example` history as exposed if the repository was ever shared; rotate it; remove it from history only when the owner decides (history rewrite is forbidden under this prompt); change the mapping to `127.0.0.1:5433:5432`; review the hosting-service visibility; keep `viva-credentials.txt` untracked.

## 8. Remaining risks
| ID | Risk | Status |
|---|---|---|
| R1 | A compromised or spoofing source can emit two *different kinds* of event sharing a specific artefact and obtain corroboration. Needs source authenticity (signed collection) or a requirement for distinct sensor families, which needs `source_type` in the gate context. | PROPOSED |
| R2 | The claim validator's "two independent clusters" test under LIMITED is cluster-level only (a repeat 3 s apart counts as two). | PARTIAL |
| R3 | The ingestion path still stores adapter-invented timestamps for alerts without one (D3 is fixed in the investigation engine only; changing adapters alters ADR-007 behaviour). | PARTIAL; owner decision |
| R4 | Years outside a plausible range (e.g. 0001, 2099) are accepted; the gate's temporal-anomaly rule applies only relative to the window. | PARTIAL |
| R5 | In-process per-case lock does not coordinate multiple workers; PostgreSQL advisory locking is not implemented or validated. | PROPOSED |
| R6 | No rate limiting specific to `force` reruns beyond the application's global limits. | UNVERIFIED |
| R7 | Real-model injection resistance and output behaviour. | UNVERIFIED |
| R8 | PostgreSQL behaviour of the stored document, triggers and new tests. | BLOCKED |
| R9 | Browser-level behaviour (no browser automation installed). | UNVERIFIED |
