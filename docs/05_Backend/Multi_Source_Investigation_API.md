# Multi-Source Investigation API (Stage 4, ADR-010)

Status: IMPLEMENTED and tested offline (SQLite, scripted LLM). PostgreSQL behaviour UNVERIFIED. Base path `/api/v1`. Authentication, RBAC and anti-enumeration are those of the existing case router; nothing new is added.

## Endpoints
| Method and path | Roles | Purpose | Success | Notable errors |
|---|---|---|---|---|
| `POST /cases/{case_id}/investigations/multisource` | case investigator or lead (and, for `use_llm`, global tier-1/2/admin via `can_execute_case_synthesis`) | Start, or reuse, a deterministic investigation of the evidence linked to the case | 201 new result stored; 200 identical evidence, stored result returned (`reused: true`) | 401 unauthenticated; 404 unassigned (anti-enumeration); 403 viewer, or `use_llm` without role; 409 case closed/archived, or evidence changed during the run; 413 more than 1,000 evidence items linked to the case; 422 invalid body or id; 500 audit write failed (generic) |
| `GET /cases/{case_id}/investigations/multisource/{section}` | case viewer, investigator, lead | Read a section of the latest stored result | 200 | 401, 404 (unassigned, or none started), 422 unknown section |

`section` is one of `status`, `timeline`, `correlation`, `attack`, `sufficiency`, `report`.

## Request body (POST)
```json
{"use_llm": false, "force": false}
```
Both optional, default false, unknown fields rejected (422). `use_llm=true` also runs the gated LLM investigation with the configured local provider (default Ollama, local only); the deterministic workflow never needs it. `force=true` appends a new audit record even if the evidence is unchanged.

## Result document (POST body, and source of every GET section)
Top level: `schema` ("multisource-v1"), `status` ("completed"), `workflow_version`, `mapping_version`, `rule_version`, `evidence_fingerprint`, `use_llm`, `created_at`, `started_by`, `reused`, `counts` (records_normalized, records_rejected, evidence_clusters, duplicates_collapsed, contradictions, incidents), `sources` (per adapter type: events, distinct raw records), `rejected` (record_index, fixed reason code, raw SHA-256 prefix), `contradictions`, `batch_sufficiency` and `batch_report_markdown` (only when no incident could be formed), `incidents[]`, `ledger` (head, verified, step hashes).
Each incident: `incident_id`, `severity`, `event_count`, `first_seen`, `last_seen`, `hosts`, `users`, `stages`, `escalated`, `link_counts`, `weakly_related`, `context_sha256`, `sufficiency` (`verdict`, `reason_codes`, `reasons[{code, meaning}]`, `abstain`, `counts`, `assessment_sha256`, `evidence_ids`), `timeline[]` (position, timestamp, source_type, host, user, title, stage, severity, outcome, raw_sha256_prefix, membership core or weak_context, duplicates_collapsed, event_id = persisted normalized-event id, contradicts), `links[]` (strong/specific only: strength, cluster pair, shared entities), `weak_link_count`, `mitre[]` (technique, tactics, rule_id, independent_evidence_count, vendor_asserted, limitation, evidence_event_ids), `asserted_only`, `llm_status` (`not_requested`, `abstained`, `validated`, `fallback:<ExceptionType>`), `llm` (null, or decision, summary, claims with category and grounding, uncertainty and data gaps, violated guardrail ids), `report_markdown`.
Not returned or stored: raw payloads, command lines, credentials, exception messages.

## Section views
`status`: run metadata, counts, sources, ledger, per-incident verdict, `stale_evidence`. `timeline`: timeline per incident. `correlation`: sources, contradictions, rejected records, links and link counts. `attack`: mappings and asserted-only techniques. `sufficiency`: verdict and reasons per incident (and the batch verdict). `report`: Markdown report, LLM section, ledger. Every view carries `status`, `created_at` and `stale_evidence` (true when the case evidence changed since the run).

## Behaviour and guarantees (each covered by a test)
* Only evidence linked to the case is read; other cases' evidence never appears.
* Repeating the request for identical evidence writes nothing (200, `reused`); `force` writes a new row.
* New evidence makes `stale_evidence` true and a later POST stores a new result.
* No evidence, or only unparseable evidence, stores an abstention (`batch_sufficiency.verdict = insufficient`) and never calls a model.
* LIMITED and INSUFFICIENT verdicts always carry reason codes and meanings; LIMITED is disclosed in the report text and, with an LLM, in the uncertainty list.
* Gate exception: fail closed (`llm_status = abstained`, reason `GATE_EVALUATION_ERROR`, no provider call). Provider failure: deterministic result plus `fallback:<Type>`.
* An audit-write failure returns 500 with a fixed message and stores nothing.

## Limits
Synchronous execution (no progress state); result size caps: report 60,000 characters per incident, 200 timeline rows, 100 links; storage is one `case_audit_events` row per run (action `case_multisource_investigation`); no pagination of sections.

## Example (from the integrated demo)
`POST /api/v1/cases/{id}/investigations/multisource` with `{}` returned 201 with one incident: 10 events from 4 adapter types, verdict `sufficient`, six rule-derived techniques, hash chain verified; the identical request returned 200 `reused: true`. Full captured outputs: `D:\AISOP-Backups\AISOP_Stage4_Integration_2026-11-12\demo_output\`.

## Stage 5 additions
* **413** when the case has more than 1,000 linked evidence rows (nothing is run or stored).
* **Truncation:** the stored result lists at most 25 incidents, 200 rejected records and 200 contradictions; `truncation` states `*_total` and `*_listed`; the `status` section carries it.
* **New rejection codes** in `rejected[].reason`: `TIMESTAMP_MISSING_OR_INVALID`, `RECORD_TOO_DEEP`, `RECORD_TOO_LARGE`, `RECORD_NOT_SERIALIZABLE` (besides `NOT_AN_OBJECT`, `NO_ADAPTER`, `ADAPTER_ERROR:<Type>`).
* **New reason code** `REPEATED_OBSERVATION_ONLY` (disclosure) and rule version `suff-v3`.
* **LLM bound:** with `use_llm=true` at most 5 incidents are analysed; others report `llm_status = skipped:llm_incident_limit`.
* **Concurrency:** concurrent identical requests for one case are serialised; later ones return the stored result (200, `reused: true`).
* **Activity feed:** `GET /cases/{id}/activity` returns, for action `case_multisource_investigation`, `details = {summary_only: true, schema, evidence_fingerprint, use_llm, counts, verdicts[], ledger_head, ledger_verified}`; use the section endpoints for the full document.
