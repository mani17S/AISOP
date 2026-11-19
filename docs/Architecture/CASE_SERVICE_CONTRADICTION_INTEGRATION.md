# Case-service integration of contradiction findings (ADR-013 Revision 2, owner decision D7)

Date: 2026-11-12. Status: IMPLEMENTED and offline-verified over SQLite (PostgreSQL NOT RUN).

## Shared code path (no fork)
| Step | Incident path | Case path |
|---|---|---|
| Evidence load | `MultiSourceInvestigationService.start` reads the case's evidence through `case_evidence` | `CaseService.synthesize_case_investigation` Phase A reads ONLY evidence linked to this case through `case_evidence` |
| Observations | `normalize_records` -> `parse_record` (envelope records) | `contradictions.observations_from_stored(...)` -> the same `parse_record`, from the PRESERVED raw payloads; key = normalized event id; non-envelope, malformed or badly hashed payloads are skipped, nothing invented |
| Detector | `detect_contradictions(machine_obs)` in `workflow.analyze` | `detect_contradictions(...)` in Phase A (the same function) |
| Gate | `evaluate_sufficiency(context, incident_candidates)` | `evaluate_sufficiency(context, contradiction_candidates)` in Phase B, after the database session is released |
| Exposure | incident `contradictions[]`, `sufficiency` section, report block, graph, UI | audit row (`sufficiency_verdict`, `sufficiency_reason_codes`, ...), `uncertainty_and_data_gaps` disclosure in the analyst-facing output |
| LLM | optional, gated, cannot change findings | same; provider failure falls back, findings and verdict unchanged (tested) |

## Preserved
Authorization (`require_case_role`, role checks, revocation re-check), case scoping (evidence selected through `case_evidence` for this case only; a contradiction in one case never appears in another: tested), the evidence snapshot and mutation checks (SEC-D24), the audit write and its failure behaviour, and no schema change or migration.

## Differences between the paths (documented, not changed)
1. **Anchor and relation:** the incident path anchors on the earliest event; the case path (no `root_event_id`) uses pairwise corroboration. Materiality is evaluated against each path's own partition. For the tested scenarios both give MATERIAL and the same verdict and codes.
2. **Assessment hash:** the assessment binds the context hash; the case path creates a fresh investigation id per call (pre-existing), so hashes differ between calls and between paths. Verdict, reason codes and evidence units are stable (tested).
3. **Undated domain evidence:** the case path builds context events from the `normalized_events.event_timestamp` column, which holds the INGESTION time for records without an event time (disclosed in the stored payload). The incident path excludes undated evidence from the timeline. The contradiction detector is unaffected (it reads the observation's own event time from the raw payload, never that column). This pre-existing difference in case synthesis was not changed ("no unrelated case-service behaviour change") and is flagged for owner review.
4. **Correlator-level markers:** the case path has no correlator, so graph and timeline markers do not exist there; findings are in the audit row and the disclosure.

## Not covered
PostgreSQL behaviour of the larger audit details (UNVERIFIED, not run). `case_report_synthesized` was not separately extended.

## Stage 7A update (2026-11-12): difference 3 (undated domain evidence) is RESOLVED
The case path no longer places a record without a usable event time on the time-ordered context: it uses the shared predicate
`evidence_domains.model.stored_event_time_unknown`, excludes such records from the context events, keeps them preserved and in the evidence
snapshot, discloses them with the incident path's `UNDATED_OBSERVATIONS` wording (also appended deterministically to
`uncertainty_and_data_gaps`), and never reads the ingestion-time column as an event time. See `EVIDENCE_TIME_SEMANTICS_AND_REPORT_PARITY.md`.
A new, separate difference was found and pinned (not changed): clean domain evidence is SUFFICIENT on the incident path and LIMITED on the case path because domain entities are stored only in the payload (section 4 of that document).
