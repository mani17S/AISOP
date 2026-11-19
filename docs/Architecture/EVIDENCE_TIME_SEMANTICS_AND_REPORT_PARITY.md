# Evidence-time semantics and incident/case report parity (Stage 7A, owner decisions D1 and D2)

Date: 2026-11-12. Status: IMPLEMENTED and offline-verified over SQLite (`backend/tests/unit/test_stage7a_undated_and_parity.py`, 25 tests). PostgreSQL persistence: UNVERIFIED (NOT RUN).

## 1. Event time versus ingestion time

| Concept | Where it lives | Meaning |
|---|---|---|
| event time | envelope `event_time`; stored payload `event_time` (ISO or `null`) | when the source says the event happened; `null` = unknown |
| timestamp quality | stored payload `time_status` | `valid`, `naive_assumed_utc`, `missing`, `invalid`, `out_of_range` |
| source collection time | envelope `collected_at` | when the source collected it; **never** promoted to event time |
| ingestion time | `normalized_events.event_timestamp` ONLY when the event time is unknown | the column is NOT NULL, so AISOP stores the ingestion instant there; the payload states `event_timestamp_is_ingestion_time: true` |
| raw representation | `raw_evidence.raw_payload` + SHA-256 | the submitted record, unchanged (no `event_time` key is added) |

Predicate (single definition, no duplicated timestamp logic): `evidence_domains.model.stored_event_time_unknown(normalized_payload)` is true when the payload flag is set or `time_status` is not dated. It is the stored-row twin of `bridge.is_dated`. Legacy rows without the keys (SIEM, Sysmon) are dated. It lives in `model.py` because importing `bridge` from `case_service` triggers the known circular import.

## 2. Before and after (case synthesis)

| | Before (Stage 6 / ADR-013 R2) | After (Stage 7A) |
|---|---|---|
| Undated domain record in `synthesize_case_investigation` Phase A | read `ev.event_timestamp` (= ingestion time) as the event's `timestamp_utc`; it entered the time-ordered context, the window, and the evidence count as if dated | excluded from the time-ordered context; counted, disclosed, still preserved, still in the evidence snapshot/fingerprint |
| Its entities | in the context | still feed non-temporal enrichment (threat intelligence lookup) |
| Disclosure to the analyst | none | `UNDATED_OBSERVATIONS: N observation(s) have no usable event time and were not placed on the timeline` in the prompt flags AND appended deterministically to `uncertainty_and_data_gaps` after the model output (so it appears whatever the model produced) |
| Incident path | excluded from the timeline; flag in context; count in `observation_counts.undated`; **no line in the incident report** | unchanged, plus a Limitations line in the incident report: "Event time unknown: N preserved record(s) ... Their ingestion time is stored separately and is not an event time." |
| Contradiction detector | reads the observation's own event time from the raw payload (never the column) | unchanged; tests now prove an undated record yields no outcome, ordering or temporal finding on either path |

Time-window filters (`time_window_start/end`) still compare the column; for an undated record that is the ingestion time, so such a record can fall inside or outside the window. Because it is excluded from the context either way, the window cannot turn it into event-time evidence. Recorded as a residual note.

## 3. Report-synthesis parity (D2): the normalized projection

Compared (meaning, not bytes): sufficiency verdict; rule version (`suff-v4`); contradiction reason codes (`CONTRADICTORY_EVIDENCE:<kind>`); undated disclosure present/absent; the coded disclosure line reaching the analyst-facing output (case path); verdict and findings independent of the LLM.

Excluded, with the reason:
| Field | Why excluded |
|---|---|
| investigation id, incident id, evidence ids, assessment SHA-256 | the case path creates a fresh investigation id per call and binds a different context hash |
| `generated_at`, `validated_at_utc` | non-deterministic |
| model narrative (`investigation_summary`, claims text, alternatives, recommended actions) | the two paths have different generators (deterministic report vs gated LLM output) |
| markdown layout, graph, timeline markers | presentation; the case path has no correlator |
| per-incident anchor / relation | the incident path anchors on the earliest event; the case path uses pairwise corroboration |

Scenario results (all asserted in the test file):
| # | Scenario | Result |
|---|---|---|
| 1 | Clean evidence | **DIFFERS, documented and pinned** (section 4) |
| 2 | Verified-causal ordering contradiction | identical projection (LIMITED + `ordering`) |
| 3 | Earlier file timestamp, no causal relationship | identical (no contradiction) |
| 4 | Outcome contradiction | identical |
| 5 | Identity contradiction | identical |
| 6 | Temporal contradiction | identical |
| 7 | Undated evidence | identical disclosure on both paths; verdict unchanged by the undated record |
| 8 | Duplicate / mirrored (declared upstream) | identical; mirrored copy equals the single-copy verdict on both paths |
| 9 | LLM unavailable | projection identical to the working-LLM run (verdict, findings) |
| 10 | Unsupported AI claim (model cites nonexistent evidence) | case path: verdict and finding stand, output not accepted as grounded. Incident path: it has no injectable model in this harness, so it is covered by the gate/detector tests, not by a paired run |

## 4. Real parity gap found (pinned, not changed): clean evidence

For clean scenario A, the incident path returns SUFFICIENT and the case path returns LIMITED (`IRRELEVANT_EVIDENCE_EXCLUDED`, `UNCORROBORATED_QUESTION`, `WEAK_LINK_ONLY`). Verified cause: domain evidence stores its entities only in `normalized_payload["entities"]`; the case path builds context entities from the ORM entity rows, which domain records do not have, so nothing links. This is a data-contract difference, not a contradiction. Fixing it changes case-synthesis output beyond this milestone, so it is pinned by `test_documented_difference_clean_domain_evidence_verdict_differs_between_paths` and left for an owner decision (option: derive context entities from the stored payload for domain events, with the same escape/bound rules).

## 5. Not covered
`case_report_synthesized` (the report endpoint, as distinct from investigation synthesis) was not paired with an incident report in this milestone: its projection is not tested. PostgreSQL storage of the larger audit details: UNVERIFIED.

---
## Stage 7B update (2026-11-12): section 4 is RESOLVED; remaining parity paired
Tests: `backend/tests/unit/test_stage7b_parity.py` (18).
* **Clean-evidence difference fixed at its cause.** (1) The case path now derives context entities for domain evidence from the observation the approved adapter re-parses from the PRESERVED raw payload (the incident path's source, via `observations_from_stored`); the stored `normalized_payload["entities"]` and any client field are never read for this, so forged or unsupported entities cannot become canonical entities (tested). (2) Each case-context event previously carried the whole stored payload (adapter, schema, model version, duplicate entity list, ...), which pushed the 8-event scenario over the 8,750-character context budget (`EVIDENCE_TRUNCATED` -> LIMITED). Domain events now carry only the analytical attributes (classification, trust class, source system, time status, event time, ingestion-time flag, upstream id). The verdict was not edited: scenarios A, B and C now give identical verdict and reason codes on both paths.
* The Stage 7A test that pinned the old difference now asserts parity.
* **`case_report_synthesized` paired**: the report path's audit row and bundle match the incident path (verdict, codes, version) for clean, ordering, outcome, identity and temporal scenarios; the contradiction code and `UNDATED_OBSERVATIONS` appear in the bundle's `investigation_gaps`.
* **Unsupported AI claim paired**: the incident path accepts the same injectable provider (`use_llm=true`); with a provider citing nonexistent evidence, verdict and findings equal the no-model baseline on the incident, case and report paths, and the claim is not accepted as grounded on either.
* Still excluded from the projection (unchanged): ids, hashes, timestamps, narrative text, layout, graph and timeline markers.
