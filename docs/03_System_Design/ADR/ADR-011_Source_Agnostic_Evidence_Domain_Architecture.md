# ADR-011: Source-Agnostic Evidence-Domain Architecture (canonical observations, investigation graph, domain adapters)

| Field | Value |
|---|---|
| **ID** | ADR-011 |
| **Status** | PROPOSED (implemented 2026-11-12; offline-tested only; Project Owner approval pending) |
| **Date Proposed** | 2026-11-12 |
| **Decision Maker** | Project Owner |
| **Extends** | ADR-007 (adapters), ADR-008 (sufficiency gate), ADR-009 (correlation and ATT&CK), ADR-010 (case-scoped integration). Supersedes nothing. |

Labels: IMPLEMENTED (code and passing offline tests), PARTIAL, PROPOSED, UNVERIFIED, NOT IMPLEMENTED.

## 1. Context
ADR-007 to ADR-010 made AISOP investigate heterogeneous alerts (SIEM, Windows security, Sysmon, firewall/IDS). Every input still had to look like an alert: a required timestamp (the ADR-007 adapters substitute "now" when it is missing and ADR-009 rejects such records), a severity, and in practice Windows or Sysmon event ids. Real investigations also use identity sign-ins, cloud audit trails, DNS and flow records, e-mail, and forensic artefacts (files, registry keys, memory findings), plus analyst notes. None of those is an alert.

## 2. Decision
Sources, vendors and event ids are inputs, not architecture. The pipeline is:

source adapters -> preserved raw record + SHA-256 -> versioned canonical `Observation` -> typed entities and relationships -> deterministic correlation (existing correlator) -> timeline -> deterministic TI enrichment (context) -> deterministic ATT&CK rules -> sufficiency gate -> optional gated LLM -> claim verification -> report.

### 2.1 Canonical observation (IMPLEMENTED: `backend/app/modules/evidence_domains/model.py`)
`Observation` keeps: evidence type and family, source system, category and collection method, the SHA-256 of the exact raw record, `event_time` separate from `collected_at` with an explicit `TimeStatus` (valid, naive_assumed_utc, missing, invalid, out_of_range), typed entities, the relationships the record itself states (`RelationSeed` with the `Predicate` vocabulary), bounded source-native attributes, adapter name and version, a `TrustClass` and `classification` (normalized, partial, unclassified). There is no required severity, vendor alert id or timestamp. A missing or invalid time stays missing; the current time is never substituted.

### 2.2 Adapters (IMPLEMENTED: `evidence_domains/adapters.py`)
Envelope `aisop.evidence/1` (JSON object) handled by six adapters (identity, cloud audit, network, e-mail, forensic, analyst) plus `UnclassifiedAdapter` for structurally valid records of unknown type. Vendor and event-id interpretation lives only inside adapters. Malformed records raise `EvidenceFormatError` with a fixed code and are quarantined; unknown-but-valid records are preserved, never interpreted, never corroborating. Native vendor formats (CloudTrail, Entra, Zeek and similar) are PROPOSED: each would be one more adapter emitting the same `Observation`. File import: `import_file` (JSON array, `{"evidence": [...]}`, or JSON Lines; 5 MiB and record bounds).

### 2.3 Reuse over re-implementation (IMPLEMENTED: `evidence_domains/bridge.py`)
A dated, machine-observed `Observation` is projected to the existing `CorrelationEvent` (severity `informational`, category = evidence type, no kill-chain stage invented). The existing correlator, `evaluate_sufficiency`, `GatedGenerator`, claim validator and report renderer are used unchanged; there is no second gate. Not projected: undated evidence, unclassified evidence and analyst statements (kept as observations and reported separately).

### 2.4 Investigation graph (IMPLEMENTED: `evidence_domains/graph.py`)
Nodes are entities; edges are typed relationships that at least one record states, each with supporting observations, independent support (distinct evidence clusters, so duplicates count once), sources and trust classes. Correlations are the existing correlator's links with strength, time distance and rationale; weak links (host, user, internal IP, process name) are exposed as "context only". Contradictions come from the correlator. Uncertainties (undated, timezone assumed, unclassified, partial, tool-asserted only, weak-only, analyst-only entities, rejected records) are listed explicitly. The graph is derived on demand from preserved raw evidence and stored only as a bounded JSON view; no graph database is introduced (incident-sized graphs fit the in-process quadratic correlation that already exists).

### 2.5 Threat intelligence is context (IMPLEMENTED: `evidence_domains/ti.py`)
`enrich()` attaches `ti_context` statements to entities that were observed; private addresses are never looked up; it cannot change corroboration, sufficiency or ATT&CK output (tested by hash equality of the assessment). Provider: synchronous `IndicatorProvider`; only the offline `StaticIndicatorSet` exists. The async `LocalThreatIntelEngine` is not wired (PARTIAL).

### 2.6 ATT&CK rules (IMPLEMENTED: `evidence_domains/domain_attack.py`, table `domain-attack-v1`)
Seven structural rules (no keyword matching): cloud role assignment, cloud account creation, MFA denial burst, e-mail link followed by DNS lookup, e-mail attachment hash on a host, registry Run key, tool-asserted injection. Analyst statements and TI never satisfy a rule; duplicates cannot inflate thresholds.

### 2.7 Application integration (IMPLEMENTED, no migration)
`POST /api/v1/cases/{case_id}/evidence/domain` (`services/domain_evidence_service.py`): validate, quarantine malformed, preserve raw payload unchanged in `raw_evidence`, deduplicate by SHA-256, write a derived `normalized_events` row, link to the case, write one `case_audit_events` row (counts and hashes, no payloads), all in one transaction. The existing `POST/GET .../investigations/multisource[...]` now routes `aisop.evidence/1` records through the observation path (`normalize_records`), adds sections `graph` and `evidence`, and `WORKFLOW_VERSION` becomes `multi-source-v2` (stored v1 results are not reused).

## 3. Consequences and deliberate limits
* `normalized_events.event_timestamp` is NOT NULL. For undated evidence it holds ingestion time so the row can exist; `normalized_payload` states `event_time: null` and `event_timestamp_is_ingestion_time: true`, and the investigation always re-derives times from the raw payload.
* Known gap (UNVERIFIED fix, documented not hidden): `evaluate_sufficiency` detects opposite outcomes only when sensor identity matches, so a success from one source and a failure from another within two seconds is represented as a correlator contradiction (graph, timeline, report) but does not by itself lower the verdict. See Stage 6 test `test_contradictions_are_represented_in_graph_timeline_and_report`.
* Raw payloads are preserved unredacted by design (evidence integrity); a secrets scan before import is an owner decision (Stage 6 owner register).
* Not validated: PostgreSQL behaviour, live browser behaviour, real vendor formats, real TI feeds, real-model output.

## 4. Alternatives rejected
Graph database (new infrastructure, no demonstrated need); a second correlation engine or gate (divergence from ADR-008/009); making unknown event types a hard error (loses evidence); counting analyst notes as corroboration (a human statement is not independent technical evidence).

## 5. Verification
`backend/tests/unit/test_evidence_domains.py` (49), `test_evidence_domain_scenarios.py` (23), `test_domain_evidence_api.py` (12), `frontend/tests/domain_evidence_panel.test.tsx` (10). See the Stage 6 test report for commands and results.

## 6. Closure addendum (2026-11-12)
Added after independent verification (details: `Stage6_Closure_Report.md`, `Stage6_Security_Review_Addendum.md`):
* Import path hardened: `BodySizeLimitMiddleware` (8 MiB cap for `.../evidence/domain`) and NUL-character quarantine (`CONTROL_CHARACTER`). SQLite and unit tested; PostgreSQL behaviour UNVERIFIED. `/alerts/ingest` has no equivalent limit (pre-existing; owner action).
* The known gap in Section 3 is now partly mitigated: the report prints a "Contradiction notice" beside the verdict when the correlator found a contradiction the gate did not weigh. The verdict logic is unchanged.
* Prompt escaping (`prompt_builder/builder.py`) is a markup-boundary control, not a defence against prompt injection by itself; the protection is the combination of excluding analyst text from the prompt, the sufficiency gate, claim verification, the deterministic fallback and human review (tested with a scripted provider only).
* Status remains PROPOSED. Stage 6 acceptance decision: CONDITIONALLY CLOSED.
