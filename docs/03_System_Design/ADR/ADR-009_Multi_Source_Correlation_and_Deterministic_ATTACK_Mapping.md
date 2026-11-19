# ADR-009: Multi-Source Evidence Correlation, Timeline and Deterministic ATT&CK Mapping

| Field | Value |
|---|---|
| **ID** | ADR-009 |
| **Status** | PROPOSED (implemented as a vertical slice on 2026-11-12, integrated into the case API by ADR-010; Project Owner approval pending) |
| **Date Proposed** | 2026-11-12 |
| **Decision Maker** | Project Owner |
| **Supersedes / Extends** | Extends ADR-007 (vendor-neutral alert ingestion), ADR-008 (evidence-sufficiency gate), ADR-001 (direct LLM abstraction). Supersedes nothing. ADR-004's deferral of Zeek/Suricata/EVTX parsers is unchanged. |

Claim labels used below: IMPLEMENTED (code and tests exist), PARTIAL, PROPOSED, BLOCKED, UNVERIFIED.

## 1. Context
AISOP had vendor-neutral adapters (ADR-007) and a post-hoc claim validator, but no component that joined evidence from different sources into an explainable incident, no deterministic ATT&CK derivation (techniques came from source tags or from the LLM and were only syntax-checked), no investigation timeline spanning sources, and no tamper-evident record of what the pipeline did. ADR-008 added a pre-model sufficiency gate; it needs a principled notion of *independent* evidence that the correlator can share. The research objective (evidence-driven investigation with sufficiency gating, claim-to-evidence verification and abstention) requires a deterministic workflow that remains useful without an LLM.

## 2. Decision (all IMPLEMENTED unless stated)
1. **One shared definition of independence** (`app/modules/evidence/independence.py`): events collapse into *evidence clusters* (same event, same attested raw digest, identical content, or near-duplicate within 2 s). Shared entities have a **link strength**: STRONG (logon session, process GUID), SPECIFIC (file hash, domain, file, registry key, URL, e-mail, public IP), WEAK (host, user, internal IP, process name). Corroboration needs a different attested cluster joined by a strong or specific link. The sufficiency gate (`suff-v2`), the claim validator (independent support groups instead of distinct UUIDs) and the correlator all use it.
2. **Normalization reuses the ADR-007 adapter registry** (`correlation/normalize.py`), adds identity normalization (`CORP\jdoe` = `jdoe@corp.local` = `jdoe`), Sysmon process/session/DNS identifiers read from the preserved raw record, an optional asset inventory (IP to host, labelled `asset_inventory`), and the SHA-256 of every raw record. Unnormalizable records are rejected with fixed reason codes, never dropped silently.
3. **Explainable correlation** (`correlation/correlator.py`): typed links between evidence clusters; incidents are the connected components over strong and specific links; a weak link may attach a *lone* observation as context but never merges two multi-evidence groups (those are reported as weakly related); three or more distinct kill-chain stages in the core raise severity to at least `high`.
4. **Deterministic ATT&CK mapping** (`correlation/mitre.py`, version `attack-map-v1`): six explicit rules over de-duplicated evidence; each mapping names its rule, evidence, independent evidence count, whether a source also asserted it, and a limitation. Source assertions with no derivation are reported as *asserted-only*.
5. **Timeline** (`correlation/timeline.py`): chronological, per-entry stage, membership (core or weak context), duplicates collapsed, contradictions, raw-digest prefix.
6. **Hash-chained ledger** (`correlation/ledger.py`) recording each workflow step; tampering, deletion and reordering are detected by `verify_chain`.
7. **Workflow and report** (`correlation/workflow.py`, `correlation/report.py`): normalize, correlate, then per incident build the existing `InvestigationContext`, run the ADR-008 gate, map techniques, render a deterministic analyst report; an LLM step is optional, only reachable through `GatedGenerator` after a permitting assessment, followed by the existing parser and claim validator; failures fall back to the deterministic report. The sufficiency verdict is printed in the report body.
8. **No new dependency, service or schema.** The existing audit table is unchanged; `workflow_audit_details` produces a payload-free dictionary that fits `case_audit_events.details` (the database write is not wired: PARTIAL).

## 3. Alternatives considered
(A) Port AiSOC's Redis/Kafka correlator: rejected (new infrastructure, tenancy and streaming scope not needed; AiSOC's STRONG/SPECIFIC/WEAK idea is adopted instead). (B) Correlate by shared host/user/IP strings: rejected (welds unrelated activity and inflates corroboration; AiSOC documents the same failure). (C) Let the LLM correlate and map ATT&CK: rejected (non-deterministic, injectable, cannot be audited; ADR-001 and ADR-008 prefer deterministic processing before optional LLM assistance). (D) Probabilistic/graph-ML correlation: deferred (needs labelled data and a literature basis). (E) Persist the ledger in the database now: Stage 4 (ADR-010) stores the ledger head and step hashes inside the audit-row result document (PARTIAL; a dedicated table remains deferred and needs a migration decision).

## 4. Consequences
Positive: explainable incidents and mappings; honest handling of weak relationships; one independence notion shared by the gate, validator and correlator; deterministic reports usable without a model; tamper-evident run record. Negative: only four adapter source types and six ATT&CK rules are covered; correlation is quadratic in evidence clusters (incident-sized batches, not streaming); synthetic scenarios only; weak-link policy may under-group genuine attacks that lack strong or specific links (visible as weakly related incidents).

## 5. Security implications
Evidence text is data: the correlator and mapper never execute or follow it; regular expressions run on bounded strings (command lines truncated to 500 characters at normalization); rejected records are preserved with a digest, not echoed; reports contain no credentials; the gate remains fail closed and is the only route to a model; asset inventory attribution is labelled and weak-linked, so a wrong inventory entry cannot create corroboration. Residual: a source that forges a shared public IP, domain or file hash can create a specific link (the ledger and raw digests make this auditable, not impossible).

## 6. Evaluation
Engineering tests with six synthetic scenarios (multi-source chain, duplicates and near-duplicates, contradiction, unrelated and weak context, unparseable batch, single uncorroborated alert) and unit tests for every module (`backend/tests/unit/test_multisource_workflow.py`, `test_evidence_independence.py`). These assert behaviour on synthetic data; they are not accuracy measurements and do not establish research novelty.

## 7. Implementation references
`backend/app/modules/correlation/` (`normalize.py: normalize_records`, `correlator.py: correlate`, `timeline.py: build_timeline`, `mitre.py: map_techniques`, `ledger.py: Ledger, verify_chain`, `workflow.py: analyze, run_workflow`, `report.py: render_incident_report`); `backend/app/modules/evidence/independence.py: cluster_evidence, entity_link_strength`; `backend/scripts/run_multisource_demo.py`; walkthrough in `docs/12_User_Guides/Panel_Viva_Walkthrough.md`; architecture in `docs/05_Backend/Multi_Source_Investigation_Workflow.md`; adaptation register in `docs/10_Research/AiSOC_Adaptation_Register.md`.

## Stage 5 addendum (2026-11-12)
`normalize_records` now rejects, with fixed reason codes, records that cannot be placed or processed safely: `TIMESTAMP_MISSING_OR_INVALID` (the ADR-007 adapters substitute the current time for a missing or unparseable timestamp; the engine no longer keeps an invented time), `RECORD_TOO_DEEP` (nesting above 32), `RECORD_TOO_LARGE` (canonical JSON above 1 MiB), `RECORD_NOT_SERIALIZABLE`. `verify_chain` fails closed on malformed input and accepts an optional trusted `expected_head` to detect a truncated tail; the ledger is tamper-evident, not immutable. The workflow caps model invocations at 5 per run (`MAX_LLM_INCIDENTS`). Decisions unchanged; status PROPOSED.
