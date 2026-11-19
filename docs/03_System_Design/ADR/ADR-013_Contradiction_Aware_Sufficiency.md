# ADR-013: Contradiction-Aware Evidence Sufficiency

| Field | Value |
|---|---|
| **ID** | ADR-013 |
| **Status** | **APPROVED for implementation (Revision 2)** by the Project Owner, recorded in the control file `AISOP_ADR013_Revision2_Implementation_Master_Prompt.md` (D:/AISOP-Control), 2026-11-12. **Implementation: PARTIAL** (ordering and outcome kinds implemented; identity, temporal and state blocked on owner decisions). Revisions 1 and 2 below are unchanged history. |
| **Date Proposed** | 2026-11-12 |
| **Revises (if approved)** | ADR-008 sufficiency rule table (`suff-v3` -> `suff-v4`). ADR-008 itself is not edited by this document. |
| **Extends** | ADR-009 (correlation), ADR-011 (observations) |

## Context
Stage 6 verification found, and a 2026-11-12 probe confirmed, that `evaluate_sufficiency` returns SUFFICIENT with `corroborating=1` for conflicting records from different sensors (network allow vs deny, sign-in success vs failure), and that two further contradiction kinds are not detected at all (one session bound to two users; one source-native event id with timestamps hours apart). Contradictions are visible in the graph and, since the closure session, in a report notice, but they do not affect the verdict.

## Decision (proposed)
Introduce a deterministic contradiction record with explicit kinds (`OUTCOME`, `IDENTITY`, `TEMPORAL`, `STATE`), materiality (`MATERIAL`, `MINOR`, `EXPLAINED`) derived from link strength, temporal overlap, source independence, reliability class and a closed list of explanation conditions, and feed it to the gate:
* a MATERIAL contradiction adds reason code `CONTRADICTION_UNRESOLVED:<kind>`, caps the verdict at LIMITED, and removes the conflicting pair from the corroborating set;
* EXPLAINED and MINOR contradictions are disclosures only;
* no numeric penalty; a contradiction can never raise a verdict;
* the verdict banner and report headline show it.
Full design: `docs/Architecture/AISOP_ARCHITECTURE_EVOLUTION_PLAN.md` section 10.

## Alternatives considered
Subtract a fixed score per contradiction (rejected: arbitrary, hides cause); leave the gate unchanged and rely on the report notice (current state: a verdict can read SUFFICIENT beside an unresolved conflict); treat every opposite outcome as a contradiction regardless of explanation (rejected: failure-then-retry is benign and is tested as non-contradictory).

## Consequences
Assessment hashes change for incidents with contradictions (rule version bump; stored results with the old version are not reused). Historical evaluation labels are not edited; the new version is run against them and differences are reported to the owner. Specification: `backend/tests/unit/test_contradiction_model_spec.py` (5 passing, 5 strict-xfail that must be un-marked when implemented).

## Open decisions for the Owner
Approve or amend; confirm the closed explanation list and the tolerance windows; decide whether to implement in Stage 6A (recommended) before Detection Engineering.

---
## Revision 2 (2026-11-12, Master Prompt 26): approval package. Status remains PROPOSED. Revision 1 above is unchanged history.
**Status check.** The repository contains no record of owner approval of ADR-013 (ADR README: PROPOSED; closure report: "ADR-008 to ADR-012 approval pending"). This revision does **not** approve it, and **production behaviour was not changed**.

### What changed in the proposal (simplifications found by inspecting the code)
1. **No new reason code.** Revision 1 proposed `CONTRADICTION_UNRESOLVED:<kind>`. The gate already has `ReasonCode.CONTRADICTORY_EVIDENCE` (effect LIMITED) and `SufficiencyFinding.qualifier` (`^[a-z_]*$`), so the proposal becomes `CONTRADICTORY_EVIDENCE:<kind>`.
2. **No new verdict.** "Indeterminate" is expressed as LIMITED plus that code (`SUFFICIENCY_VERDICT_SEMANTICS.md`).
3. **Integration by an optional argument** `evaluate_sufficiency(context, contradictions=())`, not by a new field on `InvestigationContext` (a new field would change every context hash, which ADR-008 treats as an invariant).
4. **Five kinds** (OUTCOME, IDENTITY, TEMPORAL, STATE, ORDERING), materiality by a decision table over link strength, independence, overlap, time quality and relation to the hypothesis; a closed list of explanations.
5. **Defect found while specifying (S7):** ATT&CK rule `MAP-T1566.001-ATTACHMENT-ON-HOST` ignores ordering (a file older than the e-mail still yields the technique and SUFFICIENT). Proposed as the lowest-risk first slice.

### Implementation-gate checklist (Master Prompt 26, section 10)
| # | Gate item | Status |
|---|---|---|
| 1 | Current implementation trace | DONE: `CONTRADICTION_AWARE_SUFFICIENCY_DESIGN.md` section 1 |
| 2 | Contradiction model | DONE (design): section 2 to 4 |
| 3 | Test matrix | DONE (executable specification): `CONTRADICTION_TEST_MATRIX.md`, `test_contradiction_matrix_spec.py` |
| 4 | Compatibility with ADR-008 and ADR-013 | DONE (design): single gate, hash invariants, version bump impact |
| 5 | Expected verdict-semantics changes | DONE: `SUFFICIENCY_VERDICT_SEMANTICS.md` |
| 6 | Affected Stage 5 and 6 regression tests | IDENTIFIED: 8 test lines in 5 files carry `suff-v3`; the rest expected unaffected, to be confirmed by running after step 2 |
| 7 | Bounded implementation plan | DONE: design section 8 (6 steps, 3 to 5 days estimate) |
| 8 | **Owner approval** | **NOT GIVEN: implementation is blocked on it** |

### Decision sheet for the Project Owner
| # | Decision | Recommended | Owner answer |
|---|---|---|---|
| D1 | Approve ADR-013 (Revision 2 design) | Approve | pending |
| D2 | Accept `suff-v3` -> `suff-v4` and update the 8 version literals | Accept | pending |
| D3 | Confirm tolerances: retry window 10 min, clock-skew 5 s, and the closed explanation list | Confirm or amend | pending |
| D4 | First slice: ORDERING/T1566.001 order check (lowest risk), then OUTCOME and IDENTITY | Yes | pending |
| D5 | Extend findings to `case_service` synthesis later | Yes, separate milestone | pending |
| D6 | Detection Engineering must not derive rules from incidents with unresolved MATERIAL contradictions | Yes | pending |
If D1 is answered "approve", the smallest bounded milestone is steps 1 to 3 of the plan; if not, no production file changes.

---
## Implementation record (2026-11-12). Revisions 1 and 2 above are unchanged history.
**Authorization.** The Project Owner approved ADR-013 Revision 2 for implementation, with these binding decisions: sufficiency-v3 -> v4; ordering defect first; case_service deferred; an incident with an unresolved MATERIAL contradiction is not a validated finding for Detection Engineering (it may only be a lead, with the contradiction disclosed); materiality and time semantics exactly as in the approved design, stopping only the decision-dependent behaviour where a definition is ambiguous.

**Implemented (PARTIAL).**
| Item | Status | Where |
|---|---|---|
| Typed findings (ordering, outcome; materiality; relation; explanation `timezone_assumed`) | IMPLEMENTED | `backend/app/schemas/contradiction.py` |
| Pure deterministic detector and the materiality decision table (rules 1, 3, 5, 6, 7) | IMPLEMENTED | `backend/app/modules/evidence_domains/contradictions.py` |
| Single gate integration: optional `contradictions` argument, material -> LIMITED + `CONTRADICTORY_EVIDENCE:<kind>`, pair excluded from corroboration, minor -> disclosure, findings in the assessment and its hash, `suff-v4` | IMPLEMENTED | `sufficiency_gate.py`, `schemas/sufficiency.py` |
| Ordering defect: ATT&CK `MAP-T1566.001-ATTACHMENT-ON-HOST` no longer derives delivery from an artefact older than the e-mail (shared definition with the detector) | IMPLEMENTED | `domain_attack.py::_attachment_on_host` |
| Report block, corrected reason meaning, API `contradictions` per incident, UI section and banner line | IMPLEMENTED (UI by render tests only) | `report.py`, `multisource_investigation_service.py`, `DomainEvidencePanel.tsx`, `MultiSourcePanel.tsx` |
| Detection Engineering predicate `EvidenceSufficiencyAssessment.has_unresolved_material_contradiction` (integration point for the future findings interface; no DE module exists) | IMPLEMENTED (predicate) / NOT IMPLEMENTED (interface) | `schemas/sufficiency.py` |
| IDENTITY, TEMPORAL, STATE kinds; retry-window and clock-skew explanations | **NOT IMPLEMENTED: blocked on owner decisions A1 to A4, A6, or no approved proposition (STATE)** | see below |
| Extension to `case_service` synthesis | DEFERRED by owner decision 4 | n/a |

**Open ambiguities (the exact questions for the owner).** Each stops only the behaviour that depends on it.
| # | Ambiguity | What was done | Owner question |
|---|---|---|---|
| A1 | The ADR defines the 5 s clock-skew tolerance for TEMPORAL conflicts only; the implementation brief says to respect "the approved tolerance definitions" for ordering | literal reading: **no tolerance for ordering** (a 3 s earlier artefact is a contradiction); pinned by a test | Should ordering also tolerate skew of up to 5 s (disclose as EXPLAINED instead of MATERIAL)? |
| A2 | "Within the conflict window" has no number for independent-source OUTCOME pairs | the existing correlator constant 2.0 s is reused (`OUTCOME_CONFLICT_WINDOW_SECONDS`, equality tested) | Confirm 2.0 s or specify another value |
| A3 | IDENTITY: session entities are scoped per issuing system (`system:id`), so a cross-system conflict is not representable; a same-source conflict is MINOR by the table; the spec fixture expects MATERIAL | not implemented; spec stays strict-xfail `BLOCKED-AMBIGUOUS` | How should one session bound to two principals be defined and classified? |
| A4 | TEMPORAL: native event ids are per-source, so the pair is always same-source, which the table scores MINOR (rule 4 "between independent sources" is unreachable); the spec expects MATERIAL | not implemented; strict-xfail `BLOCKED-AMBIGUOUS` | How should same-native-id conflicts be defined and classified? |
| A5 (I-1) | The design text required independence = different source system AND different collection-method family, which contradicts its own fixtures (two IdPs both via API) and the existing independence rules | independence = different source system (existing notion); errs toward more disclosure | Confirm, or require a different collection method (cross-IdP API-export conflicts would then be same-source and MINOR) |
| A6 | The meaning of `event_time` for a `forensic.file` is not defined (arrival on host vs preserved original modification time); an earlier artefact can be benign when the original mtime is preserved, but the closed explanation list has no such member and was not expanded | the ADR as written: earlier artefact with valid times and independent sources is MATERIAL (conservative: it can only lower a verdict) | Add an explanation member or require a timestamp-kind attribute? |

---
## Implementation record 2 (2026-11-12): remaining semantics and case integration. All earlier sections are unchanged history.
**Authorization.** Owner decisions D1 to D8 in the control file `AISOP_ADR013_Remaining_Semantics_and_Case_Integration_Master_Prompt.md` (D:/AISOP-Control) resolve ambiguities A1 to A6 above. Status now: **implemented for ordering, outcome, identity and temporal; case_service integrated; STATE not declared (no approved proposition definition); PostgreSQL, browser and real-model verification NOT RUN (D8).**

| Decision | Resolution | Where (code) | Tests |
|---|---|---|---|
| D1 ordering skew | 5 s tolerance also for ordering: a reversal of 5 s or less is EXPLAINED (`clock_skew_within_tolerance`), never material; more than 5 s is judged by the materiality table; a verified causal relationship is also required | `contradictions.py::CLOCK_SKEW_TOLERANCE_SECONDS`, `_ordering`, `attachment_precedes_delivery`, `classify_materiality` rule 4 | `test_ordering_clock_skew_tolerance_boundaries_D1` (4.999, 5.0, 5.001), `test_temporal_tolerance_boundaries` |
| D2 outcome window | the existing 2.0 s constant, inclusive, meaning only "two records of the same proposition describe the same attempt"; same-source pairs stay with the existing same-sensor detectors; not a correlation window | `OUTCOME_CONFLICT_WINDOW_SECONDS` (equality with `correlator.CONTRADICTION_WINDOW_SECONDS` asserted) | `test_outcome_window_boundaries_below_at_and_above_the_threshold` (1.999, 2.0, 2.001), `test_outcome_window_compares_only_the_same_proposition...` |
| D3 identity | source-local ids are never globally equal. A conflict needs one ISSUER-SCOPED session (the record names its `session_issuer`) attributed to two different canonical principals (`canonical_id` + `canonical_id_issuer`) of the SAME directory. Missing canonical id, different directories, or only different names are unresolved: no finding. Same-source conflicts are MINOR by the table | `_identity`, `_principal`; adapters (`session_issuer`, `canonical_id`) | `test_identity_*`, `test_the_same_local_session_string_in_two_unrelated_systems...`, `test_two_different_names...`, `test_verified_canonical_mapping...`, `test_canonical_ids_from_different_directories...`, `test_same_source_identity_conflict_is_minor...` |
| D4 temporal | the same underlying event is established only by an ISSUER-SCOPED `correlation` stated by both records plus the same evidence type, action and outcome; reliable event times; more than 5 s apart; independence and materiality by the table. Source-native event ids are never used | `_temporal`; adapters (`correlation`); `independence.py` (`event_correlation` is a STRONG entity type) | `test_temporal_*`, `test_source_local_event_ids_alone_never_establish_the_same_event`, `test_a_shared_correlation_id_is_not_enough...` |
| D5 independence | three states: `same_source` (same system, or the same declared `source.upstream_id`), `independent` (different systems, no shared upstream: a minimum signal, not a guarantee), `unknown` (exactly one side declares an upstream). Only `independent` can be MATERIAL. Records sharing a declared upstream are ONE evidence unit in the gate, so mirrored copies cannot corroborate each other. No score | `source_independence`, gate `_evidence_items` | `test_independence_has_three_states...`, `test_mirrored_copies_sharing_an_upstream_collection_do_not_corroborate...`, `test_unknown_independence_is_disclosed_but_never_material`, `test_known_mirrored_copy_of_a_conflicting_record...` |
| D6 earlier file timestamp | no blanket rule. A contradiction needs a VERIFIED causal relationship: the artefact states `origin_message_id` = the e-mail, the e-mail states it CONTAINS the artefact hash, and `timestamp_semantics` is `arrival` or `creation`. The first-slice fixture (earlier timestamp + shared hash) is now the NEGATIVE case. T1566.001 is withheld only for a verified violation | `_verified_causal_link`, `_event_time_means_arrival`, `domain_attack._attachment_on_host` | `test_a_reversal_over_the_tolerance_without_a_causal_relationship...`, `test_a_file_that_merely_predates_the_email_is_not_a_contradiction_through_the_real_path`, S7 and S7 negative |
| D7 case_service | the same `detect_contradictions` and the single gate; `observations_from_stored` re-derives observations from the case's preserved raw payloads; findings passed as the optional gate argument; authorization, case scoping, audit and snapshot untouched | `case_service.synthesize_case_investigation`, `contradictions.observations_from_stored` | `test_adr013_case_service.py` (10) |
| D8 PostgreSQL | not authorized | n/a | NOT RUN |

**Fixture corrections (transparent).** The first-slice ordering fixture, and the S4 (identity) and S6b (temporal) specification fixtures, encoded assumptions D3, D4 and D6 reject (a shared hash proving causality; a bare session string equal across systems; a source-native id proving the same event). Each was replaced by a valid fixture with the assertion unchanged in strength (and extended with the verdict); the old shape was kept as an explicit negative test. All four former strict expected-failures now pass as genuine tests (`29 passed, 0 xfailed` across both specification files).

**New optional evidence fields** (all additive; absent means "relationship not established"): `source.upstream_id`, `correlation{issuer,id}`, `data.session_issuer`, `data.canonical_id`+`canonical_id_issuer`, and for `forensic.file` `data.origin_message_id`+`data.timestamp_semantics`. Documented in `adapters.py`.

**Residual limitations.** Mirrored/forwarded copies are recognised only when the sources DECLARE `upstream_id`; undeclared mirroring is invisible and can only be handled by the existing duplicate and near-duplicate rules. Identity and temporal findings require the producers to emit the issuer-scoped fields above; producers that do not emit them get no such finding (never a guessed one). Detection is per incident / per case; observation-based only (SIEM/Sysmon alerts produce no candidates). The 10-minute retry window is still unused (same-source outcome pairs stay with the existing detectors).
