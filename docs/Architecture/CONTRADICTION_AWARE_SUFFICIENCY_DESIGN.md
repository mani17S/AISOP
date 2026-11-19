# Contradiction-Aware Sufficiency: Implementation Design

Date: 2026-11-12. Status: **PROPOSED, approval-ready specification. NOT IMPLEMENTED. Production behaviour is unchanged.** Governing record: ADR-013 (PROPOSED; no repository evidence of owner approval; this document does not approve it). Companion documents: `SUFFICIENCY_VERDICT_SEMANTICS.md`, `CONTRADICTION_TEST_MATRIX.md`, `ROUTE_BODY_LIMIT_INVENTORY.md`, `SERVICE_AUTHORIZATION_REVIEW.md`. Labels: IMPLEMENTED, PARTIAL, PROPOSED, UNVERIFIED, NOT IMPLEMENTED.

## 1. Verified execution path (traced from the code, 2026-11-12)
```
POST /api/v1/cases/{id}/evidence/domain          endpoints/cases.py::import_domain_evidence
  -> DomainEvidenceService._import_once           raw_evidence (payload + SHA-256), normalized_events, case_evidence, audit row
POST /api/v1/cases/{id}/investigations/multisource   endpoints/cases.py::start_multisource_investigation
  -> MultiSourceInvestigationService.start        re-reads the case's preserved raw payloads; fingerprint; idempotent reuse
  -> workflow.run_workflow -> workflow.analyze
       normalize.normalize_records                domain envelope -> adapters.parse_record -> Observation -> bridge.observation_to_event
       correlator.correlate                       build_clusters (independence.cluster_evidence: duplicates, near-duplicates),
                                                  links (independence.entity_link_strength: strong/specific/weak), incidents,
                                                  find_contradictions (OUTCOME only: same (host,user,src_ip), success vs failure, <= 2 s)
       per incident:
         workflow.build_incident_context          InvestigationContext (events, entities, flags; contradictions NOT passed)
         sufficiency_gate.evaluate_sufficiency    THE gate: assess_evidence_sufficiency -> findings -> _build -> verdict
         timeline.build_timeline / mitre.map_techniques + domain_attack.map_domain_techniques / graph.build_graph / ti.enrich
         report.render_incident_report            "Contradiction notice" printed beside the verdict (closure addition)
         optional: _llm_for_incident -> GatedGenerator.generate (refuses on abstain or context-hash mismatch)
                   -> InvestigationResponseParser -> InvestigationOutputValidator.validate(parsed, context, assessment)
                   -> apply_sufficiency_disclosure
       ledger entries (hash-chained)
  -> MultiSourceInvestigationService.build_payload   counts.contradictions, contradictions[], incidents[].sufficiency
  -> sections status|timeline|correlation|attack|sufficiency|report|graph|evidence
  -> frontend MultiSourcePanel: VerdictBanner (reasons), contradictions alert (batch level), GraphSection (graph.contradictions)
Other callers of the gate (not through the correlator): case_service.synthesize_case_investigation, investigation_service, evaluation/sufficiency_evaluator.
```
**What the gate does today for contradictions** (`sufficiency_gate.assess_evidence_sufficiency`): three same-sensor detectors on raw context events (same `(source_identifier, event_id, timestamp, action)` with different outcomes; same content with different digests; same logical event with opposite outcomes within the 2 s near-duplicate window **and the same `source_identifier`**). Effect `LIMITED`, reason code `CONTRADICTORY_EVIDENCE`. It never sees the correlator's contradictions, and it keys on `source_identifier` (host, else `sensor:<source>`), so conflicts between different sensors are invisible to it. Verified by probe: cross-IdP success/failure and firewall deny vs flow allow return SUFFICIENT with `corroborating_events = 1`.

**Existing independence rules (preserved, not modified):** `independence.cluster_evidence` (same object, same attested digest, same identity+content+time, or same identity and entities within `NEAR_DUPLICATE_WINDOW_SECONDS = 2.0`), `entity_link_strength` (strong: `process_guid`, `logon_session`; specific: hash, domain, file, registry, URL, e-mail, public IP; weak: the rest), `same_observation_class` (repetition is not corroboration), analyst and TI exclusion (Stage 6).

## 2. Typed contradiction model (PROPOSED)
The seven categories of the brief map onto existing structures; only B and C need new types.
| Category | Representation | Status |
|---|---|---|
| A Supporting evidence | corroborating evidence units (`assessment.corroborating_events`, graph edges with `independent_support`) | exists |
| B Contradictory evidence | **new** `ContradictionFinding` (below) | PROPOSED |
| C Explainable discrepancy | `ContradictionFinding` with `materiality = EXPLAINED` and a closed-list `explanation` | PROPOSED |
| D Missing evidence | `MISSING_REQUIRED_FIELD`, `UNCORROBORATED_QUESTION`, graph `uncertainties`; **new** `resolution_hint` per finding | exists / extended |
| E Stale evidence | `TEMPORAL_ANOMALY`, specific-link window (24 h), `STALE` fingerprint state | exists |
| F Unclassified evidence | `EvidenceFamily.UNCLASSIFIED`, context flag `UNCLASSIFIED_EVIDENCE` | exists |
| G Untrusted external | `TrustClass.TI_CONTEXT`, `ANALYST_OBSERVATION`, `MODEL_INFERENCE`; never inputs to the gate | exists (tested S11, S12, S13) |

```python
class ContradictionKind(StrEnum):   OUTCOME; IDENTITY; TEMPORAL; STATE; ORDERING
class Materiality(StrEnum):         MATERIAL; MINOR; EXPLAINED
class Explanation(StrEnum):         RETRY_SAME_SOURCE; CLOCK_SKEW_WITHIN_TOLERANCE; TIMEZONE_ASSUMED; SEPARATE_ATTEMPTS_PLAUSIBLE;
                                    SHARED_ACCOUNT_PLAUSIBLE; NAT_OR_PROXY_PLAUSIBLE; COLLECTION_DELAY; PARTIAL_VISIBILITY   # closed list
class HypothesisRelation(StrEnum):  ANCHOR; CORROBORATING; RELEVANT; PERIPHERAL
class ContradictionFinding(BaseModel):   # frozen, extra=forbid, fixed vocabulary only (no evidence text)
    kind: ContradictionKind
    materiality: Materiality
    evidence_ids: tuple[UUID, UUID]                  # event uuids present in the context
    sources: tuple[str, str]                         # source systems (already public in the result)
    time_quality: tuple[TimeStatus, TimeStatus]      # valid | naive_assumed_utc (undated records never reach a finding)
    proposition: str                                 # fixed key, e.g. "signin_outcome", "connection_allowed", "session_principal", "event_time", "artefact_precedes"
    claims: tuple[str, str]                          # fixed values, e.g. ("success","failure"), ("allowed","denied")
    link_strength: Literal["strong","specific","weak"]
    independence: Literal["independent","same_source"]
    overlap_seconds: float
    reliability: tuple[TrustClass, TrustClass]       # raw_observed vs tool_asserted ...
    relation: HypothesisRelation
    explanation: Optional[Explanation]
    resolution_hint: str                             # fixed code, see SUFFICIENCY_VERDICT_SEMANTICS.md
    affects_verdict: bool                            # derived: materiality == MATERIAL
```

## 3. What counts as a contradiction (and what does not)
A finding requires **the same proposition key** for both statements and **values that cannot both be true at the time in question**. Sharing an entity is never enough (tests S1, S3, S6 small-skew, S9). Proposition keys and the rule per kind:
| Kind | Proposition (key) | Conflict when | Source in the evidence |
|---|---|---|---|
| OUTCOME | `signin_outcome(user, ip)`, `connection_allowed(src, dst, port)`, `api_outcome(actor, action, resource)` | opposite polarity values within the conflict window | `Observation.outcome`, firewall/flow action, `evidence_type` |
| IDENTITY | `session_principal(session)`, `address_principal(ip, time)` | one `logon_session` bound to two different `user` entities in overlapping time | `RelationSeed` AUTHENTICATED_AS / AUTHENTICATED_FROM |
| TEMPORAL | `event_time(source_native_id)` | same `evidence_id` **within the same source system** reported with times further apart than tolerance | `Observation.evidence_id`, `event_time` |
| STATE | `file_present(host, path)` and similar | present and absent at overlapping times | forensic observations |
| ORDERING | `artefact_precedes(file, email)` | an artefact is timestamped before the event that is claimed to cause it | e-mail delivery vs `forensic.file` (defect today: T1566.001 ignores order) |
Two records from different sources are **not** assumed independent: `independence = independent` requires different `source_system` **and** different `collection_method` family; otherwise `same_source`.
Analyst statements, TI and AI output **never** produce findings (they have no structured propositions; they remain context, tests S11 to S13).

## 4. Materiality (deterministic decision table, no fixed penalties)
Evaluated top to bottom; first match wins.
1. `link_strength == weak` or no temporal overlap -> **MINOR** (disclose).
2. `same_source` and kind OUTCOME and gap within the retry window (proposed 10 minutes) -> **EXPLAINED / RETRY_SAME_SOURCE**.
3. Either `time_quality == naive_assumed_utc` and kind in {TEMPORAL, ORDERING} -> **MINOR / TIMEZONE_ASSUMED** (cannot be a MATERIAL claim on an assumed time zone).
4. Gap within clock-skew tolerance (proposed 5 s) for kind TEMPORAL between independent sources -> **EXPLAINED / CLOCK_SKEW_WITHIN_TOLERANCE**.
5. `relation in {ANCHOR, CORROBORATING}` and `independence == independent` and `link_strength in {specific, strong}` -> **MATERIAL**.
6. `relation == RELEVANT` and independent and specific/strong -> **MATERIAL**; otherwise -> **MINOR**.
7. `relation == PERIPHERAL` -> **MINOR**.
Reliability is recorded, never used to dismiss: a raw-observed vs tool-asserted conflict stays MATERIAL if it touches the hypothesis; the report states which side is the tool interpretation. Tolerances are named constants in one module and are Owner-reviewable (open decision).
`relation` is computed from the gate's own partition: `ANCHOR` = the anchor unit, `CORROBORATING` = a unit in the corroborating set, `RELEVANT` = relevant unit, else `PERIPHERAL`.

## 5. Integration point (the single gate)
* New pure module `backend/app/modules/correlation/contradictions.py`: `detect_contradictions(events, observations) -> tuple[ContradictionFinding, ...]`. It **produces facts, never verdicts**.
* `sufficiency_gate.evaluate_sufficiency(context, contradictions=())` and `assess_evidence_sufficiency(context, contradictions=())`: the gate consumes findings. For each unique pair not already flagged by the existing same-sensor detectors:
  * MATERIAL -> `SufficiencyFinding(code=CONTRADICTORY_EVIDENCE, effect=LIMITED, qualifier=<kind lower-case>, evidence_ids=[pair])` -> reason code `CONTRADICTORY_EVIDENCE:outcome` etc. (the existing `qualifier` field already allows `^[a-z_]*$`, so **no new reason code and no new verdict enum is needed**; this simplifies ADR-013's `CONTRADICTION_UNRESOLVED`).
  * the pair is removed from the corroborating set and counted in `corroborating_events` accordingly;
  * EXPLAINED and MINOR -> `FindingEffect.DISCLOSURE` (visible, no verdict effect).
* `workflow.analyze` computes findings per incident from the events it already holds and passes them in. The existing call `evaluate_sufficiency(context)` keeps working unchanged (default `()`), so the evaluation harness, `case_service` and `investigation_service` are not touched.
* **Context hash invariant:** `InvestigationContext` is not modified (its hash covers every field except four ephemeral ones, so a new field would change every context hash). The assessment hash covers the findings list, so it changes only for incidents that have findings. Rejected alternatives: a typed context field (changes all context hashes), and string-encoded flags in `uncertainty_flags` (stringly typed; kept as a fallback).
* **Rule version:** `SUFFICIENCY_RULE_VERSION` `suff-v3` -> `suff-v4` is part of every assessment hash. Impact measured by grep: 8 test lines in 5 files hard-code `EVIDENCE_SUFFICIENCY[suff-v3]` (`test_evidence_sufficiency_gate.py:271`, `test_multisource_api.py:404-405`, `test_multisource_workflow.py:333-334`, plus docstrings); updating a literal is a documented version change, not a weakened assertion. No file under `datasets/` contains an assessment hash or a rule version string (grep), so evaluation labels are not affected. The held-out split stays untouched.
* **Limitation to carry:** paths that bypass the correlator (`case_service.synthesize_case_investigation`, `investigation_service`) will not receive findings until they compute them from their own events (follow-up; recorded UNVERIFIED).

## 6. Downstream behaviour
* Claim verification: a LIMITED verdict already makes the validator demote inference claims that cite fewer than two independent clusters (`validator.py:263`, `:533`), so no validator change is needed. Measured today: claims that contradict their cited event are demoted or marked `contradicted` (rules `SEC-GR-TIER2-NO-EVIDENCE-MATCH`, `SEC-GR-CONTRADICTED-OUTCOME`).
* Report (`correlation/report.py`): replace the interim "Contradiction notice" with a structured block under the verdict: supports, contradicts (both records, sources, times, time quality, proposition and claims), uncertain, and the resolution hint. Section 5 keeps the list.
* Payload and API: `counts.contradictions` stays; add `contradictions[]` detail (fixed-vocabulary fields only); sections `correlation` and `sufficiency` carry it. Additive, so existing clients are unaffected.
* Frontend: the verdict banner shows a conflict line from the reason code; the graph section already lists contradictions. Render tests required.
* Prompt/RAG boundary: findings are fixed vocabulary plus UUIDs; the existing escaped context builder is unchanged; analyst text, TI text and retrieved knowledge never enter the gate.

## 7. Security and integrity review of the design
Case isolation: findings are computed from the same case-scoped evidence rows. Provenance: findings reference evidence ids and digests only; no payload text. Duplicate handling unchanged (clusters first, then contradictions between **units**, so duplicates cannot manufacture a contradiction; tested S2, S3). Untrusted text: no free text enters a finding. Audit: findings are part of the stored result and the ledger step `SUFFICIENCY`; audit failure still suppresses the result. Deterministic fallback: unaffected. Quadratic cost: pairwise detection is bounded by the existing `MAX_EVIDENCE_PER_RUN = 1000` and per-proposition grouping (group first, compare within groups).

## 8. Bounded implementation plan (only after owner approval of ADR-013)
| Step | Change | Tests |
|---|---|---|
| 1 | `contradictions.py` (types + `detect_contradictions` for OUTCOME across sources, IDENTITY, TEMPORAL) | new unit tests; remove xfail S4, S5, S6-temporal |
| 2 | Gate: optional `contradictions` argument, findings, corroboration exclusion, `suff-v4` | `test_evidence_sufficiency_gate.py` (+ new cases), update the 8 version literals |
| 3 | `workflow.analyze` passes findings; report block; payload detail | `test_multisource_workflow.py`, `test_multisource_api.py`, `test_evidence_domain_scenarios.py` |
| 4 | Remove xfail S5/S15; frontend banner line | frontend render tests |
| 5 | ORDERING kind and the T1566.001 order check (defect S7) | S7 |
| 6 | Dataset delta run (`evaluation/sufficiency_evaluator`, dev split only), report differences, no label edits | evaluator tests |
Affected existing tests (expected to need review): the five files above and `test_sufficiency_pipeline.py` (integration) for the version literal. Not affected: evidence independence tests, report builder tests, claim guardrail tests, Stage 5 adversarial tests (they do not assert the rule version string; to be confirmed by running them after step 2).
Estimated effort 3 to 5 days (planning estimate).

## 9. Acceptance criteria
All strict-xfail markers in `test_contradiction_model_spec.py` and `test_contradiction_matrix_spec.py` removed with tests passing except explicitly deferred ones; no existing assertion weakened; the full offline suites green; a dev-split dataset delta report reviewed by the owner; no change to any label file or `MANIFEST.sha256`.

## 10. Open decisions for the owner
Approve or amend ADR-013; confirm tolerances (retry window 10 min, clock skew 5 s) and the closed explanation list; confirm the version bump and the 8 literal updates; decide whether to fix the ORDERING defect (S7) first as the lowest-risk slice; decide whether `case_service` synthesis should also receive findings.

---
## Implementation record (2026-11-12). The sections above are the approved design and are unchanged. This records where the implementation DIFFERS or is PARTIAL.
Status: ADR-013 Revision 2 approved for implementation by the owner; implementation PARTIAL (ordering and outcome). Details of each open question: ADR-013, "Implementation record" (A1 to A6).
| Design element | Implemented as | Difference from the design text |
|---|---|---|
| Kinds | `ordering`, `outcome` | IDENTITY, TEMPORAL, STATE not implemented (A3, A4; STATE has no approved proposition). The enum declares only the implemented kinds |
| Types | `schemas/contradiction.py`: `ContradictionCandidate` (detector facts), `ContradictionFinding` (+ `relation`, `materiality`, `affects_verdict`) | `Explanation` declares only `timezone_assumed`, the one member the implemented rules can produce; the rest of the closed list stays in the ADR |
| Detector | `evidence_domains/contradictions.py::detect_contradictions` over observations; materiality in `classify_materiality` | the design said `correlation/contradictions.py`; placed under `evidence_domains` because it works on `Observation` and the ATT&CK rule must share the ordering predicate without an import cycle |
| Gate | `evaluate_sufficiency(context, contradictions=())`; relation computed from the gate's partition (anchor, corroborating as it stood BEFORE the conflict, relevant, peripheral); material -> `FindingEffect.LIMITED`, code `CONTRADICTORY_EVIDENCE`, qualifier = kind; pair removed from the corroborating set; findings de-duplicated per (kind, proposition, evidence-unit pair) | as designed. The assessment also carries the findings (`contradictions`) and hashes them |
| Materiality table | rules 1, 3, 5, 6, 7 | rule 2 (retry window, 10 min) and rule 4 (clock-skew, 5 s) are not reachable in this slice: same-source OUTCOME pairs remain with the existing same-sensor detectors, and TEMPORAL is not implemented. **No behaviour depends on the 10-minute or 5-second values** |
| Independence | different `source_system` (I-1, A5) | the design also required a different collection-method family; escalated |
| OUTCOME window | 2.0 s (I-2, A2) | the design gave no number |
| Ordering tolerance | none (I-3, A1) | the design applies the 5 s tolerance to TEMPORAL only |
| Report | structured block under the verdict; the interim "Contradiction notice" is kept only for correlator conflicts the gate did not weigh | as designed |
| Version | `SUFFICIENCY_RULE_VERSION = "suff-v4"`; stored v3 results are not reused (the fingerprint includes the version; tested) | 6 functional version literals in 4 test files updated; 2 historical comments left; no dataset or label file touched |
| `audit_details` | unchanged fixed shape | an extra key was tried and removed because an existing test pins the exact shape |
| Detection Engineering | predicate `has_unresolved_material_contradiction` | the findings interface does not exist (ADR-012 design only); the predicate is the documented integration point |
| Frontend | `ContradictionSection`, banner line, incident wiring, loader merge | additive; results stored before v4 render unchanged |
| case_service | not extended | owner decision 4 |
Known limitations: contradictions are detected only among observations in the same incident; SIEM/Sysmon alerts produce no candidates (observation path only); only sign-in and connection propositions exist for OUTCOME; the list per incident is capped at 50 in the stored result.


---
## Implementation record 2 (2026-11-12): remaining semantics, independence, case_service. Earlier records are unchanged history.
Owner decisions D1 to D8 resolved the open questions A1 to A6 (mapping and code locations: ADR-013, "Implementation record 2"). Semantic decision table applied:
| Topic | Decision applied |
|---|---|
| Ordering | verified causal relationship REQUIRED (artefact states `origin_message_id`; e-mail states it CONTAINS the hash; `timestamp_semantics` is `arrival` or `creation`); reversal <= 5 s = EXPLAINED (clock skew); > 5 s = table; naive time = MINOR (rule 3); missing time = no finding. An earlier timestamp with no causal requirement is NOT a contradiction (D6) |
| Outcome | `signin_outcome(user, ip)` and `connection_allowed(src, dst, port)`; opposite polarity; independent sources; gap <= 2.0 s inclusive (the existing correlator constant; the window means only "same attempt", nothing else) |
| Identity | issuer-scoped session + two canonical principals of one directory; everything else unresolved, never guessed; same-source = MINOR |
| Temporal | issuer-scoped `correlation` shared by two records of the same type/action/outcome; reliable times; > 5 s; independence and the table decide |
| Independence | `independent` / `same_source` / `unknown` from system names and declared `upstream_id`; only `independent` can be MATERIAL; declared-shared upstream = one evidence unit (cannot corroborate) |
| Reuse | no second value for any constant: 2.0 s and 86400 s are the existing correlator constants (equality tested); 5 s is one named constant used by ordering and temporal |

**Data-model additions (additive, optional, source-stated):** see the `backend/app/modules/evidence_domains/adapters.py` docstring. They exist because the previous model could not state a causal origin, a canonical identity, an issuer-scoped session, an issuer-scoped event correlation or a shared upstream; without them the owner's conditions cannot be satisfied and nothing would be inferred.

**Correlator surfacing:** every detector finding is also added to the correlator's contradiction list (reason `<KIND>_CONFLICT`, skipping pairs the correlator already reported), so the graph, timeline `contradicts` markers, counts and the batch alert show it; the gate still alone decides the verdict.

**case_service:** see `CASE_SERVICE_CONTRADICTION_INTEGRATION.md`.

**Event time vs ingestion time:** the detector reads only `Observation.event_time` (the record's own time) and `time_status`; `collected_at` and the stored `normalized_events.event_timestamp` column (which holds ingestion time for undated records) are never compared (tested).

Still not implemented: STATE; rule 2 (10-minute retry window); undeclared mirror detection.
