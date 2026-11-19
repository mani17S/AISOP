# Sufficiency Verdict Semantics

Date: 2026-11-12. Status: describes the **current** (IMPLEMENTED, `suff-v3`) semantics and the **proposed** (ADR-013, NOT IMPLEMENTED, `suff-v4`) extension. Sources: `backend/app/schemas/sufficiency.py`, `backend/app/modules/ai/guardrails/sufficiency_gate.py::_build`, `gated_generation.py`, `guardrails/validator.py`, `correlation/report.py`, `frontend/src/components/MultiSourcePanel.tsx::VerdictBanner`.

## 1. Existing vocabulary (verified)
`SufficiencyVerdict` has exactly three values. Derivation (`_build`): any finding with effect `INSUFFICIENT` -> INSUFFICIENT; else any `LIMITED` -> LIMITED; else SUFFICIENT. `DISCLOSURE` findings never change the verdict.
| Verdict | Meaning today | Model invocation | Claim handling | UI text (`VerdictBanner`) |
|---|---|---|---|---|
| SUFFICIENT | evidence meets the criteria; listed limitations still apply | permitted | normal | "meets the criteria for an investigation" |
| LIMITED | bounded findings only; do not treat as definitive | permitted (the prompt carries a trusted limitation note) | inference claims citing fewer than two independent clusters are demoted (`validator.py:263`, `:533`) | "Bounded findings only. These are NOT confirmed conclusions" |
| INSUFFICIENT | no usable or relevant evidence, or the gate itself failed | **refused** (`GatedGenerator` raises; the platform abstains) | n/a | "No AI analysis was run and no conclusion is offered" |
Reason codes are a fixed vocabulary (`ReasonCode`), optionally qualified (`CODE:qualifier`, qualifier `^[a-z_]*$`, max 64). `CONTRADICTORY_EVIDENCE` already exists with effect LIMITED.

## 2. Does the existing vocabulary express "indeterminate"?
**Yes, without a new enum value.** The prompt asks whether SUFFICIENT / LIMITED / INSUFFICIENT / INDETERMINATE can all be expressed:
* INSUFFICIENT already means "no basis to proceed" and forbids the model. An unresolved contradiction is not that: evidence exists and has been analysed; the analyst can still read the timeline and graph.
* LIMITED already means "bounded findings, not definitive". An investigation that cannot decide between two incompatible statements is the clearest case of that.
* "Indeterminate" is therefore expressed as **LIMITED + reason code `CONTRADICTORY_EVIDENCE:<kind>`** and presented as "Conflicting evidence" in the banner and report. Adding a fourth enum value would change `abstain`, `GatedGenerator`, the validator, the API schema, the frontend types and every consumer of the verdict for no extra behaviour. **Decision proposed: do not add an enum value.**

## 3. Proposed semantics (ADR-013, not implemented)
| Situation | Verdict effect | Reason code | Visible to the analyst |
|---|---|---|---|
| MATERIAL contradiction on the anchor, a corroborating unit, or a relevant independent pair | cap at **LIMITED**; the pair no longer counts as corroborating | `CONTRADICTORY_EVIDENCE:outcome` / `:identity` / `:temporal` / `:state` / `:ordering` | banner conflict line, report conflict block, graph, timeline |
| EXPLAINED discrepancy (closed-list explanation applies) | none | `CONTRADICTORY_EVIDENCE:<kind>` as DISCLOSURE with the explanation in the finding | disclosed, labelled "explained" |
| MINOR (weak link, peripheral, no overlap, assumed time zone) | none | DISCLOSURE | disclosed |
| Contradiction alone | **never INSUFFICIENT** | n/a | n/a |
| A contradiction plus a missing-evidence finding | LIMITED or INSUFFICIENT exactly as the existing rules decide (the contradiction cannot raise a verdict) | both codes | both listed |
| Analyst statement, TI, AI output | **no effect** | none | context sections, labelled |
A contradiction can only **lower** a verdict or add disclosure; it can never raise one, and it is never converted into a numeric penalty.

## 4. What the verdict must explain (report block, proposed)
1. **What supports the hypothesis:** the corroborating units (source, time, shared specific artefact).
2. **What contradicts it:** both records (evidence ids, source systems, times and time quality, the proposition and the two claims), the materiality rationale in one fixed sentence, and whether it affects the verdict.
3. **What remains uncertain:** missing-evidence codes and the unresolved explanation candidates.
4. **What would resolve it** (`resolution_hint`, fixed vocabulary):
| Kind | Hint shown |
|---|---|
| OUTCOME | the native log of either sensor for that exact attempt, or a third independent source |
| IDENTITY | the identity provider's session record for that session id |
| TEMPORAL | original logs with time zone, and time-synchronisation status of both sources |
| STATE | a fresh collection from the host with provenance |
| ORDERING | creation and modification times of the artefact with their provenance |
The report keeps observed facts, derived correlation, external intelligence, analyst statements and AI output in their separate sections (already IMPLEMENTED); a conflict is never described as a confirmed fact in either direction.

## 5. Compatibility
* `suff-v3` behaviour is unchanged for incidents without findings (default argument empty); the version string and therefore the assessment hash change when the version is bumped (8 test lines to update; no dataset file contains a version or assessment hash).
* The existing same-sensor detectors and the unqualified code `CONTRADICTORY_EVIDENCE` are kept; existing tests that assert `"CONTRADICTORY_EVIDENCE" in reason_codes` (`test_multisource_api.py:322`, scenario `03_contradictory_evidence`) keep passing because the new qualified codes are added only for pairs those detectors did not already flag.
* Frontend and API consumers see only additive fields.

---
## suff-v4 as implemented (2026-11-12). Sections 1 to 5 above are unchanged; this states what the code now does.
* Vocabulary unchanged: SUFFICIENT, LIMITED, INSUFFICIENT. "Indeterminate" is LIMITED plus `CONTRADICTORY_EVIDENCE:<kind>` (kinds implemented: `ordering`, `outcome`).
* A MATERIAL contradiction (independent sources, specific or strong link, relation anchor, corroborating or relevant, no applicable explanation) -> `SufficiencyFinding(CONTRADICTORY_EVIDENCE, LIMITED, qualifier=<kind>)`; the verdict is capped at LIMITED; the conflicting pair is removed from the corroborating set (`corroborating_events` falls accordingly). It never forces INSUFFICIENT and never raises a verdict. MINOR findings (weak link, peripheral, or time zone assumed) are `DISCLOSURE`: visible in `reason_codes`, no verdict effect.
* The assessment carries the findings (`assessment.contradictions`) and its SHA-256 covers them; the context hash is unchanged. Calling the gate without the argument gives the same behaviour as before for incidents without findings (the version string, and therefore every assessment hash, changed with v4).
* Detection Engineering: `assessment.has_unresolved_material_contradiction` is True only for MATERIAL findings. Such an incident must not be offered as a validated finding; it may be a lead with the contradiction disclosed. Minor findings do not trip it.
* The prompt for a LIMITED verdict lists the reason codes (so the model sees the limitation); no contradiction payload text exists to leak. Analyst statements, threat intelligence, unclassified evidence and model output can neither create nor erase findings (tested).


---
## suff-v4 complete record (2026-11-12). Earlier sections unchanged.
* Kinds: `ordering`, `outcome`, `identity`, `temporal` (reason codes `CONTRADICTORY_EVIDENCE:<kind>`). STATE is not declared.
* Materiality inputs now used: link strength, independence (`independent` / `same_source` / `unknown`), explanation (`timezone_assumed`, `clock_skew_within_tolerance`), and relation to the hypothesis. MATERIAL needs `independent` + specific/strong link + relation anchor, corroborating or relevant + no explanation. `EXPLAINED` (clock skew within 5 s) and `MINOR` (weak link, assumed time zone, same source, unknown independence, peripheral) are disclosure only. Nothing here can raise a verdict or force INSUFFICIENT.
* Corroboration: a MATERIAL pair is removed from the corroborating set; records that declare the same upstream collection are one evidence unit.
* Detection Engineering: `has_unresolved_material_contradiction` is unchanged and now also covers identity and temporal findings; an incident with such a finding is a lead with the contradiction disclosed, never a validated finding. No Sigma deployment, containment or response was added.
* The case path (`case_service`) and the incident path use the same detector and gate; assessment hashes differ between paths because the case context has no anchor and a per-call investigation id (pre-existing); verdict and reason codes agree (tested).
