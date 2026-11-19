# AISOP — P3-H3B Project Owner Decision Register

## Consolidated Governance, Evidence, Authorization and Acceptance Readiness

**Repository:** `D:\AISOP`  
**Branch:** `main`  
**Last established HEAD:** `c4e877c`  
**Document status:** READ-ONLY governance documentation  
**Project Owner authority:** All pending decisions remain with the Project Owner  

---

## Table of Contents

- [2. Project Context and Established Evidence](#2-project-context-and-established-evidence)
- [3. MITRE Technique Adjudication](#3-mitre-technique-adjudication)
- [4. Acceptance Criteria Evidence Matrix](#4-acceptance-criteria-evidence-matrix)
- [5. Test-Count Reconciliation](#5-test-count-reconciliation)
- [6. Capture-Engineering vs Detection-Quality Distinction](#6-capture-engineering-vs-detection-quality-distinction)
- [7. Conditional Acceptance Finding](#7-conditional-acceptance-finding)
- [8. Project Owner Decision Register (G1–G8)](#8-project-owner-decision-register-g1g8)
- [9. Conditional Dependency Model](#9-conditional-dependency-model)
- [10. Authorization Matrix](#10-authorization-matrix)
- [11. Recommendation Framework](#11-recommendation-framework)
- [12. Evidence Preservation and Historical Audit Records](#12-evidence-preservation-and-historical-audit-records)
- [13. Discrepancy Corrections Against Prior Reports](#13-discrepancy-corrections-against-prior-reports)
- [14. Final Milestone Status and Recommendation](#14-final-milestone-status-and-recommendation)
- [15. Verification Confirmation](#15-verification-confirmation)

---

## 2. Project Context and Established Evidence

### 2.1 Repository and Governance

| Item | Value | Classification |
|------|-------|----------------|
| Repository | `D:\AISOP` | CONFIRMED |
| Branch | `main` | CONFIRMED |
| Last established HEAD | `c4e877c` | CONFIRMED |
| Last established tracked modifications | 48 | CONFIRMED (historical; current count UNVERIFIED) |
| Untracked files | ~212 | CONFIRMED (historical) |
| ADR-001 through ADR-006 | APPROVED | CONFIRMED |

The repository state above is historical evidence, not a claim of current verification. Do not modify Git history, commit, push, reset, checkout, stash, or cherry-pick.

### 2.2 P3-H3B Scenario Inventory

| Category | Count | Scenario IDs | Status |
|----------|-------|--------------|--------|
| ADV (adversarial_ambiguous) | 5 | ADV-001 through ADV-005 | Approved |
| ATO (atomic_technique) | 5 | ATO-001 through ATO-005 | Approved |
| BEN (benign_baseline) | 4 | BEN-001 through BEN-004 | Approved |
| CHN (multi_stage_chain) | 5 | CHN-001 through CHN-005 | Approved |
| **Total approved** | **19** | | **CONFIRMED** |
| BEN-005 | 1 | Draft/unapproved | Excluded from approved count |
| **Total scenario files on disk** | **20** | | **CONFIRMED** |

**Captured fixtures (10):**
- SCN-ADV-002, SCN-ADV-003, SCN-ADV-005
- SCN-ATO-001, SCN-ATO-002, SCN-ATO-003, SCN-ATO-004, SCN-ATO-005
- SCN-BEN-002, SCN-BEN-004

**Approved scenarios unmeasured (8):**
- SCN-ADV-001, SCN-BEN-001, SCN-BEN-003, SCN-CHN-001, SCN-CHN-002, SCN-CHN-003, SCN-CHN-004, SCN-CHN-005

**Separately excluded (1):**
- SCN-ADV-004 (per prior Project Owner instruction after a prolonged operation exceeding two hours)

BEN-005 is draft/unapproved and is **not** one of the 19 approved scenarios. Do not count it as a captured or approved benchmark scenario.

Do not infer additional captures.

### 2.3 Capture Identity and Integrity

Previously established findings:

- Ten fixture files passed reported schema, prompt-hash, raw-response SHA-256, context-hash, certified-digest, and envelope-integrity checks.
- Six fixtures contain provider-reported model identity directly extracted from the Ollama response envelope.
- Four older fixtures use legacy-derived identity compatibility.
- Canonical requested model tag: `llama3.1:8b`.
- Generated assistant persona `AISOP SOC Assistant` is **not** provider model identity.

| Identity Type | Count | Definition |
|---------------|-------|------------|
| Direct provider-identified | 6 | Provider-reported model identifier directly from Ollama response envelope |
| Legacy-derived | 4 | Provider-reported model identifier absent; defaults to requested tag |
| **Total** | **10** | |

Distinguish:
- Requested model identifier.
- Provider-reported model identifier.
- Legacy-derived identity.
- Generated assistant persona.

Do not describe legacy-derived identity as direct provider evidence.

### 2.4 Evaluation Results (Measured Baseline)

The established measured baseline across the ten captured fixtures:

| Metric | Value | Classification |
|--------|-------|----------------|
| TP | 0 | CONFIRMED measured result |
| FP | 10 | CONFIRMED measured result |
| FN | 7 | CONFIRMED measured result |
| Precision | 0.0 | CONFIRMED measured result |
| Recall | 0.0 | CONFIRMED measured result |
| Macro F1 | 0.0 | CONFIRMED measured result |
| Micro F1 | 0.0 | CONFIRMED measured result |
| Benign false positives | 2 | CONFIRMED measured result |

F1=0.0 is a CONFIRMED measured result under the current ground truth and evaluator. It is not an invalid measurement, and it must not be described as invalid or meaningless merely because prompt bias is suspected.

Detection-quality generalizability is LIMITED by:
- Incomplete capture coverage (10 of 19 approved scenarios captured).
- Unresolved ground-truth adjudication.
- Evaluation-policy decisions.
- Strongly indicated but unproven prompt-template bias.

Do not claim that prompt bias is the sole cause of F1=0.0.

### 2.5 Prompt-Template Bias Assessment

| Aspect | Classification | Evidence |
|--------|---------------|----------|
| Hardcoded T1078 example in `builder.py:110-111` | CONFIRMED | `technique_id: "T1078"`, `technique_name: "Valid Accounts"` |
| Hardcoded tactics at `builder.py:112` | CONFIRMED | `tactics: ["Initial Access"]` |
| Hardcoded confidence at `builder.py:114` | CONFIRMED | `confidence: 0.8` |
| Retry forces exactly one MITRE hypothesis | CONFIRMED | `builder.py:390-391` |
| No abstention instruction | CONFIRMED | `builder.py:90-123` |
| 7 of 10 predictions match hardcoded example | CONFIRMED | Fixture extraction |
| 3 of 10 predictions differ | CONFIRMED | T1083 (ATO-004), T1053 (BEN-002), T1055 (BEN-004) |
| Prompt-template bias risk | STRONGLY INDICATED | Strong correlation (7/10 exact match) |
| Prompt bias as sole cause of F1=0.0 | NOT DEMONSTRATED | 3/10 predictions differ; no controlled A/B experiment |

---

## 3. MITRE Technique Adjudication

Preserve the latest established classifications:

| Technique | Classification | Confidence (provenance UNVERIFIED) |
|-----------|---------------|------------|
| T1036.005 Masquerading | SUPPORTED | HIGH |
| T1110 Brute Force | UNSUPPORTED | HIGH |
| T1059.003 Windows Command Shell | SUPPORTED | HIGH |
| T1059.001 PowerShell | SUPPORTED | HIGH |
| T1027 Obfuscated Files | SUPPORTED WITH CONTEXT | HIGH |
| T1071.001 Web Protocols | INSUFFICIENT | MEDIUM |
| T1071.004 DNS | INSUFFICIENT | MEDIUM |
| T1105 Ingress Tool Transfer | INSUFFICIENT | MEDIUM |
| T1003 Credential Dumping | PARTIALLY SUPPORTED | HIGH |
| T1003.001 LSASS Memory | PARTIALLY SUPPORTED, UNCERTAIN | MEDIUM |

**Confidence-column provenance limitation (UNVERIFIED):** The HIGH/MEDIUM labels in the table above lack a traceable repository source and a documented assignment methodology. They are (a) not model-generated confidences — model confidences appear only as numeric values inside captured fixture responses (e.g., `confidence: 0.8` on the biased T1078 hypotheses) and are a separate concept; (b) not ground-truth metadata — ground-truth scenario files carry only `is_mandatory`/`is_uncertain`; and (c) not defined in any inspectable authoritative project document. The classifications themselves are historically established from the P3-H3C adjudication chain and are preserved independently. Confidence in a classification and the provenance of its confidence label are separate matters: the classification stands on the telemetry evidence recorded in the adjudication records; the HIGH/MEDIUM label provenance remains UNVERIFIED pending either a located source or a documented methodology.

**Classification distribution (authoritative, total = 10):** SUPPORTED 3 (T1036.005, T1059.003, T1059.001); SUPPORTED WITH CONTEXT 1 (T1027); PARTIALLY SUPPORTED 2 (T1003; T1003.001 + UNCERTAIN); INSUFFICIENT 3 (T1071.001, T1071.004, T1105); UNSUPPORTED 1 (T1110).

This distribution is the single source of truth for technique classifications within this register. No aggregate such as "7 of 12 mappings well-supported" is used anywhere in this document; prior reports containing that erroneous aggregate are corrected in Section 13.

### 3.1 T1027 Wording Correction

The encoded PowerShell command content in SCN-ATO-001 was decoded locally and not executed during analysis.

The encoding is relevant to evaluating the T1027 hypothesis.

Encoding alone does not establish malicious obfuscation or malicious intent.

Retain SUPPORTED WITH CONTEXT based on the observed evidence and scenario context.

Do not modify ground truth, `is_mandatory`, `is_uncertain`, or evaluator logic.

### 3.2 Historical Correction Traceability — P3-H3C.6.18

- The P3-H3C.6.18 report used overly categorical wording suggesting that encoding made an obfuscation technique observable.
- This register adopts more precise wording: in SCN-ATO-001, encoded PowerShell command content was observed and decoded locally; it was not executed. The encoding is relevant to the T1027 hypothesis, but encoding alone does not establish malicious obfuscation or intent.
- The classification remains SUPPORTED WITH CONTEXT.
- The historical P3-H3C.6.18 report itself was not modified; this note records the correction without rewriting history.

---

## 4. Acceptance Criteria Evidence Matrix

Source: `P3-H3B_Capture_Protocol_Specification.md`, Section 13 ("Engineering Implementation Acceptance Criteria (Future P3-H3B Gate)").

| Criterion ID | Requirement | Existence | Historical Verification | Current Satisfaction | Result | Limitation |
|-------------|-------------|-----------|------------------------|---------------------|--------|------------|
| §13.1 | Exactly 19 approved scenarios processed; SCN-BEN-005 strictly excluded | CONFIRMED (§13.1) | BEN-005 review_status=draft; 19 approved scenario files on disk | PARTIAL | PARTIAL | Only 10 of 19 captured |
| §13.2 | All raw Sysmon events parsed via SysmonParser and projected into ContextEventItem without validation errors | CONFIRMED (§13.2) | P3-H3B spec §7.3: 28 CanonicalEvent instances produced; 0 parsing errors | UNKNOWN | UNVERIFIED | Historical documented result; not re-executed |
| §13.3 | Prompt generation produces byte-identical prompt files and matching SHA-256 hashes across independent runs | CONFIRMED (§13.3) | P3-H3B spec §8; `canonicalize_prompt_artifact()` | UNKNOWN | UNVERIFIED | Code inspection only; no execution |
| §13.4 | All prompt artifacts are valid JSON arrays of message objects, losslessly deserializable into LLMMessage | CONFIRMED (§13.4) | P3-H3B spec §8.3–8.5 | UNKNOWN | UNVERIFIED | Code inspection only; no execution |
| §13.5 | Every completed HTTP exchange produces a valid CapturedInvestigationFixture with accurate prompt_sha256, raw_response_sha256, inference_parameters, and transport metadata | CONFIRMED (§13.5) | P3-H3B spec §6, §9; 10 fixture envelopes have verified SHA-256 hashes | PARTIAL | PARTIAL | Evidence does not extend to uncaptured scenarios |
| §13.6 | Hardened 5-point idempotency: re-running skips valid captures; modifying prompt or inference parameter causes stale detection and recapture | CONFIRMED (§13.6) | P3-H3B spec §10 | UNKNOWN | UNVERIFIED | Documented protocol only; not re-executed |
| §13.7 | Atomic persistence: temporary files (.tmp.<uuid>) and atomic renames prevent file corruption | CONFIRMED (§13.7) | P3-H3B spec §10.3 | UNKNOWN | UNVERIFIED | Documented protocol only; not re-executed |
| §13.8 | Offline replay immunity: replaying all produced fixtures executes cleanly without unhandled exceptions or crashes | CONFIRMED (§13.8) | `AI_Model_Benchmark_Report_Historical_P3H3A.md` shows historical replay; `EvaluationReplayRunner` code | UNKNOWN | UNVERIFIED | Historical report; not current replay of all 10 fixtures |
| §13.9 | Zero arbitrary metric thresholds: harness accepted based on capture fidelity, error accounting, and cryptographic provenance | CONFIRMED (§13.9) | P3-H3B spec §13.9 and MF-01 decoupling finding | UNKNOWN | UNVERIFIED | Policy exists; implementation conformance not independently verified |
| §13.10 | All 920 existing offline unit regression tests continue to pass without regression | CONFIRMED (§13.10) | Milestones.md P3-H3A.6: "53 evaluation tests and 920 full regression tests" | UNKNOWN | UNKNOWN | Current suite reports 1,270 passing (P4-FINAL review); 920-specific count not freshly verified |

**Important:** Finding a requirement in a specification does not mean it has passed. Criteria §13.1 through §13.9 are documented but their current execution status cannot be verified without running tests or replaying fixtures, which is prohibited by this audit's constraints. PARTIAL is not used as a substitute for missing evidence. UNVERIFIED is used where execution or verification evidence is absent.

---

## 5. Test-Count Reconciliation

| Count | Source Document | Context | Milestone | Evidence Status |
|-------|----------------|---------|-----------|-----------------|
| 894 | Milestones.md P3-H3A.2 | "894 full unit regression tests" | P3-H3A.2 | Referenced in Milestones.md only |
| 908 | Milestones.md P3-H3A.4 | "908 full regression tests" | P3-H3A.4 | Referenced in Milestones.md only |
| 920 | Milestones.md P3-H3A.6 | "53 evaluation tests and 920 full regression tests" | P3-H3A.6 | Referenced in Milestones.md only |
| 920 | P3-H3B_Capture_Protocol_Specification.md §13.10 | "All 920 existing offline unit regression tests continue to pass without regression" | P3-H3B acceptance criterion | Referenced in spec only |
| 1,089 | Milestones.md P3-H4 | "15 unit tests, 1,089 regression baseline" | P3-H4 | Referenced in Milestones.md only |
| 1,131 | P4-FINAL review §5.1 | "Backend Unit Tests: 1,131 passed, 0 failed" | P4-FINAL review (Nov 1, 2026) | Executed during P4-FINAL review |
| 77 | P4-FINAL review §5.1 | "Backend Offline Integration Tests: 77 passed, 0 failed" | P4-FINAL review | 77 passed, 0 failed (29 deselected) |
| 17 | P4-FINAL review §5.1 | "Deep Readiness Integration Tests: 17 passed, 0 failed" | P4-FINAL review | Executed during P4-FINAL review |
| 12 | P4-FINAL review §5.1 | "Backup Utility Mock Unit Tests: 12 passed, 0 failed" | P4-FINAL review | Executed during P4-FINAL review |
| 33 | P4-FINAL review §5.1 | "Frontend Vitest Component Tests: 33 passed, 0 failed" | P4-FINAL review | Executed during P4-FINAL review |
| 1,270 | P4-FINAL review §5.1 | "TOTAL VERIFIED OFFLINE BASELINE: 1,270 passing automated tests" | P4-FINAL review | Executed during P4-FINAL review |
| 1,261 | Not found | Not located in searched Markdown documents | N/A | Not found |

These numbers represent **different test suites at different project snapshots**, not a single comparable baseline. The P4-FINAL review explicitly states: "Previous reports mentioned 114 tests (Phase 1), 474 tests (Phase 2), 920 tests (Phase 3), and 1,198 tests (Phase 4C). The current total of 1,270 passing tests accurately accounts for the cumulative additions."

The count **1,261** cited in prior audit reports does **not** appear in any searched repository document and cannot be verified.

Do not claim these are identical or directly comparable test suites. Do not claim that 1,270 is the current verified baseline. Distinguish a reported aggregate from a reproducible test result. Do not claim that 1,261 never existed; state only that it was not located in the searched documents. No tests were run during this audit.

---

## 6. Capture-Engineering vs Detection-Quality Distinction

| Dimension | Status | Evidence |
|-----------|--------|----------|
| Capture-engineering acceptance | PARTIAL | All ten acceptance criteria (§13.1–§13.10) documented in spec; current execution state unknown without re-execution |
| Fixture integrity | VALID | All 10 captured fixtures have verified SHA-256 hashes; prompt hashes verified |
| Identity verification | VALID | 6 direct + 4 legacy-derived identities correctly bound to llama3.1:8b |
| Detection-quality benchmark | LIMITED | F1=0.0 across 10 scenarios; limited for quality claims due to unresolved prompt-bias risk and incomplete coverage |
| Ground-truth validity | PARTIAL | Per Section 3 distribution (total = 10 mappings): 3 SUPPORTED, 1 SUPPORTED WITH CONTEXT, 2 PARTIALLY SUPPORTED, 3 INSUFFICIENT (T1071.001, T1071.004, T1105), 1 UNSUPPORTED (T1110); ground-truth metadata confirmed at source (see G3) |
| Evaluator correctness | VALID | All scoring semantics correctly implemented per source code |

**Key distinction:** The capture protocol engineering acceptance criteria (§13.1–13.10) concern harness fidelity, cryptographic integrity, and deterministic behavior — **not** model detection quality. Per MF-01 (decoupling finding): "A capture harness is successful if it executes faithfully, captures authentic responses without alteration, accounts for all failure modes transparently, and packages envelopes with cryptographic integrity. If the model outputs malformed JSON, hallucinates, or fails schema validation, the harness has NOT failed—the model has failed the benchmark."

**The measured F1=0.0 is a confirmed benchmark result**, not an invalid measurement. It accurately reflects the current model's performance on the ten captured fixtures under the current ground truth. Its generalizability is limited by incomplete capture coverage and unresolved ground-truth adjudication, but the measurement itself is valid.

---

## 7. Conditional Acceptance Finding

**Finding: UNVERIFIED**

The `P3-H3B_Capture_Protocol_Specification.md` Section 13 lists 10 engineering acceptance criteria but does **not** explicitly define a conditional acceptance pathway. Section 15 states:

- "STATUS: REVISION 1.1.1-PROPOSED COMPLETE — AWAITING FORMAL SIGN-OFF"
- "LIVE INFERENCE AUTHORIZATION: STRICTLY PROHIBITED UNTIL SIGN-OFF"
- "CODE IMPLEMENTATION AUTHORIZATION: STRICTLY PROHIBITED UNTIL SIGN-OFF"
- Project Owner Approval: "Status: Awaiting Review"

There is **no documented conditional acceptance route** in the specification.

Therefore:

| Aspect | Classification | Statement |
|--------|---------------|-----------|
| Conditional acceptance route | NOT ESTABLISHED AS AN AUTHORIZED ROUTE | The specification requires formal sign-off; no conditional pathway is documented |
| Conditional acceptance as hypothetical option | PROPOSED | May be presented as a hypothetical Project Owner option, not an available route |
| Conditional acceptance as approved route | NOT APPROVED | No evidence of approval in any examined document |
| Permission inferred from absence of prohibition | NOT VALID | Absence of explicit prohibition does not establish permission |

**Do not select any acceptance option.** The Project Owner retains all approval authority.

---

## 8. Project Owner Decision Register (G1–G8)

Each decision below includes: decision ID, title, decision required, established facts, **unverified facts and evidence gaps**, available options, technical consequences, evidence-integrity impact, reversibility and benchmark comparability, dependencies, recommendation (clearly labelled), Project Owner decision status, implementation authorization status, and current implementation status (distinguishing historical reports from current verification).

### G1 — Prompt Template Remediation

**Decision ID:** G1  
**Title:** Prompt template remediation  
**Decision required:** Whether to approve replacement of the hardcoded `T1078: Valid Accounts` example in `backend/app/modules/ai/prompt_builder/builder.py:110-111` with neutral placeholders and addition of an abstention instruction (e.g., output empty `mitre_attack_hypotheses: []` when evidence is insufficient).

**Established facts:**
- Hardcoded example confirmed at `builder.py:110-111` (`technique_id: "T1078"`, `technique_name: "Valid Accounts"`)
- Hardcoded tactics at `builder.py:112` (`tactics: ["Initial Access"]`)
- Hardcoded confidence at `builder.py:114` (`confidence: 0.8`)
- Retry path demands exactly one MITRE hypothesis at `builder.py:390-391`
- No abstention instruction exists at `builder.py:90-123`
- 7 of 10 predictions match hardcoded example exactly; 3 predictions differ

**Unverified facts and evidence gaps:**
- Established: hardcoded example, tactics, confidence, retry-path directive, and 7-of-10 prediction correlation (historical source inspection and fixture extraction).
- Sole causation of F1=0.0 by prompt bias is NOT PROVEN; 3 of 10 predictions differ and no controlled A/B experiment exists.
- Historical only: the 7/10 correlation derives from the ten captured fixtures; it is not a current measurement.
- Not independently verified: the current on-disk state of `builder.py` was not re-inspected in this reconciliation.
- Evidence to resolve: a controlled re-capture under a neutral prompt (requiring G1/G2/G5 authorization) would isolate prompt-induced bias.
- Project Owner judgment required: yes (G1 decision, plus any re-capture authorization under G5).

**Available options:**
1. Approve remediation design: replace example with placeholders, add abstention, modify retry path
2. Defer remediation: proceed without prompt changes
3. Request alternative remediation design

**Technical consequences:** Approve may reduce template-induced bias and enable honest abstention on benign scenarios. Does not eliminate hallucinations or prove causality. Defer leaves benchmark results subject to template bias risk; F1=0.0 persists under current prompt.

**Dependencies:** Related to G2 (retry path). If prompt-modified capture is desired, G1 must be resolved before that capture. G1 is not a universal prerequisite for G3 or G6.

**Evidence-integrity impact:** Prompt modification can change the effective prompt payload; a changed payload changes the prompt SHA-256; prompt-hash changes interact with idempotency and stale-detection under the documented protocol; existing fixtures may therefore no longer be directly comparable to newly captured fixtures; a separately identified benchmark cohort or recapture may be required for a valid comparison. Recapture is not asserted as mandatory — that depends on the authoritative protocol and a separate Project Owner decision. Existing raw evidence and historical fixtures must remain preserved.

**Reversibility and benchmark comparability:** A prompt edit can itself be reverted as a code change, but model outputs and prompt hashes generated while a modified prompt was active would not match the historical fixture set. Identity-verification comparability is not equivalent to detection-quality comparability; separate baseline cohorts would likely be required. Specific recapture obligations: UNVERIFIED pending G4/G5 decisions. Historical fixtures must not be overwritten or contaminated.

**Project Owner decision:** APPROVED by Project Owner — replace the hardcoded T1078 example with neutral placeholders and add the evidence-driven/abstention instruction  
**Implementation authorization:** GRANTED — limited to the approved G1/G2 source changes and their focused offline regression tests  
**Current implementation status:** IMPLEMENTED (offline) — `OUTPUT_TEMPLATE` hypothesis fields neutralized (`T1078`/`Valid Accounts`/`Initial Access`/`0.8` removed; neutral placeholders in place); `OUTPUT_REQUIREMENTS` now carries the evidence rule (techniques only when evidence-supported; empty `mitre_attack_hypotheses` array valid). Verified by offline regression tests (see implementation report); no live inference or capture performed.  
**Recommended option (historical, pre-approval):** Prioritize G1 as a consideration, but not as a mandatory prerequisite for G3 or G6  
**Cost/privacy/operational impact:** Local editing only; no paid or metered service; minimal compute; no privacy exposure; existing fixtures unchanged and preserved

---

### G2 — Retry-Path Modification

**Decision ID:** G2  
**Title:** Retry-path modification  
**Decision required:** Whether to approve removal or retention of the forced single-MITRE-hypothesis requirement in `build_retry_request` (`builder.py:390-391`).

**Established facts:**
- `build_retry_request` explicitly states: "Output exactly 1 atomic claim citing the event UUID, exactly 1 MITRE hypothesis, 1 alternative explanation, and 1-2 recommended analyst actions."
- Schema does not enforce `min_items` on `mitre_attack_hypotheses`, so empty arrays are schema-valid

**Unverified facts and evidence gaps:**
- Established: the forced single-hypothesis retry directive and schema-valid empty arrays (historical source inspection).
- Schema validity is NOT proof that the model abstains correctly; actual abstention behavior has not been demonstrated.
- Historical only: retry-path behavior is documented from prior source inspection; not re-verified currently.
- Not independently verified: whether retry prompts participate in prompt-hash identity and idempotency under the capture protocol.
- Evidence to resolve: a current source inspection plus a behavioral test (requiring authorization) would establish actual retry/abstention behavior.
- Project Owner judgment required: yes (G2 decision). G2 relates to G1 but neither is a universal prerequisite for the other or for G3–G6.

**Available options:**
1. Approve modification: remove or relax the forced single-hypothesis requirement
2. Retain current behavior: keep "exactly 1 MITRE hypothesis" directive
3. Request alternative: modify to "0-1 MITRE hypotheses" or "output empty array when evidence insufficient"

**Technical consequences:** Modify enables abstention on retry when evidence is insufficient; may reduce false positives on benign scenarios. Retain means retry outputs always contain at least one MITRE hypothesis.

**Dependencies:** Related to G1 (prompt template). G2 approval does not authorize implementation.

**Evidence-integrity impact:** Retry-path modification can change effective prompt payloads and execution behavior; changed payloads can change prompt SHA-256 values; prompt-hash changes interact with idempotency and stale-detection under the documented protocol; fixtures captured before and after the change may not be directly comparable; a separately identified cohort may be required. Existing raw evidence and historical fixtures must remain preserved.

**Reversibility and comparability:** A retry-path change can be reverted as a code change, but response distributions produced under the changed behavior would differ from historical fixtures, altering evaluation results; old and new benchmark results would require separate cohorts for valid comparison. Specific protocol obligations: UNVERIFIED.

**Project Owner decision:** APPROVED by Project Owner — remove the forced single-hypothesis retry requirement and permit evidence-gated abstention (0 or 1 hypothesis)  
**Implementation authorization:** GRANTED — limited to the approved G1/G2 source changes and their focused offline regression tests  
**Current implementation status:** IMPLEMENTED (offline) — `build_retry_request` directive now requires "at most 1 MITRE hypothesis", gates hypothesis inclusion on supplied evidence, and explicitly instructs empty-array abstention when evidence is insufficient. Schema (`investigation.py:563-565`, `default_factory=list`, no minimum) and parser (fallback constructs `mitre_attack_hypotheses=[]`) confirmed to accept abstention without parser failure. Verified by offline regression tests; no live inference or capture performed.  
**Recommended option (historical, pre-approval):** Review and approve modification to allow abstention on retry  
**Cost/privacy/operational impact:** Local editing only; no paid or metered service; minimal compute; no privacy exposure; historical fixtures preserved

---

### G3 — Independent Ground-Truth Review

**Decision ID:** G3  
**Title:** Independent ground-truth review  
**Decision required:** APPROVED by Project Owner — independent adjudication completed; retain all reviewed classifications and metadata. No further G3 decision required unless the Owner revises the policy.

**Established facts:**
- T1071.001 (ATO-002): INSUFFICIENT — TCP/443 connection observed, HTTPS/C2 intent not proven
- T1071.004 (ATO-003): INSUFFICIENT — DNS query observed, DNS-based C2 intent not proven
- T1105 (ATO-004): INSUFFICIENT — file creation observed, no ingress/transfer evidence
- T1003 (ATO-005): PARTIALLY SUPPORTED — LSASS VM_READ access observed, credential extraction not proven
- Ground-truth metadata, directly confirmed at source (read-only inspection of this reconciliation):
  - `datasets/ground_truth/atomic/SCN-ATO-002.json:44-48` — T1071.001: `is_mandatory: true, is_uncertain: false`
  - `datasets/ground_truth/atomic/SCN-ATO-003.json:35-39` — T1071.004: `is_mandatory: true, is_uncertain: false`
  - `datasets/ground_truth/atomic/SCN-ATO-004.json:35-39` — T1105: `is_mandatory: true, is_uncertain: false`
  - `datasets/ground_truth/atomic/SCN-ATO-005.json:36-40` — T1003: `is_mandatory: true, is_uncertain: false`
  - Related, distinct: `SCN-ATO-005.json:43-47` — T1003.001: `is_mandatory: false, is_uncertain: true`

**Unverified facts and evidence gaps:**
- Established: the four disputed telemetry classifications (Section 3) and the metadata values above (directly sourced; confirmed at source during G3 adjudication preparation).
- The telemetry classification (e.g., T1105 = INSUFFICIENT) and the ground-truth metadata (`is_mandatory=true`) are distinct concepts; the metadata records the scenario author's labeling decision, not the strength of telemetry evidence.
- Whether those metadata values are *appropriate* given the INSUFFICIENT/PARTIALLY SUPPORTED classifications was an adjudication question resolved by Project Owner decision: all metadata values retained as-is.
- Not independently verified: whether any repository documentation establishes the intent behind these metadata values beyond the scenario files themselves.

**G3 adjudication disposition (APPROVED):**
| Scenario | Technique | Approved classification | Metadata retained |
|---|---|---|---|
| SCN-ATO-002 | T1071.001 | INSUFFICIENT — RETAIN | `is_mandatory=true, is_uncertain=false` |
| SCN-ATO-003 | T1071.004 | INSUFFICIENT — RETAIN | `is_mandatory=true, is_uncertain=false` |
| SCN-ATO-004 | T1105 | INSUFFICIENT — RETAIN | `is_mandatory=true, is_uncertain=false` |
| SCN-ATO-005 | T1003 | PARTIALLY SUPPORTED — RETAIN | `is_mandatory=true, is_uncertain=false` |
| SCN-ATO-005 | T1003.001 | PARTIALLY SUPPORTED, UNCERTAIN — RETAIN | `is_mandatory=false, is_uncertain=true` |

**Available options:** Decision made — all classifications and metadata retained. Any future revision requires a new Project Owner decision.

**Technical consequences:** No reclassification occurred; FN eligibility and scoring unchanged by G3. Ground-truth changes do not improve model performance; they change how performance is measured.

**Dependencies:** Independently decidable. Does not depend on G1 or G2.

**Evidence-integrity impact:** No label changes were made; historical metrics computed under the existing labels (including the confirmed F1=0.0 baseline) remain valid as measurements against the current label set. Ground-truth files were not edited, and the prior label set is preserved for auditability.

**Reversibility and comparability:** No ground-truth edit was performed; no comparability impact. Metrics remain computed against the existing label set. Historical fixtures are unaffected and their reported metrics remain unchanged.

**Evaluation-policy limitation (documented):** "Mandatory expected targets can produce false-negative penalties even where the available telemetry is insufficient to support confident technique identification. Ground-truth evidence classification and evaluator expectation metadata are distinct. This limitation is documented for future evaluation-policy review; no policy change is authorized by this decision." Historical F1=0.0 remains valid against the original fixtures and original ground-truth labels.

**Project Owner decision:** APPROVED by Project Owner — independent adjudication completed; all five technique dispositions retained as tabulated above.  
**Implementation authorization:** GRANTED for decision recording only — no ground-truth, evaluator, or metric changes authorized.  
**Current implementation status:** IMPLEMENTED (decision recording) — G3 adjudication record updated in this Decision Register; ground-truth files and labels UNCHANGED at the cited locations; no label changes made.  
**Recommended option (historical, pre-approval):** Approve independent review of the four identified labels  
**Cost/privacy/operational impact:** Governance decision only; no paid service; minimal compute; no privacy exposure; existing fixtures unchanged

---

### G4 — Timeout and Retry Policy Changes

**Decision ID:** G4  
**Title:** Timeout and retry policy changes  
**Decision required:** APPROVED by Project Owner — failure-class retry policy (Option C, bounded timeout retry). No further G4 decision required unless the Owner revises the policy.

**Established facts:**
- Prior conflict (now resolved by owner decision): DDR-05 (spec line 94) restricted retries to "HTTP 5xx/disconnect only," while error matrix lines 520–521 permitted "abort or retry (max 2)" for timeout >120s — the spec was internally inconsistent.
- Project Owner decision: G4 APPROVED — Option C, failure-class retry policy:

  | Failure class | Max retries | Max total attempts | Backoff |
  |---------------|-------------|--------------------|---------|
  | HTTP 5xx | 2 | 3 | 2s, then 4s |
  | Connection-establishment failure (`httpx.ConnectError`) | 2 | 3 | 2s, then 4s |
  | Request timeout (>120s) | 1 | 2 | 2s |
  | Mid-transfer disconnect (`httpx.ReadError` / `httpx.RemoteProtocolError`) | 0 | 1 | none |
  | HTTP 4xx | 0 | 1 | none |

- Global settings (unchanged): concurrency=1; per-attempt timeout 120s; `num_predict=1024`. Maximum attempt counts include the initial attempt. Deterministic backoff: 2s before the 1st retry, 4s before the 2nd retry where applicable.
- Implemented in `backend/scripts/capture_live_fixtures.py`: `classify_http_failure()` + explicit retry loop in `execute_single_ollama_inference()`; tenacity removed; misleading docstrings corrected; spec DDR-05 and §11.2 updated (spec version 1.1.2-PROPOSED); harness version 1.1.2 for cohort distinction.
- Verified: 109 offline mocked unit tests pass in `backend/tests/unit/test_capture_live_fixtures.py` covering all five failure classes, attempt limits, recovery, and deterministic backoff.
- Historical capture reports: CHN scenarios and ADV-001, BEN-001, BEN-003 timed out under the old contract (historical only; not re-verified).

**Approved policy (G4 — Option C):** as tabulated above. The DDR-05 / error-matrix conflict is resolved by this owner decision; no contradictory retry instructions remain in the specification.

**Unverified facts and evidence gaps:**
- Established: the approved failure-class policy; its source implementation; mocked unit-test verification.
- Historical only: prior timeout outcomes from capture reports.
- Not independently verified: live Ollama daemon behavior under the new policy — mocked unit tests do not establish live runtime behavior; actual per-scenario attempt counts under live operation; VRAM/resource-usage effect of the policy (no measurements exist).
- Evidence to resolve: none remaining for G4 provenance — the `retry_policy` block is now recorded in batch summaries by `build_retry_policy_provenance()` and covered by offline unit tests. An authorized capture run (G5, when separately authorized) would exercise it end-to-end against the live daemon.
- Project Owner judgment required: no further G4 judgment required unless policy revision is desired.

**Available options:** Decision made — Option C implemented. Any future revision requires a new Project Owner decision.

**Technical consequences:** Timeout failures now consume at most ~242s wall-clock (2 attempts × 120s + 2s backoff) versus up to ~362s under the previous error-matrix behavior; 5xx/connect failures remain at 3 attempts; mid-transfer disconnects and 4xx fail fast on attempt 1. Reduced repeated-hang exposure versus unbounded timeout retry.

**Dependencies:** G5 capture (when separately authorized) will execute under this policy; batch summaries distinguish cohorts via harness version (1.1.2) and recorded configuration.

**Evidence-integrity impact:** Changed capture conditions alter measurement conditions and provenance; fixtures captured under the new policy are distinguishable from historical ones via harness version and batch-summary configuration; old and new cohorts are not directly comparable. No historical fixture overwritten or regenerated.

**Reversibility and comparability:** Policy change is reversible as configuration; separate batch identification required for cross-policy comparison; no historical fixture may be overwritten.

**Project Owner decision:** APPROVED — Option C, bounded timeout retry (failure-class policy above).  
**Implementation authorization:** GRANTED — limited to specification wording, harness retry logic, and focused unit tests.  
**Current implementation status:** IMPLEMENTED (offline, mocked) — source and unit tests verified; live Ollama behavior UNVERIFIED (not established by mocked tests).  
**Recommended option:** N/A — decision already made by Project Owner.  
**Cost/privacy/operational impact:** Local execution only; no paid service; wall-clock per scenario bounded by class-specific attempt limits; VRAM impact UNVERIFIED; no privacy exposure.

**Follow-up authorization (retry-policy provenance):** APPROVED separately by Project Owner — explicit retry-policy provenance recorded in future capture batch summaries (`retry_policy` block: policy id/version, per-class max retries/total attempts, backoff schedule, per-attempt timeout, concurrency). Implemented in `backend/scripts/capture_live_fixtures.py` (`build_retry_policy_provenance()` derived from active constants) with 6 focused offline unit tests; harness version 1.1.2 distinguishes the cohort. Does not authorize capture, live inference, benchmark execution, or historical summary regeneration.

---

### G5 — Remaining Scenario Capture Authorization

**Decision ID:** G5  
**Title:** Authorization to capture eight unmeasured scenarios  
**Decision required:** Whether to authorize capture of ADV-001, BEN-001, BEN-003, CHN-001, CHN-002, CHN-003, CHN-004, CHN-005.

**Established facts:**
- These 8 scenarios timed out during previous capture attempts under the 120s/2-retry contract (up to three total attempts per scenario)
- All are approved scenarios (not draft)
- ADV-004 is separately excluded (see G6)

**Unverified facts and evidence gaps:**
- Established: the eight-scenario list and their approved status (Section 2.2 inventory).
- Historical only: the timeout outcomes derive from historical capture reports.
- Not independently verified: whether these scenarios would time out again under the unchanged existing contract (timeout retryability itself is CONFLICTING / UNVERIFIED — see G4); current state of any partial artifacts from prior attempts.
- Evidence to resolve: an authorized capture run would establish current behavior; a G4 protocol clarification would resolve the retryability conflict first.
- Project Owner judgment required: yes (capture authorization, contract choice).

**Available options:**
1. Approve capture: proceed with current or modified timeout/retry contract (pending G4)
2. Defer capture: proceed without these scenarios; benchmark remains incomplete
3. Request partial capture: authorize capture of a subset only

**Dependencies:** Required for any new capture. May use existing capture contract if G4 changes are not approved. If prompt-modified capture is desired, G1 and G2 must be resolved before that capture.

**Evidence-integrity impact:** New captures must preserve fixture provenance: prompt version/hash, raw-response hash, model identity, capture policy (timeout/retry/concurrency), and batch identity. Cumulative reporting limitations apply: a benchmark total mixing historical and new fixtures must disclose which contract and prompt version produced each fixture; fixtures captured under different prompt versions or capture policies may not be directly comparable.

**Reversibility and comparability:** Capture is additive and does not overwrite existing fixtures (the documented protocol uses atomic persistence); the main comparability requirement is that old and new fixtures be reported as separate cohorts unless provenance is identical. Any overwrite or replacement of historical fixtures would be a serious evidence-integrity violation.

**Project Owner decision:** PENDING PROJECT OWNER DECISION  
**Implementation authorization:** NOT GRANTED  
**Current capture status:** Ten historical fixtures reported (Section 2.3); no new capture performed; HISTORICALLY REPORTED — NOT CURRENTLY RE-VERIFIED.  
**Recommended option:** Approve capture under existing contract if G4 changes are not approved  
**Cost/privacy/operational impact:** Local execution only; longer wall-clock time if timeouts increase; resource occupancy plausible; no paid service; existing fixtures unchanged; new fixtures add to benchmark comparability

---

### G6 — ADV-004 Disposition

**Decision ID:** G6  
**Title:** ADV-004 disposition  
**Decision required:** Whether to maintain ADV-004 exclusion or authorize a separately designed retry attempt.

**Established facts:**
- ADV-004 excluded from capture per Project Owner instruction due to a previous 2+ hour hang
- Repository evidence does not conclusively identify root cause
- No Ollama daemon logs or process traces available

**Unverified facts and evidence gaps:**
- Established: the exclusion instruction and the absence of root-cause evidence in the repository.
- Historical only: the 2+ hour execution account derives from prior owner instruction/reporting.
- Not independently verified: resource behavior during the hang (CPU/GPU/VRAM/memory), whether the hang was model-side, harness-side, or environmental; root cause remains UNKNOWN.
- Evidence to resolve: a separately designed bounded diagnostic (requiring explicit authorization, with process-level safeguards) would be needed; daemon logs from a future attempt.
- Project Owner judgment required: yes (whether any investigation or retry is worth the risk).

**Available options:**
1. Maintain exclusion: ADV-004 remains unmeasured; benchmark covers 18 of 19 approved scenarios at most
2. Authorize separately designed retry: attempt ADV-004 with different parameters
3. Authorize retry with abort conditions: attempt with bounded process-level safeguards and abort conditions

**Dependencies:** Independently decidable; related to capture planning but does not inherently depend on G5

**Evidence-integrity impact:** Any future investigation must preserve prior execution evidence — the exclusion decision, the historical 2+ hour account, and any partial artifacts — and must not overwrite or obscure them. A retry must be identifiable as a distinct batch with its own provenance.

**Reversibility and comparability:** The exclusion itself is reversible only by a new Project Owner decision; a future retry would generate new evidence but cannot retroactively explain the original hang (root cause remains UNKNOWN). ADV-004 results, if any, would form a separate cohort.

**Project Owner decision:** PENDING PROJECT OWNER DECISION  
**Implementation authorization:** NOT GRANTED  
**Current implementation status:** ADV-004 remains excluded; no retry or investigation performed; exclusion basis HISTORICALLY REPORTED.  
**Recommended option:** Maintain exclusion pending a separately designed bounded retry procedure  
**Cost/privacy/operational impact:** Local execution only; risk of prolonged operation without safeguards; unknown local compute requirements of any future diagnostic; no paid service

---

### G7 — P3-H3B Acceptance Criteria and Acceptance Decision

**Decision ID:** G7  
**Title:** P3-H3B acceptance criteria and acceptance decision  
**Decision required:** Whether to accept P3-H3B, and under what criteria.

**Established facts:**
- P3-H3B status: PARTIAL
- Identity infrastructure: valid (all 10 fixtures SHA-256 verified; 6 direct + 4 legacy-derived identities correctly bound to llama3.1:8b)
- Detection quality: F1=0.0 across 10 scenarios; limited for quality claims due to unresolved prompt-bias risk and incomplete capture
- Capture coverage: 10 of 19 approved scenarios measured; 8 unmeasured; 1 excluded
- Ground-truth adjudication: unresolved for T1071.001, T1071.004, T1003, T1105
- Evaluation-policy decisions: unresolved (T1027 optional-but-FP-exposed semantics)

**Unverified facts and evidence gaps:**
- Established: P3-H3B status PARTIAL (Milestones.md); the Section 4 acceptance matrix classifications; F1=0.0 as a confirmed measured result.
- Historical only: fixture SHA-256 verification, identity binding, and the measured baseline derive from historical capture/evaluation reports, not current re-execution.
- Not independently verified: current satisfaction of §13.2–§13.4 and §13.6–§13.10 (UNKNOWN per Section 4); §13.9 implementation conformance (UNVERIFIED).
- Conditional acceptance: PROPOSED / NOT ESTABLISHED AS AN AUTHORIZED ROUTE — no conditional pathway is documented in the authoritative specification (Section 7).
- Evidence to resolve: current verification of the UNVERIFIED criteria, plus Project Owner rulings on the G1–G6 open matters treated here as evidence gaps or risks.
- Project Owner judgment required: yes — acceptance authority rests exclusively with the Project Owner.

**Available options:**
1. Accept P3-H3B with conditions: accept identity infrastructure; defer detection-quality acceptance pending remediation and re-capture
2. Reject P3-H3B: require completion of capture, remediation, and re-evaluation before acceptance
3. Accept P3-H3B unconditionally: not recommended given incomplete coverage and limited detection-quality results

**Dependencies:** Requires an agreed acceptance basis and sufficient evidence, including explicit treatment of deferred items. Resolving a G1–G6 decision is not the same as implementing its proposed action; G7 can be considered once decisions are documented, even if implementation is pending.

**Evidence-integrity impact:** An acceptance decision must preserve the historical evidence basis and explicitly record unresolved limitations; acceptance must not be allowed to retroactively recharacterize UNVERIFIED criteria as satisfied, and the evidence available at acceptance time should be frozen as the acceptance record.

**Reversibility and comparability:** An acceptance decision can formally be revisited, but any later reversal would carry governance cost; acceptance against incomplete evidence would make future re-evaluation results harder to position against the accepted baseline. Separate baselines/cohorts remain available as described in G1/G2/G5.

**Project Owner decision:** PENDING PROJECT OWNER DECISION  
**Implementation authorization:** NOT GRANTED  
**Current implementation status:** P3-H3B status PARTIAL is the current documented milestone state; criteria satisfaction per Section 4 (UNVERIFIED/UNKNOWN where stated); no acceptance action performed.  
**Recommendation:** Do not treat conditional acceptance as an available authorized route. A conditional-acceptance approach may be considered only as a PROPOSED governance option after confirming whether the authoritative milestone specification permits it or requires a separate formal governance decision.  
**Cost/privacy/operational impact:** Governance decision only; no implementation cost; no privacy exposure

**Acceptance criteria evidence matrix:** See Section 4 above. Note that §13.9 implementation conformance is UNVERIFIED and current satisfaction is UNKNOWN. Conditional acceptance remains PROPOSED / NOT ESTABLISHED AS AN AUTHORIZED ROUTE in the specification.

---

### G8 — P3-H4 Unblocking Conditions

**Decision ID:** G8  
**Title:** Conditions for unblocking P3-H4  
**Decision required:** What conditions must be satisfied before unblocking P3-H4.

**Established facts:**
- P3-H4 status: BLOCKED
- Blocked pending P3-H3B completion and acceptance
- Historical report evidence: RateLimitMiddleware and SecurityHeadersMiddleware implemented and tested offline (15 unit tests, 1,089 regression baseline) — HISTORICAL, not current verification

**Unverified facts and evidence gaps:**
- Established: P3-H4 BLOCKED status (Milestones.md) and the formal dependency on P3-H3B completion and acceptance.
- Historical only: the middleware implementation and 1,089-test baseline are historical report evidence.
- Not independently verified: current middleware source state; current regression-suite state (the 1,270 aggregate is also a historical P4-FINAL review figure, not a fresh run).
- Evidence to resolve: current source inspection and a fresh regression run (requiring authorization) would establish current technical readiness.
- Project Owner judgment required: yes — technical readiness does not equal governance authorization to advance.

**Available options:**
1. Unblock after P3-H3B acceptance: P3-H4 proceeds only after P3-H3B is accepted (per G7)
2. Unblock with conditions: P3-H4 proceeds if specific P3-H3B sub-components are complete, even if detection quality is pending
3. Maintain block: P3-H4 remains blocked until all P3-H3B work is complete

**Dependencies:** G8 depends on the P3-H3B acceptance decision (G7) and the authoritative conditions for P3-H4 progression.

**Evidence-integrity impact:** P3-H4 implementation work must not be treated as, or reported as, retroactive proof of P3-H3B acceptance; historical P3-H4 test evidence must remain labelled historical in any progression record.

**Reversibility and comparability:** An unblocking decision is reversible by a new Project Owner decision, but advancement creates dependency expectations; the P3-H3B evidence basis at time of unblocking should be recorded so later P3-H4 results remain interpretable against the correct P3-H3B baseline.

**Project Owner decision:** PENDING PROJECT OWNER DECISION  
**Implementation authorization:** NOT GRANTED — P3-H4 advancement is not authorized  
**Current implementation status:** Middleware implementation HISTORICALLY REPORTED — NOT CURRENTLY RE-VERIFIED; P3-H4 milestone status BLOCKED.  
**Recommended option:** Maintain block until P3-H3B acceptance; then evaluate specific P3-H4 progression conditions  
**Cost/privacy/operational impact:** Governance decision only; no implementation cost; no privacy exposure

---

## 9. Conditional Dependency Model

The dependency model is **conditional**, not a rigid sequence:

```
G1 (Prompt remediation approval) ──┐
G2 (Retry-path approval)           │
G3 (Ground-truth review approval) ─┼──► G7 (P3-H3B acceptance decision) ──► G8 (P3-H4 unblocking conditions)
G4 (Timeout/retry policy) ──┐       │
                             └──► G5 (Capture authorization) ──┘
G6 (ADV-004 disposition) ──────────┘
```

**Dependency classifications:**

| Dependency | Classification | Basis |
|------------|---------------|-------|
| G1 → G2 | RELATED | Prompt/retry design decisions |
| G3 independent | INDEPENDENT | Ground-truth review does not depend on G1 or G2 |
| G4 conditional | CONDITIONAL | Required only if capture contract changes |
| G5 → G4 conditional | CONDITIONAL | G5 may use existing contract if G4 changes not approved |
| G6 independent | INDEPENDENT | ADV-004 disposition independently decidable |
| G1/G2 → prompt-modified capture | REQUIRED BY AUTHORIZATION | If prompt-modified capture desired, G1/G2 must be resolved first |
| G7 depends on G1–G6 decisions | REQUIRED BY AUTHORIZATION | Requires agreed acceptance basis and sufficient evidence |
| G8 depends on G7 | REQUIRED BY SPECIFICATION | P3-H4 blocked pending P3-H3B acceptance |

**G1 is a prioritization recommendation, not a universal prerequisite for G3 or G6.**  
**Resolving a G1–G6 decision is not the same as implementing its proposed action.**  
**G7 can be considered once decisions are documented, even if implementation is pending.**

No dependency is claimed without documentary evidence.

---

## 10. Authorization Matrix

| Activity | Current Authorization | Conditions |
|----------|----------------------|------------|
| Read relevant governance documents | AUTHORIZED | Read-only |
| Create decision register | AUTHORIZED | Documentation only |
| Modify prompt template | AUTHORIZED (G1 scope only) | G1 APPROVED by Project Owner; implemented offline |
| Modify retry logic | AUTHORIZED (G2 scope only) | G2 APPROVED by Project Owner; implemented offline |
| Modify ground truth | UNAUTHORIZED | Explicit G3 approval |
| Change timeout/retry contract | UNAUTHORIZED | Explicit G4 approval |
| Capture eight remaining scenarios | UNAUTHORIZED | Explicit G5 approval |
| Retry ADV-004 | UNAUTHORIZED | Explicit G6 approval |
| Accept P3-H3B | Not granted | Explicit G7 decision |
| Unblock P3-H4 | Not granted | Formal conditions and G8 decision |
| Run live inference | UNAUTHORIZED | Explicit authorization |
| Modify code or fixtures | UNAUTHORIZED | Relevant approval (G1/G2 scope limited to prompt builder and its tests) |

If an activity is not explicitly authorized, do not perform it.

---

## 11. Recommendation Framework

**Recommended next decision:** G1 (Prompt template remediation) — as a prioritization recommendation, not a mandatory prerequisite.

**UPDATE (post-decision):** G1 and G2 have since been APPROVED by the Project Owner and implemented offline (prompt builder neutralized; retry path permits evidence-gated abstention). The recommendation text below is retained as the historical pre-decision record.

**Reasoning:** G1 is the highest-impact prompt-design decision. The hardcoded T1078 example in `builder.py:110-111` is confirmed present, and 7/10 predictions match it exactly. Prompt-template bias is STRONGLY INDICATED as a contributing factor to F1=0.0, but sole causation is NOT DEMONSTRATED (3/10 predictions differ).

**Alternatives:**
- G3 (ground-truth review) first if ground-truth validity is considered higher priority
- G4/G5 (capture policy) first if expanding measured coverage is considered more urgent

**This is a prioritization recommendation, not a mandatory gate.** No implementation is authorized by this recommendation.

### Cost, Privacy, and Operational Impact Summary

| Decision | Cost | Privacy/Data Exposure | Operational Risk |
|----------|------|----------------------|------------------|
| G1 Prompt remediation | None (local editing) | None | Low; reversible; existing fixtures unchanged |
| G2 Retry-path modification | None (local editing) | None | Low; reversible |
| G3 Ground-truth review | Analyst time | None | Low |
| G4 Timeout/retry changes | None directly; longer execution plausible | None | Moderate; longer wall-clock, resource occupancy plausible; VRAM UNVERIFIED |
| G5 Capture authorization | Local execution only | None | Moderate; longer execution if timeouts increase; resource occupancy plausible |
| G6 ADV-004 disposition | Local execution only | None | Moderate; risk of prolonged operation without safeguards |
| G7 P3-H3B acceptance | Governance only | None | None |
| G8 P3-H4 unblocking | Governance only | None | None |

Do not introduce paid services or cloud dependencies. Respect the project's established preference for locally runnable, billing-free workflows.

---

## 12. Evidence Preservation and Historical Audit Records

### P3-H3C.6.15 Procedure Violation (CONFIRMED)

During P3-H3C.6.15:
- `check_ben005.py` was created and executed
- `check_scenarios.py` was created and executed
- `search_test_counts.py` was created and executed

These actions violated P3-H3C.6.15's explicit restrictions against creating and executing helper scripts. The current existence/deletion status of these three scripts remains UNVERIFIED. This audit does not inspect, execute, delete, or restore them.

### P3-H3C.6.16 Scope

The execution record for P3-H3C.6.16 is scoped specifically to that audit. No generalization is made to other audit sessions.

### Historical Test-Count Qualifications

| Count | Source Document | Context | Milestone | Evidence Status |
|-------|----------------|---------|-----------|-----------------|
| 894 | Milestones.md P3-H3A.2 | "894 full unit regression tests" | P3-H3A.2 | Referenced in Milestones.md only |
| 908 | Milestones.md P3-H3A.4 | "908 full regression tests" | P3-H3A.4 | Referenced in Milestones.md only |
| 920 | Milestones.md P3-H3A.6; P3-H3B §13.10 | "53 evaluation tests and 920 full regression tests" | P3-H3A.6 / P3-H3B | Referenced in Milestones.md and spec only |
| 1,089 | Milestones.md P3-H4 | "15 unit tests, 1,089 regression baseline" | P3-H4 | Referenced in Milestones.md only |
| 1,131 | P4-FINAL review §5.1 | "Backend Unit Tests: 1,131 passed, 0 failed" | P4-FINAL review (Nov 1, 2026) | Executed during P4-FINAL review |
| 77 | P4-FINAL review §5.1 | "Backend Offline Integration Tests: 77 passed, 0 failed" | P4-FINAL review | 77 passed, 0 failed (29 deselected) |
| 17 | P4-FINAL review §5.1 | "Deep Readiness Integration Tests: 17 passed, 0 failed" | P4-FINAL review | Executed during P4-FINAL review |
| 12 | P4-FINAL review §5.1 | "Backup Utility Mock Unit Tests: 12 passed, 0 failed" | P4-FINAL review | Executed during P4-FINAL review |
| 33 | P4-FINAL review §5.1 | "Frontend Vitest Component Tests: 33 passed, 0 failed" | P4-FINAL review | Executed during P4-FINAL review |
| 1,270 | P4-FINAL review §5.1 | "TOTAL VERIFIED OFFLINE BASELINE: 1,270 passing automated tests" | P4-FINAL review | Executed during P4-FINAL review |
| 1,261 | Not found | Not found in searched Markdown documents | N/A | Not found |

These numbers represent **different test suites at different project snapshots**, not a single comparable baseline. Do not claim that 1,261 never existed; state only that it was not located in the searched documents.

---

## 13. Discrepancy Corrections Against Prior Reports

| Prior Report Statement | Correction | Reason |
|--------------------------|------------|--------|
| "Detection-quality results are invalid due to unresolved prompt-template bias" | Detection-quality results are LIMITED by incomplete capture coverage, unresolved ground-truth adjudication, evaluation-policy decisions, and unproven prompt-bias risk | F1=0.0 is a confirmed measured result; prompt bias is STRONGLY INDICATED but NOT DEMONSTRATED as sole cause |
| T1105 classified as PARTIALLY SUPPORTED | T1105 is INSUFFICIENT | File creation does not establish ingress transfer |
| "7/12 mappings well-supported" | There are 10 technique mappings; 3 SUPPORTED, 1 SUPPORTED WITH CONTEXT, 2 PARTIALLY SUPPORTED, 3 INSUFFICIENT, 1 UNSUPPORTED | Arithmetic and classification error |
| §6 of this register previously repeated the erroneous "7 of 12 mappings well-supported; T1105 partially supported" aggregate | Corrected in this reconciliation to the Section 3 ten-technique distribution (see also Section 3 distribution totals) | Internal consistency defect found during final traceability verification |
| Evaluator correctness stated as VALID without qualification | Evaluator implementation mechanics are CONFIRMED correct; scoring-policy suitability is DESIGN DECISION REQUIRING OWNER APPROVAL | Implementation correctness ≠ policy appropriateness |
| Rigid dependency sequence G1→G2→G4→G5→G6→G7→G8 | Conditional dependency graph | G3 independent; G4 conditional; G5 may use existing contract; G6 independently decidable |
| "1,261" test count cited | Not found in any searched Markdown document | Search of docs/ found no occurrence of "1,261" or "1261" |
| G1 described as mandatory prerequisite for all downstream decisions | G1 is a prioritization recommendation, not a universal prerequisite | G3, G4, G5, G6 can be decided independently |
| "Every G1–G6 decision must result in implementation before G7" | Resolving a decision ≠ implementing its proposed action; G7 can be considered once decisions are documented | Decision approval ≠ implementation authorization |

---

## 14. Final Milestone Status and Recommendation

### Final Milestone Status

| Milestone | Status | Basis |
|-----------|--------|-------|
| P3-H3B | PARTIAL | 10 captured fixtures; 8 approved scenarios unmeasured; ADV-004 separately excluded; BEN-005 draft and excluded; F1=0.0 confirmed measured result; prompt-template bias STRONGLY INDICATED but sole causation NOT DEMONSTRATED; detection-quality generalizability LIMITED; Project Owner acceptance outstanding |
| P3-H4 | BLOCKED | Blocked pending P3-H3B completion and acceptance |

**P3-H3B is PARTIAL** because its acceptance requirements (§13.1–13.10) are not fully satisfied: only 10 of 19 scenarios captured, ground-truth labels unresolved, evaluation-policy decisions pending, and Project Owner acceptance outstanding. **Not** because prompt bias is proven as the sole cause of poor detection performance.

**P3-H4 remains BLOCKED** pending P3-H3B acceptance. Implementation code exists but formal advancement is gated by P3-H3B acceptance.

### Final Recommendation

**Prompt remediation (G1) is recommended as a prioritization consideration, not a mandatory prerequisite.** The hardcoded T1078 example in `builder.py:110-111` is confirmed present, and 7/10 predictions match it exactly. Prompt-template bias is STRONGLY INDICATED as a contributing factor to F1=0.0, but sole causation is NOT DEMONSTRATED (3/10 predictions differ).

**UPDATE (post-decision, G1/G2 implementation):** G1 and G2 have been APPROVED by the Project Owner and IMPLEMENTED offline (`builder.py` prompt neutralized; retry path permits evidence-gated abstention), verified by offline regression tests. The recommendation text above is retained as the historical pre-decision record. **No claim is made that the prompt changes improve F1 or prove the sole cause of the historical F1=0.0** — no re-evaluation or capture has been performed. **G3–G8 remain PENDING:** the Project Owner must explicitly approve each remaining decision before any further implementation or capture proceeds. P3-H3B remains PARTIAL (G1/G2 implementation does not constitute milestone acceptance) and P3-H4 remains BLOCKED.

**No application repository artifacts were modified during this reconciliation.** No helper scripts were executed. No ground truth, prompts, evaluator code, tests, fixtures, or specifications were changed. The only file modified across the reconciliation tasks is this Decision Register itself (`docs/00_Project_Management/P3-H3B_Project_Owner_Decision_Register.md`). P3-H3B remains PARTIAL. P3-H4 remains BLOCKED. **The Project Owner retains all approval authority.**

---

## 15. Verification Confirmation

This document was produced through read-only document inspection only. No repository files were created, edited, deleted, renamed, moved, or overwritten during the production of this reconciliation report itself (this file is the named deliverable target of the task). No helper scripts were executed. No tests were run. No live inference occurred. No scenarios were captured or recaptured. No Git mutations were performed. No Project Owner decisions were made or implied. P3-H3B remains PARTIAL. P3-H4 remains BLOCKED.

**Final reconciliation note:** The final reconciliation pass (this edit) corrected the §6 ground-truth validity summary to the Section 3 ten-technique distribution, added the §3.2 P3-H3C.6.18 correction-history note, directly sourced the G3 ground-truth metadata from the four atomic ground-truth files, recorded the G4 timeout-retryability specification conflict (DDR-05 vs error matrix), added evidence-gap, evidence-integrity, reversibility/comparability, and current-implementation-status records to G1–G8, qualified the G7 recommendation inline, rebuilt the Table of Contents, and renumbered Sections 9–15.

**G1/G2 implementation note (this edit):** The Project Owner subsequently APPROVED G1 and G2 and authorized bounded offline implementation. G1 and G2 were implemented in `backend/app/modules/ai/prompt_builder/builder.py` with focused offline regression tests in `backend/tests/unit/test_prompt_and_inference_p2.py`, and their records above now report IMPLEMENTED status. **G3–G8 remain PENDING; capture, live inference, ground-truth modification, and P3-H4 progression remain NOT AUTHORIZED.** P3-H3B remains PARTIAL; P3-H4 remains BLOCKED.

**End of Register**
