# Panel / Viva Walkthrough: what AISOP can demonstrate today

Every statement is labelled IMPLEMENTED, PARTIAL, PROPOSED, BLOCKED or UNVERIFIED and points to code. Synthetic data only. Prepare by running the demo once (section 1) and have the generated reports open.

## 1. One command to run the demo (IMPLEMENTED)
```
cd D:\AISOP
.venv\Scripts\python.exe backend\scripts\run_multisource_demo.py --out D:\AISOP-Backups\AISOP_Stage3CR_Demo_Output --llm scripted
```
`--llm scripted` exercises the gated LLM path with a deterministic scripted provider (no model, no network). Without it the run is purely deterministic. Output: one folder per scenario with `input_records.json`, `incident_N.md`, `summary.json`, `ledger.json`, plus `index.md`.

## 2. Suggested 10-minute narrative
1. **The problem** (1 min): analysts receive evidence from many tools; the risk is unsupported conclusions. Contribution direction: evidence sufficiency before AI, claim-to-evidence verification, abstention (novelty not claimed; literature review pending).
2. **Scenario 01: multi-source chain** (3 min): open `01_intrusion_chain\incident_1.md`.
   - Section 2 timeline: 10 events from SIEM, Windows identity, Sysmon, DNS/firewall, each with a raw SHA-256 prefix. Code: `correlation/normalize.py: normalize_records`, `correlation/timeline.py: build_timeline`.
   - Section 3 links: strong (logon session, process GUID) and specific (public IP, domain) links; weak links are counted but never form the story. Code: `correlation/correlator.py: correlate`, `evidence/independence.py: entity_link_strength`.
   - Section 4 ATT&CK: six techniques derived by named rules with their limitations; compare "source also asserted it". Code: `correlation/mitre.py: map_techniques`.
   - Section 1 verdict SUFFICIENT with "3 independently corroborating" units. Code: `ai/guardrails/sufficiency_gate.py: evaluate_sufficiency`.
3. **Scenario 02: duplicates and near-duplicates** (1 min): 14 records collapse to 10 evidence units; duplicates cannot inflate corroboration. Code: `independence.py: cluster_evidence`.
4. **Scenario 03: contradiction** (1 min): a failure logged 0.5 s after the success -> verdict LIMITED with `CONTRADICTORY_EVIDENCE`; note the report refuses definitive wording. Code: `correlator.py: find_contradictions`, gate contradiction rule.
5. **Scenario 04: unrelated and weak context** (1 min): other users/hosts stay separate; the same-host benign event is attached as *weak context* and marked as such. Code: `correlate` weak-attachment block.
6. **Scenarios 05 and 06: abstention and uncorroborated** (1 min): unrecognised records -> "Analyst abstention", no model call; a lone SIEM alert -> LIMITED, "asserted-only" technique shown, not trusted.
7. **Fail-closed and no bypass** (1 min): `ai/guardrails/gated_generation.py: GatedGenerator.generate` is the only production caller of `provider.generate`; show the architecture test `backend/tests/unit/test_sufficiency_gated_generation.py::test_no_unguarded_model_generate_call_in_production_tree`.

## 3. Likely questions and where the answer is
| Question | Answer and reference |
|---|---|
| Is the LLM required? | No. `workflow.analyze` is complete without it (IMPLEMENTED). |
| What stops the model being called on weak evidence? | Gate before the model; INSUFFICIENT = no call; exceptions = INSUFFICIENT (`evaluate_sufficiency`, `GatedGenerator`; tests `test_evidence_sufficiency_gate.py`, `test_multisource_workflow.py`). |
| Are two events from the same host two pieces of evidence? | No: host/user/internal IP/process name are weak links (`entity_link_strength`); a different raw record plus a specific link is required (`test_evidence_independence.py`). |
| How do you know the report was not altered? | Hash-chained ledger and context/assessment SHA-256 (`ledger.py: verify_chain`; tamper test). Integrity since submission only (PARTIAL: not persisted). |
| How does it differ from AiSOC? | Fail-closed deterministic pre-model gate; independence rule; explainable link graph; see `docs/10_Research/AiSOC_Adaptation_Register.md`. |
| Accuracy? | PARTIAL, weak. Development-split labels written by the owner (2026-11-25): gate agreement 49.3 %, AI second reviewer agreed with the owner on 35 % of 17 cases (kappa 0.07); held-out unlabelled and unrun (`docs/10_Research/Evaluation/Stage5_Evaluation_Report.md` section 8). |
| Real model results? | UNVERIFIED. Ollama-dependent tests were not run in this stage. |
| Production readiness? | No (single node, batch, synthetic data; credential-exposure remediation pending). |

## 3a. Stage 4: inside the application (ADR-010)
What AISOP does: an analyst opens a case, links evidence ingested from several sources, clicks Start in the Multi-Source Investigation tab, and receives sources, a timeline with provenance, explainable links, rule-derived ATT&CK techniques, a sufficiency verdict with reasons and a report. Difference from a SIEM/SOAR: it does not detect or respond; it assembles and qualifies evidence for a human and abstains when evidence is thin. Difference from AiSOC: fail-closed deterministic gate before any model, independence rule, no streaming platform; adapted concepts are in the adaptation register (rows 1-16). Why deterministic first: reproducible, auditable, injection-resistant; the LLM is optional (`use_llm` off by default), reachable only through `GatedGenerator`, replaceable via the provider protocol, claims verified and LIMITED disclosed. Analyst control: nothing runs automatically; no response action exists. Provenance: each timeline row shows the raw record's SHA-256 prefix and persisted event id. Hallucination and injection controls: gate, claim verification, escaped prompt, escaped UI output.
Status list: IMPLEMENTED offline - endpoints, service, panel tab, idempotency, stale flag, isolation, edge cases (`test_multisource_api.py`, `multisource_panel.test.tsx`, `scripts/run_integrated_demo.py`). PARTIAL - persistence in audit rows, synchronous run. UNVERIFIED - PostgreSQL behaviour, real Ollama output, accuracy (development labels: 49.3 % agreement, not shown reliable; held-out unrun). NOT IMPLEMENTED - background jobs, dedicated table, streaming, response actions.
Demo: `python backend/scripts/run_integrated_demo.py --out <folder on D:>` (in-process app, in-memory SQLite, scripted model).

## 3b. Stage 5: how the system resists manipulation (what was tested)
* **Independent corroboration** (`modules/evidence/independence.py: entity_link_strength, is_informative_value`; `modules/ai/guardrails/sufficiency_gate.py: assess_evidence_sufficiency, corroborates`): a second observation counts only if it is a different raw record, a different kind of observation (host + event id + type + action) and shares a specific artefact (hash, domain, public IP, URL, e-mail, process GUID, non-SYSTEM logon session). Host, user, process name and private IPs are context. Replays and placeholders do not count (found and fixed in Stage 5, `suff-v3`). Demonstrate with `python -m pytest backend/tests/unit/test_stage5_adversarial.py -k "replay or placeholder or weak"`.
* **No unsupported conclusions**: the gate runs before the model (`GatedGenerator`), INSUFFICIENT means no model call, claims are verified (`validator.py`), a hostile model output is demoted (`test_hostile_model_output...`), garbage output falls back to the deterministic report.
* **Provenance**: SHA-256 of every raw record on every timeline row; invented timestamps are rejected (`normalize.py`); the ledger (`ledger.py: Ledger, verify_chain`) is tamper-evident for edits, deletions and reordering, and detects tail truncation only against a trusted head. It is not immutable.
* **Case isolation**: `require_case_role` plus the `case_evidence` join; identical 404 for missing and unassigned cases; tested with variant ids and hostile section names.
* **Resource safety**: 1,000-evidence cap, bounded stored result, 5-call LLM cap, per-case lock (`multisource_investigation_service.py`), bounded parsing (`normalize.py`).
* **What the evaluation establishes**: dataset integrity (hash lock, no leakage, disjoint scenarios) and label-independent behaviour on the development split; accuracy only weakly: development labels exist (gate agreement 49.3 %, labels not shown reliable), held-out was never run and is unlabelled, real-world effectiveness is not claimed (`docs/10_Research/Evaluation/Stage5_Evaluation_Report.md`).
* **What remains unverified**: real-model behaviour, PostgreSQL behaviour, browser-level UI, a compromised sensor forging two kinds of event (R1), credential exposure remediation (owner actions in the security assessment).

## 4. What can be demonstrated honestly
IMPLEMENTED and demonstrable: multi-source normalization with provenance, duplicate/near-duplicate handling, explainable correlation with link strengths, timeline, deterministic ATT&CK derivation with limitations, sufficiency verdicts with reason codes, abstention, gated LLM path with claim verification (scripted provider), verified ledger, reports. PARTIAL: persistence of the ledger and workflow in the case audit tables; API route; adapters beyond the four exercised. BLOCKED/pending owner: sufficiency labels and accuracy metrics, PostgreSQL validation of the audit test, Git checkpoint, credential remediation. Not claimed: novelty, accuracy, production readiness.

## 5. Key files for the panel
`backend/app/modules/correlation/` (`normalize.py`, `correlator.py`, `timeline.py`, `mitre.py`, `ledger.py`, `workflow.py`, `report.py`, `demo_data.py`), `backend/app/modules/evidence/independence.py`, `backend/app/modules/ai/guardrails/sufficiency_gate.py`, `gated_generation.py`, `validator.py`, `backend/tests/unit/test_multisource_workflow.py` (33 tests), `docs/05_Backend/Multi_Source_Investigation_Workflow.md`, ADR-008 and ADR-009.
