# ADR-013 Revision 2 Implementation Report (sufficiency-v4, ordering first)

Date: 2026-11-12. Authority: the Project Owner's control file `AISOP_ADR013_Revision2_Implementation_Master_Prompt.md` (D:/AISOP-Control). Outcome: **PARTIAL** (the approved first slice and the cross-source outcome kind are implemented and verified offline; identity, temporal and state kinds are blocked on owner decisions; PostgreSQL, browser and real-model verification NOT RUN). Logs: `D:/AISOP-Backups/Reference_Research_2026-11-12/logs/adr013_impl/` and `.../adr013_final/` (index `results.tsv`).

## 1. Ordering defect: before and after
Reproduced through the real path (HTTP import of six records, stored raw evidence, investigation, persisted result) **before any production change**: `test_adr013_ordering_defect.py` failed (exit 1, log `00_defect_reproduction_BEFORE_fix.log`).
| | Before | After |
|---|---|---|
| Evidence pair | e-mail 2026-11-05 08:00:00Z (`mailgw-synthetic`) and file artefact 07:00:00Z (`dfir-collector-synthetic`), same SHA-256, specific link | same |
| Verdict / reasons | **SUFFICIENT**, `IRRELEVANT_EVIDENCE_EXCLUDED`, corroborating 2 | **LIMITED**, `CONTRADICTORY_EVIDENCE:ordering`, corroborating 1 |
| ATT&CK | T1566.001 derived by `MAP-T1566.001-ATTACHMENT-ON-HOST` on that pair | T1566.001 not derived (T1566.002, T1547.001, T1055 unchanged) |
| Correlator | no contradiction (it knows only opposite outcomes) | unchanged; the pure detector supplies the finding |
Where it was lost: `domain_attack._attachment_on_host` matched on the shared hash only, and neither the correlator nor the gate had any notion of ordering. Fixed by one shared predicate (`attachment_precedes_delivery`) used by both the detector and the rule.

## 2. What changed (behaviour and files)
Created: `backend/app/schemas/contradiction.py`, `backend/app/modules/evidence_domains/contradictions.py`, `backend/tests/unit/test_adr013_ordering_defect.py` (1), `backend/tests/unit/test_adr013_contradictions.py` (29).
Modified (production): `backend/app/schemas/sufficiency.py` (v4, `contradictions`, `has_unresolved_material_contradiction`), `backend/app/modules/ai/guardrails/sufficiency_gate.py` (optional argument, materiality, exclusion, de-dup), `backend/app/modules/evidence_domains/domain_attack.py`, `backend/app/modules/correlation/workflow.py`, `backend/app/modules/correlation/report.py`, `backend/app/services/multisource_investigation_service.py`, `frontend/src/types/index.ts`, `frontend/src/components/DomainEvidencePanel.tsx`, `frontend/src/components/MultiSourcePanel.tsx`.
Modified (tests): `test_contradiction_matrix_spec.py`, `test_contradiction_model_spec.py` (6 strict markers removed because the behaviour is now implemented; 2 re-labelled BLOCKED-AMBIGUOUS; 3 tests updated, see below), `test_evidence_domain_scenarios.py` (1 test replaced), `test_evidence_sufficiency_gate.py`, `test_evidence_independence.py`, `test_multisource_api.py`, `test_multisource_workflow.py` (6 `suff-v3` literals to `suff-v4`), `frontend/tests/domain_evidence_panel.test.tsx` (+5).
Modified (docs): ADR-013 (status and implementation record; Revisions 1 and 2 intact), ADR README row, `CONTRADICTION_AWARE_SUFFICIENCY_DESIGN.md`, `CONTRADICTION_TEST_MATRIX.md`, `SUFFICIENCY_VERDICT_SEMANTICS.md` (implementation records appended), this report.
Deleted: none. No migration, dependency, configuration, dataset or label change.
Tests changed because they documented the old behaviour, not weakened: `test_s5_..._visible_today`, `test_contradictory_network_observations_are_at_least_visible_today` (interim notice replaced by the structured block) and `test_contradiction_beside_a_sufficient_verdict...` (replaced by `test_cross_sensor_contradiction_now_limits_the_verdict_and_is_explained_next_to_it`).

## 3. Contradiction categories, materiality and tolerances actually used
Implemented: **ordering** (`attachment_delivery_order`: e-mail CONTAINS hash H, artefact HAS hash H, artefact strictly earlier, both times `valid`, independent sources) and **outcome** (`signin_outcome`, `connection_allowed`: opposite polarity, independent sources, gap <= 2.0 s). Materiality: ADR decision table rules 1, 3, 5, 6, 7 (weak link -> minor; time zone assumed on ordering -> minor; independent + specific or strong link + relation anchor, corroborating or relevant -> material; else minor). Thresholds are named constants in one module. **Tolerances used:** outcome window 2.0 s (= existing correlator constant, equality tested; A2); **no** clock-skew tolerance for ordering (literal ADR reading; A1); the 10-minute retry window and the 5-second skew tolerance are **not used by any implemented behaviour**. Not implemented: identity, temporal, state (A3, A4).

## 4. Sufficiency-v4 behaviour
Vocabulary unchanged. MATERIAL -> LIMITED with `CONTRADICTORY_EVIDENCE:<kind>`, pair removed from corroboration; never INSUFFICIENT on its own; never raises a verdict; MINOR is disclosure only; findings are in the assessment and its hash; the context hash is unchanged; default argument keeps existing callers unchanged; a stored v3 result is not reused (fingerprint changes; tested). Details: `SUFFICIENCY_VERDICT_SEMANTICS.md`.

## 5. Report, API, UI
Report: a block under the verdict (kind, proposition, materiality, effect, both records with source and UTC time, why, what would resolve it, "not resolved"). API: `incidents[].contradictions[]` (fixed-vocabulary fields only; verified to contain no payload text) and the `sufficiency` section. UI: `ContradictionSection` (alert role only when material), a conflicting-evidence line in the verdict banner, loader merge; results stored before v4 render unchanged. Verified by server-side render tests and typecheck/build only.

## 6. Detection Engineering boundary
No findings, validation or approval interface exists yet (`backend/app/modules/detection_engineering/**` are empty scaffolding; ADR-012 is design only), so nothing could be wired. The integration point is `EvidenceSufficiencyAssessment.has_unresolved_material_contradiction` (tested True for material, False for none or minor): the future findings interface must call it before offering a validated finding; such an incident may only be a lead with the contradiction disclosed. No Detection Engineering feature was implemented.

## 7. Tests (all executed 2026-11-12, 13:51 to 13:53 +05:30, repo venv, from D:/AISOP; every command exit 0)
`pytest` below means `.venv/Scripts/python.exe -m pytest -p no:cacheprovider`.
| Group | Command (args) | Result |
|---|---|---|
| Defect regression (real path) | `backend/tests/unit/test_adr013_ordering_defect.py -v` | 1 passed |
| Detector, gate, report, API, boundaries | `.../test_adr013_contradictions.py -v` | 29 passed |
| Specifications | `.../test_contradiction_matrix_spec.py .../test_contradiction_model_spec.py -v -rxX` | **24 passed, 4 xfailed** |
| Sufficiency family | `test_evidence_sufficiency_gate.py test_evidence_independence.py test_sufficiency_metrics_and_dataset.py test_sufficiency_gated_generation.py -q` | 67 passed |
| Workflow / API / report / scenarios | `test_multisource_workflow.py test_multisource_api.py test_deterministic_report_synthesizer.py test_evidence_domain_scenarios.py -q` | 105 passed |
| Stage 6 suites | `test_evidence_domains.py test_domain_evidence_api.py test_stage6_security.py test_stage6a_hardening.py test_body_limit_regression.py test_domain_service_regression.py -q` | 88 passed |
| Stage 5 adversarial | `test_stage5_adversarial.py -q` | 89 passed |
| Claim guardrails / synthesis | `test_output_guardrails_p2.py test_output_guardrails_secret_leakage.py test_claim_id_normalization.py test_qwen_investigation_synthesis.py -q` | 51 passed |
| **Full backend UNIT** | `backend/tests/unit -q -rxX` | **1579 passed, 4 xfailed**, 0 failed, 0 skipped, 13 warnings (61.91 s) |
| **Backend INTEGRATION, non-PostgreSQL** | `backend/tests/integration -m "not postgres and not ollama" -q` | **85 passed, 33 deselected**, 0 failed |
| PostgreSQL/Ollama | `backend/tests -m "postgres or ollama" --collect-only -q` | 33 collected, **0 executed: NOT RUN (not authorized)** |
| Frontend | `cd frontend; npm run typecheck`, `npm test`, `npm run build` | typecheck clean; **76 passed** (71 + 5), 0 failed; build clean |
| Compile | `compileall -q backend/app`; `py_compile` of the 8 changed backend modules | clean |
Arithmetic: previous unit result 1543 passed + 10 xfailed; now 1579 passed + 4 xfailed = +30 new tests and +6 specifications converted to implementation passes by removing their strict markers. Unit and integration are different directories and are not summed. A mutation check (materiality forced minor; ATT&CK ordering check disabled; workflow not passing findings) made the corresponding tests fail in all three cases, so they are not vacuous.

## 8. Expected failures and known limitations
The 4 remaining expected failures are **unimplemented specifications**, not passing features: S4 and `test_conflicting_identity_attribution...` (A3), S6b and `test_conflicting_timestamps_for_the_same_native_event...` (A4). Limitations: detection only within an incident; observation-based (SIEM/Sysmon alerts produce no candidates); outcome covers sign-in and connection propositions only; per-incident list capped at 50; STATE kind absent.

## 9. Security and residual-risk register
| # | Risk | Status |
|---|---|---|
| R1 | Findings contain only ids, source names, times and fixed vocabulary (tested: no payload text in the finding, API or prompt); the detector and gate are deterministic and run with the LLM disabled; analyst, TI, unclassified evidence and model output cannot create or erase findings (tested) | mitigated, TESTED |
| R2 | Interpretation I-1 (independence = source system) may over-flag: a conflict between two systems that share a method becomes MATERIAL. It can only lower a verdict | ACCEPTED, escalated (A5) |
| R3 | Ordering with no skew tolerance (A1) and unknown `forensic.file` time semantics (A6) can yield false-positive LIMITED | ACCEPTED, escalated |
| R4 | Cross-incident conflicts are not seen; only observation (not alert) evidence is compared | OPEN limitation |
| R5 | New stored fields (`contradictions`) on PostgreSQL JSON and the larger audit row | UNVERIFIED (NOT RUN) |
| R6 | Frontend verified by render tests only | UNVERIFIED in a live browser |
| R7 | `case_service` synthesis path does not receive findings | DEFERRED by owner decision |
| R8 | Pre-existing: importing `evidence_domains.domain_attack` before the `correlation` package raises a circular import (not caused by this change; normal application import order is unaffected) | OPEN, low |

## 10. Protected actions
NOT performed: PostgreSQL access or migration, database/role/volume change, Docker, Ollama, model download, cloud/LLM calls, dependency install, secret/config edit, reading `.env`, `.refact`, `viva-credentials.txt` or `opencode.json`, any Git mutation. PostgreSQL, live-browser and real-model verification: **NOT RUN**.

## 11. Git
Before: HEAD `c4e877c`, branch `main`, 318 status entries. After: HEAD `c4e877c`, branch `main`, 321 entries; the only difference is three new untracked files (`backend/app/schemas/contradiction.py`, `backend/tests/unit/test_adr013_contradictions.py`, `backend/tests/unit/test_adr013_ordering_defect.py`); 0 stashes. No stage, commit, stash, reset, clean, rebase, branch or push. Snapshots: `logs/adr013_impl/git_status_before.txt` and `git_status_after.txt`.

## 12. Owner decisions required
A1 (ordering skew tolerance), A2 (outcome window), A3 (identity), A4 (temporal), A5 (independence definition), A6 (file-time semantics); plus whether to extend to `case_service` next and the standing items (credential rotation, PostgreSQL/browser/real-model authorizations, body-limit default, service-authorization option B).

## 13. Next recommended bounded milestone
Resolve A1 to A6 (a 30-minute owner review), then implement the TEMPORAL and IDENTITY kinds exactly as decided (flipping the 4 strict specifications), and extend the findings to `case_service`; PostgreSQL verification of the new stored fields should be authorized alongside the Stage 5 PostgreSQL run.
