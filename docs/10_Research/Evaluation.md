# Research Question, Hypothesis and Evaluation Status

Written 2026-11-21. This page separates what is defined from what has been run. Nothing here reports an accuracy, detection rate or speed that the saved logs do not show.

## Research question
Does treating duplicate, non-independent and non-observational items as non-corroborating, and abstaining when independent evidence is insufficient, produce fewer unsupported investigation conclusions than naive correlation, on the same multi-source evidence?

## Hypothesis (H1)
On a fixed set of documented synthetic scenarios (with injected duplicates, replays, analyst notes, threat-intelligence-only support and contradictory records), AISOP's gate yields a lower **false-sufficient rate** and a lower **unsupported-claim rate** than a naive baseline that counts every matching record as corroboration. It will also abstain more often, and that cost is reported.

## What would falsify it
- AISOP's false-sufficient rate is equal to or higher than the baseline's on the held-out scenarios.
- Or its abstention is so high that the share of usable conclusions collapses.
Either result is reported as it is.

## Arms
B0 naive correlation (any two records sharing an entity corroborate); B1 B0 plus exact-duplicate removal; AISOP (clusters, link tiers, contradictions, gate). A model-only arm is added only if a local model run is verified.

## Status, exactly as logged
| Item | Status | Evidence |
|---|---|---|
| Datasets: 115 derived sufficiency cases (67 development, 48 held-out) from hand-authored scenarios, hash-locked; 20 ground-truth scenarios | Exist. **Synthetic and author-built**; nothing is real telemetry. | `docs/10_Research/Evaluation/Stage5_Evaluation_Report.md` |
| Label-independent behaviour on the development split (rule `suff-v3`) | **Run (2026-11-12).** Verdicts: 11 sufficient, 52 limited, 4 insufficient; evidence references valid 67 of 67; the 4 insufficient cases made no model call. These are behaviour figures, **not accuracy**. | same report |
| Adversarial corroboration tests (duplicates, replays, weak links, hostile text) | **Run**, in the unit suite (3,166 passed, 1 skipped on the last recorded run). They show rule behaviour on constructed inputs, not how often the rules are right on real incidents. | `D:\AISOP-Backups\AISOP_Verify_Logs\20261121_115313\unit.log` |
| Owner labels for the cases (`labels.json`) | **Not written.** Accuracy, error rates and agreement are therefore not computed. | Stage 5 report |
| Baselines B0 and B1 | **Implemented (2026-11-21)** as pure functions with tests (`backend/app/modules/evaluation/baselines.py`); the rule is fixed and was not tuned. **Behaviour on the development split only** (67 cases): B0 says SUFFICIENT for 29, B1 for 24, AISOP for 11. This shows the baselines are more permissive; it does **not** show who is right, because no labels exist. Held-out not run. | `D:AISOP-BackupsAISOP_Dev_Logs_20261120day6b_baseline_dev_behaviour.json` |
| Held-out split | **Never run.** | Stage 5 report |
| Second reviewer / agreement | **None.** | Stage 5 report |
| Live language-model benchmark (19 scenarios) | **0 of 19 captured**; model id unknown in the report. | `docs/04_Testing/AI_Model_Benchmark_Report.md` |
| Reliability checks (not part of H1) | Run: 38 passed on PostgreSQL, 3 not executable live. | `day4_r01_r12_pg_matrix.json` |

## Next steps, in order
1. Label the development cases (and a second reviewer for a subset).
2. ~~Implement B0 and B1~~ done (see the table). Compute their false-sufficient rate once labels exist.
3. Run development, then the held-out split once, and report every result with its confidence interval and the failure cases.
4. Only then call the hypothesis supported, unsupported or inconclusive.

## Threats to validity
Synthetic, author-built data; the author also wrote the rules and the labels; small sample; scenario families are uneven (the held-out split lacks some independence cases); no real-world prevalence.

## 2026-11-22: scoring script and development-split run (label-independent)
Added `backend/evaluation_tools/score_sufficiency_baselines.py (kept outside backend/scripts so that production-reachable code never imports the evaluator)` (runs B0, B1 and the AISOP gate, rule `suff-v4`, on one split; held-out only with an explicit `--held-out` flag and a run-once warning; computes false-sufficient rate with a 95% Wilson interval and abstention rate only if `datasets/sufficiency_eval/labels.json` exists, schema in the script docstring) and `datasets/sufficiency_eval/labels_template.csv` (67 development rows, label and notes columns empty). Tests: `backend/tests/unit/test_score_sufficiency_baselines.py` (7 tests; with `test_evaluation_baselines.py`, 12 passed). `labels.json` does not exist; no label was written by anyone.

Run on the development split (67 cases, manifest verified), per-case verdicts in `D:\AISOP-Backups\AISOP_Dev_Logs\20261122_sufficiency_baselines\verdicts_dev.csv`:

| Arm | SUFFICIENT | LIMITED | INSUFFICIENT |
|---|---|---|---|
| B0 | 29 | 0 | 38 |
| B1 | 24 | 0 | 43 |
| AISOP (suff-v4) | 11 | 52 | 4 |

Agreement counts: B0 SUFFICIENT where AISOP is not, 18; B1 SUFFICIENT where AISOP is not, 13; AISOP SUFFICIENT where B0 or B1 is not, 0 and 0; verdict identical to AISOP, 15 for B0 and 15 for B1; B0 equals B1 on 62 cases. These are behaviour counts, not accuracy: with no labels they do not show which arm is right, and false-sufficient rate against labels is not computed. Held-out split not run.
