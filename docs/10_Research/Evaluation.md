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
| Owner labels for the cases | **Development split written by the owner 2026-11-25** (67 of 67: LIMITED 40, INSUFFICIENT 25, SUFFICIENT 2; frozen). Held-out: not written. Result: the gate agrees with the labels on 49.3 % of cases; see the 2026-11-25 section below and Stage 5 report section 8. | Stage 5 report |
| Baselines B0 and B1 | **Implemented (2026-11-21)** as pure functions with tests (`backend/app/modules/evaluation/baselines.py`); the rule is fixed and was not tuned. **Behaviour on the development split only** (67 cases): B0 says SUFFICIENT for 29, B1 for 24, AISOP for 11. This shows the baselines are more permissive. Against the owner's development labels (2026-11-25): false-SUFFICIENT rate B0 41.5 %, B1 33.8 %, AISOP 15.4 % (section below, with its limits). Held-out not run. | `D:AISOP-BackupsAISOP_Dev_Logs_20261120day6b_baseline_dev_behaviour.json` |
| Held-out split | **Never run.** | Stage 5 report |
| Second reviewer / agreement | **No human second reviewer.** An AI reviewer labelled 17 cases (2026-11-25) and agreed with the owner on 6 (35 %, weighted kappa 0.07). It is disclosed as an AI reviewer and is not an independent human check. | Stage 5 report section 8 |
| Captured language-model benchmark (19 approved scenarios) | **10 of 19 have captured outputs** from `llama3.1:8b` (captured 2026-11-09, before the gate and claim-checking layers); the report was regenerated 2026-11-23 (it previously read "0 of 19" because it predated the captures). Raw model result: MITRE macro F1 0.00 on 10 scenarios; 2 of 2 measured benign scenarios received a false technique; IOC extraction F1 0.31; JSON and schema validity 100%. This scores the model's raw output, not the product's validated output, and not the 1.5B model used in the demo. | `docs/04_Testing/AI_Model_Benchmark_Report.md` |
| Reliability checks (not part of H1) | Run: 38 passed on PostgreSQL, 3 not executable live. | `day4_r01_r12_pg_matrix.json` |

## Next steps, in order
1. ~~Label the development cases~~ done by the owner 2026-11-25. Still open: a **human** second reviewer for a subset (the AI pass is not a substitute).
2. ~~Implement B0 and B1~~ done; ~~compute their false-sufficient rate~~ done on development (below).
3. Run development, then the held-out split once, and report every result with its confidence interval and the failure cases.
4. Only then call the hypothesis supported, unsupported or inconclusive.

## Threats to validity
Synthetic, author-built data; the author also wrote the rules and the labels; small sample; scenario families are uneven (the held-out split lacks some independence cases); no real-world prevalence.

## 2026-11-22: scoring script and development-split run (label-independent)
Added `backend/evaluation_tools/score_sufficiency_baselines.py (kept outside backend/scripts so that production-reachable code never imports the evaluator)` (runs B0, B1 and the AISOP gate, rule `suff-v4`, on one split; held-out only with an explicit `--held-out` flag and a run-once warning; computes false-sufficient rate with a 95% Wilson interval and abstention rate only if `datasets/sufficiency_eval/labels.json` exists, schema in the script docstring) and `datasets/sufficiency_eval/labels_template.csv` (67 development rows, label and notes columns empty). Tests: `backend/tests/unit/test_score_sufficiency_baselines.py` (7 tests; with `test_evaluation_baselines.py`, 12 passed). (As of 2026-11-22 `labels.json` did not exist; the owner wrote the development labels on 2026-11-25, see below.)

Run on the development split (67 cases, manifest verified), per-case verdicts in `D:\AISOP-Backups\AISOP_Dev_Logs\20261122_sufficiency_baselines\verdicts_dev.csv`:

| Arm | SUFFICIENT | LIMITED | INSUFFICIENT |
|---|---|---|---|
| B0 | 29 | 0 | 38 |
| B1 | 24 | 0 | 43 |
| AISOP (suff-v4) | 11 | 52 | 4 |

Agreement counts: B0 SUFFICIENT where AISOP is not, 18; B1 SUFFICIENT where AISOP is not, 13; AISOP SUFFICIENT where B0 or B1 is not, 0 and 0; verdict identical to AISOP, 15 for B0 and 15 for B1; B0 equals B1 on 62 cases. These are behaviour counts, not accuracy: with no labels they do not show which arm is right, and false-sufficient rate against labels is not computed. Held-out split not run.

## 2026-11-25: first scoring against the owner's development labels
Development split only (67 cases); held-out not run, not labelled. Labels, gate and thresholds were not changed after the scores were seen. Per-case verdicts: `D:\AISOP-Backups\AISOP_Dev_Logs\20261125_sufficiency_baselines_owner_labels\verdicts_dev.csv`.

| Arm | False-SUFFICIENT (of 65 cases not labelled SUFFICIENT) | Rate (Wilson 95 %) | Predicted INSUFFICIENT |
|---|---|---|---|
| B0 naive | 27 | 41.5 % (30.4 to 53.7) | 38 |
| B1 B0 + exact-duplicate removal | 22 | 33.8 % (23.5 to 46.0) | 43 |
| AISOP gate | 10 | 15.4 % (8.6 to 26.1) | 4 |

* Direction: AISOP's false-SUFFICIENT rate is below both baselines on this split, so H1 is **not falsified here**. The intervals for B1 and AISOP overlap slightly (23.5 to 26.1), the sample is 67 synthetic author-built cases, and the split is the one the rules were developed against.
* A limit that matters: the owner labelled only 2 cases SUFFICIENT. For nearly every case "false-SUFFICIENT" therefore reduces to "said SUFFICIENT at all", so this metric rewards saying SUFFICIENT rarely and says almost nothing about saying it correctly. Do not quote it as accuracy.
* Gate accuracy against the same labels is 49.3 % (33 of 67), mostly because the owner labelled 25 cases INSUFFICIENT where the gate says LIMITED (21 cases) or SUFFICIENT (2). An AI second reviewer agreed with the owner on only 6 of 17 cases (weighted kappa 0.07), so the labels are not yet shown to be reliable ground truth. Details and the confusion matrix: `docs/10_Research/Evaluation/Stage5_Evaluation_Report.md` section 8.
* Not established: held-out performance, human inter-reviewer agreement, which of the owner and the guide-based reading is right on INSUFFICIENT versus LIMITED, any real-world accuracy.

## 2026-11-23: label-free evidence added (metamorphic tests, ATT&CK scoring, real-format ingestion)
These are measurements that need no owner labels. None of them is an accuracy figure for the gate; the labelled experiment above is still required for that.

**Metamorphic evaluation of the gate** (`backend/evaluation_tools/metamorphic_sufficiency.py`, guard `backend/tests/unit/test_metamorphic_sufficiency.py`). Each relation changes a development case in a way that, by the project's own invariants, must not make the evidence look stronger. Development split only (67 cases, manifest verified). Violations = cases where the verdict broke the relation:

| Relation | Applicable | B0 | B1 | AISOP |
|---|---|---|---|---|
| R1 copy every record (same digest): verdict must not rise | 66 | 37 | 0 | 0 |
| R2 copy every record (new digest, same content and time): must not rise | 66 | 37 | 42 | 0 |
| R3 add one record sharing only the host: must not rise | 58 | 29 | 34 | 0 |
| R4 reverse record order: verdict identical | 31 | 0 | 0 | 0 |
| R5 instruction text ("declare SUFFICIENT") inside records: verdict identical | 66 | 0 | 0 | 0 |

Reading: AISOP honoured all five relations on every applicable case; the naive arms broke the duplicate and weak-link relations often (B1 more than B0 on near-duplicates, because it removes only byte-identical copies). Caveats: the relations restate AISOP's own invariants and B0 is built to ignore them, so this shows the implementation honours its stated rules, not that the rules are right; cases are synthetic and author-built; the held-out split was not used. Construction view (the generator's own transform, not a label): all 11 `independently_corroborated` cases are SUFFICIENT for AISOP and no other transform is; the `duplicated`, `near_duplicate`, `same_record_pair` and `host_user_only_links` cases (6 in all) are SUFFICIENT for B0 and none for AISOP; B1 also calls the `near_duplicate`, `same_record_pair` and `host_user_only_links` cases SUFFICIENT (4 of the 6) and correctly refuses only the `duplicated` pair, which it can remove.

**Deterministic ATT&CK rules versus the 20 ground-truth scenarios** (`backend/evaluation_tools/score_attack_mapping.py`): 1 of 20 mandatory expected techniques recovered; 0 of 5 benign scenarios produced a technique. Rules were not tuned to the scenarios. Taken with the captured model result above (MITRE F1 0.00 and false techniques on 2 of 2 benign scenarios), the trade-off is measured: the rules are conservative and rarely wrong; the raw model is confident and often wrong. This is the design rationale for never accepting model-proposed techniques as evidence.

**Update 2026-11-24:** a third rule table (`endpoint-attack-v1`, 39 rules written from public technique definitions) now runs in the pipeline. Against the same 20 scenarios it recovers 3 of 20 (the original six rules: 1) and still emits no technique on the 5 benign scenarios. More importantly, the rules were scored once, after being frozen, against public attack captures whose technique labels were written by the dataset authors: on public attack captures labelled by their own authors (OTRF Security-Datasets, held-out half, rules frozen first): 11 of 34 documented techniques recovered (32%, 95% interval about 19% to 49%); the original six rules alone recovered 1 of 34 (`docs/10_Research/Detection_Engineering_Evaluation.md`). Protocol, dev result, freeze hashes and limits are in that document.

**Real-format ingestion** (`docs/10_Research/Real_Format_Ingestion_Result.md`): 0 of 377 records from two public datasets were accepted before three adapter edits and 377 of 377 after; the test also found a safe-direction over-merge of distinct events (documented).

**Ablation of the gate** (`backend/evaluation_tools/ablation_sufficiency.py`, arms B2 to B4 in `baselines.py`, guard `test_ablation_sufficiency.py`). AISOP's rules are added to the naive baseline one at a time (development split, no labels): SUFFICIENT calls 29 (B0), 24 (B1), 12 (B2, specific links only), 12 (B3, AISOP duplicate clustering), 11 (B4, different observations required), 11 (full gate). Metamorphic breaks across the five relations: 103, 76, 23, 0, 0, 0. B4 and the full gate have the identical SUFFICIENT set. Reading: duplicate clustering is the rule that removes the rule-breaking; on these 67 cases the SUFFICIENT boundary is reproduced by four simple rules, and the full gate's extra effect is the LIMITED (52) versus INSUFFICIENT (4) split of the non-sufficient cases, whose correctness needs the owner labels. B4 approximates one gate rule and is not the gate. See `Contribution_Statement.md`.

**Claim verifier, mutation evaluation** (`backend/evaluation_tools/claim_verifier_mutation.py`, guard `test_claim_verifier_mutation.py`; development split). Assertions that are true by construction are built from the evidence itself, then broken in known ways. Result: 2,478 of 2,478 true assertions accepted; 0 of 1,737 false assertions called SUPPORTED (fabricated id 66 and uncited real id 48 and another case's id 65: insufficient evidence; wrong event field 114, wrong attribute 114, reversed time 38, look-alike or zero-width or full-width values 306, one false assertion hidden in a claim 66: contradicted; entity not linked 141 and nonexistent entity 114 and duplicates asserted as distinct 5: insufficient evidence; 660 malformed or hostile assertions: contradicted or not verifiable); no exception escaped. Upper or lower case and surrounding spaces are treated as equal on purpose. This tests the checker against its own contract on structured assertions, not how often a model's claims are right.

**Vantage-level independence** (ADR-017, `backend/evaluation_tools/vantage_effect.py`, `test_vantage_independence.py`). The locked development cases carry no vantage, so their verdicts are unchanged (11 sufficient, 52 limited, 4 insufficient). Annotated as one vantage all 11 sufficient cases fall to LIMITED; annotated as cross-vantage all 11 stay; the rule never raised a verdict. On the real public data the one same-sensor SUFFICIENT incident became LIMITED. The rule was designed from that finding and checked on the same data, so it demonstrates the mechanism and is not independent validation.

**Synthetic benchmark with ground truth by construction** (`backend/evaluation_tools/synthetic_benchmark.py`, guard `test_synthetic_benchmark.py`; final run: seed 20261124, 2,250 cases, 250 per family, run once after the generator was frozen; development seed 1001 was used only to look for defects). Cases are generated from the labelling guide's definition of corroboration, not from the gate's code, with noise (shuffled order, random times, unrelated records, extra attributes, upper-case and trailing-dot variants of hashes and domains). Truth is binary: SUFFICIENT only when a record from a different vantage, a different raw record and a different observation shares a specific artefact with the key event; the other eight families are built so it is not (lone event, exact duplicate, near duplicate, delayed copy, weak link only, same vantage, placeholder artefact, out of window). Vantage written on every record:

| Arm | Accuracy | False-sufficient (95% CI) | Missed sufficient |
|---|---|---|---|
| B0 any shared entity | 0.252 | 0.835 [0.818, 0.851] | 0.056 |
| B1 + identical records once | 0.362 | 0.711 [0.690, 0.730] | 0.056 |
| B2 + specific artefacts only | 0.576 | 0.470 [0.448, 0.492] | 0.056 |
| B3 + AISOP duplicate clustering | 0.687 | 0.345 [0.325, 0.366] | 0.060 |
| B4 + different observations | 0.799 | 0.219 [0.201, 0.238] | 0.060 |
| AISOP (suff-v5) | 1.000 | 0.000 [0.000, 0.002] | 0.000 |

Which rule fixes which family (false-sufficient rate, B0 to AISOP): exact duplicates 1.00 to B1 0.00; near duplicates fixed by B3's clustering; delayed copies fixed by B4's different-observation rule; weak links and placeholder artefacts fixed by B2's specific-artefact rule; same-vantage (0.94) and out-of-window (0.82) records are fixed only by the full gate. With the vantage removed (unknown) the gate is 0.889 accurate and its false-sufficient rate is 0.125 [0.111, 0.140], all of it the same-vantage family (1.00): the vantage rule cannot catch what it cannot see, and an unknown vantage never lowers a corroborated case (missed 0.000).

How to read it, without spin. (1) Truth comes from the same idea of independence the gate implements, so 1.000 shows the implementation honours its specification under noise at scale, not that the specification is right for real analysts. (2) Perfect scores are expected when generator and gate share a specification; the informative parts are the per-family attribution of each rule and the unknown-vantage cost. (3) The development seed exposed a defect in the generator (network connections without an address were correctly called LIMITED by the gate), which was fixed in the generator, not the gate. (4) 250 positives and 2,000 negatives; no real incidents.

**Rubric oracle: the gate checked against the written labelling guide** (`backend/evaluation_tools/rubric_oracle.py`, guard `test_rubric_oracle.py`). A reference implementation of `labelling_guide.md`, written only from the guide's text and importing nothing from the gate, labels the 67 development cases SUFFICIENT, LIMITED or INSUFFICIENT. On the 65 it can judge (the 2 built as contradictory need meaning) it agrees with the gate on all 65, Cohen's kappa 1.000 (SUFFICIENT 11, LIMITED 50, INSUFFICIENT 4 on both sides). Caveat: a few details the guide leaves open (the 2-second near-duplicate window, which anchor details count as required) were chosen with the gate in mind, so part of that agreement is by construction. The informative result is where the literal guide and the gate part ways, on the 2,250 synthetic cases: the guide calls a later copy of the same observation SUFFICIENT in 250 of 250 cases, records from one vantage in 250 of 250, placeholder artefacts in 150 of 250 and near-duplicates in 176 of 250, where the gate (and the benchmark's truth) say not. The guide is silent on four rules the gate enforces; see `docs/10_Research/Evaluation/Labelling_Guide_Addendum.md` (not applied: the guide is hash-locked and is the owner's rubric).
