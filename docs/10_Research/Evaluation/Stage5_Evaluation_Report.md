# Stage 5 Evaluation Report - Evidence-Sufficiency Gate (suff-v3)

Date 2026-11-12, updated 2026-11-25. Status labels: IMPLEMENTED, PARTIAL, BLOCKED, UNVERIFIED. This report separates what was measured from what cannot yet be measured. Sections 1 to 7 are the 2026-11-12 state, kept as written except where a status changed; **section 8 (added 2026-11-25) is the first accuracy result, against the project owner's own development labels, and it is a weak one.** The held-out split was not run or inspected, no label was written by an assistant, and no historical evaluation output was altered.

## 1. Dataset provenance (`datasets/sufficiency_eval`)
* 115 derived cases: development 67, held-out 48; opaque ids `SUFC-xxxxxxxxxx`; every case file is listed in `MANIFEST.sha256` (hash lock verified: IMPLEMENTED).
* Provenance: **synthetic**. Every base scenario is a hand-authored `SCN-*` scenario (dev 11, held-out 8); cases are degradations (transforms) of them. Nothing is real telemetry.
* Labels: on 2026-11-12 `labels.json` was absent for both splits. Since 2026-11-25 the **development** split has owner-authored labels (`dev/labels.json`, section 8); the held-out split still has none. Labels are owner-authored; code never generates them.

## 2. Integrity checks (`backend/scripts/dataset_integrity_report.py`, exit 0; output `logs/dataset_integrity.json`)
| Check | Result |
|---|---|
| manifest hash lock; case files and manifest agree | pass |
| unique opaque case ids; id format | pass (115 unique) |
| base scenarios disjoint between splits | pass (0 shared) |
| identical evidence content in both splits (leakage) | pass (0 pairs) |
| scenario families present in both splits (`global` = scope-free degradations, dev only) | pass |
| identical content within a split | informational: 3 (dev), 2 (held-out) |
Family distribution: dev adversarial_ambiguous 20, atomic_technique 15, benign_baseline 12, multi_stage_chain 18, global 2; held-out 12/12/12/12.

### Coverage gaps (reported, not corrected; the held-out split is hash-locked and unseen)
Held-out contains **no** `host_user_only_links`, `same_record_pair`, `empty_scope` or `all_out_of_window` cases. These probe exactly the independence rules and the abstention paths, so the rules are only exercised on the development split. Neither split contains replay (D1) or placeholder (D2) cases; the Stage 5 defects were found by adversarial tests, not by this dataset. Whether to add cases is an owner decision (it changes the hash lock and must happen before any held-out run); the Stage 5 behaviour is covered by unit tests instead.

## 3. Metric definitions and availability
All metrics need owner labels (`compute_metrics`, `backend/app/modules/evaluation/sufficiency_evaluator.py`). Status as of 2026-11-25: computed on the **development** split only (section 8); held-out BLOCKED (no labels, never run):
| Metric | Definition (denominator) | Status |
|---|---|---|
| confusion matrix, accuracy | label x prediction over labelled cases | measured on dev (section 8) |
| per-class precision / recall / F1 | TP/predicted-as-c; TP/labelled-c; 2TP/(2TP+FP+FN); undefined when the denominator is 0 | measured on dev; SUFFICIENT row rests on 2 labelled cases |
| macro F1 | mean F1 over classes that have labelled cases | measured on dev |
| false-SUFFICIENT rate | predicted SUFFICIENT among cases labelled LIMITED or INSUFFICIENT | measured on dev |
| false-INSUFFICIENT rate | predicted INSUFFICIENT among cases labelled SUFFICIENT or LIMITED | measured on dev |
| predicted abstention rate | predicted INSUFFICIENT / all cases | computable without labels |
| coverage vs risk | abstain-only: share allowed to proceed, and of those the share labelled INSUFFICIENT; strict: share predicted SUFFICIENT, and of those the share not labelled SUFFICIENT | measured on dev |
| Wilson 95 % intervals | on the two false-rate numerators/denominators above | measured on dev |
| weighted Cohen's kappa | linear-weighted, two reviewers, cases both labelled | measured on 17 cases against an AI second reviewer only (section 8); no human second reviewer |
| gate-on vs gate-off model-call prevention | provider calls with and without the gate, scripted counting provider | measured (below) |
| evidence-reference validity | share of assessments whose cited ids all exist in the context | measured (below) |

## 4. What was measured (development split only; label-independent; `logs/dev_evaluation_label_independent.json`)
| Measure | Result |
|---|---|
| rule version | suff-v3 |
| predicted distribution | SUFFICIENT 11, LIMITED 52, INSUFFICIENT 4 (identical to suff-v2: the Stage 5 rule changes alter no development case) |
| deterministic on re-run | true (same assessment hash) |
| evidence-reference validity | 1.0 (67/67) |
| model-invocation prevention on predicted-INSUFFICIENT cases | 1.0 (4/4; 0 calls) |
| model calls, gate on / gate off | 63 / 67 |
| claims generated on predicted-INSUFFICIENT cases, gate on / off | 0 / 12 |
| claims needing review, gate on / off | 126 / 135 |
Caveats: the 11 SUFFICIENT predictions are all `independently_corroborated` variants, which are synthetic positives by construction; the provider is scripted, so grounding and review figures describe the harness, not a model. These are engineering-behaviour figures, **not accuracy**.

## 5. Adversarial corroboration tests (non-dataset evidence)
`test_stage5_adversarial.py` section A, 40+ cases: identical raw digests with different ids, near-identical and replayed records (0.5 s to 1 h), same host/different users, same user/different hosts, private/loopback/link-local addresses (weak), public IP/domain/file hash/URL/e-mail/process GUID/logon session (corroborate), placeholders and malformed values (weak), case/whitespace variants, missing/zero provenance, injected instruction text, specific links 3 days apart, evidence of another case. Defects D1 and D2 were reproduced before the fixes. These establish rule behaviour on constructed inputs; they do not estimate how often the rules are right on real incidents.

## 6. Separation of conclusions
| Claim | Established? |
|---|---|
| The demonstration scenarios produce the expected structure | yes (synthetic demonstration success) |
| The gate is deterministic, fail-closed and cannot be disabled by configuration | yes (tests) |
| Development-set accuracy | **Measured, 49.3 % agreement with the owner's labels (33 of 67)**; weak, and the labels themselves are not shown to be reliable (section 8) |
| Held-out performance | **BLOCKED**: no labels; split never run |
| Human reviewer agreement | **BLOCKED**: no human second reviewer. An AI second reviewer labelled 17 cases and agreed with the owner on 6 (35 %, weighted kappa 0.07) |
| Real-world effectiveness or operational detection accuracy | **not established, not claimed** |
| Resistance to a compromised source (R1) | not established |

## 7. Reproducibility
```
python backend/scripts/dataset_integrity_report.py --out <file on D:>            # integrity, exit 0 = pass
python -m pytest backend/tests/unit/test_stage5_adversarial.py backend/tests/unit/test_evidence_sufficiency_gate.py backend/tests/unit/test_evidence_independence.py
```
The development evaluation is `evaluate_split('dev')` in the evaluator module (the held-out split requires labels and `final_heldout=True` and was not run). Remaining owner steps: a human second reviewer for at least 25 % (the AI pass in section 8 is not a substitute), then, only if the development labels are judged reliable, label held-out independently and run it once.

## 8. Development result against the owner's labels (added 2026-11-25)
Reported exactly as measured. Nothing was changed after the scores were seen: labels, gate, thresholds and cases are as they were.

**Labels.** All 67 development cases were labelled by the project owner with the interactive tool (`label_cases.py`), under `labelling_guide.md` plus `Labelling_Guide_Addendum.md`. Distribution: LIMITED 40, INSUFFICIENT 25, SUFFICIENT 2. The file is frozen: SHA-256 `80d3205c3eb6c5f60272d49b79f477774b38b26e2bc363fd3d419be2a333f1b1` (`dev/labels.json`, `dev/labels.freeze.txt`). The labelling tool writes `datasets/sufficiency_eval/labels.json` while the evaluator reads `dev/labels.json`; the second file is a byte-identical copy. Full output: `D:\AISOP-Backups\AISOP_Dev_Logs\sufficiency_dev_owner_labels_20261125.json` (outside the repository).

**Gate against the owner's labels (suff-v3 behaviour, 67 cases).**
| Label \ gate | SUFFICIENT | LIMITED | INSUFFICIENT |
|---|---|---|---|
| SUFFICIENT (2) | 1 | 1 | 0 |
| LIMITED (40) | 8 | 30 | 2 |
| INSUFFICIENT (25) | 2 | 21 | 2 |

* Accuracy 0.4925 (33 of 67); macro F1 0.3146.
* False-SUFFICIENT rate 0.1538 (10 of 65 cases not labelled SUFFICIENT; Wilson 95 % 0.086 to 0.261). On cases labelled INSUFFICIENT: 0.08 (2 of 25).
* False-INSUFFICIENT rate 0.0476 (2 of 42; 95 % 0.013 to 0.158).
* Per class (support): SUFFICIENT precision 0.09, recall 0.50 (2 labelled cases, so not interpretable); LIMITED precision 0.58, recall 0.75 (40); INSUFFICIENT precision 0.50, recall 0.08 (25).
* Coverage versus risk: abstain-only coverage 0.94, of those allowed to proceed 36.5 % are labelled INSUFFICIENT; strict coverage 0.16, of the SUFFICIENT predictions 90.9 % (10 of 11) are not labelled SUFFICIENT.
* Model-invocation prevention on cases the owner labelled INSUFFICIENT: 0.08 (2 of 25); a gate-off run would have called the provider on all 25. The scripted provider means this is a mechanism figure, not a model-quality one.
* Where the disagreement sits: 21 of the 25 INSUFFICIENT labels are LIMITED in the gate, and 8 of the 40 LIMITED labels are SUFFICIENT in the gate. In both large off-diagonal cells the gate rates the evidence higher than the owner did (LIMITED where the owner said INSUFFICIENT; SUFFICIENT where the owner said LIMITED); only 2 + 1 cases go the other way. Which of the two is right is what the labels cannot settle (see below).

**Second reviewer (AI, not human).** A fresh Claude subagent, instructed to read only the two guides and the 17 `--every 4` development cases and to avoid labels, gate output, reports and Git history, wrote `dev/labels.reviewer2.json` (labeller "Claude AI reviewer"; model version not recorded by the subagent). It read two code files for the schema and the case selection. Blindness rests on that instruction and on the subagent starting with no conversation history; it was not independently verified. It labelled 4 SUFFICIENT, 12 LIMITED, 1 INSUFFICIENT.
* Agreement with the owner: 6 of 17 (35.3 %), linear-weighted kappa 0.073, i.e. close to chance. The 11 disagreements: 7 cases the owner labelled INSUFFICIENT and the AI LIMITED (single uncorroborated event, or missing root event); 4 cases the owner labelled LIMITED and the AI SUFFICIENT (second record sharing a specific domain; the AI noted that the "second sensor" status comes from the summary text, because the source identifier is the same as the root's).
* In the disagreeing cases the owner's justification notes mostly argue that the activity is legitimate or not demonstrably malicious. The guide asks for evidence sufficiency, not attack truth, so that is a plausible contributor to the INSUFFICIENT-versus-LIMITED gap. This is an observation, not an adjudication: no label was changed.

**What this does and does not establish.**
* It establishes a measured, reproducible disagreement between the gate and one labeller on 67 synthetic derived cases, and that two readings of the labelling guide (the owner's and an independent AI's) diverge on the same cases.
* It does **not** show that the gate is wrong, because the labels are not shown to be reliable ground truth: agreement between two labellers is near chance, and the AI reviewer is not an independent human. It does not show the gate is right either. The SUFFICIENT class has 2 labelled cases and says nothing.
* A human second reviewer on the same 17 (or all 67) cases, working only from the guide, is the missing step. Re-labelling by the owner after seeing these scores would not be blind and is not offered as a fix. The held-out split stays closed.
