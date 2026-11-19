# Stage 5 Evaluation Report - Evidence-Sufficiency Gate (suff-v3)

Date 2026-11-12. Status labels: IMPLEMENTED, PARTIAL, BLOCKED, UNVERIFIED. This report separates what was measured from what cannot yet be measured. No labels were written or inferred, the held-out split was not run or inspected, and no historical evaluation output was altered.

## 1. Dataset provenance (`datasets/sufficiency_eval`)
* 115 derived cases: development 67, held-out 48; opaque ids `SUFC-xxxxxxxxxx`; every case file is listed in `MANIFEST.sha256` (hash lock verified: IMPLEMENTED).
* Provenance: **synthetic**. Every base scenario is a hand-authored `SCN-*` scenario (dev 11, held-out 8); cases are degradations (transforms) of them. Nothing is real telemetry.
* Labels: `labels.json` is absent for both splits (only `labels.template.json`). Labels are owner-authored; code never generates them.

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
All metrics need owner labels (`compute_metrics`, `backend/app/modules/evaluation/sufficiency_evaluator.py`):
| Metric | Definition (denominator) | Status |
|---|---|---|
| confusion matrix, accuracy | label x prediction over labelled cases | BLOCKED (no labels) |
| per-class precision / recall / F1 | TP/predicted-as-c; TP/labelled-c; 2TP/(2TP+FP+FN); undefined when the denominator is 0 | BLOCKED |
| macro F1 | mean F1 over classes that have labelled cases | BLOCKED |
| false-SUFFICIENT rate | predicted SUFFICIENT among cases labelled LIMITED or INSUFFICIENT | BLOCKED |
| false-INSUFFICIENT rate | predicted INSUFFICIENT among cases labelled SUFFICIENT or LIMITED | BLOCKED |
| predicted abstention rate | predicted INSUFFICIENT / all cases | computable without labels |
| coverage vs risk | abstain-only: share allowed to proceed, and of those the share labelled INSUFFICIENT; strict: share predicted SUFFICIENT, and of those the share not labelled SUFFICIENT | BLOCKED |
| Wilson 95 % intervals | on the two false-rate numerators/denominators above | BLOCKED |
| weighted Cohen's kappa | linear-weighted, two reviewers, cases both labelled | BLOCKED (no second reviewer; none invented) |
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
| Development-set accuracy | **BLOCKED**: no labels |
| Held-out performance | **BLOCKED**: no labels; split never run |
| Human reviewer agreement | **BLOCKED**: no second reviewer |
| Real-world effectiveness or operational detection accuracy | **not established, not claimed** |
| Resistance to a compromised source (R1) | not established |

## 7. Reproducibility
```
python backend/scripts/dataset_integrity_report.py --out <file on D:>            # integrity, exit 0 = pass
python -m pytest backend/tests/unit/test_stage5_adversarial.py backend/tests/unit/test_evidence_sufficiency_gate.py backend/tests/unit/test_evidence_independence.py
```
The label-independent development evaluation is `evaluate_split('dev')` in the evaluator module (the held-out split requires labels and `final_heldout=True` and was not run). Owner steps to unblock: write `dev/labels.json` following `labelling_guide.md` without looking at gate output, freeze thresholds, then label held-out independently, a second reviewer for at least 25 %, then run held-out once.
