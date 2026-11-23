# Contribution statement and threats to validity

Written 2026-11-23. Everything here is limited to what the repository measured. Nothing claims a result on real incidents, and nothing claims novelty beyond "applied combination, effect partly measured".

## The question
When an investigation tool is asked to explain a security incident, when is the evidence behind the question good enough to ask a model at all, and how are its answers kept honest? AISOP answers with two testable mechanisms and one stated limit.

## The claim (narrow on purpose)
1. **A deterministic, fail-closed evidence-sufficiency gate** counts independent observed evidence before any model call. Copies and near-copies count once; a shared host or user is context, not corroboration; analyst notes, threat intelligence and model output never corroborate.
2. **Claim-level verification** checks each statement a model makes against the stored evidence by code that uses no model, and falls back to a deterministic report when a claim fails.
3. **Stated limit:** independence is *record-level* (a different raw record linked by a specific or strong artefact), not *vantage-level* (a different sensor). Proposed for later in ADR-017.

This is an applied combination. Each ingredient has precedent (see `Literature_Review.md`): abstention on insufficient context (Joren et al., read in part), discounting copied sources (Dong et al., abstracts only; a 2011 dependent-alert fusion paper known from a search summary only), and claim verification (DeepFaith, abstract only). The combination in a deterministic SOC tool was not found in the 15 sources opened; that is a limited search.

## What was measured (all development split, 67 synthetic cases, no labels)
| Evidence | Result | Source |
|---|---|---|
| Metamorphic relations (copies, near-copies, host-only context must not raise the verdict; order and hostile text must not change it) | AISOP broke none of 5 relations; the naive baselines broke the duplicate relations on 37 to 42 of 66 cases | `evaluation_tools/metamorphic_sufficiency.py` |
| Ablation (rules added to the naive baseline one at a time) | SUFFICIENT calls fall 29 -> 24 -> 12 -> 12 -> 11 across arms B0 to B4; metamorphic breaks fall 103 -> 76 -> 23 -> 0 -> 0; AISOP breaks 0; B4 and AISOP have the identical SUFFICIENT set | `evaluation_tools/ablation_sufficiency.py` |
| ATT&CK rules against 20 scenarios | 1 of 20 expected techniques recovered; 0 of 5 benign scenarios produced a technique | `evaluation_tools/score_attack_mapping.py` |
| Raw captured model (`llama3.1:8b`) | MITRE F1 0.00 on 10 scenarios; false techniques on 2 of 2 benign scenarios | `docs/04_Testing/AI_Model_Benchmark_Report.md` |
| Real-format ingestion | 377 of 377 records from two public datasets accepted after fixes (0 before); one SUFFICIENT verdict on real data examined | `Real_Format_Ingestion_Result.md` |

## What the ablation says about the contribution (stated without spin)
- The **duplicate clustering** is the rule that removes the rule-breaking (B3 and B4 break none; B2 still breaks 23). That is the part of the design that earns its place.
- On these 67 cases the SUFFICIENT boundary is reproduced exactly by four simple rules. So the full gate's extra machinery (LIMITED tier, provenance, contradictions, truncation, root event) does **not** change which cases are SUFFICIENT here. Its extra effect is on the other side: it splits the non-sufficient cases into LIMITED (52) and INSUFFICIENT (4). Whether that split is correct is the open question that the owner labels are needed to answer.
- B4 is an approximation of one gate rule, not the gate; the arms measure behaviour, not correctness.

## What is NOT shown
Accuracy or false-sufficient rate against human labels (none exist); behaviour on real incidents; a second reviewer's agreement; the held-out result (never run); that the rules help an analyst; that the gate beats a stronger baseline than B0 to B4; any claim of novelty or superiority over any product.

## Hypothesis and what would falsify it (unchanged from `Evaluation.md`)
H1: on the fixed scenarios the gate gives a lower false-sufficient rate than the naive arms. It is falsified if its rate is equal or higher on the held-out split, or if its abstention is so high that usable conclusions collapse. Neither can be decided until the labels exist.

## Threats to validity
| Threat | Effect | Mitigation |
|---|---|---|
| One author wrote the scenarios, the rules and (will write) the labels | Agreement shows consistency, not truth | A second reviewer labels every 4th case; report agreement |
| Labelling rubric restates the gate's own rule | Agreement with labels may be high by construction | Say so; compare against B0 to B4 on the same labels |
| Synthetic, small, uneven scenario families | No prevalence, wide intervals | Wilson intervals; no generalisation claim |
| Metamorphic relations restate the project's invariants | Zero violations shows fidelity, not correctness | Present as property testing only |
| Record-level independence (ADR-017) | Same-sensor records can reach SUFFICIENT (seen on real data) | Disclosed; proposed fix |
| Held-out split unused | No out-of-sample result | Run once after the rules are frozen |
| Real-data test is one forwarder shape | Ingestion generality unproven | Disclosed |

## Reproduce
```
.venv\Scripts\python.exe backend\evaluation_tools\metamorphic_sufficiency.py --out D:\AISOP-Backups\AISOP_Dev_Logs\metamorphic_run
.venv\Scripts\python.exe backend\evaluation_tools\ablation_sufficiency.py --out D:\AISOP-Backups\AISOP_Dev_Logs\ablation_run
.venv\Scripts\python.exe backend\evaluation_tools\score_attack_mapping.py
```
Guards: `backend/tests/unit/test_metamorphic_sufficiency.py`, `test_ablation_sufficiency.py`, `test_attack_mapping_ground_truth.py`.
