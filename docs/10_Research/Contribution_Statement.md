# Contribution statement and threats to validity

Written 2026-11-23. Everything here is limited to what the repository measured. Nothing claims a result on real incidents, and nothing claims novelty beyond "applied combination, effect partly measured".

## The question
When an investigation tool is asked to explain a security incident, when is the evidence behind the question good enough to ask a model at all, and how are its answers kept honest? AISOP answers with three testable mechanisms.

## The claim (narrow on purpose)
1. **A deterministic, fail-closed evidence-sufficiency gate** counts independent observed evidence before any model call. Copies and near-copies count once; a shared host or user is context, not corroboration; analyst notes, threat intelligence and model output never corroborate.
2. **Claim-level verification** checks each statement a model makes against the stored evidence by code that uses no model, and falls back to a deterministic report when a claim fails.
3. **Vantage-level independence** (ADR-017, implemented 2026-11-24): records are different witnesses only if they were seen from different vantage points (a source type at a host). When the whole chain of specific links around the key event comes from one known vantage, the verdict is capped at LIMITED with a stated reason. It can only lower a verdict, and an unknown vantage never triggers it.

This is an applied combination. Each ingredient has precedent (see `Literature_Review.md`): abstention on insufficient context (Joren et al., read in part), discounting copied sources (Dong et al., abstracts only; a 2011 dependent-alert fusion paper known from a search summary only), and claim verification (DeepFaith, abstract only). The combination in a deterministic SOC tool was not found in the 15 sources opened; that is a limited search.

## What was measured (development split, 67 synthetic cases, no labels, plus public real data where stated)
| Evidence | Result | Source |
|---|---|---|
| Metamorphic relations (copies, near-copies, host-only context must not raise the verdict; order and hostile text must not change it) | AISOP broke none of 5 relations; the naive baselines broke the duplicate relations on 37 to 42 of 66 cases | `evaluation_tools/metamorphic_sufficiency.py` |
| Ablation (rules added to the naive baseline one at a time) | SUFFICIENT calls fall 29 -> 24 -> 12 -> 12 -> 11 across arms B0 to B4; metamorphic breaks fall 103 -> 76 -> 23 -> 0 -> 0; AISOP breaks 0; B4 and AISOP have the identical SUFFICIENT set | `evaluation_tools/ablation_sufficiency.py` |
| ATT&CK rules against 20 author-written scenarios | 3 of 20 expected techniques recovered (1 with the original six rules); 0 of 5 benign scenarios produced a technique | `evaluation_tools/score_attack_mapping.py` |
| ATT&CK rules against third-party labelled captures | 11 of 34 documented techniques recovered on the held-out half (32%, interval about 19% to 49%); the original six rules recovered 1 of 34; rules frozen before the run | `evaluation_tools/score_attack_datasets.py`, `docs/10_Research/Detection_Engineering_Evaluation.md` |
| Raw captured model (`llama3.1:8b`) | MITRE F1 0.00 on 10 scenarios; false techniques on 2 of 2 benign scenarios | `docs/04_Testing/AI_Model_Benchmark_Report.md` |
| Claim verifier, mutation evaluation (assertions true or false by construction, built from the evidence and not from the verifier) | All 2,478 true assertions accepted; 0 of 1,737 false assertions called SUPPORTED across 12 fault classes (fabricated and uncited ids, another case's id, wrong values, reversed time, duplicates as distinct, hostile and look-alike values, one false assertion hidden among true ones); no exception escaped | `evaluation_tools/claim_verifier_mutation.py` |
| Vantage-level independence | Locked cases unchanged (11 sufficient); annotated as one vantage all 11 fall to LIMITED, as cross-vantage all 11 stay; never raised; on real public data the one same-sensor SUFFICIENT incident became LIMITED | `evaluation_tools/vantage_effect.py`, ADR-017 |
| Synthetic benchmark with ground truth by construction (2,250 randomised cases, nine families, noise; fresh seed run once) | False-sufficient rate B0 0.835, B1 0.711, B2 0.470, B3 0.345, B4 0.219, AISOP 0.000 [0.000, 0.002]; AISOP accuracy 1.000 with the vantage known and 0.889 with it unknown (all error in the same-vantage family); each rule is shown to fix a named family | `evaluation_tools/synthetic_benchmark.py` |
| Rubric oracle (independent reference implementation of the labelling guide) | Agrees with the gate on 65 of 65 judged development cases (kappa 1.000, partly by construction); reveals that the written guide is silent on four rules the gate enforces (repeated observation, same vantage, placeholder artefacts, near-duplicate definition); a proposed addendum is written for the owner | `evaluation_tools/rubric_oracle.py`, `Labelling_Guide_Addendum.md` |
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
| The benchmark's truth is built from the same definition of independence the gate implements | 1.000 shows conformance under noise, not that the definition is right | Say so; the owner labels are the independent check |
| Vantage is coarse (source type at a host) | Two sensor instances of one type at one host count as one witness | Disclosed in ADR-017 |
| The vantage rule was designed from a real-data finding and then checked on the same data | Demonstrates the mechanism; not independent validation | Say so; needs labels and a second dataset |
| Rule table renamed `suff-v5` on 2026-11-24 | Results from before are labelled `suff-v4` | The version is in the evidence fingerprint, so older stored results recompute |
| Held-out split unused | No out-of-sample result | Run once after the rules are frozen |
| Real-data test is one forwarder shape | Ingestion generality unproven | Disclosed |

## Reproduce
```
.venv\Scripts\python.exe backend\evaluation_tools\metamorphic_sufficiency.py --out D:\AISOP-Backups\AISOP_Dev_Logs\metamorphic_run
.venv\Scripts\python.exe backend\evaluation_tools\ablation_sufficiency.py --out D:\AISOP-Backups\AISOP_Dev_Logs\ablation_run
.venv\Scripts\python.exe backend\evaluation_tools\score_attack_mapping.py
.venv\Scripts\python.exe backend\evaluation_tools\claim_verifier_mutation.py --out D:\AISOP-Backups\AISOP_Dev_Logs\claim_mutation_run
.venv\Scripts\python.exe backend\evaluation_toolsantage_effect.py
```
Guards: `backend/tests/unit/test_metamorphic_sufficiency.py`, `test_ablation_sufficiency.py`, `test_attack_mapping_ground_truth.py`, `test_claim_verifier_mutation.py`, `test_vantage_independence.py`.
