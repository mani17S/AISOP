# Defence day checklist (verified 2026-11-24)

One page to run from. Everything here was checked on 2026-11-24 against the repository and the running local demo. Longer answers are in `Defence_Walkthrough.md`; the evidence behind every number is in `docs/10_Research/` and `Panel_Criticism_Validation.md`.

## 1. The day before
1. `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\demo_check.ps1 -Start` until it prints "All checks OK", then `-WarmUp` (loads the model). Verified today after a backend restart on the latest code: all checks OK.
2. Run the suites once and quote only what they print: `.venv\Scripts\python.exe -m pytest backend/tests/unit -q` (about 4 minutes; last full run 3,827 passed, 1 skipped, 1 expected failure) and, in `frontend/`, `npm test` (307 of 307).
3. Keep the demo keys, `.env` and the credential files off screen. Rotate the Render database password, the Render API key and the Cloudflare deployment token after the defence (they were pasted into a chat).
4. Read in full the papers you will be asked about (arXiv 2411.06037; the data-fusion and dependent-alert papers listed in `Literature_Review.md`). Do not cite a paper you have not read.

## 2. The five-minute demo (all local; the hosted site is not live)
Use the built-in scenarios (verified verdicts under the current rule):
| Scenario | What it shows | Verdict today |
|---|---|---|
| `01_intrusion_chain` | Several sources joined by specific artefacts | SUFFICIENT |
| `02_duplicates_near_duplicates` | Copies collapse to one piece of evidence | SUFFICIENT, `DUPLICATE_EVIDENCE_COLLAPSED` |
| `03_contradictory_evidence` | A conflict caps the verdict | LIMITED, `CONTRADICTORY_EVIDENCE` |
| `04_unrelated_and_weak_context` | Weak links are context | one SUFFICIENT, three LIMITED |
| `05_insufficient_unparseable` | Unusable input is refused | no incident |
| `06_uncorroborated_single_alert` | One alert alone is not proof | LIMITED |
On a case with evidence, open the multi-source result and show the **Management summary** (records to evidence units to incidents, verdict mix, telemetry present and absent, what to collect next, data quality); it is the answer to "what does a security leader get from this?". The CISO view of the whole project is `CISO_Brief.md`; the executive decision paper is `Executive_Brief.md` (a bounded six-week read-only pilot, with `Pilot_Plan.md`, `Security_Governance_Summary.md` and the SBOM behind it).
Then: the AI action (shows seconds and a Cancel button; if the model is slow say so and show the fallback), the lead's approval and the gated export, the Security page with a probe. Run the UI at a phone width once to show it is responsive.

## 3. Numbers you may quote (and what each does not show)
| Say | Source | It does not show |
|---|---|---|
| 3,827 backend and 307 frontend tests pass | the runs above | correctness, only behaviour |
| On the 67 locked cases AISOP says sufficient for 11, naive baselines for 29 and 24 | `Evaluation.md` | which is right (no human labels yet) |
| On 2,250 randomised synthetic cases with truth by construction, the false-sufficient rate falls 0.835, 0.711, 0.470, 0.345, 0.219 as each rule is added, then 0.000 (95% CI 0.000 to 0.002) for the gate | `Evaluation.md`, `synthetic_benchmark.py` | that the definition of independence is right: truth shares the gate's definition |
| 0 of 1,737 false assertions were called supported by the claim verifier; 2,478 of 2,478 true ones were | `claim_verifier_mutation.py` | how often a model's claims are right |
| Vantage rule: one-sensor corroboration is capped at LIMITED; found on real public data; locked cases unchanged; none ever raised | ADR-017, `vantage_effect.py` | independent validation (designed from that finding) |
| 377 of 377 records from two public datasets ingested (0 before fixes) | `Real_Format_Ingestion_Result.md` | other vendors' formats |
| ATT&CK rules recovered 1 of 20 expected techniques with 0 false techniques on 5 benign scenarios; the raw captured model scored F1 0.00 | `Evaluation.md` | coverage; do not say AISOP maps ATT&CK well |

## 4. Likely hard questions, one line each
- *What is new?* An applied combination: deterministic fail-closed sufficiency gate with independence and vantage rules, plus claim verification; each ingredient has precedent; effect measured on synthetic data, not yet on human labels.
- *Isn't the gate just a few rules?* On the locked cases four rules reproduce its SUFFICIENT set; what the gate adds is the LIMITED tier, provenance and contradiction handling, and it needs your labels to be judged.
- *Where is the accuracy?* Not claimed. The labelled run is the next step.
- *Was the code AI-written?* Largely, under written rules; show the live change in `Code_Guide_and_Live_Change.md`.
- *Why only 1 of 20 techniques?* Conservative on purpose; rules were not tuned to the scenarios.
- *Is it hosted?* Not live; the demo is local.

## 5. Do not claim
Production-ready; OWASP compliant; zero-day detection; accuracy, F1 or superiority over any baseline or product; novelty or "first"; real customer data; tamper-proof logs; model correctness; broad ATT&CK coverage; the hosted site is live; a PentAGI test.

## 6. If something fails live
Say so, restart with `demo_check.ps1 -Start` (about 15 seconds), use the recorded fallback for the AI step, and never improvise numbers.

## 7. Still open (owner)
Label the 67 development cases (the labelling tool shows the addendum rules), a second reviewer on every 4th, one held-out run reported either way; create the Workers AI token and the Render service or drop the hosted claim; rehearse aloud including one live code change.
