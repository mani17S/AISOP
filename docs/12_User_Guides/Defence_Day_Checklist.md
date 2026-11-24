# Defence day checklist (verified 2026-11-24)

One page to run from. Everything here was checked on 2026-11-24 against the repository and the running local demo. Longer answers are in `Defence_Walkthrough.md`; the evidence behind every number is in `docs/10_Research/` and `Panel_Criticism_Validation.md`.

## 1. The day before
1. `pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\demo_check.ps1 -Start` until it prints "All checks OK", then `-WarmUp` (loads the model). Verified today after a backend restart on the latest code: all checks OK.
2. Run the suites once and quote only what they print: `.venv\Scripts\python.exe -m pytest backend/tests/unit -q` (about 4 minutes; last full run 3,883 passed, 1 skipped, 1 expected failure) and, in `frontend/`, `npm test` (307 of 307).
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
**Real attack telemetry, one command (about 3 seconds, terminal only; the data is a public MIT-licensed capture kept outside the repository, so check it is on the machine):**
`.venv\Scripts\python.exe backend\scripts	riage_file.py D:\AISOP-Reference-Data\otrf_dev_20261124\SDWIN-201018225619\host0\cmd_lsass_memory_dumpert_syscalls_2020-10-1822561997.json --out D:\AISOP-Backups\AISOP_Dev_Logs	riage_demo_lsass`
Verified 2026-11-24: 118 records, all accepted, 15 incidents, every one LIMITED (a single source at one host, said so in the summary), ledger verified; T1003.001 derived by `EP-T1003.001-LSASS-MEMORY-READ` and pointing to records #50 and #52 (the `lsass.exe` access events). Say: this capture is from the half of the public datasets I developed the rules on, so it is a demonstration, not the held-out evidence; the held-out number is 11 of 34. The summary also lists the telemetry that is absent, which is what a pilot would collect next.

Then: the AI action (shows seconds and a Cancel button; if the model is slow say so and show the fallback), the lead's approval and the gated export, the Security page with a probe. Run the UI at a phone width once to show it is responsive.

## 3. Numbers you may quote (and what each does not show)
| Say | Source | It does not show |
|---|---|---|
| 3,883 backend and 307 frontend tests pass | the runs above | correctness, only behaviour |
| On the 67 locked cases AISOP says sufficient for 11, naive baselines for 29 and 24 | `Evaluation.md` | which is right (no human labels yet) |
| On 2,250 randomised synthetic cases with truth by construction, the false-sufficient rate falls 0.835, 0.711, 0.470, 0.345, 0.219 as each rule is added, then 0.000 (95% CI 0.000 to 0.002) for the gate | `Evaluation.md`, `synthetic_benchmark.py` | that the definition of independence is right: truth shares the gate's definition |
| 0 of 1,737 false assertions were called supported by the claim verifier; 2,478 of 2,478 true ones were | `claim_verifier_mutation.py` | how often a model's claims are right |
| Vantage rule: one-sensor corroboration is capped at LIMITED; found on real public data; locked cases unchanged; none ever raised | ADR-017, `vantage_effect.py` | independent validation (designed from that finding) |
| 377 of 377 records from two public datasets ingested (0 before fixes) | `Real_Format_Ingestion_Result.md` | other vendors' formats |
| ATT&CK rules recovered 11 of 34 documented techniques (32%, interval about 19% to 49%) on the held-out half of public attack captures labelled by their authors, rules frozen first; 3 of 20 author-written scenarios; 0 false techniques on 5 benign scenarios; the raw captured model scored F1 0.00 | `Detection_Engineering_Evaluation.md`, `Evaluation.md` | coverage and the direction of the gain; do not say AISOP maps ATT&CK well or completely |

## 4. Likely hard questions, one line each
- *What is new?* An applied combination: deterministic fail-closed sufficiency gate with independence and vantage rules, plus claim verification; each ingredient has precedent; effect measured on synthetic data, not yet on human labels.
- *Isn't the gate just a few rules?* On the locked cases four rules reproduce its SUFFICIENT set; what the gate adds is the LIMITED tier, provenance and contradiction handling, and it needs your labels to be judged.
- *Where is the accuracy?* Not claimed. The labelled run is the next step.
- *Was the code AI-written?* Largely, under written rules; show the live change in `Code_Guide_and_Live_Change.md`.
- *Why only about a third?* Two reasons, both measured. The rules only claim what a command line or a typed event shows, so lateral movement, Kerberos and in-memory techniques are mostly not covered; and some captures do not contain the telemetry at all. The first number was 0 of 50 with the original six rules; the endpoint rules were written from public technique definitions, frozen, then scored once on data I had not looked at. Dev looked better (49%) because I had inspected it; I report the lower held-out number.
- *Is 32% good?* No. It is a start with an honest number and a method for improving it with a fresh held-out set each time. There is no benign corpus, so a false-positive rate is not claimed.
- *Is it hosted?* Not live; the demo is local.

## 5. Do not claim
Production-ready; OWASP compliant; zero-day detection; accuracy, F1 or superiority over any baseline or product; novelty or "first"; real customer data; tamper-proof logs; model correctness; broad ATT&CK coverage; the hosted site is live; a PentAGI test.

## 6. If something fails live
Say so, restart with `demo_check.ps1 -Start` (about 15 seconds), use the recorded fallback for the AI step, and never improvise numbers.

## 7. Still open (owner)
Label the 67 development cases (the labelling tool shows the addendum rules), a second reviewer on every 4th, one held-out run reported either way; create the Workers AI token and the Render service or drop the hosted claim; rehearse aloud including one live code change.
