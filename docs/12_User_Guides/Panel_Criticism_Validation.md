# Panel Criticism: Validation Record (2026-11-23)

Purpose: for each criticism the panel raised, what was re-checked today, the command or source, the result, and what the check does NOT prove. Everything below was produced on 2026-11-23 on the author's machine against commit `4938508` plus the documentation edits in the commit that adds this file. Data is synthetic and author-built. Nothing here claims production readiness.

## Checks run today

| Check | Command | Result |
|---|---|---|
| Backend unit suite | `.venv\Scripts\python.exe -m pytest backend/tests/unit -q` | 3,717 passed, 1 skipped, 1 expected failure, 0 failed (4 min 12 s). 10 more tests were added afterwards (`test_attack_mapping_ground_truth.py`, 10 passed alone, and the 128 architecture and evaluation guard tests re-ran clean); the full suite was not re-run after that addition |
| Reliability, OWASP-mapped and adversarial suites | `pytest backend/tests/unit/test_reliability_matrix.py test_owasp_probe_suite.py test_stage5_adversarial.py` | 168 passed, 1 skipped |
| Frontend | `npm run typecheck`, `npm test`, `npm run build` in `frontend/` | typecheck clean, 290 of 290 tests, build succeeded |
| npm advisories | `npm audit --omit=dev`, `npm audit` | 0 in what ships; 2 (1 moderate, 1 high) in the dev-server toolchain (vite, esbuild), not part of the build |
| Alert adapters | `get_default_registry().list_adapters()` | 8 registered |
| Baselines on the development split | `backend/evaluation_tools/score_sufficiency_baselines.py` | B0 sufficient 29, B1 24, AISOP 11, of 67. Against the owner's development labels (2026-11-25) false-sufficient: B0 41.5 %, B1 33.8 %, AISOP 15.4 %; gate accuracy 49.3 % |
| Licence scan | package metadata of the 72 installed Python distributions and the frontend dependencies | see the last section |

## The five criticisms

### 1. Lack of research novelty: PARTLY ADDRESSED, NOT CLEARED
- Done: a 15-source literature and product review (`docs/10_Research/Literature_Review.md`), a stated and falsifiable hypothesis (`docs/10_Research/Evaluation.md`), baselines implemented and scored, and novelty wording limited to what the sources support.
- Finding: each ingredient has precedent (abstention on insufficient context, discounting dependent sources, claim verification). The deterministic, fail-closed combination for SOC evidence was not found in the pages read. That is a limited search, not proof of absence.
- Not proven: whether the gate gives fewer false-sufficient conclusions than the baselines. On the 67 development cases the owner's labels give a false-sufficient rate of 15.4 % for the gate against 41.5 % (B0) and 33.8 % (B1), but only 2 cases are labelled SUFFICIENT and an AI second reviewer agreed with the owner on just 6 of 17, so this is weak, development-only evidence; held-out is not run. Three key papers were read only in part.
- Needs the owner: label the cases (`datasets/sufficiency_eval/labels_template.csv`), then run the scorer. A model must not write these labels, because the result would then measure the model against itself.

### 2. Weak SOC architecture understanding: ADDRESSED IN DOCUMENTS, NEEDS THE OWNER'S EXPLANATION
- Done: architecture diagrams with each part marked IMPLEMENTED, PARTIAL or PLANNED; ADRs 007 to 016; the walkthrough places AISOP as an investigation and evidence-qualification layer after detection, not a detector.
- Not proven: any analyst's judgement of usefulness (no user study); fit with a real SIEM or SOAR.
- Needs the owner: be able to explain telemetry versus alert versus evidence versus investigation, and to name the tiers, kill chain and chain of custody, aloud.

### 3. Limited alert ingestion: ADDRESSED ON SYNTHETIC DATA
- Done: 8 adapters in the default registry, 6 source-agnostic domain adapters, a Suricata EVE converter; batch limit 1,000; duplicates skipped by SHA-256. Adapter and ingestion tests pass in the full suite above.
- Not proven: parsing of real vendor exports. All records are samples written for this project.

### 4. Concern that UI and code are AI-generated: DEFENSIBLE, NOT REMOVABLE
- Done: the AI assistance is disclosed (`CLAUDE.md`, `docs/12_User_Guides/Sources_and_Acknowledgements.md`); behaviour is covered by 3,717 backend and 290 frontend tests, adversarial and OWASP-mapped suites, an architecture test that fails if the model is called outside the gate; the interface follows a written design constitution and was reviewed against three design references.
- Not proven: authorship per file. Tests written with AI help are evidence of behaviour, not proof of correctness.
- Needs the owner: walk through three files without notes and make one small live change, then show the test fail and pass.

### 5. Crash when handling multiple alerts: ADDRESSED, ORIGINAL CAUSE UNPROVEN
- Done: reliability matrix R01 to R12 (concurrent ingest, duplicates, malformed and large input, commit failure, model timeout, retry bounds) passes in the offline suite; the measured IPv6 `localhost` stall is fixed by using `127.0.0.1`; limits and a per-case lock exist.
- Not proven: that the panel's crash had that cause; behaviour under real concurrent load. The PostgreSQL matrix figures (38 passed, 3 not executable live) are from a saved log of an earlier run and were not re-run today.

## A weakness this validation found (ATT&CK coverage)
Run: `.venv\Scripts\python.exe backend\evaluation_tools\score_attack_mapping.py` (new today) feeds each of the 20 hand-authored ground-truth scenarios through the same normalisation and rule engines the product uses, with no model, and compares the techniques emitted with the scenario's expected list.

| Measure | Result |
|---|---|
| Mandatory expected techniques recovered | 1 of 20 (recall 0.05) |
| Techniques emitted | 4, of which 2 were not in the expected list (both T1564.003 Hidden Window, which the scenario's own command line does show, but the author had not listed it) |
| Benign scenarios with any technique emitted | 0 of 5 |

Reading of the result:
- The rule table is small by design (6 rules in the correlation engine, 7 in the domain engine, 13 in all) and every rule states a limitation. The system prefers to say nothing over mapping a technique it cannot support. That gives no false techniques on benign activity, and very low recall.
- Many "expected" techniques are the kind a model proposes from context (for example T1059.003 for a `cmd.exe /c echo` line), which the rules deliberately do not claim.
- The synthetic scenarios use reserved documentation addresses (`198.51.100.45`). The rule "a scripting host connects to a public address" correctly does not treat these as public, so it never fires on this data.
- The scenarios and the rules share one author, so even the 1 of 20 shows consistency, not accuracy.
- Decision: the rules were NOT extended to match these scenarios. Rules written after reading the scenarios and then scored on them would give a flattering number that would not hold on new data. Extending coverage is future work and needs scenarios written afterwards.
- What the panel may be told: "The mapping is conservative by design: 52 evidence-backed rules in three tables (6 + 7 + 39), no false techniques on 5 benign scenarios, and low recall on my 20 scenarios (1 of 20 when measured on the first 13 rules, before the endpoint table was added; 3 of 20 with it, per `docs/10_Research/Evaluation.md`, not re-run here). Broader coverage is future work."
- What must not be said: that AISOP maps ATT&CK well, covers the matrix, or detects these attacks.
- Guard added: `backend/tests/unit/test_attack_mapping_ground_truth.py` (10 tests) asserts the benign scenarios emit nothing and every record is accepted. It deliberately does not assert recall.

## Things found and corrected during this validation
- The walkthrough gave the scorer's path as `backend/scripts/...`; it is `backend/evaluation_tools/...`. Corrected.
- Test counts in the walkthrough were out of date (3,171 and 3,631 backend, 256 frontend). Replaced with today's figures.
- One sentence in the "do not claim" list was garbled. Corrected.

## Licence scan (installed dependencies, metadata only)
- Python, 72 distributions: mostly MIT, BSD and Apache-2.0. Items to note: `psycopg` and `psycopg-binary` are LGPL-3.0 (used unmodified as a library); `certifi` and `pathspec` are MPL-2.0 (unmodified). None is copyleft in a way that affects this project's use.
- Frontend runtime: `react` and `react-dom` MIT; three fonts under OFL-1.1 (bundled font files, licence permits redistribution with the font). Dev dependencies listed as MIT or Apache-2.0.
- Not covered: transitive frontend packages beyond the declared ones, and the licences of the models (Qwen, nomic-embed-text, Llama 3.3 via Cloudflare). Check each model's licence terms before stating them. This reads declared metadata; it is not legal advice.

## Work done after this record was first written (2026-11-23, same day)
| Criticism | What was added | New evidence | Closure estimate (was) |
|---|---|---|---|
| Novelty and evaluation of evidence | Metamorphic evaluation of the gate; regenerated captured-model benchmark; ATT&CK scorer | AISOP broke 0 of 5 stated relations on the 67 development cases, the naive baselines broke the duplicate relations on 37 to 42 of 66; raw `llama3.1:8b` MITRE F1 0.00 with false techniques on 2 of 2 benign scenarios; rules 1 of 20 with 0 false techniques on benign | 50 (was 45); evaluation evidence 40 (was 28). Still no labelled accuracy; the relations restate the project's own invariants |
| SOC architecture understanding | `docs/03_System_Design/SOC_Placement_and_Vocabulary.md` | Value-chain diagram, tool classes, vocabulary mapped to source objects, 60-second script | 68 (was 55). Documents only; not yet rehearsed or questioned |
| Multi-source ingestion | Three adapter edits; real public samples; 10-record attributed fixture; 4 tests | 0 of 377 real records accepted before, 377 of 377 after; over-merge of distinct events found and documented | 68 (was 60). One forwarder shape only; no real Suricata or vendor EDR export |
| UI / AI-generated code | `docs/12_User_Guides/Code_Guide_and_Live_Change.md` | Three files with where-to-find-it, AI use stated plainly, live change verified (10 named tests fail, restored with no diff) | 64 (was 58). Perception cannot be proven away; depends on the owner explaining it aloud |
Also fixed: the benchmark report printed a benign false-positive rate of 2 of 2 as "1.0%" (now 100.0%, with a test). Full backend suite after these changes: 3,742 passed, 1 skipped, 1 expected failure (25 new tests); later the same day, after the ablation, labelling tool and second UI pass: 3,754 passed, 1 skipped, 1 expected failure and 301 of 301 frontend tests. These closure figures are reviewer estimates in the 2026-11-23 review's own scale, not measurements.

## Second addition (2026-11-23, later the same day)
| Criticism | What was added | Closure estimate (was) |
|---|---|---|
| Novelty and evidence evaluation | Ablation arms B2 to B4 and `ablation_sufficiency.py`; `Contribution_Statement.md` (claim, measured evidence, what is not shown, threats to validity); ADR-017 (PROPOSED) for vantage-level independence | Novelty 54 (was 50); evidence evaluation 48 (was 46). The ablation also showed that four simple rules reproduce the gate's SUFFICIENT set on the development cases, so what the full gate adds is the LIMITED tier, whose correctness needs labels |
| SOC architecture | Unchanged this round | 72 |
| Ingestion | Unchanged this round (second real source not built; declined) | 72 |
| UI and AI-code concern | Second UI pass (compact phone header, two-column tablet cards, a scroll-fade defect fixed), second verified live-change drill (5 named tests fail when the brute-force threshold changes) | 76 (was 74) |
These are reviewer estimates in the review's own scale. Novelty cannot honestly pass the high 50s, and evidence evaluation the high 40s, until the 67 labels exist.

## Third addition (2026-11-24): a built contribution, not a rescoring
| Criticism | What was added | Closure estimate (was) |
|---|---|---|
| Novelty | Vantage-level independence implemented in the gate (ADR-017): a record is a different witness only if seen from a different vantage point; one-vantage corroboration is capped at LIMITED with `SAME_VANTAGE_ONLY`. Found on real public data, measured on controlled annotations (11 sufficient cases fall under one vantage, 11 stay under cross-vantage, none ever raised), checked on both ingestion paths, 22 new tests plus a parity test | 60 (was 54). Not higher: designed from a real-data finding and checked on the same data; vantage is coarse; no labelled evidence that the cap is right; the rule table label was `suff-v4` until the owner approved ADR-017 on 2026-11-24 and it became `suff-v5` |
| Evidence evaluation | Claim-verifier mutation evaluation (`claim_verifier_mutation.py`): 2,478 of 2,478 true assertions accepted, 0 of 1,737 false assertions called SUPPORTED across 12 fault classes, no exception escaped | 56 (was 48). Still no labelled accuracy for the gate, which is what would move it past the low 60s |
| SOC architecture, Ingestion, UI and AI-code | Unchanged this round | 72, 72, 76 |
Honest ceiling: with the owner's 67 labels, a second reviewer and one held-out run reported either way, novelty and evidence evaluation could reasonably reach the high 60s. Without them these are the most the evidence supports. The rule change was made on the owner's instruction to add a contribution; the owner approved ADR-017 on 2026-11-24 and the rule table is now `suff-v5`.

## Fourth addition (2026-11-24): scale evidence
| Criticism | What was added | Closure estimate (was) |
|---|---|---|
| Evidence evaluation | Synthetic benchmark of 2,250 cases with truth by construction, nine families, nine-arm comparison with confidence intervals, development seed separated from the reported seed; the rule table renamed `suff-v5` on the owner's approval of ADR-017 | 62 (was 56) |
| Rubric check | A reference implementation of the written labelling guide agrees with the gate on 65 of 65 judged cases (partly by construction) and exposes four rules the guide never states; a proposed addendum is written for the owner to adopt before labelling (the guide itself is hash-locked and was not changed). 3 more tests (`test_rubric_oracle.py`) passed on their own after the full run. | (part of the 62 above) |
| Novelty | Per-rule attribution at scale: each rule fixes a named family of failures, and the vantage rule is shown to be necessary (same-vantage and out-of-window families are fixed only by the full gate) | 62 (was 60) |
Why not higher: the benchmark's truth shares the gate's definition of independence, there is no human-labelled result, no second reviewer, and no real incidents. Past about 65 these two criticisms need the owner's labels; 75 is not supportable by simulation alone, and claiming it would be the kind of overstatement a panel finds.

## Fifth addition (2026-11-24): a second real source
| Criticism | What was added | Closure estimate (was) |
|---|---|---|
| Ingestion | A second real format: a public SSH server log (2,000 lines) through a year-explicit syslog converter and a stricter, broader Linux auth adapter; three real-data defects found and fixed; 13 tests | 77 (was 72). Two real sources now (Windows forwarder, SSH syslog); still no real vendor EDR or Suricata export, one dataset each, year assumed for the SSH log |

## Sixth addition (2026-11-24): the company's view
A CISO-facing layer: a deterministic management summary in every multi-source result (workload reduction, verdict mix, telemetry present and absent in the supplied evidence, what to collect next, data quality, ledger) shown in the case workspace, and `CISO_Brief.md` (what it is for, five questions answered with measured evidence and limits, a pilot design, what to build next). 7 backend and 6 frontend tests; verified live through the API on the `suff-v5` rule. It supports the SOC-architecture and UI/AI-code answers (a defined user and purpose); it does not change the research scores.

## What still needs the owner (nothing here can be done by an assistant honestly)
1. Label the 67 development cases, then run the scorer and report the result either way.
2. Read in full: Joren et al. (arXiv 2411.06037), Zomlot et al. (AISec 2011), Dong et al. (PVLDB 2009), DeepFaith (arXiv 2607.24348), and the two arXiv papers cited in the review, before citing any of them.
3. Rehearse the 10-minute walkthrough aloud, including one live code change.
4. Create the Cloudflare Workers AI token and the Render service (`docs/11_Deployment/Hosting_Plan.md`), then rotate the Render database password after the defence.

---

# Addendum 2026-11-25: the submitted abstract and the five original criticisms, re-assessed independently

Method: three read-only reviews of the repository (abstract claims against code, criticisms 1 to 3, criticisms 4 and 5) plus the owner's own checks. Items marked VERIFIED were re-checked by command or file read on 2026-11-25; the rest come from the reviews and are marked REVIEW. Nothing here changes an approved decision or restarts development. It adjusts the order of work only.

## A. The abstract against the code
| Abstract claim | Status | Evidence |
|---|---|---|
| Alert ingestion, parsing and normalization | IMPLEMENTED | 8 alert adapters, Sysmon parser (JSON), 6 domain adapters; tests exist (REVIEW) |
| Deterministic IOC extraction | IMPLEMENTED | `evidence/entity_extractor.py`; shown as "Extracted Observables" in the UI (REVIEW) |
| MITRE ATT&CK mapping | IMPLEMENTED, narrow | evidence-backed rules only; recall 1 of 20 on the author's scenarios, 0 false techniques on 5 benign |
| Timeline-based correlation | IMPLEMENTED | `correlator.py`, `timeline.py`, multi-source panel (REVIEW) |
| Local LLM through Ollama | IMPLEMENTED | local default, non-local refused unless an operator opts in; Ollama healthy in the demo (VERIFIED 2026-11-25) |
| Deterministic processing before the LLM | IMPLEMENTED | one fail-closed gate; an architecture test forbids model calls outside it (REVIEW) |
| Threat-intelligence enrichment | PARTIAL | two small local files (Feodo 5 rows, Tor exit nodes); the AbuseIPDB provider is wired nowhere in the app (VERIFIED); VirusTotal and OTX are empty; the multi-source flow attaches no threat intelligence (REVIEW) |
| RAG | PARTIAL | pgvector over a local knowledge base, but only in single-case AI synthesis and only when the analyst types a filter of 3 or more characters; not in the multi-source flow (REVIEW) |
| Confidence estimation | PARTIAL | the deterministic measure is the sufficiency verdict; per-claim confidence is reported by the model, capped by guardrails and labelled "model-reported" in the UI (REVIEW) |
| Investigation recommendations | PARTIAL | the model path lists non-destructive actions; the deterministic path says what to collect next, never a response action (REVIEW) |
| Root cause analysis | NOT IMPLEMENTED as named | the string "root cause" appears nowhere in backend or frontend (VERIFIED). Closest: model hypotheses and alternative explanations |
| Analyst validates AI insights and decides | PARTIAL | a lead approves or rejects the whole stored multi-source result, and export is gated on that; there is no per-claim human accept or reject, and the single-case report path has no approval gate (REVIEW) |
| Interactive dashboard for review | PARTIAL | the Overview shows health and five cases; the real review surface is the case workspace |

Safe wording for the panel instead of the abstract's phrases:
- Not "root cause analysis": say "evidence-grounded incident summary, ATT&CK technique hypotheses and alternative explanations".
- Not "confidence estimation": say "a deterministic evidence-sufficiency verdict (sufficient, limited, insufficient) with reasons, plus model-reported confidence that is capped and labelled as not a measure of evidence strength".
- Not "threat intelligence enrichment" without a qualifier: say "offline local feeds, context only; external services are designed but not enabled".
- Not "RAG powers each investigation": say "optional retrieval over a local playbook knowledge base during single-case AI synthesis".
- Never claim: live or real-time threat intelligence, detection, zero-day coverage, a percentage reduction in unsupported conclusions beyond the recorded evaluation, or production readiness.

Strengths the abstract does not mention and the panel should hear: the fail-closed sufficiency gate that abstains before any model call; duplicates counted once, with analyst, intelligence and AI output kept apart from observed evidence; contradiction detection; raw SHA-256 and a hash-chained audit trail; claim verification with demotion; the product works with the model switched off.

## B. The five criticisms: status after independent review
| # | Criticism | Status | The honest gap |
|---|---|---|---|
| 1 | Research novelty | PARTLY | The defensible claim is narrow: a deterministic, fail-closed evidence-sufficiency gate. The gate agrees with the owner's labels on 49.3 %; one labeller; 2 SUFFICIENT labels; held-out never run; the labelling rule is the gate's own definition, so benchmark conformance is not accuracy. Only a human second reviewer and one held-out run, reported either way, move this |
| 2 | SOC architecture | PARTLY | Placement (after detection, evidence qualification) is coherent. Vocabulary errors in the docs: IOC versus observable, "incident" for a correlation cluster, "verdict" reused for a sufficiency grade, kill chain merged with ATT&CK, a diagram arrow showing the SIEM feeding the EDR; no lifecycle mapping; Architecture.md section 8 is stale |
| 3 | Telemetry | PARTLY | Real public data has passed only for Sysmon, Windows Security and Linux SSH. EDR, email, cloud and Suricata adapters are tested on sample-shaped data. No real CrowdStrike, Entra or Zeek record has been ingested; CrowdStrike appears only as an alias string |
| 4 | AI-generated UI and code | PARTLY, not removable | 52 of 65 commits carry a Claude co-author trailer and 50 of 65 fall within 22 to 25 November (VERIFIED). Strengths: ADRs with owner approval dates, owner-authored labels, disclosed AI use, honest negative results. Weak spots: `case_service.py` (2,000 lines, one 630-line method), a 3,500-line stylesheet, large components with many inline styles, 11 empty placeholder files including four provider stubs |
| 5 | Multiple-alert reliability | PARTLY | Batch cap 1,000 and per-record savepoints are tested, but the reliability tests share one synchronous session. Correlation runs synchronously on the event loop (no `to_thread` anywhere, VERIFIED), so a large investigation blocks every other request. Never load-tested. The demo backend once stopped silently (cause unproven) |

## C. Code defects found while assessing (not yet fixed; owner's call)
1. Invented defaults violate the "never invent a source identity" rule: host `"WORKSTATION-01"` (EDR adapter), `"UNKNOWN-HOST"` (Sysmon adapter), user `"unknown"` (Windows Security adapter) (VERIFIED). A shared invented host could create false links between unrelated alerts.
2. The firewall and IDS adapter always sets provider `"Suricata-IDS"` (VERIFIED), whatever the product.
3. Ingestion error text echoes `str(exc)` on the Sysmon path (REVIEW).

## D. Adjustments to the existing priorities (no new plan)
1. Evidence for criticism 1: a human second reviewer and the held-out run, reported whatever the result. Nothing else raises it.
2. Criticism 5: run one real load test (for example 1,000 alerts, then a 1,000-event investigation while polling `/health`) and record it; if health stalls, move `analyze` off the event loop.
3. Fix the invented defaults and the provider label, with tests.
4. Correct the document contradictions: the "13 rules" figure against about 52, the addendum status in Evaluation.md, Architecture.md section 8, mangled paths, the SOC vocabulary, and the stale line numbers in the code guide (search by function name).
5. Remove or clearly mark the empty placeholder files, especially the provider stubs.
6. Practise the two live code changes and a plain answer on authorship, using the three files the code guide names (`independence.py`, `sufficiency_gate.py`, `mitre.py`), not `case_service.py`.
7. Detection engineering stays PROPOSED; do not present it as delivered.

Not established by this addendum: user testing, accessibility with a screen reader, performance under load, behaviour on real vendor exports.

## E. Addendum, 2026-11-26: Known limitations found by the 2026-11-26 review
An independent read-only review of the uncommitted responsiveness change set (full table: `docs/05_Backend/Investigation_Responsiveness_Profiling_2026-11-25.md` section 19) found two limits a panel member could probe. Neither has been fixed at the time of this addendum. The review read the code only: pytest, the live app and a PostgreSQL run were not part of it.

1. **The case verdict badge covers at most 25 incidents.** The badge is computed from the incidents stored for the case, at most 25. If a case has more, the badge may not include the worst one, and the note that the list was truncated appears only in a tooltip. A panel member could ask: "Can a case with 100 incidents show a milder badge than it deserves?" Honest answer: yes, if the worst incident is not among the stored 25. A fix is planned (show the truncation as visible text); a test with 26 or more incidents where the unstored one is the worst is planned too. Neither is done.
2. **An alert with no severity can understate an incident.** The adapters now store a missing severity as "unknown" instead of inventing one. Correlation and the persisted event then map "unknown" to "informational", the lowest level, so an alert with no severity counts as the lowest severity inside an incident, and the incident severity can be lower than the truth. A panel member could ask: "Is the missing severity invented?" Honest answer: no, it is derived from a missing field and not invented, but it is a real limitation and it is disclosed here. Whether the published evaluation scores need recomputing after the adapter change was not checked. The evaluation dataset case files are frozen and hash-locked, which suggests they are unaffected; that was not verified.

Related, for the criticism 5 row above: the same review confirmed a defect in the verdict badge (it shows "Not assessed" after closing, updating or transferring a case, with a false tooltip, and it is not refreshed after an investigation is started until the page is reloaded; a code fix is under way, not done) and found that a closed browser tab leaves the worker finishing its job and discarding the result. Both are recorded in section 19 of the profiling record.

Update, 2026-11-26 (later): the badge truncation limit (item 1 above) is now shown as visible text, for example "Limited (partial)", with an aria-label and a title, instead of only in a tooltip; the badge still reflects at most 25 stored incidents. The verdict defect after closing, updating or transferring a case, and the stale header badge, are fixed and were checked live (profiling record section 21). The missing-severity limitation (item 2 above, finding 6) is unchanged and still open.
