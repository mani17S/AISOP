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
| Baselines on the development split | `backend/evaluation_tools/score_sufficiency_baselines.py` | B0 sufficient 29, B1 24, AISOP 11, of 67. No labels exist, so no accuracy |
| Licence scan | package metadata of the 72 installed Python distributions and the frontend dependencies | see the last section |

## The five criticisms

### 1. Lack of research novelty: PARTLY ADDRESSED, NOT CLEARED
- Done: a 15-source literature and product review (`docs/10_Research/Literature_Review.md`), a stated and falsifiable hypothesis (`docs/10_Research/Evaluation.md`), baselines implemented and scored, and novelty wording limited to what the sources support.
- Finding: each ingredient has precedent (abstention on insufficient context, discounting dependent sources, claim verification). The deterministic, fail-closed combination for SOC evidence was not found in the pages read. That is a limited search, not proof of absence.
- Not proven: whether the gate gives fewer false-sufficient conclusions than the baselines. The 67 development cases have no labels, so only stricter-than-baseline behaviour (29 and 24 against 11 sufficient) is shown. Three key papers were read only in part.
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
- What the panel may be told: "The mapping is conservative by design: 13 evidence-backed rules, no false techniques on 5 benign scenarios, and low recall on my 20 scenarios (1 of 20). Broader coverage is future work."
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
Also fixed: the benchmark report printed a benign false-positive rate of 2 of 2 as "1.0%" (now 100.0%, with a test). Full backend suite after these changes: 3,742 passed, 1 skipped, 1 expected failure (25 new tests). These closure figures are reviewer estimates in the 2026-11-23 review's own scale, not measurements.

## What still needs the owner (nothing here can be done by an assistant honestly)
1. Label the 67 development cases, then run the scorer and report the result either way.
2. Read in full: Joren et al. (arXiv 2411.06037), Zomlot et al. (AISec 2011), Dong et al. (PVLDB 2009), DeepFaith (arXiv 2607.24348), and the two arXiv papers cited in the review, before citing any of them.
3. Rehearse the 10-minute walkthrough aloud, including one live code change.
4. Create the Cloudflare Workers AI token and the Render service (`docs/11_Deployment/Hosting_Plan.md`), then rotate the Render database password after the defence.
