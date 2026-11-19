# ADR-013 Revision 2: remaining semantics and case_service integration (implementation report)

Date: 2026-11-12. Authority: owner decisions D1 to D8 in `D:/AISOP-Control/AISOP_ADR013_Remaining_Semantics_and_Case_Integration_Master_Prompt.md`. Predecessor: `ADR013_Revision2_Implementation_Report.md` (unchanged). Logs: `D:/AISOP-Backups/Reference_Research_2026-11-12/logs/adr013_remaining/` and `.../adr013_remaining_final/` (index `results.tsv`).

## 1. Outcome — COMPLETE for the authorized offline scope
Every completion criterion in the brief is verified offline. **UNVERIFIED / NOT RUN** (D8 and standing restrictions): PostgreSQL persistence, live browser, real-model behaviour. Limitations that remain are listed in section 12.

## 2. Baseline
Branch `main`, HEAD `c4e877c`, 321 `git status` entries, 0 stashes. The first slice was inspected before editing (report, ADR-013, design, matrix, semantics, detector, gate, workflow, report, service, `case_service`, all ADR-013 tests and the four expected-failures, the Detection Engineering predicate). Its offline results reproduced (1579 passed, 4 expected-fail).

## 3. Semantic decisions applied
| Decision | Applied |
|---|---|
| D1 ordering | 5 s tolerance also for ordering (<= 5 s EXPLAINED, never material); > 5 s only with a verified causal relationship; event time kept apart from collection/ingestion time; missing or low-quality time never upgraded or invented |
| D2 outcome | the existing 2.0 s constant (equality asserted), inclusive; compares only identical propositions (`signin_outcome`, `connection_allowed`) from independent sources; not a correlation window; boundary tests 1.999 / 2.0 / 2.001 |
| D3 identity | issuer-scoped session + two canonical principals of one directory; local ids and user names never equal; missing / different-directory canonical ids unresolved; same-source = MINOR |
| D4 temporal | issuer-scoped `correlation` + same event type/action/outcome + reliable times + > 5 s; source-native event ids never used |
| D5 independence | `independent` / `same_source` / `unknown`; only `independent` can be MATERIAL; declared shared upstream = one evidence unit; no score |
| D6 earlier file | no blanket rule; verified causal relationship required |
| D7 case_service | same detector and gate; authorization and case scoping untouched |

## 4. Ordering regression
Original fixture (artefact one hour earlier than the e-mail, shared hash only) encoded an unsupported causal assumption (D6). **Corrected fixture:** the artefact record states `origin_message_id` (the e-mail), the e-mail states it CONTAINS the hash, and `timestamp_semantics` is `arrival`; time one hour earlier. `test_adr013_ordering_defect.py` keeps its three original assertions (T1566.001 not derived, verdict not SUFFICIENT, `CONTRADICTORY_EVIDENCE:ordering`) through the real HTTP import-to-investigation path. **Negative test (real path):** the original shape now yields no contradiction, verdict SUFFICIENT, T1566.001 still derived. Same pair in the matrix as S7 and S7 negative.

## 5. Identity implementation
`_identity` groups dated observations by their single issuer-scoped `logon_session`; a finding needs two `principal` entities (`issuer:id`, from `canonical_id` + `canonical_id_issuer`) with the SAME issuer and DIFFERENT ids within 86400 s (the existing specific-link window). A session id is issuer-scoped only when the record names `session_issuer`; otherwise it stays `<own system>:<id>`. Provenance (source names, times, evidence ids) is preserved; user names and ids are never copied into findings (tested). Positive, same-string-two-systems, two-names, compatible-mapping, different-directory, same-source and invalid-field cases are tested.

## 6. Temporal implementation
Records stating the same issuer-scoped `correlation` and describing the same event (type, action, outcome) with both `valid` event times more than 5 s apart: MATERIAL when independent with a strong link (relation by the gate); MINOR for a naive time (rule 3) or the same source. Within 5 s: no finding for temporal (benign skew is not a conflict); for ordering: EXPLAINED disclosure. Time-zone offsets are normalised; `collected_at` and the stored ingestion-time column are never compared.

## 7. Outcome window
Exactly: two dated observations with the same proposition key, opposite polarity, different (non-same-source) sources, time gap in `[0, 2.0]` seconds inclusive. Boundary results: 1.999 s compared, 2.0 s compared, 2.001 s not compared (detector and workflow). The constant is `correlator.CONTRADICTION_WINDOW_SECONDS` semantically (same inclusive "opposite outcomes within a couple of seconds"); no mismatch found, so no stop was needed.

## 8. Case-service integration
`case_service.synthesize_case_investigation` Phase A: `detect_contradictions(observations_from_stored(...))` over this case's preserved raw payloads; Phase B: `evaluate_sufficiency(context, candidates)`. 10 parity tests: for ordering, outcome, identity and temporal conflicts both paths give verdict `limited` and the same `CONTRADICTORY_EVIDENCE:<kind>` codes; clean scenario unchanged; pre-existing file not a contradiction; case isolation; 404 for an unassigned analyst; deterministic across calls and under LLM failure. Differences documented in `CASE_SERVICE_CONTRADICTION_INTEGRATION.md` (anchor, hash binding, ingestion-time column for undated rows: flagged, not changed).

## 9. Detection Engineering boundary
Predicate `has_unresolved_material_contradiction` unchanged; it now also trips for identity and temporal findings (tested) and not for minor/explained ones. No findings interface, Sigma deployment, containment or response exists or was added.

## 10. Files
Created: `backend/tests/unit/test_adr013_semantics.py` (33), `backend/tests/unit/test_adr013_case_service.py` (10), `docs/Architecture/CASE_SERVICE_CONTRADICTION_INTEGRATION.md`, this report.
Modified (production): `schemas/contradiction.py` (kinds, explanation, independence state), `modules/evidence_domains/contradictions.py` (rewritten detector), `adapters.py` (optional fields + docstring), `model.py` (`upstream_id`), `bridge.py`, `scenarios.py` (`env` optional args), `domain_attack.py` (via the shared predicate, unchanged call), `modules/evidence/independence.py` (`event_correlation` as a STRONG entity type), `modules/correlation/models.py` (`upstream_id`), `workflow.py` (global detection, correlator surfacing, per-incident filter), `report.py` (explanations), `ai/guardrails/sufficiency_gate.py` (mirrored copies = one unit), `services/case_service.py`, `services/domain_evidence_service.py` (`upstream_id` in stored payload).
Modified (tests): `test_adr013_ordering_defect.py`, `test_adr013_contradictions.py` (causal fixture, D1 boundaries), `test_contradiction_matrix_spec.py`, `test_contradiction_model_spec.py` (S4, S6b, S7 corrected; markers removed), `frontend/tests/domain_evidence_panel.test.tsx` (+2).
Modified (frontend): `src/types/index.ts`, `src/components/DomainEvidencePanel.tsx`.
Modified (docs): ADR-013 and README row; design, matrix and semantics documents (records appended; earlier text intact).
Deleted: none. No migration, dependency, configuration, dataset or label change.

## 11. Tests (executed 2026-11-12, 14:34 to 14:36 +05:30; `pytest` = `.venv/Scripts/python.exe -m pytest -p no:cacheprovider`; every exit code 0)
| Group | Command (args) | Result |
|---|---|---|
| Identity, temporal, outcome boundaries, independence, adapters, trust | `backend/tests/unit/test_adr013_semantics.py -v` | 33 passed |
| Ordering regression + negative + gate/report/API/DE predicate | `test_adr013_ordering_defect.py test_adr013_contradictions.py -v` | 33 passed |
| Specifications (matrix + model) | `test_contradiction_matrix_spec.py test_contradiction_model_spec.py -v -rxX` | **29 passed, 0 xfailed** |
| Case-service parity | `test_adr013_case_service.py -v` | 10 passed |
| Sufficiency gate family | `test_evidence_sufficiency_gate.py test_evidence_independence.py test_sufficiency_metrics_and_dataset.py test_sufficiency_gated_generation.py -q` | 67 passed |
| Incident workflow / API / report | `test_multisource_workflow.py test_multisource_api.py test_deterministic_report_synthesizer.py test_evidence_domain_scenarios.py -q` | 105 passed |
| Existing case synthesis + hardening | `test_case_synthesis_api.py test_stage6a_hardening.py -q` | 35 passed, 2 warnings |
| Stage 6 domain suites | `test_evidence_domains.py test_domain_evidence_api.py test_stage6_security.py test_body_limit_regression.py test_domain_service_regression.py -q` | 84 passed |
| Stage 5 adversarial + guardrails | `test_stage5_adversarial.py test_output_guardrails_p2.py test_output_guardrails_secret_leakage.py test_claim_id_normalization.py test_qwen_investigation_synthesis.py -q` | 140 passed |
| **Full backend UNIT** | `backend/tests/unit -q -rxX` | **1630 passed, 0 failed, 0 skipped, 0 xfailed**, 13 warnings (61.97 s) |
| **Backend INTEGRATION, non-PostgreSQL** | `backend/tests/integration -m "not postgres and not ollama" -q` | **85 passed, 33 deselected** |
| PostgreSQL/Ollama | `backend/tests -m "postgres or ollama" --collect-only -q` | 33 collected, **0 executed: NOT RUN** |
| Frontend | `cd frontend; npm run typecheck`, `npm test`, `npm run build` | typecheck clean; **78 passed** (after adding 2 tests; 76 in the group run before); build clean |
| Compile | `compileall -q backend/app`; `py_compile` of 16 changed backend modules | clean |
Arithmetic: previous unit result 1579 passed + 4 xfailed = 1583 tests; now 1630 passed = +47 new tests (33 + 10 + 1 + 1 + 2 net from the boundary parametrisation) and the 4 former expected-failures converted into passes. Unit and integration are different directories and are not summed. Mutation checks (removing the causal requirement; forcing the tolerance to 0; ignoring declared upstream; not passing findings in `case_service`) made the corresponding tests fail each time.
Corrections found on the way: a variable shadowing bug of mine in the adapter (`key`), fixed before any test depended on it; a helper bug in my own test (`09:60:01`); two sloppy `or`-based assertions replaced; an assertion that assumed identical assessment hashes across case-path calls was wrong (pre-existing fresh investigation id) and was replaced by a check of the stable fields.

## 12. Expected failures and remaining limitations
Expected failures: **none**. Limitations: mirrored/forwarded copies are recognised only when the sources declare `source.upstream_id` (undeclared mirroring is invisible beyond the existing duplicate rules); identity and temporal findings need producers to emit issuer-scoped session / canonical-principal / correlation fields (absent fields yield no finding, never a guess); observation-based only (alerts produce no candidates); per incident / per case only; STATE kind not declared; the 10-minute retry window unused; only sign-in and connection propositions for OUTCOME; the case path differs from the incident path in anchor, hash binding and undated-row handling (documented).

## 13. Security and residual risks
Findings hold ids, source names, times and fixed vocabulary only (tested: no user names, ids, resources or message text). Detector and gate are deterministic and run with the LLM disabled; analyst statements, threat intelligence, unclassified evidence and model output cannot create, erase or resolve findings (tested on the incident and case paths). New fields are validated with fixed codes and are additive. Residual: (R1) wrong or missing producer-declared linkage can under-report (never over-report beyond MINOR); (R2) case-path undated-row ingestion-time behaviour (pre-existing, flagged); (R3) larger stored audit payloads on PostgreSQL UNVERIFIED; (R4) frontend verified by render tests only; (R5) pre-existing circular import when `domain_attack` is imported before the `correlation` package (application order unaffected); (R6) `event_correlation` added to the STRONG entity types in `independence.py`: it only affects records that carry a `correlation` field.

## 14. PostgreSQL / browser / Ollama
**NOT RUN.** Blocked tests: the 33 PostgreSQL/Ollama-marked tests (collected only). Separate owner authorization is required for each: PostgreSQL verification (stored `contradictions[]`, audit-row size, unique-hash race), a live-browser check of the contradiction section, and a local-model run.

## 15. Protected actions not performed
No PostgreSQL / Docker access or change, migration, database / role / volume change, model download, cloud or LLM call, dependency install, secret or configuration edit, credential read (`.env`, `.refact`, `viva-credentials.txt`, `opencode.json` untouched), deployment or RBAC change, historical dataset / label edit, test deletion or weakening, or Git mutation.

## 16. Git
Before: HEAD `c4e877c`, `main`, 321 entries, 0 stashes. After: HEAD `c4e877c`, `main`, 323 entries (two new untracked test files), 0 stashes. No stage, commit, stash, reset, clean, rebase, branch or push. Snapshots: `logs/adr013_remaining/git_status_before.txt` and `git_status_after.txt`.

## 17. Next bounded milestone and owner decisions
Next: authorize PostgreSQL verification of the Stage 5/6/ADR-013 stored fields in one run (also covering the unique-hash race), and decide the two review items below. Owner decisions: (1) should undated domain evidence be excluded from case-synthesis context events, matching the incident path (currently it enters with ingestion time; flagged, unchanged)? (2) should `case_report_synthesized` also be covered by a parity test? (3) which producers will emit `upstream_id`, `correlation`, `canonical_id` and `origin_message_id` so the new findings have data to work on (an integration question, not a code question)? Standing: credential rotation, body-limit default, service-authorization option B, Impeccable engine decision.
