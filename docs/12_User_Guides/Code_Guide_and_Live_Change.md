# Code guide for the defence: three files to explain and one live change

Written 2026-11-23. Purpose: the panel suspected the UI and code were AI-generated and not understood. This is not a way to hide that AI helped. It is the evidence of understanding: where the key decisions live, why, and a change you can make and prove in front of the panel. Read the code itself before the defence; this page only points to it. This page points to code by file plus function or constant name, not by line number, because line numbers drift as files change; search the file for the name. The names were checked against the files on 2026-11-25.

## How AI was used (state this plainly)
AI coding assistants wrote and edited much of the implementation under written rules (`CLAUDE.md`: invariants, no scope creep, tests before claims). The owner set the scope, approved the decisions recorded as ADRs (`docs/03_System_Design/ADR/`), and the behaviour is pinned by tests (3,742 backend and 290 frontend on 2026-11-23). Tests written with AI help show behaviour, not independent correctness. Authorship per file cannot be proven and should not be claimed either way.

## The three files

### 1. `backend/app/modules/evidence/independence.py` (what counts as independent evidence)
- `NEAR_DUPLICATE_WINDOW_SECONDS = 2.0` (constant near the top of the file): records with the same identity and entities within this window are one piece of evidence.
- `entity_link_strength` (function): STRONG or SPECIFIC (file hash, domain, public IP, path) versus WEAK (host, user, internal IP). Only strong and specific links corroborate.
- `cluster_evidence` (function): merges identical keys, identical raw digests, identical content, and near-duplicates. This is what makes "duplicates count once" true.
- Say: "A copy of a record is not a second witness. This function is where I decide which records are the same witness."

### 2. `backend/app/modules/ai/guardrails/sufficiency_gate.py` (when the AI may be asked at all)
- `assess_evidence_sufficiency` (function): counts independent evidence, applies the rules, returns SUFFICIENT, LIMITED or INSUFFICIENT with reason codes.
- `evaluate_sufficiency` (function): the single entry point; on any internal error it fails closed.
- Say: "The model is only called if this says evidence is enough. If it says INSUFFICIENT, no model call is made. There is one gate, and a test fails if any production code calls the model another way."

### 3. `backend/app/modules/ai/guardrails/claim_verifier.py` (what happens to the model's answer)
- `verify_claim` (function): each claim must cite events that exist (tier 1) and the quoted observable must actually be in those events (tier 2). The model's own confidence is ignored.
- Say: "The model can only suggest. Every claim is checked against the stored evidence by code that does not use a model, and a failed check falls back to the deterministic report."

Supporting: `correlation/correlator.py` (links records into incidents), `correlation/mitre.py` (the first of three conservative ATT&CK rule tables: 6 rules here, 7 in `evidence_domains/domain_attack.py`, 39 in `correlation/mitre_endpoint.py`, 52 in all), `ai/prompt_builder/` (evidence as untrusted data), `core/auth.py` and `core/rbac.py` (keys and roles), `middleware/security_events.py` (the Security page's data).

## Live change you can make and prove (verified 2026-11-23)
Goal: show you control the core rule and that tests defend it.
1. Open `backend/app/modules/evidence/independence.py` and find the constant `NEAR_DUPLICATE_WINDOW_SECONDS`. Change `NEAR_DUPLICATE_WINDOW_SECONDS = 2.0` to `0.0`. Meaning: "a near copy is no longer treated as the same evidence".
2. Run: `.venv\Scripts\python.exe -m pytest backend/tests/unit -q -k "independence or near_dup or corroborat or sufficiency or claim_verifier"`
3. Expected (observed on 2026-11-23): **10 tests fail**, among them `test_near_duplicates_merge_within_the_window_only`, `test_near_duplicate_is_collapsed_and_does_not_corroborate`, `test_500_near_identical_records_are_one_unit_of_evidence_never_independent_corroboration`, `test_duplicates_are_deduplicated_at_ingestion_and_near_duplicates_collapse_in_the_engine`, and the demo scenario `02_duplicates_near_duplicates`.
4. Say what each failure means, then change it back to `2.0` and re-run to show the tests pass (with the filter in step 2, 245 tests were selected on 2026-11-23: 10 failed with the change, all passed after restoring it).
Do not run the full suite during the demo (about 4 minutes); use the filtered command.
Second change (different file, verified 2026-11-23): the constant `FAILED_LOGON_THRESHOLD = 3` in `backend/app/modules/correlation/mitre.py` (it is used by the rules `MAP-T1110-REPEATED-FAILED-LOGON` and `MAP-T1078-SUCCESS-AFTER-FAILURES`) is the brute-force rule ("three failed logons in ten minutes from one origin"). Set it to `5` and run `.venv\Scripts\python.exe -m pytest backend/tests/unit -q -k "T1110 or logon or brute or mitre or attack_map or multisource_workflow or reliability_matrix"`. Observed: **5 tests fail** (`test_chain_is_mapped_by_rules_with_evidence_and_limitations`, `test_duplicates_do_not_inflate_rule_evidence_and_two_failures_are_not_a_brute_force`, `test_end_to_end_without_an_llm_produces_a_complete_analyst_report`, the `01_intrusion_chain` demo scenario, and `test_r02_multiple_sequential_alerts_multi_source_without_cross_case_contamination`); 103 pass. Set it back to `3` and re-run to show all pass. Say: "I changed a detection rule and the tests that describe its behaviour told me exactly what depends on it."

## UI rationale in five lines
The interface is for an analyst under time pressure: plain tokens in one CSS file, text at 12 px or larger, no decoration, no motion, evidence class always visible (observed, inferred, external, analyst, AI). Server-reported role and time zone are shown, not chosen. Rules: `frontend/AGENTS.md` and `docs/08_Frontend/AISOP_Website_Design_Constitution.md`; three design references were consulted and logged in `D:\AISOP-Control\Reports\Reference_Use_Log.md`. Tests enforce the 12 px floor and the no-localStorage rule.

## Questions to expect and honest answers
- "Did AI write this?" Largely yes, under written rules; I can explain these three files and change them (show the live change).
- "How do you know it is correct?" Behaviour is pinned by tests and by the label-free measurements in `docs/10_Research/Evaluation.md`; correctness against real incidents is not claimed.
- "What would you change first?" Real-format sources beyond the forwarder shape; the over-merge of distinct events found in `docs/10_Research/Real_Format_Ingestion_Result.md`; MFA.
