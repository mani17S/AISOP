# Stage 6 Panel and Viva Walkthrough: Source-Agnostic Investigation

## One-sentence claim
AISOP investigates evidence of any supported domain (identity, cloud, network, e-mail, forensic) without needing a SIEM alert or a Sysmon event id, and it keeps observed evidence, external intelligence, analyst statements and AI output visibly separate.

## Data flow in 60 seconds
Source record (`aisop.evidence/1`) -> stored unchanged with SHA-256 -> adapter makes a canonical `Observation` (time never invented) -> projected to the existing correlation engine -> graph, timeline, rule-based ATT&CK, the one sufficiency gate -> optional gated LLM -> claim check -> report. Modules: `backend/app/modules/evidence_domains/` (`model`, `adapters`, `bridge`, `graph`, `ti`, `domain_attack`), integration in `correlation/{normalize,workflow,report}.py` and `services/{domain_evidence_service,multisource_investigation_service}.py`.

## Demonstrations (offline, synthetic, from `D:\AISOP`)
1. `.venv\Scripts\python.exe backend\scripts\stage6_demo.py A --report`: identity and cloud. Five denied MFA prompts, a sign-in, a new cloud user and an admin policy, joined by the shared public IP. Techniques T1621, T1136.003, T1098.003, each with its rule id and limitation.
2. `... stage6_demo.py B --report`: DNS and firewall records (network) joined to a process and file artefact (endpoint) through the resolved IP and a file hash, not through host names. No technique is derived, and the report says so.
3. `... stage6_demo.py C --report`: phishing e-mail, DNS lookup, dropped file, Run key, memory finding. The analyst statement appears in section 4d and does not change the verdict (tested by identical assessment hash).
4. `... stage6_demo.py neg`: duplicates, analyst-only, unrelated, bad times, unknown type, contradiction, malformed.

## Questions to expect
* **Why not just accept any JSON?** Source agnostic is not validation-free: each record is checked per type; malformed ones are quarantined with a fixed code, valid-but-unknown ones are preserved as unclassified and can never corroborate.
* **What happens with a missing timestamp?** It stays missing, the record is listed as undated, and is excluded from the timeline. Not replaced by the current time (tests: `test_time_parsing_never_invents_a_time`).
* **How do you stop duplicates inflating confidence?** Same raw hash, same identity and entities within 2 s, or identical content collapse into one evidence unit; graph edges report independent support, ATT&CK thresholds use distinct raw records.
* **Is threat intelligence evidence?** No. `TrustClass.TI_CONTEXT`, section 4c, tested to leave the sufficiency hash and techniques unchanged.
* **Is the LLM needed?** No. Deterministic output is complete; the LLM runs only through `GatedGenerator`; failure falls back; no provider call when evidence is insufficient (tested).
* **Why no graph database?** Incident-sized graphs are derived on demand from preserved raw evidence; the correlation already runs in process.
* **Is it production ready / accurate?** Not claimed. Detection accuracy and hallucination reduction were not measured.

## Limitations to state yourself
Envelope input only (native vendor formats PROPOSED); SQLite-tested, PostgreSQL unverified; UI verified by server-side render tests and typecheck, not a live browser; the sufficiency gate does not penalise cross-sensor contradictions (shown in the negative demo; reported, not hidden); TI provider not wired into the API.

Test evidence: `Stage6_Test_and_Evaluation_Report.md` in the Stage 6 workspace (84 new backend tests, 1497 unit, 85 integration, 71 frontend; all passing offline).
