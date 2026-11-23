# SOC concepts drill (answer aloud, then check)

Use with `docs/03_System_Design/SOC_Placement_and_Vocabulary.md`. Answers are short on purpose. Where an answer is about AISOP, the source file is named so you can open it if asked.

1. **What is telemetry?** Raw recorded facts from systems (process started, DNS lookup, logon). Not a judgement.
2. **What is an alert?** A detector's claim that some telemetry matters. It can be wrong; AISOP keeps it as the vendor's claim, not proof.
3. **What is an incident?** A set of related evidence describing one story. AISOP's `Incident` joins records by strong or specific links (`correlation/correlator.py`).
4. **What is evidence?** Observed, hashed, independent records. Analyst notes, threat intelligence and model output are not evidence in AISOP.
5. **SIEM in one line?** Collects and stores logs at scale, searches them and raises alerts. AISOP is not one.
6. **EDR?** An agent on the endpoint that sees processes, files and network and can isolate the host. AISOP reads its output.
7. **XDR?** EDR plus identity, email, cloud and network detection in one product.
8. **SOAR?** Automates response playbooks and tickets. AISOP has no response actions.
9. **TIP / threat intelligence?** Known-bad indicators and context. In AISOP it is optional context and never corroborates.
10. **Where does AISOP sit?** Between detection and response: it qualifies the evidence behind alerts.
11. **Tier 1 versus tier 2?** Tier 1 triages alerts; tier 2 investigates deeper. Roles `analyst_tier_1`, `analyst_tier_2`, plus the case lead who approves export (`core/rbac.py`).
12. **What is triage?** Deciding quickly which alerts deserve investigation.
13. **What is the kill chain / ATT&CK?** A vocabulary of attack stages and techniques. AISOP maps techniques only from 13 evidence-backed rules.
14. **What is corroboration?** Another independent record supporting the same fact. A shared host or user is not corroboration; a shared file hash, domain, public IP or file path is.
15. **Why do duplicates count once?** A copy is not a second witness. `evidence/independence.py: cluster_evidence`.
16. **What is chain of custody?** Proof evidence was not altered. SHA-256 per record plus a hash-chained ledger; tamper-evident since submission, not immutable.
17. **What does SUFFICIENT mean in AISOP?** The evidence is adequate for a model-assisted investigation of the question. It is not a verdict that an attack happened.
18. **What is a false positive?** An alert about harmless activity. AISOP's raw-model benchmark showed false techniques on benign scenarios; its rules showed none on 5.
19. **Event time versus ingestion time?** When it happened versus when AISOP received it. AISOP stores and shows both, never substituting one for the other.
20. **Why UTC?** One reference so records from different zones order correctly; the UI can also show IST.
21. **What does the model do?** Optionally drafts an explanation. Each claim is checked against stored evidence; failures fall back to the deterministic report.
22. **Why not trust the model's confidence?** It is not calibrated; AISOP ignores it. The captured raw model gave 0.8 for nearly everything.
23. **What is prompt injection?** Hostile text in evidence trying to instruct the model. Evidence is fenced as untrusted data, and the gate and verifier do not depend on the model obeying a prompt.
24. **Can AISOP detect zero-days?** No claim is made. It does not detect; it qualifies evidence.
25. **What would a real SOC need that AISOP lacks?** Scale and streaming, a real log store, response automation, SSO and MFA, metrics, and validation on real data.

## Common traps
- Do not say AISOP "detects", "responds", "replaces a SIEM" or is "enterprise-grade".
- Do not say a SUFFICIENT verdict means the attack is confirmed.
- Do not say independence means a different sensor: in AISOP it means a different raw record linked by a specific or strong artefact (see the note in `docs/10_Research/Real_Format_Ingestion_Result.md`).
