# AISOP from a CISO's seat

Written 2026-11-24 from the viewpoint of a security leader deciding whether a tool like this earns a place in the company. It separates what is measured from what is not. Nothing here claims production readiness.

## What problem it addresses
Analysts lose time reading piles of alerts and logs that repeat each other, and AI assistants that sound sure of themselves are risky when the evidence is thin. AISOP is an **investigation and evidence-qualification layer** that sits after detection and before any response. It keeps every record with a hash, groups records that really belong together, counts independent evidence, and says "not enough" instead of guessing. An optional AI model may draft an explanation, and every claim is checked against the stored evidence by code that does not use a model.

## The five questions a CISO asks, answered honestly
| Question | What AISOP gives | Evidence (measured) | What it does not give |
|---|---|---|---|
| **Does it reduce analyst reading?** | A management summary: records to evidence units to incidents | Public Windows data: 377 records became 20 incidents. Public SSH log: 2,000 lines became 852 evidence units and 23 incidents | No measured time saved per analyst; no user study |
| **Where are my blind spots?** | Which telemetry types (endpoint, network, identity, cloud, email) are absent from the supplied evidence, and what to collect next | Deterministic; tested (`test_management_view.py`) | It describes the evidence given, not the company's whole logging, and not detection coverage |
| **Can I defend a conclusion to an auditor?** | Raw records kept with SHA-256; a hash-chained ledger; claim-by-claim verification; case audit trail; a lead's approval before any export | 0 of 1,737 false assertions accepted by the claim verifier; 3,883 backend and 307 frontend tests | Tamper-evident since submission, not immutable; no independent audit |
| **Does it stay inside my data rules?** | Local-first by default; the hosted AI option is opt-in, synthetic data only, and states what leaves the machine | ADR-016; privacy page; token never in a response or log | The hosted demo is not live; evidence text goes to a third party when it is on |
| **What must I not tell the board?** | A written list of claims not to make | `Defence_Walkthrough.md` section 6 | It is not detection, not response, not a SIEM, not proven on real incidents |

## What it deliberately does not do
It does not detect attacks, take response actions, replace the SIEM or EDR, or decide that something is malicious. Anything outward-facing (a report export) needs a lead's approval. The management summary never recommends a response action; every "next step" is a request for more evidence.

## What the evidence says about the quality of its judgements (all synthetic or public lab data)
- On 2,250 randomised cases with truth known by construction, the rate at which it wrongly calls evidence sufficient is 0.000 (95% CI 0.000 to 0.002), against 0.835 for a naive "any shared entity" rule; each rule it adds fixes a named family of failures.
- Its newest rule (ADR-017) says a flood of identical failed logins seen by one sensor is one witness, not many; on the real SSH log, 18 of 23 incidents were capped for exactly that reason.
- Its ATT&CK rules are conservative and cover about a third of the techniques tested: on public attack captures labelled by their own authors, 11 of 34 documented techniques were recovered (interval about 19% to 49%; the original six rules found 1), with each hit tied to a specific command line or event; no technique was produced on 5 benign scenarios. It is not a complete detection product. A raw language model scored F1 0.00 and gave false techniques on benign activity, which is why model-proposed techniques are never accepted as evidence.
- No human-labelled accuracy exists yet. That is the main open item.

## If I were running a pilot (what I would ask for)
1. **Scope:** one analyst team, sanitised exports from one SIEM and one EDR, no response actions, no production credentials, read-only.
2. **Success measures, set before the pilot:** analyst minutes per incident with and without the summary; the share of AISOP "sufficient" verdicts that analysts agree with (false-sufficient rate against their labels); the share of "limited" verdicts where the suggested evidence request was useful.
3. **Gates before any wider use:** step-up MFA for approvals (ADR-015 is proposed, not built), a restricted database role, metrics and alerting, an independent penetration test, a data-protection review of any hosted model.
4. **Stop conditions:** any false-sufficient verdict an analyst would have acted on; any evidence text leaving the environment unexpectedly.

## What I would build next, in order of value to the company
1. Agreement study with analysts (labels, second reviewer, held-out run) so the verdicts have a measured error rate.
2. A real Suricata or EDR export through the adapters, and a documented way to split exports larger than the 1,000-row per-run API limit (the correlation step was made 3 to 35 times faster on 2026-11-24 with identical output: 1,500 hard-shaped synthetic records went from 515 s to about 15 s).
3. MFA and signed approvals (ADR-015), then a security-event notification channel.
4. A detection-engineering feedback loop (ADR-012): findings that are repeatedly LIMITED because a source is missing become a request to the logging owners.

## Where the supporting material is
- Decision requested of the executive team: `Executive_Brief.md`. Pilot design with measures and stop conditions: `docs/11_Deployment/Pilot_Plan.md`.
- Security and governance view for a CISO, a data protection officer and a risk committee: `docs/07_Security/Security_Governance_Summary.md`.
- Software bill of materials and the known-advisory check: `docs/07_Security/sbom/` (re-run with `.venv\Scripts\python.exe scripts\supply_chain_check.py --out docs\07_Security\sbom`).
- How much analyst time a pilot must save to pay for itself, using the company's own numbers: `scripts/roi_model.py`.
