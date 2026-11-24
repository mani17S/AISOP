# AISOP: executive brief and the decision requested

Written 2026-11-24 for a CISO and the executive team. It states what is proven, what is not, and asks for one bounded decision. It does not claim production readiness, a return on investment, or detection capability.

## The decision requested
**Approve a six-week, read-only pilot** of AISOP on sanitised exports from one SIEM and one EDR, with one analyst team in shadow mode, no response actions, no production credentials, and success measures fixed before it starts (`docs/11_Deployment/Pilot_Plan.md`). Outcome at week six: continue, change, or stop, on measured results.

## What it is, in one paragraph
AISOP sits between detection and response. It takes the alerts and logs a SIEM or EDR already exports, keeps every record with a cryptographic hash, groups records that truly belong together, counts how much independent evidence supports a story, and says "not enough" instead of guessing. An optional AI model can draft an explanation, but every claim is checked against the stored evidence by code that does not use a model, and nothing leaves without a lead's approval. It is not a SIEM, not an EDR, not a detection engine and not an automated responder.

## Why it could matter to the business
| Business concern | What AISOP offers | Status |
|---|---|---|
| Analyst time lost reading repeated alerts | Groups repeats into evidence units and incidents; a management summary shows records to incidents (public SSH log: 2,000 lines to 23 incidents; public Windows data: 377 records to 20) | **Measured on public lab data. Time saved per analyst is NOT measured; the pilot measures it** |
| Risk of confident but wrong AI conclusions | The model is called only when independent evidence is adequate; every claim is checked against evidence; model-proposed ATT&CK techniques are never accepted (a raw model scored F1 0.00 on the project's own scenarios) | Measured on synthetic data and captured model output |
| Audit and defensibility | Raw records kept with SHA-256; hash-chained ledger; case audit trail; role-based access; lead approval before export | Implemented and tested; tamper-evident since submission, not immutable; no independent audit |
| Data protection | Local-first by default; the optional hosted model is opt-in and synthetic-data-only | Documented (ADR-016); the hosted option is not live |
| Visibility of logging gaps | The management summary lists which telemetry types are absent from the supplied evidence and what to collect | Implemented; it describes the supplied evidence, not the whole estate |

## Evidence so far, and what it does not show
- 3,874 backend and 307 frontend tests pass; the claim verifier rejected 1,737 of 1,737 false assertions in a mutation test; on 2,250 randomised synthetic cases with truth known by construction the gate wrongly called evidence sufficient in 0.000 of cases (95% CI 0.000 to 0.002) versus 0.835 for a naive rule.
- Supply chain (2026-11-24): 221 components inventoried (SBOM in `docs/07_Security/sbom/`); 71 run in production and none has a published advisory in the public OSV database; the only advisories (vite, esbuild) are in development-server tools that are not in the production build. This is a lookup of known advisories, not a guarantee.
- **Not shown:** accuracy against human labels (none yet); behaviour on real incidents; analyst time saved; performance at the company's real volume (the API accepts 1,000 evidence rows per run; the library handled 2,000 records in about 3 seconds on a laptop); any real vendor EDR or Suricata export.

## Cost and resources
- **Licences:** none for the project's own code; dependencies are open source (no copyleft packages flagged in the licence review; LGPL and MPL items are used unmodified). Language-model licences have not been reviewed.
- **Infrastructure:** runs on one machine; measured only on a laptop with a 4 GB GPU. Pilot sizing for real volumes has not been measured.
- **People:** the pilot needs about one analyst team's time for shadow-mode comparison and one engineer to run the exports and the tool; the pilot cost is the company's to estimate. `scripts/roi_model.py` shows how much analyst time the pilot must save to repay itself (for hypothetical inputs of 40 investigations a week, 45 minutes each, 60 per hour and a 12,000 pilot, about 12.8% in the first year). **That percentage is what the pilot must measure; it is not a forecast.**

## Principal risks and what contains them
| Risk | Containment |
|---|---|
| A wrong "sufficient" verdict is acted on | Measured false-sufficient rate on synthetic data is 0; pilot stop condition: any false-sufficient verdict an analyst would have acted on; analysts decide, the tool does not act |
| Sensitive evidence leaves the environment | Local-first; hosted model off by default and synthetic-only; pilot uses sanitised data and a local model |
| Weak authentication (static API keys, no MFA) | Pilot only with a small named group, keys with expiry, lockout and revocation; MFA and signed approvals (ADR-015) are required before any wider use |
| Over-reliance on an AI summary | Every AI statement is labelled and checked; the deterministic report is complete without the model |
| Scope creep into response actions | No response action exists; export needs a lead's approval |

## Decision gates
Week 0: data handling and access approved. Weeks 1 to 2: setup on sanitised exports. Weeks 3 to 5: shadow mode. Week 6: results against the pre-agreed measures, and the continue, change or stop decision. Stop at any time if a stop condition is met.
