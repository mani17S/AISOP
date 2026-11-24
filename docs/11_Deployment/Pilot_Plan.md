# AISOP pilot plan (proposed; needs the company's approval)

Six weeks, read-only, shadow mode. Nothing in this plan has been run; it is the design a CISO would be asked to approve. The measures are fixed before the pilot starts so that the result cannot be argued afterwards.

## Scope
- **In:** sanitised exports from one SIEM and one EDR; one analyst team; AISOP running on one company-controlled machine with the local model only; evidence classes the adapters already handle (Windows event forwarder exports, Linux auth syslog, Suricata EVE converted, SIEM and EDR alert JSON).
- **Out:** production credentials; any write access to the SIEM, EDR or any production system; response or containment actions; hosted AI; real customer personal data beyond what the sanitisation rules allow.
- **Shadow mode:** analysts do their normal work; separately the same incidents are run through AISOP; the two are compared. AISOP output is never the only basis for a decision.

## Roles
| Role | Responsibility |
|---|---|
| Executive sponsor | Approves scope, budget and the week-six decision |
| CISO | Approves data handling, access and stop conditions |
| Data protection / legal | Approves the sanitisation rules and retention |
| SOC lead | Names the analysts, owns the comparison and the labels |
| Pilot engineer | Exports, runs the tool, keeps the pilot log; does not judge incidents |
| Independent reviewer | Labels a sample of incidents without seeing AISOP output (second reviewer) |

## Data rules
Sanitise before export (remove customer identifiers, secrets and personal data not needed to judge the incident); keep the export on the pilot machine only; retention for the pilot period plus 30 days, then deletion with a recorded confirmation; no evidence text sent to any external service; access through named accounts with the lowest role that works; every export and approval is in the case audit trail.

## Timeline
| Week | Work | Output |
|---|---|---|
| 0 | Approvals: scope, data rules, access, measures, stop conditions | Signed one-page charter |
| 1 | Set up on a company machine; ingest a first small export (the offline tool `backend/scripts/triage_file.py` does this from one file with no database: it prints records accepted and rejected and writes the reports); confirm the adapters accept the real formats; check the company's logging against `docs/10_Research/Detection_Coverage_and_Telemetry.md` (which events each rule needs) | Acceptance rate per source; any parsing defects listed; a list of rules that cannot fire because the telemetry is not collected |
| 2 | Ingest the pilot data set (about 100 to 300 incidents' worth); fix only parsing defects, not rules | Frozen configuration and rule version |
| 3 to 5 | Shadow mode: for each incident record analyst minutes with and without the AISOP summary, the analyst's own conclusion, and AISOP's verdict | Pilot log |
| 5 | Independent reviewer labels a sample (at least 25%) without seeing AISOP output | Labels and agreement |
| 6 | Analysis against the measures; decision | Results memo and decision |

## Measures (fixed in week 0)
1. **Analyst time per investigation**, with and without the summary (the number `scripts/roi_model.py` needs).
2. **False-sufficient rate**: share of incidents the reviewer judged not sufficient that AISOP called SUFFICIENT, with a confidence interval. Target set by the CISO; any single false-sufficient verdict an analyst would have acted on is a stop condition.
3. **Usefulness of "what to collect next"**: share of LIMITED verdicts where the suggested evidence request was judged useful by the analyst.
4. **Parsing coverage**: share of real records accepted, per source.
5. **Throughput**: time to process a batch at the pilot's real volume (known: the API accepts at most 1,000 evidence rows per investigation run, ADR-010, so larger exports are split; the correlation step handled 1,500 hard-shaped synthetic records in about 15 seconds after the 2026-11-24 speed-up, 515 seconds before).
6. **Workload view**: records to incidents on the real data (do not read this as time saved).

## Stop conditions (any one ends the pilot)
A false-sufficient verdict an analyst would have acted on; evidence text found leaving the environment; a security finding in AISOP rated high or critical that cannot be fixed within the week; the sponsor withdraws.

## Prerequisites the project does not yet have
Step-up MFA and signed approvals (ADR-015, proposed); a restricted database role for the app; metrics (alert notification exists, see `docs/07_Security/Security_Alert_Notifications.md`, but has not run against a real receiver); a documented way to split exports larger than the 1,000-row per-run limit; an independent penetration test of the pilot build; a review of the language model's licence terms.

## Decision memo template (week 6)
Measures achieved against the targets; incidents where AISOP and the analysts disagreed and why; defects found; cost against budget; recommendation (continue, change, stop); conditions for any wider use.
