# Where AISOP sits in a SOC, and what each SOC word means here

Written 2026-11-23 from the source. It answers the panel's question: "How do SIEM, EDR, XDR and SOAR differ, how do events, alerts and incidents differ, and where does your tool fit?" Everything about AISOP below was checked against the repository; statements about commercial products are general industry usage, not tested claims.

## 1. The SOC value chain and where AISOP is

```mermaid
flowchart LR
  subgraph COLLECT["1 Collect and store"]
    EP["Endpoints, network, identity, cloud, email<br/>produce events (telemetry)"]
    EDR["EDR agent on the endpoint<br/>records its own telemetry and detects"]
    SIEM1["SIEM: ingests logs plus EDR alerts and logs,<br/>stores, searches, runs correlation rules"]
  end
  subgraph DETECT["2 Detect"]
    ALERTS["ALERTS from EDR, XDR, IDS<br/>and SIEM rules"]
  end
  subgraph INVEST["3 Triage and investigate"]
    AISOP["AISOP<br/>qualifies the evidence behind alerts,<br/>groups it into a correlation cluster (AISOP "incident"),<br/>says when evidence is not enough"]
    ANALYST["Analyst tier 1 / tier 2 / lead"]
  end
  subgraph RESPOND["4 Respond"]
    SOAR["SOAR / EDR response<br/>isolate, block, ticket<br/>NOT in AISOP"]
  end
  EP -->|"logs"| SIEM1
  EP -->|"the agent observes the endpoint directly"| EDR
  EDR -->|"alerts and logs"| SIEM1
  EDR -->|"EDR alerts"| ALERTS
  SIEM1 -->|"rule matches"| ALERTS
  ALERTS -->|"exported alerts and the events behind them"| AISOP
  AISOP --> ANALYST
  ANALYST -->|"decision, outside AISOP"| SOAR
```

AISOP is an **investigation and evidence-qualification layer** between detection and response. It consumes exports of alerts and events; it does not collect at scale, detect, or respond.

## 2. What each tool class is, and whether AISOP is one

| Class | What it does (industry usage) | Is AISOP this? |
|---|---|---|
| SIEM | Collects and stores logs at scale, searches, correlates, raises alerts | **No.** Batch import, one node, no long-term log store |
| EDR | Agent on the endpoint: sees processes, files, network; detects and can isolate | **No.** It reads EDR output; it has no agent |
| XDR | EDR plus identity, email, cloud and network in one detection product | **No** |
| SOAR | Automates playbooks across tools: enrichment, triage and ticketing steps as well as response actions | **Partly overlaps, mostly no.** Overlap: AISOP adds local threat-intelligence context and groups evidence, which supports triage. It has no playbook engine and never executes a response action (no isolate, block or disable); export needs lead approval |
| TIP | Holds threat intelligence | **No.** Optional offline TI items are context and never corroborate |
| Case management | Tracks an investigation and its decisions | **Partly yes**: cases, roles, audit, lead review [`models/case.py`, `api/v1/endpoints/cases.py`] |

## 3. The words, and the AISOP object each one becomes

| Word | Meaning | In AISOP | Source |
|---|---|---|---|
| Event / telemetry | One recorded fact, e.g. a process started | A raw record, stored verbatim with its SHA-256, then a canonical event/observation | `correlation/normalize.py`, `evidence_domains/` |
| Alert | A detector's claim that some events matter | A vendor alert normalised to a canonical alert; kept as the vendor's claim, not as proof | `alerts/adapter_protocol.py` and `alerts/adapters/` |
| Observable | Any item seen in events: IP, hash, domain, file, host, user. A host or user seen in a log is an observable, not an IOC | Extracted as an entity. Each has a link strength that says how well it can tie two records together: STRONG or SPECIFIC (hash, domain, public IP, path) versus WEAK (host, user, internal IP). Link strength is not a judgement that the item is malicious | `evidence/entity_extractor.py`, `evidence/independence.py: entity_link_strength` |
| IOC (indicator of compromise) | An observable that has been assessed as indicative of compromise, for example a hash known to belong to malware | AISOP does not decide that an observable is an IOC. A local threat-intelligence match is shown as context and never counts as corroboration | `threatintel/local_engine.py`, invariants in `CLAUDE.md` |
| Evidence | Material an investigator can rely on | An independent, observed, hashed record. Duplicates count once; analyst notes, threat intelligence and model output are **never** evidence | `evidence/independence.py`, invariants in `CLAUDE.md` |
| Incident | In the NIST SP 800-61 sense, a violation or imminent threat of violation of security policy, declared and handled by people | AISOP's `Incident` is only a **correlation cluster** of related alerts and records: core clusters joined by strong links, weak context attached but not merged, ATT&CK tactic stages, severity. It is not a declared or confirmed incident; the analyst decides whether one exists | `correlation/models.py: Incident`, `correlation/correlator.py` |
| Investigation | The analyst's work on an incident | A stored investigation result per case, with sufficiency verdict and reason codes | `ai/guardrails/sufficiency_gate.py`, multi-source service |
| Case | The container for the work and who may see it | `Case` with roles lead / analyst / viewer and an audit trail | `models/case.py` |
| Verdict | In SOC use, the analyst's decision on an alert: true positive, false positive, benign or malicious | AISOP reuses the word "verdict" in code and screens for its **sufficiency grade** (SUFFICIENT, LIMITED, INSUFFICIENT). That grade only says how well the independent evidence supports a bounded investigation. It is not a malicious or benign verdict and not a true or false positive call; SUFFICIENT does not mean an attack happened. The analyst makes the SOC verdict | `schemas/sufficiency.py` |
| Chain of custody | Proof evidence was not altered | SHA-256 per record plus a hash-chained ledger (tamper-evident since submission) | `correlation/ledger.py` |
| ATT&CK (and the kill chain) | Two different models. MITRE ATT&CK is a knowledge base of tactics (the goal) and techniques (the method). The Lockheed Martin Cyber Kill Chain is a separate seven-phase model | AISOP uses **ATT&CK only**. Its "stage" is an ATT&CK tactic name, ordered by a fixed list of 14 tactics (`STAGE_ORDER`); the code comments call this "kill-chain" ordering, but no Cyber Kill Chain phases are used. Techniques come from 52 evidence-backed rules in three tables: 6 `attack-map-v1` + 7 `domain-attack-v1` + 39 `endpoint-attack-v1` (older pages said 13: that was 6 + 7, before the endpoint table was added on 2026-11-24). Model-proposed techniques are never accepted as evidence | `correlation/correlator.py: STAGE_ORDER`, `correlation/mitre.py`, `evidence_domains/domain_attack.py`, `correlation/mitre_endpoint.py` |
| Tier 1 / tier 2 / lead | Analyst levels | Global roles `analyst_tier_1`, `analyst_tier_2`, `security_admin`, plus case-lead approval before export | `core/rbac.py` |

## 4. One incident through the chain (synthetic scenario `01_intrusion_chain`)
1. **Collect:** a workstation logs a PowerShell start, a DNS lookup, an outbound connection, a file write. (events)
2. **Detect:** an EDR and a network IDS each raise an alert about the same host. (alerts, two sources)
3. **AISOP:** ingests both exports, hashes each record, collapses duplicates, links records that share a *specific* artefact (the same domain, public IP, hash) across sources, attaches host/user-only matches as context, orders by ATT&CK tactic stage, and asks the gate whether independent evidence supports the story.
4. **Outcome:** SUFFICIENT only when another record from a different source corroborates the key event through a specific shared artefact. Otherwise LIMITED or INSUFFICIENT with reasons, and the model is not called when INSUFFICIENT.
5. **Respond:** the analyst decides; any containment happens in other tools.

## 4a. Investigation lifecycle mapping
Stages follow the NIST SP 800-61 incident handling lifecycle (detection and analysis; containment, eradication and recovery; post-incident activity), split finer here. Routes are under `/api/v1` (checked by route name on 2026-11-25; screen behaviour not re-tested).

| Stage | What AISOP does | What AISOP does not do | Surface |
|---|---|---|---|
| Detection and alert | Receives exported alerts and events, hashes and stores them, normalises vendor alerts to a canonical alert | Detect anything itself, collect at scale | `POST /alerts/ingest`, `POST /evidence/ingest`, `POST /cases/{id}/evidence/domain`; Alerts and Evidence pages |
| Triage | Supports it: groups related records into a correlation cluster, shows severity from the sources, links, ATT&CK tactic stages and the sufficiency grade | Decide true or false positive, set priority for the analyst | Alerts page; case list; multi-source tab |
| Scoping and investigation | Timeline, explainable links, rule-derived ATT&CK techniques, investigation graph, sufficiency gate, optional model draft whose claims are checked against stored evidence | Treat model output or threat intelligence as evidence; accept techniques no rule derived | `POST /cases/{id}/investigations/multisource`, `GET .../multisource/{section}`, `.../synthesize`; Cases page, `MultiSourcePanel` |
| Containment | Nothing | Isolate hosts, block, disable accounts | None (other tools) |
| Eradication | Nothing | Remove malware or persistence | None (other tools) |
| Recovery | Nothing | Restore systems | None (other tools) |
| Lessons learned | Keeps a case audit trail and, after lead review, exports a report draft | Run a post-incident review; no such feature was found among the routes listed here | `POST /cases/{id}/investigations/multisource/review`, `GET .../export`, `GET /cases/{id}/reports/export`, `GET /cases/{id}/activity`; Reports page |

AISOP covers triage support, investigation and scoping, and report drafting only. It records the analyst's decisions and any recommendation; it does not act on them. Containment, eradication and recovery happen in other tools, outside AISOP. Anything outward-facing, such as a report export, needs the case lead's approval.

## 5. What AISOP does not claim
Detection, response, real-time operation, scale, vendor-validated parsing (sources are synthetic, sample-shaped), or a user-tested workflow. Measured limits are in `docs/12_User_Guides/Panel_Criticism_Validation.md`.

## 6. Sixty-second spoken version
"A SOC collects events, detectors turn some of them into alerts, and analysts investigate alerts and then respond. SIEM stores and searches logs, EDR watches the endpoint, XDR joins several detection sources, and SOAR automates enrichment, triage and response steps. AISOP is none of those, though it overlaps with SOAR on triage support and never runs a response action. It sits between detection and response. It takes the alerts and events they export, keeps every record with a hash, groups the ones that truly belong together, and counts how much independent evidence there is. A shared host or user is context, not corroboration. If the evidence is thin it says so and does not ask the AI. The analyst, not the tool, decides, and nothing leaves without a lead's approval."
