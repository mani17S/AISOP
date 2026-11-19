# AISOP Architecture Evolution Plan

Date: 2026-11-12. Status: **PROPOSED plan. Not approved.** It changes no approved ADR (only ADR-007 is approved) and does not alter Stage 6's CONDITIONALLY CLOSED decision. Labels: IMPLEMENTED, PARTIAL, PROPOSED, BLOCKED, UNVERIFIED, NOT IMPLEMENTED. Companion documents: `REFERENCE_REPOSITORY_ENGINEERING_REVIEW.md`, `ZERO_BILLING_INFRASTRUCTURE_OPTIONS.md`, `FRONTEND_ANALYST_UX_REVIEW.md`, `docs/Project_Management/AISOP_NEXT_PHASE_ROADMAP.md`, `docs/Detection_Engineering/*`, ADR-012 and ADR-013 (both PROPOSED).

## 1. Original AISOP vision
An evidence-driven, analyst-controlled investigation platform: ingest alerts and evidence, validate and normalise, extract IOCs and entities, enrich with threat intelligence, map to ATT&CK, correlate into context, retrieve knowledge (RAG), optionally ask a pluggable LLM, produce evidence-grounded reports, and keep the human analyst in charge. Detection Engineering is the next capability. GRC and compliance management are out of scope. The platform must stay useful with the LLM disabled and must be explainable in an academic evaluation.

## 2. Current architecture (Stage 5 and 6; verified 2026-11-12)
```
sources (SIEM, Sysmon, identity, cloud, network, e-mail, forensic, analyst)
   |  POST /alerts/ingest (ADR-007 adapters)      POST /cases/{id}/evidence/domain (ADR-011 adapters)
   v                                              v
raw_evidence (payload unchanged + SHA-256) --> normalized_events --> case_evidence (case scope, RBAC)
   |
   v  POST /cases/{id}/investigations/multisource          (MultiSourceInvestigationService, ADR-010)
re-normalise preserved raw -> Observation / CorrelationEvent -> correlate (clusters, strong/specific/weak links, contradictions)
   -> timeline -> ATT&CK rules (7 domain + 6 SIEM/Sysmon) -> graph -> TI context (offline) -> evaluate_sufficiency (the ONE gate)
   -> [optional GatedGenerator -> parser -> claim validator] -> report -> ONE audit row (hash-chained ledger head)
   v
sections: status | timeline | correlation | attack | sufficiency | report | graph | evidence  -> React panels
```
Verified results: unit 1509, integration (not postgres/ollama) 85 with 33 deselected, frontend 71, typecheck and build clean (closure addendum; to be re-run with this stage's changes, see the roadmap and final report). PostgreSQL paths BLOCKED; live browser UNVERIFIED; real-model behaviour UNVERIFIED.

## 3. Existing modules to reuse
| Concern | Module (path) | Notes |
|---|---|---|
| Canonical evidence | `backend/app/modules/evidence_domains/{model,adapters,bridge,graph,ti,domain_attack,scenarios}.py` | Stage 6 |
| Correlation, timeline, ledger, report | `backend/app/modules/correlation/{correlator,timeline,ledger,report,workflow,normalize,mitre}.py` | Stage 3C-R |
| Independence rules | `backend/app/modules/evidence/independence.py` | link tiers, clustering |
| Sufficiency gate | `backend/app/modules/ai/guardrails/{sufficiency_gate,gated_generation}.py`, `schemas/sufficiency.py` | ADR-008 |
| Claim verification | `backend/app/modules/ai/guardrails/validator.py`, `response_parser/`, `prompt_builder/` | escaped prompt; claim checks |
| Case scope, RBAC, audit | `core/rbac.py`, `api/dependencies.py::require_case_role`, `models/case.py::CaseAuditEventModel` | append-only triggers |
| Services | `services/{multisource_investigation_service,domain_evidence_service,case_service}.py` | |
| Middleware | `middleware/body_limit.py` (new, now covers import and `/alerts/ingest`) | |
| Frontend | `frontend/src/components/{MultiSourcePanel,DomainEvidencePanel}.tsx` | |
| Detection scaffolding | `backend/app/modules/detection_engineering/**` | **empty** (0-byte files) |

## 4. Reference comparison
See `REFERENCE_REPOSITORY_ENGINEERING_REVIEW.md` (five repositories, commits recorded, depth and gaps stated).

## 5. AiSOC ideas selected
(1) typed tools that reject undeclared arguments; (2) contradiction and "not evaluated" states in the decision (not a score); (3) claim-support check for unsupported "authorized/benign" assertions; (4) one-direction post-verification (may only lower confidence or route to a human); (5) ledger event vocabulary with prompt and artefact digests; (6) deterministic, verifiable export bytes with prompts as digests; (7) rule fixtures that prove a rule fires on a positive and stays silent on a same-shape negative, a quarantine tier, provenance, and a gate that is shown capable of failing. **Rejected:** microservices, RLS-per-tenant stack, best-effort audit, a signing key equal to the app secret, autonomous closure.

## 6. PentAGI ideas selected
Bounded tool results and argument sizes; per-run cancellation and bounded cleanup; provider abstraction (already `LLMProvider`); observability as a first-class concern. **Rejected:** planner plus specialist agents, mentor agent, autonomous exploitation, sandboxed execution of arbitrary tools, any shell or network tool. No source reuse (Go; EULA scope is penetration testing; AGPL SDK exception limited to the official project).

## 7. Impeccable integration
Installed manually at project level (`.claude/skills/impeccable/`, Apache-2.0, no hook, no engine). Used for guidance only; the detector is BLOCKED pending an owner decision. First output: `FRONTEND_ANALYST_UX_REVIEW.md` (12 findings, source-level). Subordinate to `frontend/AGENTS.md` and the design constitution.

## 8. Karpathy development process
Installed and merged in `CLAUDE.md`. Applied this stage: baseline run before changes; probes before specifications; one fix per gap with a test; weak tests of my own corrected and disclosed; reports separate verified from unverified.

## 9. Free infrastructure options
Keep the local stack (PostgreSQL+pgvector, Ollama, in-process analysis). Hosted free tiers rejected for evidence. Optional self-hosted additions only. See `ZERO_BILLING_INFRASTRUCTURE_OPTIONS.md`.

## 10. Contradiction-aware evidence model (Priority 1)
**Problem (verified by probe on 2026-11-12).** The gate (`sufficiency_gate.py`) sees contradictions only for the same sensor identity, and the correlator (`find_contradictions`) detects only opposite outcomes within 2 s. Observed: network allow-vs-deny and cross-IdP success-vs-failure leave the verdict SUFFICIENT with `corroborating=1`; one session id bound to two users and one native event id with timestamps hours apart produce no contradiction at all. The closure session added a report notice only.

**Vocabulary (categories, not scores).** Every pair or claim relation is exactly one of:
| Relation | Meaning |
|---|---|
| INDEPENDENT_CORROBORATION | different evidence units, independent sources, joined by a strong or specific link, no unexplained conflict |
| SUPPORT | agrees but is not independent (same source family, same raw record, near-duplicate) |
| CONTRADICTION | incompatible statements about the same entity and overlapping time (kinds below) |
| MISSING | evidence the rule table or the finding needs but the case lacks |
| UNCLASSIFIED | preserved but not interpreted; cannot corroborate or contradict |
| STALE | evidence changed or aged beyond the investigation fingerprint |
| EXTERNAL_CONTEXT | TI or analyst statement: never changes the above |

**Contradiction kinds:** `OUTCOME` (success vs failure, allow vs deny), `IDENTITY` (one session, token or address bound to different principals in overlapping time), `TEMPORAL` (same source-native event id with incompatible times), `STATE` (e.g. file present vs absent on the same host at overlapping time), each a small deterministic rule over canonical observations.

**Materiality, without fixed penalties.** A contradiction record carries: the two observations; the shared entity and its link strength (`entity_link_strength`); temporal overlap in seconds; source independence (different systems and collection methods); each side's reliability class (trust class, attested digest, tool-asserted vs raw); relevance to the investigation anchor; and **explanation candidates** drawn from a closed list (`RETRY_WITHIN_WINDOW`, `CLOCK_SKEW_WITHIN_TOLERANCE`, `SAME_SOURCE_LAG`, `SHARED_ACCOUNT`, `NAT_OR_PROXY`) that only apply when their stated condition holds. Materiality is a deterministic function of those fields into `MATERIAL | MINOR | EXPLAINED`:
* specific or strong link + independent sources + overlapping time + no explanation => MATERIAL;
* explained by a closed-list condition => EXPLAINED (disclosed, no verdict effect);
* weak link only, or no temporal overlap => MINOR (disclosed).

**Verdict rule (proposed suff-v4).** A MATERIAL contradiction (a) is added as reason code `CONTRADICTION_UNRESOLVED:<kind>`, (b) caps the verdict at LIMITED, (c) removes the conflicting pair from the corroborating set (two statements that disagree cannot corroborate each other), and (d) is shown in the verdict banner and the report headline. EXPLAINED and MINOR are disclosures. It never raises a verdict. No "minus N points" arithmetic.

**Implementation location.** Richer `Contradiction` objects in a new `correlation/contradictions.py` (called from `correlate`), carried into `InvestigationContext` as a typed field, consumed by `evaluate_sufficiency`; bump `SUFFICIENCY_RULE_VERSION` (assessment hashes change by design); the stored-result fingerprint already includes the rule version, so old results are not reused. This revises ADR-008 behaviour, so it is proposed as **ADR-013 (PROPOSED)** rather than a silent edit.
**Evaluation labels.** `datasets/ground_truth` and `datasets/sufficiency_eval` labels are not modified. The new rule version is run against them and any verdict change is reported as a delta for owner review.
**Tests (written first, executable):** `backend/tests/unit/test_contradiction_model_spec.py`: 5 passing (already correct) and 5 strict-xfail (GAP-1 verdict cap, GAP-1 no mutual corroboration, GAP-1 sign-in conflict, GAP-2 identity, GAP-3 timestamp). Required additions when implemented: explained conflict stays disclosure-only; duplicate across sources unchanged; reliability asymmetry (tool-asserted vs raw); regression of the 1509 existing tests and the sufficiency-hash tests.
**Acceptance:** all 5 xfail markers removed with tests passing; no existing test changed except documented hash/version updates; a re-run on the sufficiency dataset with a delta report.

## 11. Investigation ledger evolution (Priority 2)
**Today (verified).** `correlation/ledger.py` is an in-process, hash-chained `Ledger` (genesis, per-entry `prev` hash, `verify_chain`). The stored result keeps only `{seq, step, entry_hash}` per step plus the head (`MultiSourceInvestigationService.build_payload`), inside one append-only `case_audit_events` row; entries' detail objects are not persisted. Analyst decisions are not in the chain.
**Decision.** Do not build a second audit system or a new table. Extend the existing ledger and persist its **full bounded entries** in the same audit row's `details`.
**Entry vocabulary (adapted from AiSOC, tailored):** `investigation_id`, `case_id`, `evidence_refs` (evidence id + raw SHA-256), `step`, `actor` (`system` | `llm:<provider>:<model>` | `analyst:<username>`), `prompt_template_id` and `prompt_sha256` (digest, never the prompt text), `model_identity` where applicable, `tool_calls` (name, validated-args digest, result digest, duration), `retrieval_citations` (knowledge chunk ids and digests), `sufficiency` (verdict, reason codes, assessment hash), `claim_verification` (claim id, grounding, decision), `analyst_decision` (accept/reject/annotate with reason), `time_utc`, `prev_hash`, `entry_hash`. **Never stored:** secrets, raw evidence text, full prompts or model outputs (digests and ids only), unnecessary personal data.
**Integrity.** Hash chain (exists). Independent signing is optional later (see export).
**Failure semantics.** Keep AISOP's stricter rule: ledger/audit write failure suppresses the result (do not copy AiSOC's best-effort).
**Tests:** chain verification after persistence round trip; tamper, delete and reorder detection from the stored row; size bound and truncation disclosure; no-secret/no-raw-text property test over scenarios A/B/C; analyst-decision entries chain correctly; viewer cannot append.
**Acceptance:** a stored investigation can be verified offline from the stored row alone; every claim in the report maps to a ledger entry.

## 12. Agent and tool architecture (Priority 3)
**Options compared against an actual AISOP problem.** The problem to solve: let an analyst (or one bounded model call) ask for more evidence context without unrestricted data access, while keeping results reproducible and auditable.
| Option | Pros | Cons | Fit |
|---|---|---|---|
| A. Deterministic pipeline + single gated model invocation per incident (**today**) | reproducible, testable, no agent loop, local-model friendly | no interactive follow-up | baseline, keep |
| B. A + one **controlled investigator with typed read-only tools** (bounded steps) | answers follow-ups from evidence; every call audited; simple | needs registry, step cap, tests; local models call tools unreliably (UNVERIFIED) | **Recommended next step, after Stage 6A and Stage 7** |
| C. Planner + specialist workers | parallelism, role separation | cost and non-determinism multiply; agent-to-agent loops; weak local models; no AISOP workload needs parallelism (incident-sized data, sequential local inference) | **Rejected** |
| D. Independent agents sharing a ledger | decoupling | same as C plus consistency problems | **Rejected** |
The six "specialist roles" in the brief map to **deterministic modules plus prompts of the one gated call**, not six agents: evidence analysis (graph), IOC/TI (`ti.py`), timeline (`timeline.py`), ATT&CK (rule tables), report (`report.py`), detection assistant (ADR-012 proposer). **Parallelism is not needed.**
**Typed tool registry (PROPOSED; no code yet).** Each tool: pydantic input model with `extra="forbid"` (undeclared keys rejected, as in AiSOC `argument_error`); case id taken from the authenticated context, never from tool arguments; read-only; bounded output (cap bytes and rows, truncation flagged); timeout; audit entry (name, args digest, result digest); explicit permission scope mapped to existing case roles; errors returned as structured results, never raised into the model loop. Initial set (all read-only unless stated): `get_case_evidence`, `query_related_entities`, `read_timeline`, `get_threat_intel` (local only), `inspect_attack_mapping`, `request_additional_evidence` (**creates a visible analyst task note; fetches nothing**), `draft_investigation_summary` (returns a candidate for review), `propose_detection_opportunity` (returns a candidate; cannot approve or export). No write to evidence, no database or shell access, no network.
**Hard limits:** step cap per run; no agent-to-agent calls; the model's output is untrusted and always passes claim verification; tool results that originate from evidence text are escaped and cannot add instructions.
**Tests:** schema rejection of unknown keys and wrong types; cross-case argument injection ignored (case from context); bounded output; timeout; audit written for every call and for failures; prompt-injection text inside tool results stays data (scripted provider); deterministic fallback when the loop fails.

## 13. Detection Engineering
As designed in ADR-012 and `docs/Detection_Engineering/`. AiSOC-derived refinements (PROPOSED): every rule ships with at least one positive and one same-shape negative fixture, and is only VALIDATED if the positive matches **and** the negative does not (and a self-test shows the check can fail); a quarantine state for rules that cannot be proven; a provenance block (evidence ids, investigation fingerprint, generator, validator versions); suppression or tuning notes stored as analyst-approved metadata, never auto-applied; Sigma stays the portable format. AISOP does not import AiSOC's rule engine. Prerequisite DE-0: a canonical process-creation observation.

## 14. Security architecture
Trust boundaries: (1) untrusted telemetry and analyst text -> adapters (validate, bound, quarantine) -> preserved raw + canonical observation; (2) deterministic core (graph, correlation, ATT&CK, gate) trusts only canonical observations; (3) model boundary: escaped, bounded, analyst text excluded, output untrusted, claim-verified, fallback deterministic; (4) analyst boundary: nothing outward-facing (report accepted, rule approved, export) without a human action.
Controls IMPLEMENTED and tested: case RBAC with anti-enumeration; request body limits (import 8 MiB, `/alerts/ingest` 16 MiB); per-record size/depth/NUL checks; fixed-code errors; atomic import with audit; idempotent and race-safe import (SQLite-tested). Controls PROPOSED: ledger persistence, typed tools, export signing, contradiction-aware verdict. UNVERIFIED: PostgreSQL behaviour, real-model injection behaviour, TLS/proxy, rate-limit interplay. Prompt escaping is a markup control only, not an injection defence. Credential exposure in `opencode.json`/`viva-credentials.txt` is an open owner action.

## 15. Data flow (target)
```
evidence -> [adapters + limits] -> raw + observation -> correlate + contradictions(NEW) -> timeline/graph/ATT&CK
   -> sufficiency suff-v4(NEW) -> report (deterministic) -> analyst
                         \-> [optional: one gated model call or bounded typed-tool loop(NEW, Stage 8)] -> claim verification + claim-support(NEW)
   every step -> ledger entry (extended) -> case_audit_events.details (bounded)
validated findings -> detection opportunity -> Sigma candidate -> validate/test -> FP review -> ANALYST APPROVAL -> file export (never deploy)
analyst-approved investigation -> deterministic export bundle (+ optional signature) (Stage 8)
```

## 16. Deployment considerations
Single host, local Docker for PostgreSQL+pgvector (existing), local Ollama optional, FastAPI and React; no new service. The Stage 5 owner items (bind database port to loopback, credentials, PostgreSQL validation) remain separate and open. Export signing needs an owner decision on key handling (no `cryptography` dependency exists; stdlib HMAC with a dedicated key is possible without new dependencies, a public-key signature would need approval).

## 17. Resource and cost constraints
Zero billing; local hardware only; no model downloads in this stage; no hosted service. Effort estimates are in the roadmap.

## 18. Implementation sequence
Stage 6A (correctness and security gaps, with the contradiction model) -> Stage 7 (Detection Engineering foundation, starting with DE-0) -> Stage 8 (ledger, tools, grounding, export) -> Stage 9 (frontend and operational hardening). Reasoning: contradictions first because Detection Engineering must not derive rules from contradicted incidents; ledger before tools because tool calls need the audit vocabulary. See roadmap for acceptance gates.

## 19. Risks and limitations
Revising the gate changes assessment hashes and could shift historical verdicts (mitigation: versioned rule table, delta report, no label edits). Local models may call tools badly (mitigation: tools optional, deterministic path first). Scope creep toward a SOAR/agent platform (mitigation: section 20). Time: all four stages cannot fit a short window (mitigation: Stage 6A and 7 are the academic core). PostgreSQL and real-model claims stay unverified until authorized.

## 20. What AISOP deliberately will not implement
Autonomous penetration testing, exploitation, credential attacks, lateral movement, persistence or destructive testing; unrestricted agent loops or agent-to-agent communication; shell, network or database-admin tools for models; automatic rule deployment or auto-approval; automatic closure of investigations; hosted services for evidence; GRC, compliance, policy or audit workflows; claims of guaranteed zero-day detection; a clone of AiSOC or PentAGI.

---
## Component table (required per proposed component)
| Component | Reuse | New | Data contract | API boundary | Security boundary | Tests required | Acceptance |
|---|---|---|---|---|---|---|---|
| C1 Contradiction-aware verdict | `correlator.py`, `independence.py`, `sufficiency_gate.py`, `schemas/sufficiency.py` | `correlation/contradictions.py`; `suff-v4` | `ContradictionRecord{kind, observations, entity, strength, overlap_s, independence, reliability, explanations[], materiality}`; reason code `CONTRADICTION_UNRESOLVED` | none new (existing sections add fields) | deterministic only; no model input | spec file (5 xfail -> pass) + new cases + regression + dataset delta | ADR-013 approved; markers removed; delta report reviewed |
| C2 Ledger extension | `correlation/ledger.py`, `workflow_audit_details`, `CaseAuditEventModel` | extended entry schema; bounded persistence of entries; verifier from stored row | ledger entry fields in section 11 | `GET .../multisource/ledger` (read-only, viewer+) | digests only; no secrets/raw text; audit failure suppresses result | round-trip, tamper/reorder/delete, size bound, no-secret property | offline verification of a stored run |
| C3 Typed tool registry | `require_case_role`, services, pydantic | `modules/ai/tools/{registry,tools}.py` | per-tool pydantic models, `extra=forbid`, bounded results | internal; optional `POST .../ask` later | case from context; read-only; step cap; escape tool output | schema, injection, bounds, timeout, audit | scripted-provider loop passes; fallback intact |
| C4 Claim-support check | `ai/guardrails/validator.py` | `claim_support.py` (concept from AiSOC) | `ClaimSupport{scored|None, supported, contradicted}` | none | deterministic; negation-aware | benign/authorised claim with and without support; hedged text | unsupported "authorized" claim cannot be validated |
| C5 Investigation export | ledger, report, graph | `export/bundle.py` | deterministic JSON bytes; evidence hashes; prompts as digests; approvals list | `GET .../export` (lead) | download bytes = signed bytes; dedicated key; no raw sensitive text | byte-identical re-export; tamper detection | independent offline verification |
| C6 Detection Engineering | ADR-012 design, scenarios, graph | DE-0 observation then DE modules | see architecture doc | per ADR-012 | human approval; no deploy | per roadmap DE-0..DE-8 | per roadmap |
| C7 Frontend changes | `MultiSourcePanel`, `DomainEvidencePanel`, `index.css` | focus, captions, responsive, messages | existing API | none | no `dangerouslySetInnerHTML` | render tests + live check (authorized) | UX review findings U2, U3, U6, U8 closed |
| C8 Hardening (body limits, race-safe import) | `middleware/body_limit.py`, `domain_evidence_service.py` | none | n/a | `/alerts/ingest`, `.../evidence/domain` | 413 before parse | `test_stage6a_hardening.py` | IMPLEMENTED this stage (SQLite-tested) |
