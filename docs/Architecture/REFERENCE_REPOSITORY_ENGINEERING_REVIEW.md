# Reference Repository Engineering Review

Date: 2026-11-12. Purpose: identify engineering ideas that solve real AISOP problems; nothing here is a request to clone or merge a product. Status labels: IMPLEMENTED, PARTIAL, PROPOSED, UNVERIFIED, NOT IMPLEMENTED.

**Method and honesty about depth.** I read specific files in each checkout (named below), not whole repositories. Anything I did not open is listed as "not studied". Counts and claims quoted from READMEs are the projects' own claims, not measurements of mine. No reference code was copied into AISOP. No upstream-latest check was made beyond the shallow clones taken today.

## 0. Commits reviewed
| Repository | Local path | Commit | Date | Licence | Checkout |
|---|---|---|---|---|---|
| AiSOC | `D:\AiSOC` (existing, clean) | `8a06f2eb51cd9f9386b840061070c92bf18c89f0` | 2026-11-10 | MIT | existing, untouched |
| PentAGI | `D:\AISOP-Backups\Reference_Research_2026-11-12\pentagi` | `cffed9485aa1cca70762cd08a57ac62a80406258` | 2026-10-23 | MIT + EULA (+ NOTICE on a bundled AGPL SDK) | new shallow clone |
| Impeccable | `...\impeccable` | `b4bff1626c344067788c2679f048a20057c7cc5a` | 2026-11-11 | Apache-2.0 | new shallow clone |
| Karpathy skills | `D:\AISOP-Backups\Karpathy_Skills_Review\repo_multica` | `2c606141936f1eeef17fa3043a72095b4765b9c2` | 2026-04-20 | MIT declared, no LICENSE file | earlier clone |
| free-for-dev | `...\free-for-dev` | `72ad7e24c4f354f84eb02fddfa036f297ea9936f` | 2026-11-11 | not determined (no LICENSE file in the listing) | new shallow clone |

---
## A. AiSOC (primary defensive reference)
**Architecture (observed).** Microservice platform: `services/{agents,fusion,connectors,ingest,api,actions,enrichment,threatintel,ueba,...}`, `packages/` (SDKs, `aisoc-detections`), `detections/` rule library, web app. PostgreSQL with row-level security; agents service writes the ledger through raw `asyncpg`. README states Docker Compose with 8 GB memory and 15 generated secrets. Version 23.1.0.

**Engineering patterns that matter to AISOP (files opened)**
| Pattern | Where | What it does | AISOP relevance |
|---|---|---|---|
| Investigation ledger | `services/agents/app/investigator/ledger.py`, `services/api/migrations/008_investigation_ledger.sql` | Tables `investigation_runs`, `investigation_events` (append-only trigger, `UNIQUE(run_id, seq)`), `investigation_artifacts` (blob + `sha256`); per-tenant RLS. Writes are **best-effort**: DB failure is logged and the agent continues (a separate durable path raises `LedgerPersistError` for auto-triage outcomes) | AISOP already has a hash-chained `Ledger` (`correlation/ledger.py`) and append-only `case_audit_events`. AISOP is stricter (audit failure suppresses the result). Learn the event vocabulary and artifact digests, not the best-effort semantics |
| Typed, bounded tools | `services/agents/app/tools/tool.py`, `registry.py`, `llm/tool_loop.py` | Frozen `Tool` dataclass with JSON-schema parameters; `argument_error()` rejects **undeclared keys** and schema violations and returns a sentence to the model rather than raising; added after a security advisory (arguments come from a model whose context includes attacker text) | Direct template for an AISOP tool registry (PROPOSED). `jsonschema` is not in AISOP's requirements; pydantic models can play the same role with no new dependency |
| Claim support, not just indicator grounding | `services/agents/app/confidence/claim_support.py` | Shows an output can score 1.0 on "indicators present in evidence" and still assert an unsupported *sanctioned/authorized* claim; scores decisive claims separately; returns `None` (not `0.0`) when there is nothing to trace; negated and hedged mentions are not claims | Strengthens AISOP claim verification: AISOP's validator checks cited evidence ids and categories; it does not detect an unsupported "this was authorized/benign" assertion (PROPOSED check) |
| One-direction reviewer | `services/agents/app/agents/reviewer.py` | Deterministic second pass that may only **demote or escalate** one step, never close; shipped **off** because measured balanced accuracy did not improve; the measurement is recorded in the docstring | Model for AISOP post-verification: may only lower confidence or route to analyst; and the discipline of recording the measurement |
| Decision contract with "not evaluated" | `agents/auto_triage_agent.py` (~line 990) | `supporting_evidence`, `contradictory_evidence`, `groundedness` are `None` when not scored | AISOP verdict model should distinguish "none found" from "not evaluated" (contradiction model) |
| Signed, replayable evidence bundle | `services/api/app/api/v1/endpoints/investigations.py` (`export_evidence_bundle`, ~line 1152) | Deterministic bytes (two exports identical), served as a download so the signed bytes are the verified bytes; prompts exported as **digests**, not text; approvals field present but empty rather than omitted | Template for AISOP export (PROPOSED). Weakness seen: signing key is the application `SECRET_KEY` |
| Executable detection rules | `detections/README.md` | A rule is "executable" only if a vendor-shaped fixture produces a hit through the real normaliser and engine **and** an empty event of the same shape produces nothing; a "prove-gate" mode deliberately breaks the pipeline to show the gate can fail; tiers native / imported / quarantined / community; provenance block | Strongest input for the AISOP Sigma workflow: positive and negative fixtures per rule, and quarantine for rules that cannot be proven |

**Strengths:** security discipline (advisory-driven fixes), explicit measurement and honest "off by default" decisions, deterministic export bytes, per-tenant isolation in the database.
**Weaknesses / limits:** heavy infrastructure (many services, Docker VM, 15 secrets); best-effort ledger; export signed with an application secret; its own notes report local-model verdict accuracy near a 0.25 floor, which is a reminder that agent verdicts need independent checks; README quantities (rule counts, speed) are claims.
**Dependencies/infrastructure:** PostgreSQL, Docker Compose, several services, optional hosted or local LLM.
**Licence:** MIT: reuse permitted with notice, but AISOP adapts concepts only. Any code copy needs a provenance entry.
**Not studied this session:** `services/fusion` internals (earlier AISOP code already cites its link tiers), `services/enrichment`/`threatintel`, `ueba`, `mcp`, mesh, web UI, observability stack.
**What AISOP should not adopt:** the microservice and RLS stack, best-effort audit semantics, a signing key shared with the app secret, autonomous closure.

## B. PentAGI (multi-agent engineering reference only)
**Architecture (observed).** Go backend (`backend/pkg/{tools,providers,docker,graph,controller,...}`), React frontend, PostgreSQL/pgvector memory, optional Graphiti knowledge graph, Langfuse and Grafana observability, Docker-sandboxed tool execution. README describes a primary agent, a planner (the adviser in planning mode producing 3 to 7 steps), an enricher, specialist agents (researcher, developer, executor and others), and an adviser/mentor invoked automatically on stuck patterns.
**Patterns (files opened):** `pkg/tools/executor.go`: tool results capped at 16 KB, argument values capped at 1 KB, bounded cleanup writes when a flow's context ends; `pkg/docker/{client,sandbox}.go`: container lifecycle with discard timeouts; `pkg/providers/`: one provider package per LLM vendor behind a catalog; typed argument structs (`args.go`).
**Strengths:** disciplined tool result and argument bounds; per-flow cancellation and cleanup; provider abstraction; observability from the start.
**Weaknesses / limits:** designed for autonomous offensive testing; large surface (shell, browser, network tools); Go, so no code reuse into a Python/FastAPI backend; multi-agent cost and non-determinism; a mentor model patching a weak model is an admission that agent loops drift.
**Licence (read, not legally interpreted):** `LICENSE` MIT. `EULA.md` (93 lines) grants a "non-exclusive, non-transferable, revocable licence... solely for lawful penetration testing purposes", says source is MIT, but also says you "may not sublicense, sell, lease, or distribute the PentAGI software or its derivatives in any form other than stated in the license agreement" while "modification and redistribution are permitted under the MIT license". Those clauses are in tension and the acceptable-use scope is penetration testing. `NOTICE`: the bundled VXControl Cloud SDK is AGPL-3.0 "with a special exception for this official PentAGI project", so a derivative would not automatically inherit that exception. **Conclusion: no source reuse and no derivative; concepts only. Any reuse needs legal review.** AISOP is not a penetration-testing product, so the EULA's licensed purpose does not match AISOP's use.
**Not studied:** agent prompts and templates, graph and GraphQL layers, frontend, provider internals, Graphiti integration, test suites.
**What AISOP should not adopt:** autonomous exploitation, shell or arbitrary network tools, credential attacks, lateral movement, persistence, destructive testing, unrestricted agent-to-agent loops, Docker-socket access from the app.

## C. Impeccable (frontend quality skill)
**Architecture (observed).** Repository builds per-tool skill folders; the Claude Code build is `.claude/skills/impeccable/` (SKILL.md v4.8.2, `reference/*.md` commands such as critique, audit, harden, polish, document), a launcher script, and a Rust engine ("detector") distributed as a platform binary. `npx impeccable install` can add hooks and subagents.
**Safety review (done before install):** the launcher `scripts/impeccable` and the npm shim download a checksum-verified engine binary from GitHub releases into `~/.impeccable` (C: on this machine) on first use; the shipped hook runs that launcher on session start, after every Edit/Write and on Stop, **outside model approval**; the README discloses a design-catalog fetch and optional anonymous telemetry.
**AISOP decision (IMPLEMENTED):** manual project-level copy only at `D:\AISOP\.claude\skills\impeccable\` (SHA-256 of `SKILL.md` matches upstream, licence and NOTICE copied, `ATTRIBUTION.md` added); no hook, no subagents, no installer, no engine download; `CLAUDE.md` forbids running the launcher without owner approval. Karpathy skill verified byte-identical afterwards.
**Consequences:** the deterministic detector has NOT been run (BLOCKED: needs the downloaded binary, owner decision, and `IMPECCABLE_HOME` on D:). The skill's own critique protocol requires the detector and isolated sub-agents; my review is therefore a **manual, single-context, degraded critique** (see `FRONTEND_ANALYST_UX_REVIEW.md`). Skill recognition by Claude Code: UNVERIFIED until restart.
**Strengths:** concrete command library, accessibility and responsive guidance, explicit anti-pattern lists, deterministic rules. **Weaknesses:** engine download and hooks conflict with a locked-down environment; generic taste advice can conflict with AISOP's design constitution (which wins).

## D. Karpathy skills
Four principles (think before coding, simplicity first, surgical changes, goal-driven execution) in one SKILL.md (67 lines); MIT declared, no LICENSE file. Installed and merged into `D:\AISOP\CLAUDE.md` with AISOP precedence (IMPLEMENTED); recognition UNVERIFIED until restart. Weakness: generic; "ask when unclear" must not become a reason to stall on well-specified tasks.

## E. free-for-dev
A long, community-curated list; entries give one-line free-tier descriptions. Licence: no LICENSE file in the listing (not determined). It is a directory, not a service: every limit in it can change and none was verified against the provider. Use: shortlist only. See `ZERO_BILLING_INFRASTRUCTURE_OPTIONS.md`.

---
## F. Summary: what AISOP learns, and where it applies
| Idea | Source | AISOP module/file | Decision |
|---|---|---|---|
| Typed tool descriptor with undeclared-key rejection | AiSOC `tool.py` | new `backend/app/modules/ai/tools/` (PROPOSED), reuse `require_case_role`, `case_audit_events` | Adopt (Stage 8) |
| Bounded tool results and arguments | PentAGI `executor.go` | same registry | Adopt concept |
| Claim-support check for "authorized/benign" assertions; `None` vs `0` | AiSOC `claim_support.py` | `ai/guardrails/validator.py` | Adopt (Stage 8) |
| One-direction post-verification | AiSOC `reviewer.py` | after claim verification in `correlation/workflow.py` | Adopt concept |
| Contradiction and "not evaluated" states in the verdict | AiSOC decision contract | `ai/guardrails/sufficiency_gate.py`, `schemas/sufficiency.py` | Adopt (Stage 6A) |
| Ledger event vocabulary + digests of prompts | AiSOC ledger | extend `correlation/ledger.py` + `case_audit_events.details` | Adopt (Stage 8), no new table |
| Deterministic signed bundle, prompts as digests | AiSOC export | new export module | Adopt concept; own key management (Stage 8) |
| Positive and negative fixtures per rule, quarantine tier, prove-the-gate | AiSOC detections | Detection Engineering (ADR-012) | Adopt (Stage 7) |
| Planner plus specialists, mentor agent | PentAGI | none | Do not adopt (see evolution plan, section 12) |
| Docker sandboxed autonomous execution | PentAGI | none | Do not adopt |
| Hooks, engine download | Impeccable | none | Not installed |

---
## Continuation 2026-11-12 (Master Prompt 26). Earlier sections are unchanged history. Only files actually opened are listed.

### AiSOC (commit 8a06f2eb, unchanged checkout)
| Area | Opened | Finding | Use for AISOP |
|---|---|---|---|
| Fusion architecture | `services/fusion/app/services/fusion_engine.py` (header and imports), `services/fusion/app/` file listing | "orchestrates deduplication -> correlation -> ML scoring"; separate modules for dedup, correlator, attack-chain grouper, enrichment, entity risk, UEBA boost, narrative | the same ordering AISOP already has (cluster duplicates before correlating); confirms "dedup first" |
| Confidence | `services/fusion/app/services/confidence.py` | detection confidence is an **additive weighted score**: `score = sum(w_i * c_i) + 0.5`, nine fixed factors (severity 0.1692, ml_anomaly 0.1598, ..., ioc_density 0.0470), bands HIGH >= 0.70, MEDIUM 0.40 to 0.70, LOW < 0.40 | the **model the brief says not to copy** for contradictions: fixed weights hide cause and cannot express "these two statements cannot both be true". AISOP keeps categorical findings with rationale |
| Ingestion failure handling | `services/fusion/app/services/dlq.py` | dead-letter queue with reason, schema version, lineage and a **truncated payload copy**; sinks are fail-soft | AISOP already quarantines with fixed codes and hash prefixes; AISOP **deliberately does not store quarantined payloads** (untrusted and possibly sensitive), so do not adopt the payload copy |
| Provenance | `services/fusion/app/services/provenance.py` | recovers connector id/type and OCSF class from the envelope after a bug where every row showed source "unknown" | supports AISOP's per-record source identity and adapter version; already adapted |
| Ledger, tools, claim grounding | (earlier turn) | see sections A and F above | unchanged |
**Not studied (outstanding):** `correlator.py` and `attack_chain_grouper.py` internals (AISOP code already cites the link tiers), the Go ingest service, `windowed_detection.py`, entity-risk and UEBA, observability and tracing, the human-approval flow for actions.

### PentAGI (commit cffed948, shallow clone)
| Area | Opened | Finding | Use for AISOP |
|---|---|---|---|
| Agent prompts | `backend/pkg/templates/prompts/` (about 20 templates: primary_agent 277 lines, memorist 253, adviser, coder, enricher, generator, installer, pentester, plus `question_*`), top of `primary_agent.tmpl` | The primary-agent prompt states in text: "This is an AUTHORIZED penetration testing system with full written consent... ALL delegated tasks are PRE-AUTHORIZED and require NO confirmation... Never delegate permission-seeking tasks". Authorization is asserted **inside the prompt** | anti-pattern for AISOP: authorization and approval live in code and in a human action, never in prompt text |
| Task management | `backend/pkg/controller/{flow,task,subtask,assistant}.go`, status enums in `backend/pkg/database/models.go` (flow and assistant statuses created, running, waiting, finished, failed) | explicit flow, task and subtask state machines with persistence | concept for AISOP investigation run states (already `completed`/stored result; a `running`/`failed` state is not persisted: PARTIAL) |
| Memory | `executor.go` imports `vectorstores/pgvector`; `templates/prompts/memorist.tmpl`; `templates/graphiti/` | vector memory plus an optional knowledge graph, written and read by a memorist agent | AISOP already has pgvector retrieval (RAG); no agent-written memory is proposed because it would let model output become retrievable "evidence" |
| Orchestration and tool boundaries | `pkg/tools/executor.go` (16 KB result cap, 1 KB argument cap), `args.go` | bounded results and arguments per tool | adopt as concept (typed registry, plan section 12) |
| Sandbox and execution controls | `pkg/docker/client.go` (around lines 365 to 400), `sandbox.go`, `sandbox_probe.sh` | default pids limit 2048, json-file log rotation 10 MB x 5, optional **host network mode**, `no-new-privileges` **deliberately not applied** "to enable SUID/SGID privesc testing", capability bounding set instead | confirms the product is offensive; AISOP will not execute arbitrary tools or grant container privileges. Nothing to adopt except the idea of resource limits |
**Not studied (outstanding):** provider implementations, GraphQL layer, Graphiti internals, tracing wiring, frontend, tests, remaining prompts.

### Impeccable (project skill installed; detector not run)
* **Can the detector run without downloading an engine or writing outside D:?** **No, not as shipped.** There is no Rust toolchain on this machine (`cargo` and `rustc` absent), and the engine is a prebuilt binary: `skill/scripts/engine-checksums.txt` pins `impeccable-windows-x64.exe` version 0.1.22 with a SHA-256. First use downloads it from GitHub releases into `~/.impeccable` (C:). `~/.impeccable` does not exist yet and the npm cache is already on D: (`D:\npm\node_cache`).
* **A controlled D:-only route exists but was not taken:** download the single pinned asset into a D: folder, verify the SHA-256 against the manifest in the reviewed commit, set `IMPECCABLE_BIN` and `IMPECCABLE_HOME` to D: paths, then run `detect` on `frontend/src`. This still executes a downloaded third-party binary and its runtime network and telemetry behaviour is UNVERIFIED, so it needs an explicit owner decision.
* **Initialization:** `reference/init.md`: `init` is an interactive interview that writes `PRODUCT.md` (never `DESIGN.md`) using the engine's `context` command; the repository has neither file. Not run.
* Installed skill verified present and byte-identical to upstream; listed as an available skill in this session; not invoked.

### Karpathy skills
Invoked in this session; loads from `D:\AISOP\.claude\skills\karpathy-guidelines`. Applied here: probes before specifications; two of my own tests found vacuous and corrected; no unrelated refactoring; no production change without approval.

### free-for-dev: primary-page verification (read 2026-11-12 through a fetch sub-agent; its report is model output, quoted fact by fact)
Only services I actually recommended were checked.
| Service | What the primary page states | Not stated or unverified |
|---|---|---|
| Bugsink (https://www.bugsink.com/) | self-hosted column: "Self-hosted", "Free", "Unlimited users", "All Features", "Volume based on hardware"; "Self-host on your own servers and handle millions of events with no per-event billing". Hosted free plan: "15K / Evaluation", "15K monthly events", "Single user", "5K events retained"; data location "EU (GDPR-friendly)" | **software licence not stated** on the homepage (GitHub repo not fetched); **credit-card requirement not stated**; retention is a count (5K events), no time period; `/pricing/` returned 404 so the homepage pricing section was used |
| Opik (https://github.com/comet-ml/opik) | GitHub sidebar "Apache-2.0 license"; README: "Apache-2.0 licensed, free to self-host the full platform"; FAQ: server, web app and core observability and evaluation features "can be self-hosted without a commercial license" | page text truncated at 39,959 of 52,886 characters (the quoted parts were verbatim); not checked against the repository's LICENSE file |
Not verified from primary sources and therefore **not relied on**: Neon, Aiven, Koyeb and the other hosted rows (all rejected anyway), and the general-knowledge self-hosted rows (Prometheus, Grafana, Langfuse, MinIO). Recommendation unchanged: no hosted service; keep the local stack.
