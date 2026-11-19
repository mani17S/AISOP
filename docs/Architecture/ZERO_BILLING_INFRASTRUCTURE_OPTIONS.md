# Zero-Billing Infrastructure Options for AISOP

Date: 2026-11-12. Source of the shortlist: `free-for-dev` commit `72ad7e24c4f354f84eb02fddfa036f297ea9936f` (read from the local shallow clone only). Status: **PROPOSED research, no service was contacted, signed up for, or connected.**

## 1. Principles and what the research can and cannot say
* AISOP direction (unchanged): zero mandatory billing, local inference where practical, self-hosted storage, minimal external dependencies, deterministic fallback. Evidence handled by AISOP is security-sensitive; it must not leave the deployment without an explicit Owner decision.
* free-for-dev gives one-line descriptions. For every hosted entry below, **expiry, credit-card requirement, data retention, privacy terms, region availability and lock-in are UNVERIFIED**: the list does not state them reliably and I did not open provider terms (no network research was authorized beyond cloning). They must be read from the provider before any use. Free tiers are not permanent.
* Rows marked "general knowledge" describe self-hosted software I know from training, not from the list and not verified today: confirm licence and resource needs before adoption.

## 2. What AISOP already has (the baseline to beat)
| Need | Current state (verified in repo) |
|---|---|
| Database + vectors | Local PostgreSQL 17 + pgvector in Docker Compose (`docker-compose.yml`, image `pgvector/pgvector:pg17`, host port 5433). Zero billing. Validation of the Stage 5/6 storage paths is BLOCKED pending authorization |
| LLM | Local Ollama (`OLLAMA_BASE_URL`, ADR-001); deterministic path works without it |
| Threat intelligence | Offline local engine and feed parsers (`modules/threatintel/{local_engine,feeds}`); no external calls in tests |
| Observability | `loguru` logs and request correlation middleware; no external service |
| CI | None verified in this session (a `.github/` folder exists untracked; not inspected) |

## 3. Category by category
Columns: **Local / self-hosted option first**, then hosted shortlist from the list (limits are the list's wording; all UNVERIFIED).

### 3.1 PostgreSQL and vectors
| Option | Free-tier conditions as listed | Card / retention / privacy / region / lock-in | Verdict |
|---|---|---|---|
| **Local PostgreSQL + pgvector (current)** | none: self-hosted | no card; data stays local; no lock-in (standard Postgres) | **Keep** |
| Neon | "0.5 GB storage per project, 100 CU-hours/month, scales to zero after 5 minutes" | all UNVERIFIED | Not recommended: evidence leaves the machine; scale-to-zero latency |
| Aiven | "free PostgreSQL... 1 CPU, 1 GB RAM, 1 GB storage" | UNVERIFIED | Same objection |
| Koyeb, Gigalixir, Runsite | small free Postgres tiers with tight limits (e.g. 10,000 rows, 2 connections, 30 days) | UNVERIFIED | Unsuitable for evidence storage |
Hosted databases are rejected for production evidence. They could host synthetic demo data only, after approval.

### 3.2 Object and evidence-file storage
Local filesystem or MinIO (general knowledge) beside PostgreSQL; hashing and integrity are AISOP's job, not the store's. free-for-dev storage entries (file sharing, backups such as BorgBase "10 GB free backup space") are not suitable for evidence; an encrypted local backup is preferable. No hosted option recommended.

### 3.3 CI/CD and testing
Local scripts and the existing offline test commands are the baseline. Hosted CI entries exist (for example Buildkite "free for 3 users and 5k job minutes/month" as listed). **Recommendation:** none now; AISOP tests must stay runnable offline with no billing. If a hosted CI is wanted later, use it only with synthetic data and no secrets, after reading its terms.

### 3.4 Monitoring, logging, error tracking
| Option | Notes | Verdict |
|---|---|---|
| **Structured logs to local files + health endpoints (current)** | no dependency | Keep |
| Self-hosted Prometheus + Grafana (general knowledge) | standard, free, local | PROPOSED for Stage 9 if needed |
| Bugsink (listed: "free for up to 5,000 errors/month, or unlimited use when self-hosted") | self-hosting removes the quota and the data-leaves-site problem | Candidate (self-hosted only) |
| Hosted log tools (listed examples: 3-day retention, 1 GB/month, 100k lines/day) | retention too short; logs may contain evidence-derived text | Reject |
| Uptime monitors (Better Stack, Pingzo, ...) | external probe of a local system is not meaningful | Reject |

### 3.4a AI evaluation and tracing
Listed: Comet Opik (open source), Arize AX (free plan "25k spans"), Braintrust ("1,000 private eval rows/week"). Prompts and outputs contain investigation data, so hosted evaluation is rejected. **Candidate: self-hosted Opik or Langfuse (general knowledge) only if Stage 8 needs trace UI**; the AISOP hash-chained ledger already records the decisions that matter. Prefer no new component.

### 3.5 Authentication
AISOP has its own analyst token and RBAC model (implemented, tested). Hosted auth entries (for example Aserto "free up to 1000 MAUs") would introduce a dependency and external identity data. **Reject** for the current scope.

### 3.6 Threat intelligence feeds
free-for-dev is weak here (it lists general data APIs, e.g. a free IP-geolocation API with daily limits). AISOP's direction: local, curated, offline-loadable feeds (existing `feeds/manager.py`). Feeds that are public bulk downloads (for example CISA KEV, which AiSOC's README says it pulls without an API key) can be fetched **by the Owner on a schedule** into a local file; AISOP then reads the file. Terms and licences per feed: UNVERIFIED. No live lookups from the investigation path.

### 3.7 Security testing of AISOP itself
Listed commercial scanners (for example Aikido "10 repos", Corgea "2 repos") send source code to a vendor: reject for this codebase. Prefer local tools after approval (general knowledge: `pip-audit`, `bandit`, `semgrep` OSS, `npm audit`): each needs dependency approval and an offline-capable install path.

### 3.8 Documentation hosting
Static site generated from `docs/` and served locally or from the repository host's free static hosting for **non-sensitive** docs only; no secrets, no customer data. Terms UNVERIFIED.

### 3.9 Local AI inference and model evaluation
| Option | Notes |
|---|---|
| **Ollama (current)** | local; model weights are large downloads (not done in this task) |
| llama.cpp / vLLM (general knowledge) | alternatives behind the `LLMProvider` protocol (`ai/llm/protocol.py`) |
| Evaluation | existing offline harness (`modules/evaluation`, sufficiency dataset); real-model runs need authorization and hardware |
Real-model behaviour (prompt injection, claim verification, quality) remains UNVERIFIED until an authorized local run.

## 4. Recommendation
1. Change nothing mandatory: the current local stack already satisfies zero billing.
2. Optional, self-hosted only, in this order of value: encrypted local backup of the PostgreSQL volume and evidence files; Prometheus/Grafana or Bugsink if operational visibility is requested; Opik/Langfuse only if trace UI becomes necessary.
3. Do not connect AISOP to any hosted service without explicit Owner approval and a per-service terms review (card, retention, privacy, region, lock-in).
4. Re-verify any listed limit at the time of use: the list is a starting point, not a guarantee.

## 5. Requires Owner approval before any use
Any hosted service; any new dependency or scanner; model downloads; scheduled feed downloads.

---
## Addendum 2026-11-12 (Master Prompt 26): primary-source verification of the services actually recommended
Bugsink: self-hosting stated as free with unlimited users, all features and "Volume based on hardware"; software licence, hosted-tier card requirement and retention period (only "5K events retained" on the free plan) are **not stated** on the homepage. Opik: Apache-2.0 and "free to self-host the full platform" per its repository README. Details and limits of this check: `REFERENCE_REPOSITORY_ENGINEERING_REVIEW.md`, "Continuation 2026-11-12". Hosted entries that were not verified (Neon, Aiven, Koyeb and others) remain rejected and are not relied on. Recommendation unchanged.
