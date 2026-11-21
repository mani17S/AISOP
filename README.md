# AISOP — AI-Assisted Security Operations Platform

> **Local-First, Privacy-Preserving Defensive Security Workbench at ₹0 Additional Cost.**
> Grounded alert triage, cryptographic evidence provenance, deterministic telemetry normalization, local threat-intelligence shielding, scoped RBAC case management, and human-in-the-loop AI investigation synthesis powered by PostgreSQL 17, `pgvector`, and Ollama.

---

## 1. Project Overview & Governance Notice

AISOP (AI-Assisted Security Operations Platform) is an on-premises, local-first defensive workbench designed to streamline security alert triage and incident investigation.

### Core Architectural Principles:
1. **Deterministic Processing Precedes AI Reasoning:** Raw security telemetry is cryptographically hashed (SHA-256), deduplicated, normalized, and stored in relational schemas *before* any language model is invoked. AI never touches raw, unvalidated network streams directly.
2. **Epistemic Partitioning & Mandatory Human-in-the-Loop Review:** AI-generated conclusions, MITRE ATT&CK technique classifications, and remediation proposals are strictly separated from verified forensic facts. The platform operates exclusively in an advisory capacity: **zero autonomous containment, zero automatic blocking, and zero destructive tooling.** Every investigation action and report requires explicit review and approval by a human security analyst.
3. **Local-First Privacy at ₹0 Cloud Cost:** All LLM inference (`llama3.1:8b`, `qwen3:4b`), semantic embeddings (`nomic-embed-text`), vector similarity searches, and telemetry databases run entirely within local workstation or container boundaries. Sensitive host observables, internal IP addresses, and forensic artifacts are never transmitted to external cloud APIs.

> [!WARNING]
> **Operational Scope Disclosure:**
> AISOP is a defensive investigation and triage workbench for security analysts and academic research. It is **not** a fully autonomous SOC replacement, **not** an automated SOAR containment engine, and **not** a replacement for commercial enterprise-scale distributed SIEMs (e.g. Splunk, Microsoft Sentinel).

---

## 2. Problem Statement

Modern Security Operations Centers (SOCs) face four foundational structural challenges:
1. **Alert Fatigue & Context Fragmentation:** Analysts sift through thousands of daily alerts across disparate tools without immediate, unified correlation against internal knowledge playbooks or forensic timelines.
2. **Cloud Privacy & Compliance Liabilities:** Forwarding raw incident logs, proprietary source code, or internal network topology to public LLM APIs (e.g. OpenAI, Anthropic) risks violating regulatory mandates (GDPR, HIPAA, PCI-DSS) and leaks active intrusion data.
3. **Hallucination & Epistemic Drift in AI Tools:** Generative AI models frequently fabricate indicators of compromise (IOCs), confuse observed evidence with prior training data, and generate ungrounded incident narratives.
4. **Prohibitive SaaS & Consumption Licensing:** Educational institutions, independent security researchers, and small defensive teams cannot justify enterprise SIEM costs (often exceeding ₹10,000+/month) or per-token cloud API consumption billing.

---

## 3. AISOP's Proposed Solution

AISOP resolves these challenges through an integrated, local-first engineering architecture:
- **Local Ingestion & Normalization:** High-throughput REST batch ingestion accepting raw Windows Sysmon and vendor-neutral telemetry, resolving observables into a canonical data model (`CanonicalEvent`).
- **Cryptographic Provenance:** Every evidence item receives an immutable SHA-256 digest on ingestion, enabling deduplication, cryptographic tamper verification, and an auditable chain of custody.
- **Threat Intelligence & Bogon Shielding:** The `PrivateNetworkShield` classifies indicators and prevents external exfiltration or SSRF by strictly dropping private, loopback, and link-local IP addresses (RFC 1918 / RFC 3927) before feed lookup.
- **Scoped RBAC & Multi-Analyst Case Management:** Role-based access control (`admin`, `lead`, `analyst`, `read_only`) enforced via constant-time token comparison, with strict case scoping and BOLA/IDOR prevention.
- **RAG via pgvector:** Semantic search over curated MITRE ATT&CK defense playbooks using 768-dimensional cosine distance embeddings in PostgreSQL 17.
- **Epistemically Guarded Investigation Synthesis:** Context assembly that strictly escapes untrusted observables within XML boundaries, validates model outputs through a 3-tier guardrail system, and generates role-tailored reports (Executive Brief, Technical Incident Response, Detection Engineering Playbook).

---

## 4. Current Implementation Truth & Reality Matrix

To maintain engineering integrity, AISOP explicitly distinguishes between verified runtime implementations, partially implemented modules, and deferred architecture:

| Capability / Layer | Current Status | Operational Reality & Grounding |
| :--- | :---: | :--- |
| **Evidence Ingestion API** | **Implemented & Verified** | `POST /api/v1/evidence/ingest` accepts raw telemetry batches up to 2,000 events / 64 KB per payload with per-event atomic savepoints. |
| **Cryptographic Provenance** | **Implemented & Verified** | Computes deterministic SHA-256 digests on raw payloads; detects duplicates idempotently without creating orphaned rows. |
| **Telemetry Normalization** | **Implemented & Verified** | Deterministic normalization for Sysmon Event IDs (1, 3, 7, 8, 10, 11, 12–14, 22) into `CanonicalEvent`; Vendor-neutral alert schema (ADR-007). |
| **Atomic Entity Extraction** | **Implemented & Verified** | Extracts atomic indicators (IPs, hostnames, users, processes, file hashes, domains) into relational schemas. |
| **Threat Intelligence Shield** | **Implemented; unit-tested** | `PrivateNetworkShield` enforces zero-egress for private/bogon IPs (offline probe tests pass); `LocalThreatIntelEngine` supports offline Feodo Tracker and Tor exit node lookups. **Not applied inside the multi-source investigation** (it performs no threat-intelligence lookups). An opt-in external provider adapter is uncommitted and unverified. |
| **Vector Knowledge Store (RAG)** | **Verified on PostgreSQL; corpus uncommitted** | PostgreSQL 17 `pgvector` with HNSW cosine indexing (`Vector(768)`) and Alembic migration lifecycle (`0004_p3h2_rbac_case_scoping`); the 5 pgvector tests pass on a disposable PostgreSQL. A 7-document knowledge base (35 chunks) was ingested and retrieved with source attribution on a demo database. Retrieval runs inside case synthesis only when the analyst supplies a query filter (otherwise it is skipped and the result says so); a live check confirmed retrieval, local-model use and a verified result in that path. It is **not** used by the deterministic multi-source investigation. The knowledge-base files are not yet committed. |
| **API Authentication & RBAC** | **Implemented & Verified** | Bearer token and API key validation via constant-time hashing; 4 global roles (`admin`, `lead`, `analyst`, `read_only`) with case-assignment scoping. |
| **Ingress Rate Limiting** | **Implemented & Verified** | In-memory token-bucket rate limiter (`RateLimitMiddleware`) with trusted-proxy IP resolution. |
| **Security Headers** | **Implemented & Verified** | `SecurityHeadersMiddleware` injects CSP (`frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`, and conditional HSTS. |
| **Deep Readiness Probe** | **Implemented & Verified** | `GET /api/v1/health/ready` validates PostgreSQL relational reachability, `pgvector` extension catalog presence, schema availability, and 768-dim vector compatibility. |
| **Analyst Web UI** | **Implemented & Verified** | React 18 + TypeScript + Vite SPA (`frontend/`; hand-written stylesheet and self-hosted fonts, no CSS framework and no icon library): Alerts triage dashboard, 6-area Investigation Workspace, multi-source investigation panel with an optional on-demand AI explanation step, and 4-tab Report Viewer. 201 frontend tests pass (2026-11-21 run). Not yet walked end to end in a browser by the full automated walk. |
| **Role-Tailored Reporting** | **Implemented & Verified** | Deterministic synthesizer generating Executive, Technical, and Detection Playbook briefs with Markdown export. |
| **Automated CI/CD Pipeline** | **Implemented & Verified** | GitHub Actions workflow (`.github/workflows/ci.yml`) for offline backend tests, frontend build/typecheck/tests, and `pip-audit`. |
| **Database Backup Script** | **Implemented & Verified** | PowerShell utility (`scripts/backup_postgres.ps1`) using `pg_dump -Fc` with SHA-256 sidecars and JSON audit metadata. 12 mock unit tests pass. |
| **Database Disaster Recovery** | **Partially Implemented** | Backup script and 3-tier validation runbook exist in `docs/11_Deployment/Deployment_Guide.md`; live restore drill on running container pending operator authorization. |
| **Private TLS Reverse Proxy** | **Partially Implemented** | Hardened Nginx configuration template created (`deploy/nginx/nginx.conf`) and documented in `TLS_Reverse_Proxy_Guide.md`; inactive pending live certificate issuance and port binding. |
| **Ground-Truth AI Benchmark** | **Partially Implemented** | Offline evaluation framework and 20 curated telemetry scenarios verified (53 tests pass); live model capture execution pending operator authorization (REQ-8.5). |
| **Multi-Source Investigation** | **Implemented; verified on PostgreSQL at API level** | Case-scoped investigation that re-normalizes preserved raw evidence, correlates sources by typed link strength, collapses duplicates, builds a timeline, maps ATT&CK only through 13 evidence-backed rules and applies one sufficiency gate. Works with the language model off. Verified on synthetic data only: live end-to-end run 19 of 19 checks; reliability matrix R01-R12 on PostgreSQL 38 passed, 3 not executable live. Not verified on real telemetry. |
| **Lead Review Record** | **Implemented; verified offline and live on PostgreSQL (API level)** | Lead-only approve or reject of one stored investigation, shown in the status and report sections and in the workbench. The multi-source export is gated on it (3 more backend tests, 14 live PostgreSQL checks in total); the case-synthesis reports are not gated. |
| **Local TLS Proxy (lab)** | **Implemented; verified through the proxy** | `scriptsproxy_up.ps1` plus `deploy/nginx/nginx.local.conf`: TLS 1.2/1.3 on loopback, header CSP, docs blocked, read-only container; 18 of 18 security probes and a clean browser walk through it. Self-signed, local only. |
| **Modular LLM Layer** | **Implemented; tested offline (8 tests)** | A provider registry plus a shape checker (it never calls a model): a new provider is added by registering a factory and selecting it with `LLM_PROVIDER`, with no change to core code. Local Ollama is the only provider that exists; the OpenAI, Anthropic and Gemini folders are empty placeholders. All providers inherit the local-first, off-unless-selected and gate rules. See `docs/06_AI/Adding_an_LLM_Provider.md`. |
| **Evidence Class Markers** | **Implemented; verified in the browser** | Each record's backend trust class (observed, tool-asserted, analyst statement, external intelligence, derived, AI inference, analyst confirmed) is shown as a distinct glyph shape plus the word, with a legend; the class comes only from the backend and nothing is derived in the browser. 2 render tests. |
| **Suricata EVE Source** | **Implemented; tested offline and live on PostgreSQL (synthetic records)** | `backend/app/modules/evidence_domains/suricata_eve.py` translates EVE `alert`, `dns` and `flow` records into the standard evidence envelope (other event types are counted as skipped, not interpreted); `backend/scripts/eve_to_envelopes.py` converts a file for the import endpoint. Records from one sensor and one flow count as one piece of evidence; a Suricata severity or category is kept as an attribute and creates no verdict or ATT&CK mapping. 8 tests plus 9 live checks. Not tested on real Suricata output. |
| **Alert Time Integrity** | **Implemented & Verified** | An alert with no usable event time is rejected per alert and never stored with the ingestion time (13 preserved reliability tests pass). |
| **Security Probe Suite** | **Implemented; run offline and live** | OWASP-mapped probes: 33 offline test cases and 18 live probes pass; findings and open items in `docs/07_Security/Security_Test_Findings.md`. This is not a penetration test. |
| **Direct SIEM Pull Connectors** | **Absent (By Design)** | Telemetry ingestion is strictly push-based REST. Automated pull connectors for Splunk, Elastic, or Sentinel are out of scope. |
| **Keyset / Cursor Pagination** | **Partially Implemented** | Shallow queries ($M \le 1000$) use index-backed offset pagination ($O(K)$); high-depth keyset pagination deferred (REQ-15.3). |
| **Distributed Cache / Workers** | **Deferred with Justification** | Redis (`REQ-11.4`), Celery task queues (`REQ-15.4`), and Prometheus `/metrics` (`REQ-14.5`) deferred to preserve single-workstation simplicity. |

---

## 5. System Architecture & Ingestion Workflow

```mermaid
flowchart TD
    subgraph "External Ingress (Private Network)"
        Forwarder["Sysmon Forwarder / REST Client"] -->|POST JSON batch| Proxy["Nginx TLS Reverse Proxy (deploy/nginx/)"]
    end

    subgraph "Ingress Security Perimeter"
        Proxy -->|Port 8000| SecHeaders["SecurityHeadersMiddleware<br/>(CSP, HSTS, DENY)"]
        SecHeaders --> RateLimit["RateLimitMiddleware<br/>(Token Bucket + Trusted Proxies)"]
        RateLimit --> Auth["verify_api_key / RBAC<br/>(Constant-time Bearer Check)"]
    end

    subgraph "FastAPI Backend Pipeline"
        Auth --> IngestAPI["POST /api/v1/evidence/ingest"]
        IngestAPI --> Hasher["Cryptographic Hasher<br/>(SHA-256 Digest)"]
        Hasher --> Dedup{"Deduplication<br/>(Existence Lookup)"}
        Dedup -- "Duplicate Hash" --> Skip["Skip & Record Provenance"]
        Dedup -- "Unique Hash" --> Parser["Sysmon / Neutral Parser"]
        Parser --> Extractor["Atomic Entity Extractor<br/>(IP, Host, User, Hash, Domain)"]
        Extractor --> Savepoint["Nested Atomic Savepoint<br/>(session.begin_nested)"]
    end

    subgraph "Persistence Tier (Internal Port 5433 / Zero LAN Exposure)"
        Savepoint --> DB[("PostgreSQL 17 Engine<br/>raw_evidence, normalized_events")]
        DB --> Knowledge[("knowledge_embeddings<br/>Vector 768-dim HNSW Index")]
    end

    subgraph "Local Threat Intelligence"
        Extractor --> Shield["PrivateNetworkShield<br/>(Bogon / RFC 1918 Dropper)"]
        Shield -- "Public Indicator" --> TI["LocalFeedManager<br/>(Feodo / Tor Blocklists)"]
    end

    subgraph "AI Investigation & Synthesis (Local Port 11434)"
        DB & TI --> Context["InvestigationContextBuilder<br/>(XML Escaped Boundaries)"]
        Context --> Ollama["Ollama LLM Provider<br/>(llama3.1:8b / qwen3:4b)"]
        Knowledge <--> Embedder["OllamaEmbedder<br/>(nomic-embed-text 768d)"]
        Ollama --> Guardrails["3-Tier Epistemic Guardrails<br/>(Schema, Length, Claim Audit)"]
    end

    subgraph "Analyst Experience (Port 3000)"
        Guardrails --> CasesAPI["Case Management & Reporting APIs"]
        CasesAPI --> UI["React 18 SPA (frontend/)<br/>Alerts, Investigation Workspace, Report Viewer"]
    end
```

---

## 6. Technology Stack

- **Backend Runtime:** Python 3.12, FastAPI, Pydantic v2, Uvicorn.
- **Database & Object Relational Mapping:** PostgreSQL 17 with `pgvector` 0.8.x extension, SQLAlchemy 2.0 (async), `psycopg` 3.x async driver, Alembic migrations.
- **Local Language Models:** Ollama daemon (Windows native / localhost:11434), `llama3.1:8b`, `qwen3:4b`, `nomic-embed-text` (768 dimensions).
- **Frontend Workbench:** React 18, TypeScript, Vite, self-hosted Geist and JetBrains Mono fonts (`@fontsource`; the Newsreader package is installed but no longer loaded), Node's built-in test runner with esbuild and jsdom. No Tailwind and no icon library.
- **Package & Environment Management:** `uv` (fast Python package installer & resolver), npm / Node.js 20.
- **Defensive Tooling:** Custom token bucket rate limiter, Loguru structured logging, Pytest, `pip-audit`.
- **Infrastructure & Deployment:** Docker Compose (`aisop-postgres`), PowerShell 7 automation (`aisop.ps1`, `scripts/backup_postgres.ps1`), Nginx TLS reverse proxy template (`deploy/nginx/nginx.conf`), GitHub Actions CI.

---

## 7. Repository Layout

```text
D:\AISOP
├── .github/
│   └── workflows/
│       └── ci.yml                     # Multi-job GitHub Actions CI workflow
├── backend/
│   ├── alembic.ini                    # Alembic migration configuration
│   ├── app/
│   │   ├── api/                       # API routers and endpoints (/api/v1)
│   │   │   └── v1/endpoints/          # alerts, cases, evidence, health, investigations, reports
│   │   ├── core/                      # Settings, auth perimeter, RBAC contracts, logging
│   │   ├── db/                        # Database engine, session managers, Alembic versions
│   │   ├── middleware/                # Rate limit, security headers, correlation IDs
│   │   ├── models/                    # SQLAlchemy ORM models (analyst, case, knowledge, etc.)
│   │   ├── modules/                   # AI context builder, prompt builder, guardrails, threat intel
│   │   ├── schemas/                   # Pydantic v2 request/response schemas
│   │   └── services/                  # Ingestion, case management, investigation synthesis
│   └── tests/
│       ├── conftest.py                # Isolated in-memory SQLite fixtures & fail-closed PostgreSQL guard
│       ├── unit/                      # offline unit tests (3,166 passed, 1 skipped on the last recorded run)
│       └── integration/               # offline integration tests (85 passed) and PostgreSQL-marked tests (34 passed, 1 skipped on a disposable database)
├── frontend/
│   ├── src/
│   │   ├── components/                # AlertsTable, InvestigationWorkspace, ReportViewer, etc.
│   │   ├── types/                     # TypeScript API domain contracts
│   │   └── App.tsx                    # Main application view switcher
│   ├── tests/                         # 33 Vitest/Node component tests
│   ├── package.json                   # React 18, Vite and font dependencies
│   └── vite.config.ts                 # Port 3000, 127.0.0.1 host binding, dev proxy
├── deploy/
│   └── nginx/
│       └── nginx.conf                 # Hardened TLS 1.2/1.3 reverse proxy configuration template
├── scripts/
│   └── backup_postgres.ps1            # Custom-format (pg_dump -Fc) automated database backup script
├── datasets/
│   ├── ground_truth/                  # 20 curated AI evaluation attack scenarios
│   └── samples/alerts/                # Sysmon and vendor-neutral sample alert telemetry
├── docs/                              # Comprehensive engineering documentation
│   ├── 00_Project_Management/         # Compliance matrix, readiness summary, milestones ledger
│   ├── 01_User_Guides/                # Professor demonstration runbook
│   ├── 03_System_Design/              # System architecture, ADRs, Health & Readiness guide
│   ├── 04_Testing/                    # Test cases, benchmark reports, evaluation architecture
│   ├── 07_Security/                   # Security architecture, OWASP assessment, BOLA report
│   ├── 11_Deployment/                 # Deployment guide, DR runbook, TLS reverse proxy guide
│   └── 12_User_Guides/                # Developer automation guide (aisop.ps1)
├── docker-compose.yml                 # PostgreSQL 17 + pgvector container definition
├── pyproject.toml                     # Python dependencies & pytest configuration
└── README.md                          # Authoritative project reality & documentation entry point
```

---

## 8. Prerequisites & Supported Environment

- **Operating System:** Windows 10/11 x64 (PowerShell 7 / `pwsh` recommended).
- **Python Environment:** Python 3.12 (managed via `uv` or `venv` at `.venv`).
- **Node.js Environment:** Node.js 20 LTS and npm (for frontend development and building).
- **Docker Desktop:** Running Docker engine for containerized PostgreSQL (`aisop-postgres`).
- **Ollama AI Daemon:** Windows native Ollama running on `http://localhost:11434`.
- **System Memory:** Minimum 16 GB RAM (32 GB recommended for running local 8B parameter models alongside IDE and database).

---

## 9. Local Development & Quick Start (Step-by-Step)

### Step 1: Clone Repository and Set Up Python Virtual Environment
Open PowerShell 7 in `D:\AISOP`:
```powershell
# Using uv (recommended for deterministic resolution)
uv venv .venv --python 3.12
.\.venv\Scripts\Activate.ps1
uv pip install -e .
```

### Step 2: Configure Environment Variables
Copy the template configuration:
```powershell
Copy-Item .env.example .env
```
Inspect `.env` to verify key defaults:
- `DATABASE_URL=postgresql+psycopg://aisop:aisop@localhost:5433/aisop_dev`
- `OLLAMA_BASE_URL=http://localhost:11434`
- `OLLAMA_MODEL=llama3.1:8b` *(or `qwen3:4b`)*
- `EMBEDDING_MODEL=nomic-embed-text`
- `EMBEDDING_DIMENSIONS=768`
- `RATE_LIMIT_ENABLED=True`
- `SECURITY_HEADERS_ENABLED=True`

> [!IMPORTANT]
> **Host Port Isolation:** Host port `5433` maps to the Docker container's PostgreSQL port `5432`. This prevents port collisions with native Windows PostgreSQL installations listening on default port `5432`.

### Step 3: Launch PostgreSQL with pgvector
Start the containerized database:
```powershell
docker compose up -d postgres
```
Verify container health:
```powershell
docker ps --filter "name=aisop-postgres"
```

### Step 4: Apply Database Migrations
Apply Alembic migrations up to head revision (`0004_p3h2_rbac_case_scoping`):
```powershell
uv run alembic -c backend/alembic.ini upgrade head
```

### Step 5: Start Ollama and Pull Required Models
Ensure the Ollama daemon is running, then pull the 768-dim embedding model and default reasoning LLM:
```powershell
# Mandatory for knowledge retrieval & pgvector 768d schema
ollama pull nomic-embed-text

# Local reasoning model (choose one based on available GPU VRAM)
ollama pull llama3.1:8b
# OR for lighter systems:
ollama pull qwen3:4b
```
Verify installed models:
```powershell
curl.exe -s http://localhost:11434/api/tags
```

### Step 6: Build & Launch Frontend Workbench
In a separate terminal, install dependencies and launch the Vite development server:
```powershell
cd frontend
npm install
npm run dev
```
The frontend is accessible at [http://localhost:3000](http://localhost:3000).

### Step 7: Launch Backend FastAPI Server
On Windows, async `psycopg` requires `WindowsSelectorEventLoopPolicy` to prevent ProactorEventLoop errors:
```powershell
.\.venv\Scripts\python.exe -c "import asyncio, sys, uvicorn; sys.platform == 'win32' and asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy()); uvicorn.run('app.main:app', app_dir='backend', port=8000, loop='none')"
```
Interactive API documentation:
- **Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc:** [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Deep Readiness Endpoint:** [http://localhost:8000/api/v1/health/ready](http://localhost:8000/api/v1/health/ready)

---

## 10. Testing Instructions & Test Baseline

AISOP enforces a multi-tier testing strategy. All unit tests execute 100% offline using in-memory SQLite and mock transports without requiring Docker or Ollama.

### 1. Backend Unit Test Suite (3,166 passed, 1 skipped)
```powershell
uv run pytest backend/tests/unit -q
# Result (2026-11-21 run, logged): 3166 passed, 1 skipped, 0 failed in about 4 minutes
```

### 2. Backend Offline Integration Suite (85 Passing Tests)
```powershell
uv run pytest backend/tests/integration -m "not postgres and not ollama" -q
# Result (logged): 85 passed, 39 deselected in about 10 s
```

### 3. Deep Database & pgvector Readiness Suite (17 Passing Tests)
```powershell
uv run pytest backend/tests/integration/test_health_api.py -v
# Result: 17 passed in ~1s (covers healthy, missing extension, missing schema, dimension mismatch, and secret sanitization)
```

### 4. Database Backup Utility Unit Tests (12 Passing Tests)
```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tests/test_backup_postgres.ps1
# Result: 12 passed, 0 failed (deterministic mock execution; zero database modification)
```

### 5. Frontend Test Suite (201 Passing Tests)
```powershell
cd frontend
npm test
# Result (2026-11-21 run, logged): 201 passed, 0 failed; npm run typecheck and npm run build also pass
```

### Test Scope & Invariant Summary:
- **Recorded results (not a single summed total):** backend unit 3,166 passed (1 skipped); offline integration 85 passed; PostgreSQL 34 passed (1 skipped by design: the Alembic downgrade test); frontend 201 passed. Logs are kept under `D:\AISOP-Backups\AISOP_Dev_Logs_20261120\` (outside the repository). The PostgreSQL run needs the launcher `scripts/pg_verify.ps1`, which uses a disposable database only.
- **Fail-Closed PostgreSQL Guard:** Tests targeting real PostgreSQL require an explicit disposable database URL (`TEST_DATABASE_URL=..._disposable`) and opt-in flag (`ALLOW_DESTRUCTIVE_POSTGRES_TESTS=1`). Protected databases (`aisop_dev`, `aisop_prod`, `postgres`) are rejected fail-closed to prevent accidental data loss.

---

## 11. Security & Operational Limitations

1. **Push-Based Telemetry Ingestion:** AISOP accepts security logs via HTTP REST (`POST /api/v1/evidence/ingest`). It does not contain active pull connectors to poll cloud SIEM APIs (Splunk, Sentinel).
2. **Point-in-Time Recovery (PITR) Not Supported:** Database backups are custom archive snapshots (`pg_dump -Fc`). PITR to a specific second requires continuous Write-Ahead Log (WAL) archiving (e.g. pgBackRest), which is deferred.
3. **Ground-Truth Evaluation Live Capture Gated:** The AI evaluation framework is fully implemented and tested (53 tests pass offline), but live model capture execution against Ollama is gated awaiting project owner authorization (REQ-8.5).
4. **Reverse Proxy: lab version only.** The hardened production template `deploy/nginx/nginx.conf` is still inactive (it needs certificates issued by an operator). A separate LOCAL lab proxy is available: `scriptsproxy_up.ps1` starts the official nginx image on `https://127.0.0.1:8443` with a self-signed certificate kept outside the repository, security headers as real response headers, `/docs` and the OpenAPI file blocked, and a read-only container with dropped capabilities. The 18 live security probes and a browser walk (including the AI step) pass through it. It uses a self-signed certificate, sends no HSTS (deliberately: HSTS is per host and would lock `localhost`), and is not a production deployment. A free public domain was not used: it needs outside registration and a tunnel would route traffic through a third party.
5. **Shallow vs. Deep Pagination:** Investigation queries use index-backed offset pagination ($O(K)$ shallow scan). High-depth pagination ($M > 1000$) incurs $O(K+M)$ traversal costs; keyset/cursor pagination is deferred.
6. **Synthetic Data Only:** every sample and scenario is author-built. No real vendor export has been run through any adapter, and no accuracy or detection-rate figure exists.
7. **Review Record, No Export Gate:** the case lead can approve or reject a stored multi-source investigation (`POST /api/v1/cases/{id}/investigations/multisource/review`). The record is append-only, bound to the evidence fingerprint the lead saw, and becomes stale if the evidence changes. It is tested offline and live on PostgreSQL (10 of 10 API-level checks). The multi-source report can be released only through `GET /api/v1/cases/{id}/investigations/multisource/export`, which refuses (409) unless the lead approved the current result and the evidence is unchanged, and audits each release. The case-synthesis report path (`ReportViewer` downloads) has **no** review gate.
8. **Development Dependency Advisories:** `npm audit` reports two findings in the Vite and esbuild development server (1 high, 1 moderate). The production build is static files and is not affected; the upgrade is deferred. `pip-audit` found no known vulnerabilities in the pinned list.
9. **Optional AI Is Slow and Limited on a Laptop:** with a small local model the AI explanation took about 8 seconds warm and 12 to 13 seconds cold on the demo case, and one of its two incidents fell back to the deterministic output. It is optional, on demand, has a timeout, and never changes the deterministic result.
10. **Single Process:** the rate limiter and per-case locks are in process memory, so run one worker.

---

## 12. Roadmap & Deferred Features

- **Live Ollama AI Evaluation Capture:** Execute `capture_live_fixtures.py` across 19 attack scenarios to establish live F1 model benchmarks (REQ-8.5).
- **Operational Database Restore Drill:** Execute a physical disaster recovery drill against a disposable database on the live container (REQ-3.7).
- **Keyset / Cursor Pagination:** Implement cursor-based pagination on `normalized_events` to optimize high-depth timeline traversal (REQ-15.3).
- **Asynchronous Task Queue:** Introduce Celery / RQ worker queues for multi-gigabyte asynchronous telemetry processing batches (REQ-15.4).
- **Prometheus Telemetry Exporter:** Provide `/metrics` endpoint with Prometheus metrics for container orchestration observability (REQ-14.5).
- **Enterprise SSO / SAML / OIDC:** Identity federation for large enterprise deployments (Layer 4 deferred).

---

## 13. Documentation Index

| Topic | Document Reference | Purpose |
| :--- | :--- | :--- |
| **Academic Demonstration** | [`docs/01_User_Guides/Professor_Demonstration_Runbook.md`](docs/01_User_Guides/Professor_Demonstration_Runbook.md) | 8-step reproducible offline evaluation runbook for professors and reviewers. |
| **System Architecture** | [`docs/03_System_Design/Architecture.md`](docs/03_System_Design/Architecture.md) | Detailed subsystem design, entity models, and API specifications. |
| **Health & Readiness** | [`docs/03_System_Design/Health_and_Readiness_Architecture.md`](docs/03_System_Design/Health_and_Readiness_Architecture.md) | Liveness vs. Readiness semantics, pgvector catalog inspection, and operator runbook. |
| **Deployment & Backup** | [`docs/11_Deployment/Deployment_Guide.md`](docs/11_Deployment/Deployment_Guide.md) | Operational backup procedures, SHA-256 verification, and 3-tier recovery checklist. |
| **TLS Reverse Proxy** | [`docs/11_Deployment/TLS_Reverse_Proxy_Guide.md`](docs/11_Deployment/TLS_Reverse_Proxy_Guide.md) | Nginx ingress architecture, trust boundaries, header deduplication, and private PKI. |
| **Security Architecture** | [`docs/07_Security/Security_Architecture.md`](docs/07_Security/Security_Architecture.md) | Defense-in-depth security perimeter, threat model, and token hashing invariants. |
| **OWASP Threat Model** | [`docs/07_Security/OWASP.md`](docs/07_Security/OWASP.md) | OWASP Top 10:2025 and API Security:2023 mitigation mapping. |
| **Developer Automation** | [`docs/12_User_Guides/Developer_Guide.md`](docs/12_User_Guides/Developer_Guide.md) | Local automation script (`aisop.ps1`) user guide for health audits and testing. |
| **Milestones Ledger** | [`docs/00_Project_Management/Milestones.md`](docs/00_Project_Management/Milestones.md) | Complete historical ledger across all phases and hardening milestones. |
| **15-Layer Compliance** | [`docs/00_Project_Management/AISOP_15_Layer_Engineering_Compliance_Matrix.md`](docs/00_Project_Management/AISOP_15_Layer_Engineering_Compliance_Matrix.md) | Authoritative 86-requirement engineering audit and compliance register. |
| **Engineering Summary** | [`docs/00_Project_Management/AISOP_Engineering_Readiness_Summary.md`](docs/00_Project_Management/AISOP_Engineering_Readiness_Summary.md) | Executive readiness summary, risk assessment, and roadmap prioritization. |

---

## 14. License & Academic Disclosure

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

Developed as a defensive security research and engineering project focusing on local-first AI decision support, forensic provenance, and cost-bounded operations.
