# AISOP Security Architecture Specification

| Field | Value |
|---|---|
| **Document ID** | SEC-ARCH-001 |
| **Status** | APPROVED BASELINE |
| **Last Updated** | 2026-10-16 |
| **Governing ADRs** | [ADR-001](../03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md), [ADR-002](../03_System_Design/ADR/ADR-002_Vector_Database.md), [ADR-003](../03_System_Design/ADR/ADR-003_Python_Version.md), [ADR-004](../03_System_Design/ADR/ADR-004_Initial_Ingestion_Scope.md), [ADR-005](../03_System_Design/ADR/ADR-005_Frontend_Stack.md), [ADR-006](../03_System_Design/ADR/ADR-006_SDLC_and_DevSecOps_Strategy.md) |
| **Related Documents** | [ARCH-001](../03_System_Design/Architecture.md), [OWASP Assessment Matrix](OWASP.md) |

---

## 1. System Security Philosophy & High-Assurance Invariants

AISOP (AI-Assisted Security Operations Platform) operates as an analytical copilot for Security Operations Center (SOC) incident responders and threat hunters. Because the platform ingests potentially hostile telemetry, stores cryptographic evidence, and generates actionable investigative guidance, it is governed by four non-negotiable architectural security principles:

1. **Local-First Air-Gapped Operation:** The platform runs entirely on local analyst workstations or isolated staging networks. Telemetry, investigation notes, and raw evidence are never transmitted to external commercial AI APIs (OpenAI, Anthropic, Google Cloud) by default.
2. **Determinism over AI Heuristics:** Ingestion parsing, canonical normalization, entity extraction, deduplication, and database retrieval operate strictly via deterministic code. Non-deterministic AI/LLM models are strictly excluded from the ingestion and persistence critical path.
3. **Strictly Advisory & Non-Destructive Design:** In accordance with the AISOP Charter and [ADR-001](../03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md), AISOP is an advisory system, **not an autonomous SOAR platform**. The application contains zero tools or endpoints capable of executing host containment, killing processes, blocking IP addresses on firewalls, or modifying system configurations. All remediation recommendations require human-analyst review and manual authorization.
4. **Untrusted Data Isolation:** All endpoint telemetry, raw logs, and ingested markdown documents are treated as untrusted, potentially adversarial evidence. They are sanitized, validated against bounded schemas, and isolated behind strict memory ceilings.

---

## 2. Trust Boundaries & Data Flow Architecture

The AISOP security perimeter is partitioned into four explicit trust boundaries:

```mermaid
flowchart TD
    subgraph TB1 ["Trust Boundary 1: External Telemetry & Ingress (Untrusted)"]
        A["External Endpoints / Log Forwarders\n(Sysmon JSON Telemetry)"]
        B["Knowledge Base Documents\n(MITRE ATT&CK Markdown)"]
    end

    subgraph TB2 ["Trust Boundary 2: Ingress Boundary & Bounds Hardening"]
        C["Pydantic Validation Layer\n(MAX_BATCH=2000, MAX_PAYLOAD=64KB)"]
        D["Path Traversal Defense &\nDocument Loader"]
    end

    subgraph TB3 ["Trust Boundary 3: Deterministic Core & Persistence"]
        E["Canonical Hasher (SHA-256)\n& Option A Deduplication"]
        F["Sysmon Normalizer & Entity Extractor\n(12 Event IDs, Role Isolation)"]
        G["SQLAlchemy 2.0 Async Session\n(Parameterized AST, Savepoint Isolation)"]
        H["PostgreSQL 17 + pgvector Container\n(Port 5433, Isolated Test DB)"]
    end

    subgraph TB4 ["Trust Boundary 4: AI Reasoning & Vector Retrieval (Advisory)"]
        I["KnowledgeRetriever\n(SQL Cosine <=> with Threshold Boundary)"]
        J["OllamaEmbedder\n(768-dim Hard Assertion, nomic-embed-text)"]
        K["OllamaProvider\n(Direct HTTP, JSON Schema Enforcement)"]
        L["Human SOC Analyst Dashboard\n(Human-in-the-Loop Decision Gate)"]
    end

    A -->|HTTP POST /ingest| C
    B -->|Local Disk Read| D
    C -->|Validated IngestRequest| E
    D -->|Validated SourceSections| J
    E -->|Batched IN (...) Lookup| G
    E -->|New Evidence Only| F
    F -->|Normalized Events & Entities| G
    G -->|Native UUID, JSONB, Vector| H
    H -->|HNSW Cosine Search| I
    I -->|Reference Context| K
    J -->|768-dim Vectors| G
    K -->|Advisory Hypothesis (Citations Required)| L
```

### Boundary Definitions
* **Trust Boundary 1 (Untrusted External Inputs):** Comprises external network log forwarders, Sysmon agents, and unverified documentation files. Payloads may contain malformed JSON, recursive objects, buffer overflow attempts, SQL injection, or indirect prompt injection strings.
* **Trust Boundary 2 (Perimeter Validation):** Evaluates all incoming payloads against strict Pydantic v2 schemas. Requests violating size, length, or format bounds are terminated immediately with `HTTP 422 Unprocessable Entity` before database transactions are acquired.
* **Trust Boundary 3 (Deterministic Core & Persistence):** Operates on validated internal data transfer objects. Manages database transactions using nested savepoints (`session.begin_nested()`), ensuring that processing failures in child entities roll back cleanly without leaving orphaned raw evidence rows.
* **Trust Boundary 4 (AI Reasoning & Advisory Layer):** Wraps untrusted telemetry and reference knowledge into structured prompts. Enforces strict vector dimensions, treats model output as untrusted until validated against Pydantic schemas, and presents findings strictly as advisory hypotheses to the human analyst.

---

## 3. Ingestion & Document Processing Boundaries

### 3.1 Telemetry Ingress Bounds & Budget
The ingestion endpoint (`POST /api/v1/evidence/ingest`) enforces strict perimeter ceilings configured in [config.py](../../backend/app/core/config.py):
* **Maximum Batch Size (`MAX_BATCH_SIZE = 2000`):** Ingestion requests containing more than 2,000 events are rejected fail-fast at the API gateway.
* **Maximum Event Payload Size (`MAX_EVENT_PAYLOAD_BYTES = 65536`):** Any single event payload exceeding 64 KB fails validation, preventing JSON parser resource exhaustion.
* **Aggregate Ingestion Memory Budget:** $\text{MAX\_BATCH\_SIZE} \times \text{MAX\_EVENT\_PAYLOAD\_BYTES} = 2000 \times 64\text{ KB} = 128\text{ MB}$.
* **Source Identifier Boundaries:** `source_type` and `source_identifier` are constrained to bounded string lengths ($1 \le \text{length} \le 128$) with whitespace stripping and regex validation (`^[a-zA-Z0-9_\-\.]+$`).

### 3.2 Cryptographic Deduplication & Integrity
* **Deterministic Hashing:** The `CanonicalHasher` produces a SHA-256 digest over canonical compact JSON (`json.dumps(payload, sort_keys=True, separators=(',', ':'))`). This eliminates duplicate persistence caused by JSON key order variations or non-significant whitespace.
* **Option A Batch Deduplication:** Deduplication evaluates candidate hashes against the database in bounded 1,000-element chunks (`IN (...)`), preventing oversized SQL statements.
* **Concurrent Race Isolation:** Collisions on `raw_evidence.sha256_hash` trigger nested savepoint rollbacks (`begin_nested()`), skipping duplicates without failing the entire batch or leaving the session in an invalid state.

### 3.3 Knowledge Base Loading & Document Chunking Boundaries
* **Path Traversal Defense:** `KnowledgeSourceLoader` strictly resolves file paths relative to `knowledge_base/`. Any attempt to traverse directories using `..` or access unauthorized system files raises an immediate `ValueError`.
* **Format Whitelisting:** Only files with the `.md` extension are accepted; executable scripts or binary files are rejected.
* **Deterministic Sliding Window:** `DocumentChunker` splits documents using a 512-word target size with a 64-word overlap. Each chunk produces a deterministic SHA-256 hash (`content_hash`) over its stripped content.
* **Atomic Document Replacement:** Ingestion executes an atomic lifecycle: existing chunks for a `source_document` are deleted and new chunks persisted within a single transaction, preventing partial indexing or orphaned vector embeddings.

---

## 4. Database & Embedding Integrity

### 4.1 PostgreSQL 17 & pgvector Isolation
* **Port Isolation:** Containerized PostgreSQL 17 runs on host port `5433` (`pgvector/pgvector:pg17`), isolating it from any native Windows PostgreSQL services running on port `5432`.
* **Zero SQLite Dialect Fallback:** Integration tests validate `dialect == "postgresql"`. Running PostgreSQL-specific tests against SQLite raises an immediate assertion to prevent silent datatype drift.
* **Versioned Schema Migrations:** All DDL statements are version-controlled via Alembic revisions (`0001_initial_evidence_schema`, `0002_add_pgvector_and_knowledge_schema`). The application startup routine (`lifespan`) performs zero automatic schema alterations.

### 4.2 Vector Dimension & Embedding Space Integrity
* **Strict 768-Dimension Assertion:** In accordance with [ADR-002](../03_System_Design/ADR/ADR-002_Vector_Database.md), the `OllamaEmbedder` asserts `len(embedding) == 768` before returning any vector. If an unexpected dimension is returned, it raises `EmbeddingDimensionError` immediately, preventing corruption of pgvector's HNSW index.
* **SQL-Level Threshold Boundaries:** `KnowledgeRetriever` constructs SQL queries with explicit threshold bounding (`WHERE distance <= 1.0 - min_similarity`). This guarantees that distance filtering occurs inside the PostgreSQL query planner, preventing irrelevant documents from truncating legitimate top-$K$ candidates.

---

## 5. LLM / RAG Prompt Injection & Output-Handling Risks

### 5.1 Prompt Injection Reality & Delimiter Limitations
* **Delimiters are Not Security Boundaries:** Encapsulating untrusted telemetry inside XML tags (e.g. `<evidence>...</evidence>`) or Markdown fences serves as a semantic formatting aid, **not a complete prompt-injection barrier**. Modern LLMs can still be confused or instructed to break out of delimiters.
* **Multi-Layered Injection Defense:**
  1. *Role Separation:* System instructions explicitly instruct the model to treat all evidence content strictly as passive reference data.
  2. *Refusal of Meta-Instructions:* Prompts instruct the model that instructions embedded within logs or retrieved chunks must never supersede core investigation guidelines.
  3. *Adversarial Regression Testing:* Prompt injection test cases using synthetic attacker-crafted Sysmon logs are executed to empirically verify that model output does not execute malicious instructions.

### 5.2 Untrusted Output Validation & Evidence Grounding
* **Untrusted Model Output:** LLM responses are treated as untrusted data until validated. In Phase 2, responses requiring structured data must be parsed and validated through Pydantic v2 schemas.
* **Mandatory Evidence Citations:** Every generated hypothesis or IOC association must include an explicit citation array containing the exact `event_id` and raw evidence cryptographic hash. Hypotheses lacking traceable citations are rejected or flagged with low confidence.
* **Explicit Uncertainty Modeling:** When telemetry is ambiguous or insufficient, prompts instruct the model to express explicit uncertainty rather than hallucinating definitive attack narratives.

### 5.3 System Prompt Confidentiality
* **No Reliance on Secrecy:** System prompts are treated as potentially discoverable. AISOP system prompts never contain API keys, database credentials, internal network topologies, or private analyst notes.
* **Prompt Extraction Defense:** Models are instructed to decline meta-prompts requesting the disclosure of system instructions, but architectural safety relies on the complete absence of sensitive information within the prompt itself.

---

## 6. Credentials, Logging & Sensitive Data Handling

### 6.1 Configuration & Secret Management
* **Environment Variable Injection:** All sensitive configurations (`DATABASE_URL`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) are managed via Pydantic `BaseSettings` reading from `.env` files.
* **Git Hygiene:** `.env` is permanently registered in `.gitignore`. Committed configuration files contain only safe local development defaults (`.env.example`).

### 6.2 Structured Logging & Automated Redaction
* **Sink Pipeline Redirection:** All standard library loggers (Uvicorn, FastAPI, SQLAlchemy) are intercepted by Loguru to ensure a unified, security-controlled logging pipeline.
* **Recursive Sensitive Key Redaction:** `redact_sensitive_data()` recursively traverses log context dictionaries, replacing values for known sensitive keys (`password`, `token`, `secret`, `api_key`, `authorization`, `cookie`, `private_key`) with `"[REDACTED]"`.
* **String Pattern Masking:** Regular expressions automatically scrub Bearer tokens, Basic authentication strings, and key-value credential patterns from freeform log strings.
* **Payload Truncation:** Full raw telemetry payloads are never logged. Error samples are sanitized and truncated via `_safe_sample()` prior to emission.

---

## 7. Deployment Threat Model & Access Control Roadmap

### 7.1 Deployment Tier Assumptions

```
Security Control Matrix by Deployment Stage
┌──────────────────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ Security Control             │ Local Prototype  │ Isolated Staging │ Multi-User / Prod│
├──────────────────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ Host Binding                 │ 127.0.0.1 (Loop) │ Isolated Docker  │ Network Exposed  │
│ Input Bounds Enforcement     │ Implemented      │ Implemented      │ Implemented      │
│ Option A Deduplication       │ Implemented      │ Implemented      │ Implemented      │
│ Structured Logging Redaction │ Implemented      │ Implemented      │ Implemented      │
│ API Token Authentication     │ Unimplemented    │ Unimplemented    │ Mandatory (Gate) │
│ Role-Based Access Control    │ Unimplemented    │ Unimplemented    │ Mandatory (Gate) │
│ Ingress Rate Limiting        │ Unimplemented    │ Unimplemented    │ Mandatory (Gate) │
│ TLS / HTTPS Termination      │ Not Applicable   │ Optional         │ Mandatory (Gate) │
│ Content Security Policy / CSP│ Not Applicable   │ Planned (P4)     │ Mandatory (Gate) │
└──────────────────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

> [!WARNING]
> **Network Exposure Warning:**  
> In its current state (Phase 1 & Phase 2), AISOP's API endpoints are **unauthenticated**. This architecture is safe **only** when bound to local workstation loopback interfaces (`127.0.0.1`) during development. Exposing the current API to untrusted local area networks or the public internet prior to completing the Phase 3 Authentication and RBAC milestone is strictly prohibited.

### 7.2 Access Control Roadmap (Phase 3 & Phase 4)
* **API Key Ingress Gateway:** Telemetry ingestion routes (`/api/v1/evidence/ingest`) will require cryptographic machine API keys.
* **SOC Analyst Authentication:** Investigation endpoints will authenticate analysts via OAuth2 / JWT tokens.
* **Role-Based Access Control (RBAC):** Analysts will operate under bounded roles (`analyst`, `senior_investigator`, `admin`) restricting case deletion and administrative configuration.
* **Frontend XSS Sanitization (Phase 4):** All markdown rendered in the React investigation dashboard will pass through `DOMPurify` to neutralize script injection from malicious logs or poisoned LLM responses.

### 7.3 Canonical API Token Environment Policy & Credential Classes (P3-H2)
The platform enforces database-backed canonical API tokens adhering to the 92-character schema `aisop_<env>_<16-hex-prefix>_<64-hex-secret>`:

* **Separation of Credential Class and Runtime Environment:**
  * **Credential Class (`<env>` in token):** Represents the operational trust classification embedded in the token (`live` or `test`).
  * **Runtime Environment (`settings.ENVIRONMENT`):** Defines the deployment mode (`development`, `staging`, `production`).
* **Environment Policy Enforcement:**
  * **`test` Tokens (`aisop_test_...`):** Permitted **only** in local development (`ENVIRONMENT="development"`). Strictly rejected with `HTTP 401 Unauthorized` in `staging` and `production` to prevent test-fixture or CI credentials from accessing sensitive environments.
  * **`live` Tokens (`aisop_live_...`):** Permitted across `development`, `staging`, and `production`, subject to database-backed client verification, expiration validation, analyst active status, and constant-time SHA-256 digest comparison against `analyst_api_clients.hashed_secret`.
  * **Database Isolation:** Because each environment connects to an independent database instance (`aisop_dev`, `aisop_test`, or production), `live` tokens minted for development cannot authenticate against staging or production systems.
  * **Legacy Static Keys:** Disabled by default (`API_AUTH_ALLOW_LEGACY_KEYS=False`). When explicitly enabled, legacy keys authenticate machine requests only (`analyst=None`) and fail closed with HTTP 401 if routed to analyst-identity endpoints.

---

## 8. Continuous DevSecOps Gates & Residual Risk Register

### 8.1 Multi-Tier Test Verification Commands
In accordance with [ADR-006](../03_System_Design/ADR/ADR-006_SDLC_and_DevSecOps_Strategy.md), the test suite is partitioned into four distinct verification commands:

```bash
# Tier 1: Fast Offline Unit & Mock Suite (In-memory SQLite, MockTransports, Schema checks)
uv run pytest -m "not postgres and not ollama"

# Tier 2: Live Local Ollama AI Daemon Integration (Localhost:11434, nomic-embed-text)
uv run pytest -m ollama

# Tier 3: Live PostgreSQL 17 + pgvector Container Integration (Port 5433, aisop_test DB)
uv run pytest -m postgres

# Tier 4: Comprehensive Release Regression Suite (All services active)
uv run pytest
```

### 8.2 Dependency Auditing Gate
```bash
# Automated Supply Chain Vulnerability Scan
uv run pip-audit
```
* **Release Gate Requirement:** Zero High or Critical CVEs in the active dependency tree.

### 8.3 Residual Risk Register

| Risk ID | Description | Current Status | Planned Mitigation Milestone |
|---|---|:---:|---|
| **RES-001** | Unauthenticated API Ingress allows arbitrary localhost clients to ingest events. | Mitigated (P3-H1) | Phase 3 Milestone P3-H1: API key and Bearer token authentication perimeter implemented. |
| **RES-002** | Absence of RBAC allows any connected client to view all investigation events. | Active in Prototype | Phase 3: Implement role-based scoping in SQLAlchemy query service. |
| **RES-003** | Lack of rate-limiting leaves ingestion open to local process connection flooding. | Active in Prototype | Phase 3: Implement `slowapi` token-bucket rate limiter. |
| **RES-004** | Indirect prompt injection via hostile log content could influence AI hypotheses. | Partially Mitigated | Phase 2 Milestone 5: Implement adversarial testing and schema validation. |
| **RES-005** | Markdown XSS injection if AI responses are rendered raw in browser. | Unimplemented | Phase 4: Enforce DOMPurify in React frontend dashboard. |

## Stage 5 security assessment of the multi-source investigation (2026-11-12)
Threat model, attack surface, trust boundaries (including the trust assumption behind each evidence relationship), threat scenarios, fixed defects D1-D9/U1, ledger guarantees, the credential/deployment workstream (owner actions only; nothing changed) and remaining risks: `docs/07_Security/Stage5_Security_Assessment.md`. LLM-specific controls and the real-model test plan: `docs/06_AI/Stage5_LLM_Security_Report.md`.
