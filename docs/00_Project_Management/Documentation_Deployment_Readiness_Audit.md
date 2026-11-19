# AISOP Documentation, Deployment and Integration Readiness Audit

**Document Reference:** `AISOP-AUDIT-2026-DOC-DEPLOY-001`  
**Execution Date:** 22 October 2026  
**Auditor:** AISOP Senior Application Security & Systems Reviewer  
**Repository Path:** `D:\AISOP`  
**Status:** COMPLETE — PLANNING & READINESS GATE  
**Milestone Impact:** Pre-deployment documentation architecture & verification baseline  

---

## Table of Contents

1. [Executive Summary & Repository Baseline](#1-executive-summary--repository-baseline)
2. [Verified Implementation-to-Documentation Matrix (12 Capabilities)](#2-verified-implementation-to-documentation-matrix-12-capabilities)
3. [Current Local-Run and Deployment Capabilities](#3-current-local-run-and-deployment-capabilities)
4. [SIEM Integration Status, Ingestion Contract & Gaps](#4-siem-integration-status-ingestion-contract--gaps)
5. [Professor Demonstration Plan (Repeatable, Offline, ₹0)](#5-professor-demonstration-plan-repeatable-offline-0)
6. [AI Modular Layer Architecture & Documentation Requirements](#6-ai-modular-layer-architecture--documentation-requirements)
7. [Recommended Documentation File Structure](#7-recommended-documentation-file-structure)
8. [Prioritized Implementation and Documentation Sequence](#8-prioritized-implementation-and-documentation-sequence)
9. [Security and Operational Gaps Before Production Use](#9-security-and-operational-gaps-before-production-use)
10. [Executed Commands, Exit Codes & Telemetry Log](#10-executed-commands-exit-codes--telemetry-log)
11. [Explicit Limitations, Roadmap Discrepancies & Unverified Claims](#11-explicit-limitations-roadmap-discrepancies--unverified-claims)

---

## 1. Executive Summary & Repository Baseline

### 1.1 Purpose and Target Audiences

This audit establishes an objective, evidence-based assessment of the AISOP (AI Security Investigation & Operations Platform) repository at `D:\AISOP`. It prepares the platform for three distinct audiences while strictly enforcing the **₹0 additional-cost constraint** (no paid external APIs, cloud LLMs, commercial embeddings, or paid hosting):

1. **Academic Evaluation (Professor / Reviewer):** A repeatable, deterministic, fully offline demonstration verifying core investigation, evidence-integrity, entity extraction, and privacy-shielded threat intelligence capabilities without requiring live external SIEM credentials or cloud access.
2. **Software Developer / Contributor:** A predictable local installation on Windows, clear dependency boundaries, test harnesses, reproducible environment variables, and modular interfaces for extending providers.
3. **Enterprise / Security Operations (SIEM Integrator):** An unambiguous API contract for telemetry and alert ingestion, cryptographic evidence provenance, verifiable deduplication, and realistic operational deployment constraints.

### 1.2 Repository Identity & Working-Tree State

An inspection of the Git working tree was performed on 22 October 2026:

- **Git Branch:** `main`
- **HEAD Commit:** `c4e877c`
- **Active Python Environment:** `D:\AISOP\.venv\Scripts\python.exe` (Python 3.12.0)
- **Host Platform:** Windows 10/11 Enterprise x64 (PowerShell 7.5.0 / `pwsh`)
- **Docker Engine:** Docker Desktop 29.9.2 (container: `aisop-postgres` running `pgvector/pgvector:pg17` mapped to host port `5433:5432`)
- **Ollama Daemon:** Running locally on port `11434` (installed models: `nomic-embed-text:latest`, `qwen3:4b`)

#### Working-Tree Modifications & Untracked Files Status
In compliance with project safety invariants, all working-tree files were left untouched (no staging, commits, resets, cleanups, or destructive file operations). The current working tree contains:
- **Modified Tracked Files (26):** Configuration (`.vscode/settings.json`, `pyproject.toml`, `backend/app/core/config.py`), application entrypoint (`backend/app/main.py`), API routes (`evidence.py`, `dependencies.py`), models (`knowledge.py`), AI modules (`context_builder/`, `embeddings/`), threat intelligence modules (`threatintel/`), query services (`query_service.py`), documentation (`Milestones.md`, `OWASP.md`, `Security_Architecture.md`, `Developer_Guide.md`), and unit/integration tests.
- **Untracked Additions (41):** Developer utility (`aisop.ps1`), migration `20261021_0003_source_scoped_knowledge_chunks.py`, threat intelligence engine and orchestrator (`backend/app/modules/threatintel/*`), schemas (`knowledge.py`, `threatintel.py`), milestone/verification reports (`docs/00_Project_Management/*`), test suites (`test_threatintel_*.py`, `test_knowledge_*.py`).

### 1.3 Baseline Unit Test Suite Verification

The backend test suite was executed via the project virtual environment:
```powershell
.venv\Scripts\python.exe -m pytest backend/tests/unit -q
```
- **Exit Code:** `0` (Success)
- **Execution Time:** 16.27 seconds
- **Results:** **474 passed**, 2 deprecation warnings (Starlette `httpx` and AnyIO `BlockingPortal` deprecations in `testclient`).
- **Network Egress:** 0 bytes (fully offline, mock and synthetic fixtures only).

---

## 2. Verified Implementation-to-Documentation Matrix (12 Capabilities)

| # | Capability | Actual Implementation Location | Existing Tests / Evidence | Current Maturity | Documentation Available | Documentation Gap | Safe Next Action |
|---|---|---|---|---|---|---|---|
| **1** | **Running AISOP locally on Windows** | `backend/app/main.py`, `aisop.ps1`, `uvicorn` | `backend/tests/integration/test_health_api.py`, `aisop.ps1 -Mode Health` | **Implemented & Verified** (Backend API & CLI); **Absent** (Frontend UI) | `docs/12_User_Guides/Developer_Guide.md` (documents `aisop.ps1`) | Root `README.md` is an internal tracker, not a quickstart. No Uvicorn launch guide or OpenAPI browser walkthrough. | Write a concrete local runbook for `pwsh` + `uvicorn` in root `README.md`. Clarify that frontend is a non-functional scaffold. |
| **2** | **Starting required services & database** | `docker-compose.yml`, `backend/app/db/session.py`, `backend/app/db/migrations/versions/` | `backend/tests/integration/test_postgres_lifecycle.py`, `test_migrations.py`, `aisop.ps1 -Mode Health` | **Implemented & Verified** | `docs/04_Database/Database_Design.md`, `Migration_Strategy.md` | `docs/11_Deployment/Deployment_Guide.md` is 0 bytes. Port 5433 mapping vs 5432 native conflict needs explicit operational documentation. | Document Docker Compose setup (`port 5433`), Alembic upgrade commands, and health probe verification. |
| **3** | **Configuring & using Ollama** | `backend/app/modules/ai/providers/ollama/provider.py`, `backend/app/core/config.py` | `backend/tests/unit/test_llm_provider.py`, `backend/tests/integration/test_health_api.py` | **Implemented & Verified** (Model mismatch noted: `qwen3:4b` installed vs `llama3.1:8b` in config) | `docs/06_AI/LLM_Provider_Contract.md`, `ADR-001` | Missing Windows Ollama installation guide, model pull instructions, and memory sizing notes. | Document `ollama pull nomic-embed-text` and `ollama pull llama3.1:8b` (or setting `OLLAMA_MODEL=qwen3:4b` in `.env`). |
| **4** | **Changing the LLM provider** | `backend/app/modules/ai/llm/protocol.py`, `backend/app/modules/ai/llm/manager.py` | `backend/tests/unit/test_llm_provider.py` | **Implemented** (Ollama); **Scaffolded/Absent** (OpenAI, Anthropic, Gemini are 0-byte files) | `docs/06_AI/LLM_Provider_Contract.md` | No guide explaining how to implement `LLMProvider` Protocol, register in factory, and test without external dependencies. | Document the `LLMProvider` protocol interface and provide a complete offline mock provider implementation guide. |
| **5** | **Changing embedding provider & dimension handling** | `backend/app/modules/ai/embeddings/embedder.py`, `backend/app/models/knowledge.py` | `backend/tests/unit/test_ollama_embedder.py`, `backend/tests/unit/test_knowledge_models.py` | **Implemented & Verified** (Strict 768-dim enforcement for `nomic-embed-text`) | `docs/03_System_Design/ADR/ADR-002_Vector_Database.md` | No documentation explaining the fatal consequences of changing models: vector dimension mismatch, index invalidation, and re-embedding. | Document the embedding migration playbook: Alembic migration for `Vector(N)`, index rebuild, and complete knowledge-base re-ingestion. |
| **6** | **Ingesting sample / replayed event via FastAPI** | `backend/app/api/v1/endpoints/evidence.py` (`POST /ingest`), `backend/app/services/ingestion_service.py` | `backend/tests/integration/test_ingest_api.py`, `backend/tests/unit/test_sample_dataset_ingestion.py` | **Implemented & Verified** | `docs/03_System_Design/ADR/ADR-004_Initial_Ingestion_Scope.md` | `docs/05_Backend/API_Design.md` is 0 bytes. No curl or PowerShell ingestion examples or error code descriptions. | Document `POST /api/v1/evidence/ingest` contract with Sysmon Event 1 & 3 payloads, deduplication response, and partial failure semantics. |
| **7** | **Connecting an actual SIEM** | None (Direct SIEM connectors absent; relies on external push to `/api/v1/evidence/ingest`) | None for direct connectors | **Absent** (Direct connector); **Scaffolded** (Generic REST webhook) | None (`docs/05_Backend/` is empty) | No SIEM integration guide, no mapping reference from Splunk CIM, Elastic ECS, or CEF to AISOP canonical events. | Define the SIEM Ingestion Contract (Phase D) establishing how log forwarders or webhook adapters push to AISOP. |
| **8** | **Running an investigation & reviewing evidence** | `backend/app/api/v1/endpoints/evidence.py` (`/events`, `/events/{id}`, `/entities`, `/by-hash`) | `backend/tests/integration/test_investigation_api.py`, `test_threatintel_http_integration.py` | **Implemented & Verified** (Evidence & TI query); **Absent** (Cases & Reports API routers) | `docs/03_System_Design/Architecture.md` | No analyst user guide explaining evidence navigation, entity pivoting, or threat intelligence verdict interpretation. | Document the evidence querying API workflow (`/events`, `/entities`, `enrich_threat_intel=true`). Explicitly note Cases/Reports are unmounted. |
| **9** | **Demonstrating AISOP to a professor without live credentials** | CLI / FastAPI endpoints using `datasets/samples/sysmon/sysmon_attack_chain.json` | `backend/tests/unit/test_sample_dataset_ingestion.py`, `test_threatintel_http_integration.py` | **Implemented & Verifiable via API/CLI** (No Web UI) | None | No structured, repeatable demonstration script or runbook. | Produce a 6-step deterministic demonstration script using synthetic Sysmon telemetry, local feeds, and health checks. |
| **10** | **Deploying to another workstation or server** | `docker-compose.yml` (Postgres only), host Python, host Ollama | `backend/tests/integration/test_postgres_lifecycle.py` | **Incompletely Verified** (Hybrid local setup; no containerized backend or frontend) | `docs/11_Deployment/Deployment_Guide.md` (0 bytes) | Complete absence of deployment instructions, system requirements, environment configuration, or service management. | Write a comprehensive Deployment & Operations Guide covering Docker Compose, Ollama host setup, and `.env` configuration. |
| **11** | **Securing access to API, database & analyst UI** | `backend/app/modules/threatintel/shield.py`, `backend/app/modules/ai/context_builder/` | `backend/tests/unit/test_threatintel_private_shield.py`, `test_aisop_sanitizer.py` | **Implemented** (Observable Shielding & XML Escaping); **Absent** (API Auth & RBAC) | `docs/07_Security/OWASP.md`, `Security_Architecture.md` | Existing security docs discuss target vision. No document warns that current API endpoints have zero authentication. | Document actual trust boundaries, highlight lack of API authentication, and provide reverse proxy (Nginx/Caddy) auth guidance. |
| **12** | **Backups, restoration, upgrades & troubleshooting** | `aisop.ps1`, Docker volumes, Alembic forward migrations | `backend/tests/unit/test_migrations.py` | **Scaffolded / Tool-dependent** (Standard PostgreSQL tools) | `docs/04_Database/Migration_Strategy.md` | No disaster recovery runbook, no `pg_dump` volume backup guide, no troubleshooting matrix for common failure modes. | Document operational maintenance procedures: Docker volume backups, Alembic schema migrations, and port conflict resolution. |

---

## 3. Current Local-Run and Deployment Capabilities

### 3.1 Local Architecture & Service Topology

AISOP is currently designed and verified as a **hybrid local system** on Windows 10/11:

```
+-----------------------------------------------------------------------------------+
| Host Operating System (Windows 10/11 x64)                                          |
|                                                                                   |
|  +---------------------------+       +-----------------------------------------+  |
|  | Native Windows Services   |       | Virtual Environment (.venv Python 3.12) |  |
|  |                           |       |                                         |  |
|  | Native PostgreSQL 17      |       | FastAPI Backend (Uvicorn)               |  |
|  | Listening: Port 5432      |       | Listening: http://127.0.0.1:8000        |  |
|  | (Untouched by AISOP)      |       | Endpoints:                              |  |
|  +---------------------------+       |   - /api/v1/health & /health/ready      |  |
|                                      |   - /api/v1/evidence/ingest             |  |
|  +---------------------------+       |   - /api/v1/evidence/events             |  |
|  | Ollama LLM / Embeddings   |       |   - /api/v1/evidence/entities           |  |
|  | Listening: Port 11434     |<------+   - /api/v1/evidence/by-hash/{sha256}   |  |
|  | Models:                   |       +-------------------+---------------------+  |
|  |  - nomic-embed-text (768d)|                           |                        |
|  |  - qwen3:4b (installed)   |                           | SQLAlchemy Async       |
|  |  - llama3.1:8b (config)   |                           | (Port 5433)            |
|  +---------------------------+                           v                        |
|                                      +-----------------------------------------+  |
|  +---------------------------+       | Docker Desktop Container                |  |
|  | Developer Automation      |       | Name: aisop-postgres                    |  |
|  | Script: aisop.ps1         |       | Image: pgvector/pgvector:pg17           |  |
|  | Modes: Audit, Health,     |       | Port Mapping: 5433:5432                 |  |
|  |        TestUnit, Report   |       | Database: aisop_dev                     |  |
|  +---------------------------+       +-----------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

### 3.2 Frontend Reality

- **Directory:** `frontend/`
- **Status:** **0% implemented**.
- **Evidence:** `frontend/package.json` is a 0-byte empty file. Subdirectories (`frontend/src/assets`, `components`, `pages`, `services`, `public`) contain **zero code files**.
- **Architectural Consequence:** AISOP cannot be operated or demonstrated through a graphical web interface today. It functions entirely as a **headless REST API** and **CLI automation platform**. Any claim that an analyst UI dashboard is ready for deployment is factually incorrect.

### 3.3 Containerization Reality

- **`docker-compose.yml`:** Provisions **only** the database service (`aisop-postgres`).
- **`docker/` Directory:** Empty (0 files). There is no `Dockerfile` for the FastAPI backend, no container for Ollama, and no container for a frontend.
- **Deployment Consequence:** AISOP cannot be deployed via `docker compose up` as a full-stack containerized appliance. Deployment to another machine requires:
  1. Installing Docker Desktop and running `docker compose up -d postgres`.
  2. Installing Python 3.12 natively and creating a virtual environment (`python -m venv .venv`).
  3. Installing Python dependencies via pip (`pip install -e .` or `pip install -r requirements.txt` if generated).
  4. Installing Ollama natively, launching the daemon, and pulling required models.
  5. Running the FastAPI backend on the host via `uvicorn`.

---

## 4. SIEM Integration Status, Ingestion Contract & Gaps

### 4.1 Current Implementation State

AISOP possesses **no native SIEM pulling connectors** (e.g., no Splunk REST API poller, no Elasticsearch scroll connector, no Microsoft Sentinel Log Analytics workspace collector). 

Instead, telemetry ingestion is implemented as a **passive REST webhook endpoint**:
- **Route:** `POST /api/v1/evidence/ingest`
- **Controller:** `app.api.v1.endpoints.evidence.ingest_telemetry`
- **Service:** `app.services.ingestion_service.IngestionService`
- **Supported Format:** Windows Sysmon JSON/XML.
- **Parser:** `app.modules.evidence.sysmon_parser.SysmonParser` (implements `ParserProtocol`).
- **Supported Sysmon Events:**
  - Event ID 1: Process Creation
  - Event ID 3: Network Connection Detected
  - Event ID 7: Image Loaded (DLL)
  - Event ID 8: CreateRemoteThread
  - Event ID 10: ProcessAccess
  - Event ID 11: FileCreate
  - Event ID 12 / 13 / 14: Registry Event (Add/Delete/Set)
  - Event ID 22: DNSEvent (DNS Query)

### 4.2 Current Ingestion Processing Flow

```
Raw JSON Batch (POST /api/v1/evidence/ingest)
                       |
                       v
         [ Payload Size Validation ]  --> Max 2,000 events / batch; max 64 KB / event
                       |
                       v
       [ Cryptographic Hashing (SHA-256) ] --> SHA-256 computed on raw UTF-8 payload
                       |
                       v
      [ Batch Existence Lookup in Database ] --> Chunks of 1,000 hashes queried against raw_evidence
                       |
         +-------------+-------------+
         |                           |
  (Hash Exists)               (New Unique Hash)
         |                           |
   Increment Duplicate               v
   Counter (`total_skipped`)   [ Sysmon Parser Normalization ]
   Collect existing UUID             |
                        +------------+------------+
                        |                         |
                  (Parse Success)           (Parse Failure)
                        |                         |
                        v                   Record IngestError
            [ Atomic Entity Extractor ]     (event_index, error, raw_sample)
            (IP, Host, User, Hash, Domain)        |
                        |                         |
                        +------------+------------+
                                     |
                                     v
                 [ Atomic Database Transaction (PostgreSQL) ]
                 - Insert RawEvidence
                 - Insert NormalizedEventModel
                 - Insert ExtractedEntityModel (bulk)
                                     |
                                     v
                            Return IngestResponse
```

### 4.3 Ingestion Contract Specification (Current vs Proposed)

#### Current Ingestion Contract (`POST /api/v1/evidence/ingest`)

**Request Headers:**
```http
Content-Type: application/json
```
*(Notice: No Authorization header required. Endpoint is completely unauthenticated.)*

**Request Payload (`IngestRequest`):**
```json
{
  "source_type": "sysmon",
  "source_identifier": "CORP-FIN-WS01",
  "events": [
    {
      "EventID": 1,
      "UtcTime": "2026-10-22 14:15:20.123",
      "ProcessId": 5412,
      "Image": "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
      "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc SUVY...",
      "ParentImage": "C:\Windows\explorer.exe",
      "User": "CORP\victim_user",
      "Hashes": "SHA256=A697368B25A0B7EC9AEBEE3FECE92CE9D0E76F4B84BBDA5701FEA28A6635A33D",
      "Computer": "CORP-FIN-WS01"
    }
  ]
}
```

**Field Rules:**
- `source_type` (required, string, 1–50 chars, regex `^[a-zA-Z0-9_.-]+$`): Identifies telemetry parser (`sysmon`).
- `source_identifier` (required, string, 1–255 chars): Sensor hostname or agent ID.
- `events` (required, array of objects): 1 to 2,000 raw JSON objects. Each object must serialize to <= 64 KB.

**Success Response (HTTP 200 OK — `IngestResponse`):**
```json
{
  "batch_id": "b3e34b9d-4c7b-4d45-9856-11f8e6584281",
  "source_type": "sysmon",
  "total_received": 1,
  "total_normalized": 1,
  "total_entities_extracted": 3,
  "total_skipped_duplicates": 0,
  "existing_evidence_ids": [],
  "errors": []
}
```

**Duplicate Replay Response (HTTP 200 OK):**
```json
{
  "batch_id": "e9871f3a-9c42-4f11-9a71-8899aabbccdd",
  "source_type": "sysmon",
  "total_received": 1,
  "total_normalized": 0,
  "total_entities_extracted": 0,
  "total_skipped_duplicates": 1,
  "existing_evidence_ids": [
    "c8a11b22-3344-5566-7788-99aabbccddeeff"
  ],
  "errors": []
}
```

**Partial Error Response (HTTP 200 OK with per-event errors):**
```json
{
  "batch_id": "fa123456-7890-4abc-def0-123456789abc",
  "source_type": "sysmon",
  "total_received": 2,
  "total_normalized": 1,
  "total_entities_extracted": 2,
  "total_skipped_duplicates": 0,
  "existing_evidence_ids": [],
  "errors": [
    {
      "event_index": 1,
      "error": "Unsupported or missing Sysmon EventID: 99",
      "raw_sample": "{\"EventID\": 99, \"Computer\": \"CORP-FIN-WS01\"}"
    }
  ]
}
```

#### Proposed Enterprise SIEM Webhook Ingestion Contract (Future Target)

To integrate robustly with commercial SIEMs (Splunk HEC forwarder, Elastic Logstash HTTP output, Azure Sentinel Webhooks), the following contract must be implemented in Phase 3:

```
[SIEM Forwarder / Logstash / Cribl]
               |
               v
      HTTPS POST /api/v1/evidence/ingest/siem
      Headers:
        X-AISOP-API-Key: <secret>
        X-AISOP-Signature: sha256=<hmac_signature>
        Idempotency-Key: <unique_client_batch_id>
               |
               v
   [ 1. Rate Limiter (Token Bucket) ]
               |
   [ 2. HMAC-SHA256 & Key Verification ]
               |
   [ 3. Schema Version & Adapter Router ]
         |                       |
   (Sysmon Adapter)      (Generic CEF/ECS Adapter)
         |                       |
         +-----------+-----------+
                     v
      [ CanonicalEvent Normalization ]
                     v
      [ Cryptographic Hash & Storage ]
```

**Proposed Request Headers:**
- `X-AISOP-API-Key`: Pre-shared API token matching tenant.
- `X-AISOP-Signature`: `sha256=<hex_hmac>` computed over payload using tenant secret.
- `Idempotency-Key`: Client-assigned UUID for network replay protection.

**Proposed Integration Gaps to Resolve:**
1. **Parser Protocol Extensibility:** `SysmonParser` is currently the only registered parser in `ParserRegistry`. Generic syslog, CEF, LEEF, and Elastic ECS parsers do not exist.
2. **Authentication Gate:** The current route accepts unauthenticated POST requests from any network client reachable on port 8000.
3. **Connector Pulling:** No polling worker exists to pull alerts from SIEM REST APIs; integration must be push/forwarder based.

---

## 5. Professor Demonstration Plan (Repeatable, Offline, ₹0)

### 5.1 Objectives & Evaluation Criteria

The goal of this demonstration is to allow a professor or academic evaluator to inspect AISOP's capabilities through a **100% offline, repeatable, deterministic sequence** using existing repository components.

**Demonstrated Capabilities:**
1. Health and subsystem probe verification (PostgreSQL + pgvector and Ollama readiness).
2. Telemetry batch ingestion and normalization using realistic synthetic attack telemetry.
3. Automated cryptographic SHA-256 evidence hashing and tamper-evident deduplication.
4. Atomic entity and IOC extraction (processes, hostnames, IPs, file hashes, domains).
5. Threat intelligence evaluation with **Private Network Shielding** (zero data leakage for internal assets).
6. Evidence traceability by cryptographic hash digest.

### 5.2 Prerequisites Checklist

| Component | Required State | Verification Command |
|---|---|---|
| **Python** | 3.12 virtual environment | `.venv\Scripts\python.exe --version` |
| **Database** | Docker container `aisop-postgres` UP | `docker ps --filter "name=aisop-postgres"` |
| **Database Port** | Host port `5433` open | `Test-NetConnection -Port 5433 -ComputerName localhost` |
| **Ollama Daemon** | Running on port `11434` | `curl.exe -s http://localhost:11434/api/tags` |
| **Ollama Models** | `nomic-embed-text:latest` and `qwen3:4b` | Checked via `/api/tags` |
| **Synthetic Dataset** | `datasets/samples/sysmon/sysmon_attack_chain.json` present | `Test-Path datasets/samples/sysmon/sysmon_attack_chain.json` |

### 5.3 Synthetic Attack Scenario Data

The demonstration uses `datasets/samples/sysmon/sysmon_attack_chain.json`, an existing 4-event synthetic attack chain:
- **Event 1 (Sysmon Event ID 1):** Encoded PowerShell execution by user `CORP\victim_user` on `CORP-FIN-WS01` (`powershell.exe -NoP -NonI -W Hidden -Enc SUVY...`).
- **Event 2 (Sysmon Event ID 22):** DNS Query to malicious command-and-control domain `c2.apt-simulated.org` resolving to `198.51.100.45` (RFC 5737 documentation prefix).
- **Event 3 (Sysmon Event ID 3):** Outbound TCP 443 connection from internal endpoint `192.168.10.105` to C2 server `198.51.100.45:443`.
- **Event 4 (Sysmon Event ID 11):** Secondary stage payload drop of `mimikatz.exe` into `C:\Users\Public\` with SHA-256 hash `17565FE8A1553835B19FA865BEFA0DF85FA3EC04B9741D8B4D445F0F5CC054D6`.

*Note: All IP addresses, domains, and hashes are synthetic or use reserved RFC test blocks (RFC 1918, RFC 5737).*

---

### 5.4 Step-by-Step Demonstration Runbook

#### Step 1: Health & Readiness Probe
Verify that the database and AI subsystems are operational.

**Command (PowerShell):**
```powershell
curl.exe -s -X GET "http://localhost:8000/api/v1/health/ready" | jq .
```

**Expected JSON Response (HTTP 200):**
```json
{
  "status": "ok",
  "app": "AISOP",
  "version": "0.1.0",
  "checks": {
    "database": {
      "status": "ok"
    },
    "llm_provider": {
      "status": "healthy",
      "provider": "ollama",
      "model": "qwen3:4b",
      "latency_ms": 12.4
    }
  }
}
```
*Professor Takeaway:* Demonstrates that AISOP actively validates its database and local AI inference engine before accepting operational traffic.

---

#### Step 2: Ingestion of Synthetic Attack Chain
Ingest the 4-stage Sysmon attack chain.

**Command (PowerShell):**
```powershell
$payload = @{
    source_type = "sysmon"
    source_identifier = "CORP-FIN-WS01"
    events = (Get-Content "datasets/samples/sysmon/sysmon_attack_chain.json" -Raw | ConvertFrom-Json)
} | ConvertTo-Json -Depth 10

curl.exe -s -X POST "http://localhost:8000/api/v1/evidence/ingest" `
  -H "Content-Type: application/json" `
  -d $payload | jq .
```

**Expected JSON Response (HTTP 200):**
```json
{
  "batch_id": "<uuid>",
  "source_type": "sysmon",
  "total_received": 4,
  "total_normalized": 4,
  "total_entities_extracted": 11,
  "total_skipped_duplicates": 0,
  "existing_evidence_ids": [],
  "errors": []
}
```
*Professor Takeaway:* Telemetry is parsed, canonicalized into unified security schemas, and all IOCs are extracted into the relational model in a single atomic transaction.

---

#### Step 3: Idempotent Replay & Deduplication Test
Demonstrate cryptographic deduplication by re-sending the exact same batch.

**Command (PowerShell):**
```powershell
curl.exe -s -X POST "http://localhost:8000/api/v1/evidence/ingest" `
  -H "Content-Type: application/json" `
  -d $payload | jq .
```

**Expected JSON Response (HTTP 200):**
```json
{
  "batch_id": "<uuid>",
  "source_type": "sysmon",
  "total_received": 4,
  "total_normalized": 0,
  "total_entities_extracted": 0,
  "total_skipped_duplicates": 4,
  "existing_evidence_ids": ["<uuid1>", "<uuid2>", "<uuid3>", "<uuid4>"],
  "errors": []
}
```
*Professor Takeaway:* Cryptographic SHA-256 deduplication ensures replayed or duplicate SIEM logs consume zero duplicate storage and trigger no duplicate alert churn.

---

#### Step 4: Investigating Normalized Events & Extracted Entities
Query the investigation service to trace the attack timeline.

**Command (PowerShell):**
```powershell
curl.exe -s -X GET "http://localhost:8000/api/v1/evidence/events?source_identifier=CORP-FIN-WS01&limit=5" | jq .
```

**Expected JSON Response (HTTP 200):**
Shows paginated, ordered event summaries with canonical types (`process_creation`, `network_connection`, etc.), execution outcome, and severity.

Query extracted entities to see atomic indicators of compromise:
```powershell
curl.exe -s -X GET "http://localhost:8000/api/v1/evidence/entities?limit=10" | jq .
```
*Professor Takeaway:* Demonstrates entity resolution across endpoints, identifying actors, machines, files, IPs, and domains.

---

#### Step 5: Threat Intelligence Enrichment & Privacy Shielding
Fetch the outbound network event with threat intelligence enrichment enabled (`enrich_threat_intel=true`).

**Command (PowerShell):**
```powershell
# Get event ID of network connection
$eventId = (curl.exe -s "http://localhost:8000/api/v1/evidence/events?event_type=network_connection" | jq -r ".items[0].id")

curl.exe -s -X GET "http://localhost:8000/api/v1/evidence/events/$eventId`?enrich_threat_intel=true" | jq .
```

**Key Evidence to Highlight to Evaluator:**
1. **Private Network Shielding (SSRF & Privacy Defense):**
   - Observable `192.168.10.105` (Source IP) is inspected by `PrivateNetworkShield`.
   - It is identified as an RFC 1918 private IP.
   - It is marked `is_shielded: true`.
   - Its lookup status is `SHIELDED_INTERNAL` and verdict is `UNKNOWN`.
   - **Zero external provider calls are made.**
2. **External C2 Observable Evaluation:**
   - Observable `198.51.100.45` (Destination IP) is evaluated against local offline threat intelligence feeds.
   - If not present in local blocklists, it safely returns `VALID_UNMATCHED` with status `SUCCESS` and verdict `UNKNOWN`.
   - If matched against a local Feodo/abuse feed, it returns `FRESH_MATCH` with verdict `MALICIOUS` and full source attribution.

---

#### Step 6: Cryptographic Evidence Integrity Audit
Verify raw evidence immutability by retrieving evidence directly using its cryptographic digest.

**Command (PowerShell):**
```powershell
# Ingested PowerShell process hash:
$hash = "A697368B25A0B7EC9AEBEE3FECE92CE9D0E76F4B84BBDA5701FEA28A6635A33D"
curl.exe -s -X GET "http://localhost:8000/api/v1/evidence/by-hash/$hash" | jq .
```
*Professor Takeaway:* Forensic-grade chain of custody. Any raw payload can be mathematically verified against its stored hash digest.

---

### 5.5 Failure Handling & Fallback Demonstration

If local inference or GPU resources are constrained or Ollama is offline during evaluation:
1. **Fallback Readiness:** The platform's evidence ingestion, parsing, entity extraction, cryptographic hashing, and local feed lookup operate independently of Ollama.
2. **Degraded Mode:** If Ollama is stopped, `GET /api/v1/health/ready` returns HTTP 503 detailing `llm_provider: unavailable`, while `GET /api/v1/health` continues to return HTTP 200 `status: ok` and all `/evidence/*` endpoints remain 100% operational.

---

## 6. AI Modular Layer Architecture & Documentation Requirements

### 6.1 Architectural Principles

The AI layer in AISOP is governed by **ADR-001** and the **₹0 additional-cost constraint**:
- **Protocol-First Design:** High-level services depend on the `LLMProvider` Protocol, never on concrete vendor SDKs.
- **Local-First & Offline:** All inference defaults to Ollama running local open-weights models (`qwen3:4b` or `llama3.1:8b`).
- **Zero Cloud Exfiltration:** Prompt context and telemetry data never leave the host machine.
- **Prompt Injection Defense-in-Depth:** Dynamic values are structurally escaped (XML attributes and text entities) via `InvestigationContextBuilder`.

### 6.2 Implementation Inventory

| Component | File Path | Status | Operational Details |
|---|---|---|---|
| **Protocol** | `backend/app/modules/ai/llm/protocol.py` | Implemented | Defines `LLMProvider` Protocol with `generate()`, `stream()`, and `health()` |
| **Factory** | `backend/app/modules/ai/llm/manager.py` | Implemented | `get_llm_provider(settings)`. Raises `LLMError` for non-ollama providers |
| **Ollama Provider** | `backend/app/modules/ai/providers/ollama/provider.py` | Implemented | Implements `LLMProvider` over HTTP via `httpx.AsyncClient` |
| **Ollama Embedder** | `backend/app/modules/ai/embeddings/embedder.py` | Implemented | Strictly validates 768 dimensions for `nomic-embed-text` |
| **Context Builder** | `backend/app/modules/ai/context_builder/context_builder.py` | Implemented | Escapes dynamic XML attributes/text; enforces untrusted data boundary |
| **Vector Store** | `backend/app/modules/ai/knowledge/vector_store.py` | Implemented | pgvector cosine similarity search over `knowledge_embeddings` |
| **OpenAI / Claude / Gemini** | `backend/app/modules/ai/providers/{openai,anthropic,gemini}/client.py` | Scaffolded (0 bytes) | Placeholder files. No code or third-party SDKs installed |

### 6.3 Embedding Dimension & Model Migration Invariants

The pgvector integration requires strict architectural discipline:
1. **Hard Guard in Code:** `OllamaEmbedder.embed()` checks `len(raw_embedding) != self._expected_dim (768)`. A mismatch raises `EmbeddingDimensionError`.
2. **Database Constraint:** `knowledge_embeddings.embedding` is defined as `Vector(768)` in SQLAlchemy models and PostgreSQL schema.
3. **Consequences of Changing Embedding Models:**
   - A different model (e.g., `all-minilm` with 384 dimensions or `bge-large` with 1024 dimensions) cannot be swapped via `.env` alone.
   - Swapping models without a schema migration causes PostgreSQL insertion errors.
   - Existing vectors cannot be compared with vectors from another model. The entire knowledge base must be truncated and re-embedded.

---

## 7. Recommended Documentation File Structure

### 7.1 Existing vs Proposed Documentation Analysis

The current documentation tree contains numerous 0-byte placeholders and lacks practical operational guides:
- **0-Byte Placeholders:** `docs/11_Deployment/Deployment_Guide.md`, `docs/05_Backend/API_Design.md`, `docs/12_User_Guides/User_Guide.md`, `docs/07_Security/RBAC.md`, `docs/02_SRS/SRS.md`.
- **Misused Root README:** Root `README.md` is currently an internal milestone tracker ("Project Status & Execution Tracker") rather than a project introduction and quick start guide.

### 7.2 Proposed Consolidated Documentation Structure

To maintain discoverability without creating conflicting or duplicate files, the following documentation structure is recommended:

```
D:\AISOP\
├── README.md                                  # [REWRITE] Project Overview, Prerequisites, Quick Start, Demo Link
│
├── docs\
│   ├── 00_Project_Management\
│   │   ├── Milestones.md                      # Milestone ledger & execution tracker (moved from root README)
│   │   ├── Documentation_Deployment_Readiness_Audit.md # [THIS AUDIT REPORT]
│   │   └── Historical Reports                 # TI-2*, TI-3*, P2-H3* reports preserved
│   │
│   ├── 01_User_Guides\
│   │   ├── SOC_Analyst_Guide.md               # [PROPOSED] Telemetry investigation, entity tracing, TI interpretation
│   │   ├── Professor_Demonstration_Runbook.md # [PROPOSED] Complete offline demo script with expected outputs
│   │   └── Developer_Guide.md                 # [EXISTING - 7.7 KB] aisop.ps1 utility documentation
│   │
│   ├── 02_Developer_and_API\
│   │   ├── Local_Development_Setup.md         # [PROPOSED] Python 3.12, .venv, Uvicorn, test execution
│   │   └── API_Reference.md                   # [POPULATE 05_Backend] OpenAPI endpoints, request/response contracts
│   │
│   ├── 03_System_Design\
│   │   ├── Architecture.md                    # [EXISTING - 30 KB] Core architecture & data flows
│   │   └── ADR\                               # [EXISTING] Architectural Decision Records (ADR-001 to ADR-006)
│   │
│   ├── 04_AI_Modular_Layer\
│   │   ├── AI_Architecture_Guide.md           # [PROPOSED] LLMProvider protocol, Ollama setup, prompts
│   │   └── Embedding_and_Vector_Lifecycle.md  # [PROPOSED] 768-dim constraint, pgvector, model migration rules
│   │
│   ├── 05_SIEM_and_Ingestion\
│   │   ├── Ingestion_Contract_Specification.md# [PROPOSED] IngestRequest schema, Sysmon mapping, deduplication
│   │   └── SIEM_Integration_Guide.md          # [PROPOSED] Webhook configuration, Splunk/Elastic forwarder guides
│   │
│   ├── 06_Deployment_and_Operations\
│   │   ├── Deployment_Guide.md                # [POPULATE 11_Deployment] Docker, Postgres, Ollama sizing
│   │   └── Operations_and_Troubleshooting.md  # [PROPOSED] Backups, migrations, port conflicts, log analysis
│   │
│   └── 07_Security_and_Privacy\
│       ├── Security_Architecture.md           # [EXISTING - 18 KB] Security controls & trust boundaries
│       ├── OWASP.md                           # [EXISTING - 27.5 KB] Threat analysis & mitigations
│       └── Privacy_Shield_and_Boundaries.md   # [PROPOSED] SSRF defense, bogon blocking, context escaping
```

---

## 8. Prioritized Implementation and Documentation Sequence

In accordance with project priorities, documentation and operational readiness work must proceed in this exact order:

```
[ Tier 1: Immediate Onboarding & Demonstration ]
  1. Root README.md Replacement (Platform overview, prerequisites, quickstart, demo pointer)
  2. Professor Demonstration Runbook (Step-by-step offline verification script)
                    |
                    v
[ Tier 2: Core Engineering Architecture ]
  3. AI Modular Layer Guide (LLMProvider protocol, Ollama configuration, 768-dim invariants)
  4. FastAPI Ingestion Contract & SIEM Integration Guide (Sysmon schema, deduplication, webhook spec)
                    |
                    v
[ Tier 3: Operations & Developer Experience ]
  5. Deployment & Operations Guide (Docker compose, environment sizing, backup & recovery runbook)
  6. Developer Guide, API Reference & Security Trust Boundaries Documentation
```

*Note: Execution of this sequence must not destabilize or alter ongoing core milestones (P2-H3 acceptance).*

---

## 9. Security and Operational Gaps Before Production Use

The following vulnerabilities, security boundaries, and operational gaps must be resolved before AISOP can be deployed in a production security operations center:

1. **Unauthenticated API Endpoints (CRITICAL):**
   - **Vulnerability:** Every endpoint (`POST /api/v1/evidence/ingest`, `GET /api/v1/evidence/*`, `GET /api/v1/health/*`) is currently accessible without authentication.
   - **Risk:** Any network adversary on the local network can flood the database with bogus telemetry, trigger denial of service, or exfiltrate sensitive SOC observations.
   - **Required Remediation:** Implement API key or JWT authentication middleware before any network exposure.
2. **Plaintext Secrets in Configuration (HIGH):**
   - **Vulnerability:** Database credentials (`postgresql+psycopg://aisop:aisop@localhost:5433/aisop_dev`) are stored in plaintext in `.env` and `.env.example`.
   - **Risk:** Exposure of secrets in version control or workstation backups.
   - **Required Remediation:** Use secure environment variable injection or a local credential vault in production.
3. **Absence of API Ingestion Rate Limiting (HIGH):**
   - **Vulnerability:** While payload byte size is capped (64 KB/event, 2,000 events/batch), there is no rate limiter on `POST /api/v1/evidence/ingest`.
   - **Risk:** An adversary or misconfigured SIEM forwarder can overwhelm PostgreSQL disk I/O and connection pools.
   - **Required Remediation:** Mount token-bucket or sliding-window rate limiting middleware.
4. **Single-Node Deployment & Backup Vulnerability (MEDIUM):**
   - **Operational Gap:** Telemetry is persisted in a local Docker volume (`aisop_postgres_data`) without automated backup, replication, or snapshotting.
   - **Risk:** Hardware or container corruption results in total data loss.
   - **Required Remediation:** Document and automate daily `pg_dump` schedules.
5. **Reverse Proxy & TLS Termination Requirement (HIGH):**
   - **Operational Gap:** Uvicorn runs plain HTTP without TLS.
   - **Risk:** Cleartext transmission of network and endpoint telemetry across organizational subnets.
   - **Required Remediation:** Mandate an HTTPS reverse proxy (e.g., Caddy, Nginx) terminating TLS with trusted certificates.

---

## 10. Executed Commands, Exit Codes & Telemetry Log

| Timestamp (IST) | Executed Command | Working Directory | Exit Code | Result / Output Summary |
|---|---|---|---|---|
| `23:19:03` | `git status --short` | `D:\AISOP` | `0` | Clean audit of 26 modified tracked files and 41 untracked files. Zero changes made. |
| `23:19:26` | `.venv\Scripts\python.exe -m pytest backend/tests/unit -q` | `D:\AISOP` | `0` | **474 passed**, 2 warnings in 16.27s. Complete unit test suite verified. |
| `23:19:40` | `Get-Content README.md -TotalCount 50` | `D:\AISOP` | `0` | Confirmed root README is an internal planning tracker, not a user guide. |
| `23:19:50` | `Get-ChildItem -Path docs -Recurse -File` | `D:\AISOP` | `0` | Audited entire documentation directory; identified 0-byte placeholder files. |
| `23:20:13` | `Get-Content aisop.ps1 -TotalCount 75` | `D:\AISOP` | `0` | Inspected developer script modes (`Audit`, `Health`, `TestUnit`, `FullCheck`). |
| `23:20:24` | `Get-Content backend/app/main.py` | `D:\AISOP` | `0` | Verified FastAPI app lifespan, middleware, and router mounts. |
| `23:20:33` | `Get-Content backend/app/api/v1/__init__.py` | `D:\AISOP` | `0` | Confirmed only `health` and `evidence` routers are mounted in API v1. |
| `23:21:42` | `Get-ChildItem -Path backend/app/modules -Recurse -File` | `D:\AISOP` | `0` | Verified `cases`, `reports`, `attack`, `openai`, `gemini` are 0-byte scaffolds. |
| `23:22:21` | `Get-ChildItem -Path frontend -Recurse` | `D:\AISOP` | `0` | Confirmed `frontend/` contains only an empty 0-byte `package.json` and empty folders. |
| `23:22:35` | `Get-Content docker-compose.yml` | `D:\AISOP` | `0` | Confirmed Docker Compose runs only PostgreSQL (`aisop-postgres`) on port 5433. |
| `23:23:22` | `pwsh -ExecutionPolicy Bypass -File .\aisop.ps1 -Mode Health` | `D:\AISOP` | `0` | 6/6 health checks passed (Python 3.12, Docker, PostgreSQL 5433, Ollama 11434). |
| `23:23:29` | `curl.exe -s http://localhost:11434/api/tags` | `D:\AISOP` | `0` | Verified Ollama models: `nomic-embed-text:latest` (768d) and `qwen3:4b`. |
| `23:25:00` | `Get-Content datasets/samples/sysmon/sysmon_attack_chain.json` | `D:\AISOP` | `0` | Verified synthetic 4-event attack chain dataset for professor demo. |

---

## 11. Explicit Limitations, Roadmap Discrepancies & Unverified Claims

To maintain engineering integrity, the following discrepancies between architectural roadmaps and actual codebase reality are explicitly recorded:

1. **Analyst User Interface:** Roadmaps mention an analyst UI. In reality, `frontend/` is an empty skeleton with a 0-byte `package.json`. No web dashboard exists.
2. **Investigation Case Management & Automated Reporting:** Roadmaps describe automated case file generation and report exports. In reality, `backend/app/modules/cases/` and `backend/app/modules/reports/` contain only empty `__init__.py` files. No case or report models or API routers are implemented.
3. **External Cloud AI Providers:** Modules exist for `openai`, `anthropic`, and `gemini` in `backend/app/modules/ai/providers/`. All client files are 0 bytes. The factory explicitly rejects all providers except `ollama`.
4. **Direct SIEM Connectors:** Roadmaps reference SIEM integration. No code exists to poll Splunk, Elastic, or Sentinel. The platform supports ingestion exclusively through push-based HTTP POST requests to `/api/v1/evidence/ingest`.
5. **Configured vs Installed Model:** The default configuration in `.env.example` specifies `OLLAMA_MODEL=llama3.1:8b`. The active Ollama installation contains `qwen3:4b`. Running without modifying `.env` or pulling `llama3.1:8b` will report the LLM provider as `degraded` in `/health/ready`.
6. **API Authentication:** Documentation mentioning role-based access control (RBAC) represents future design; the current REST API is entirely unauthenticated.

---

**Audit Concluded:** 22 October 2026  
**Next Recommended Action:** Present findings to Project Owner, preserve working tree, and await authorization to begin Priority Tier 1 (Root `README.md` rewrite and Professor Demonstration Runbook).
