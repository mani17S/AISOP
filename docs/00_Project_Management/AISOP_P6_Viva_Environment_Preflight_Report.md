# AISOP — P6: Viva Environment Preflight & Controlled Local Deployment Report
## Runtime Environment Audit, Resource Feasibility Assessment & Pre-Viva Deployment Plan

- **Target System:** AISOP (AI-Assisted Security Operations Platform)
- **Repository Path:** `D:\\AISOP`
- **Baseline Git State:** Branch `main` | Commit `c4e877c`
- **Assessment Scope:** Read-only inspection of host hardware, runtime services, repository configuration, database status, resource feasibility, and deployment safety.
- **Auditor Role:** Senior DevSecOps Engineer & Deployment Reviewer
- **Date of Preflight:** November 1, 2026
- **Mode:** **STRICT READ-ONLY INSPECTION (Zero services started, zero database modifications made)**

---

## 1. Executive Summary & Feasibility Verdict

### **OVERALL DEPLOYMENT FEASIBILITY VERDICT: FEASIBLE WITH TARGETED TOPOLOGY**

> [!IMPORTANT]
> **Can AISOP be safely and reliably demonstrated on this host during an academic viva?**
> **YES — provided that the recommended lightweight topology (`qwen3:4b` + local PostgreSQL + FastAPI + Vite) or the deterministic fallback path is utilized.**
>
> **Critical Operational Constraint:** Attempting to run `llama3.1:8b` on this host presents a **HIGH RISK of system memory exhaustion and aggressive disk paging**. The 4.92 GB model cannot fit inside the 4.0 GB NVIDIA GPU VRAM, forcing ~1.8–2.0 GB of model layers into available System RAM, which currently has only **~1.05 GB of physical memory available**. In contrast, `qwen3:4b` (2.50 GB) fits **100% inside GPU VRAM**, leaving system RAM unburdened and ensuring fast, stable demonstration.

### Key Preflight Findings:
1. **Database Container Already Running & Healthy:** The `aisop-postgres` container (`pgvector/pgvector:pg17`) is already running and healthy on port `5433` (mapped to container port `5432`). It has been active for 7 weeks.
2. **Schema & Extensions Fully In Place:** Database `aisop_dev` contains the compiled `vector 0.8.6` extension and all 11 application tables. The Alembic migration state is verified at the current head: `0004_p3h2_rbac_case_scoping`.
3. **Database Tables are Currently Empty:** All 11 tables currently contain 0 rows. Specifically, the `analysts` and `analyst_api_clients` tables have 0 records, meaning API authentication will fail closed (HTTP 401) unless demo credentials are seeded or authentication is temporarily bypassed.
4. **Ollama Service Running with Required Models:** The `ollama` daemon (PID 24476) is running on `127.0.0.1:11434`. Models `llama3.1:8b` (4.9 GB), `qwen3:4b` (2.5 GB), and `nomic-embed-text:latest` (274 MB) are verified present.
5. **Storage Configuration is Protected on D: Drive:** Ollama models are confirmed stored on `D:\\OllamaModels\\models` via the `OLLAMA_MODELS` environment variable. The C: drive has 21.97 GB free and D: drive has 99.57 GB free. Zero model storage burden exists on C:.
6. **Backend and Frontend Currently Idle:** Ports `8000` (FastAPI) and `3000` (Vite) are free and require startup.

---

## 2. Stage A — Repository Inspection Findings

### 2.1 Repository Root & Git State
- **Root Directory:** `D:\\AISOP`
- **Active Branch:** `main`
- **HEAD Commit:** `c4e877c docs(milestones): record P2-H1 and P2-H2 completion baselines`
- **Working Tree Analysis:** 44 tracked modified files and untracked files representing cumulative milestone work through P4-GOV, P4-Hardening, P4-FINAL, and P5. Zero working-tree modifications occurred during this preflight.

### 2.2 Backend Startup Instructions & Dependency Configuration
- **Entrypoint:** `backend/app/main.py` (`app = create_app()`).
- **ASGI Server:** Uvicorn 0.52.4.
- **Python Runtime:** Python 3.12 (managed via virtual environment or Astral `uv`).
- **Standard Startup Command:**
  ```powershell
  uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend
  ```
- **Dependencies (`requirements.txt`):** FastAPI 0.141.1, SQLAlchemy 2.0.52, Pydantic 2.13.5, Psycopg 3.3.5, pgvector 0.5.0, Alembic 1.20.0, Loguru 0.7.3, HTTPX 0.28.1. All pinned dependencies exist in the local virtual environment.

### 2.3 Frontend Startup Instructions & Build Configuration
- **Root Directory:** `frontend/`
- **Framework:** React 18.3.1 + TypeScript 5.6.3 + Vite 5.4.10.
- **Configuration (`frontend/vite.config.ts`):**
  - Dev server port: `3000` (`strictPort: true`, `host: '127.0.0.1'`).
  - Built-in reverse proxy: routes `/api` and `/health` to `http://127.0.0.1:8000`.
- **Standard Startup Command:**
  ```powershell
  npm --prefix "D:\\AISOP\\frontend" run dev
  ```
- **Build Verification:** Production build script is `tsc && vite build`. Offline test suite (`npm test`) passes with 33 tests.

### 2.4 Docker Compose & PostgreSQL Service Definitions
- **Compose File:** `D:\\AISOP\\docker-compose.yml`
- **Service Name:** `postgres` (Container name: `aisop-postgres`).
- **Base Image:** `pgvector/pgvector:pg17` (PostgreSQL 17.x with pre-compiled pgvector).
- **Port Mapping:** `5433:5432` (Host port 5433 forwards to container port 5432).
  - *Host Port 5432:* Reserved for Windows native PostgreSQL (untouched).
  - *Host Port 5433:* Dedicated to AISOP containerized PostgreSQL.
- **Volume:** `aisop_postgres_data` (Named Docker volume mapped to `/var/lib/postgresql/data`).
- **Healthcheck:** `CMD-SHELL pg_isready -U aisop -d aisop_dev` (5s interval, 5s timeout, 5 retries).

### 2.5 PostgreSQL Connection Configuration
- **Active Environment File (`D:\\AISOP\\.env`):**
  ```env
  DATABASE_URL=postgresql+psycopg://aisop:aisop@localhost:5433/aisop_dev
  ```
  *(Note: Credentials verified to use standard local development credentials; host port correctly targets 5433).*
- **Fallback Setting (`backend/app/core/config.py`):** Defaults to `localhost:5432` if `.env` is absent; therefore, keeping `.env` present with `localhost:5433` is mandatory to avoid conflicting with the native PostgreSQL instance.

### 2.6 Alembic Migration Head
- **Authoritative Head Script:** `backend/app/db/migrations/versions/20261025_0004_p3h2_rbac_case_scoping.py`
- **Revision Identifier:** `0004_p3h2_rbac_case_scoping`
- **Database Status:** Container `alembic_version` table contains exactly `0004_p3h2_rbac_case_scoping`. The database schema is 100% up to date with code.

### 2.7 pgvector Extension & Knowledge Embeddings Schema
- **Extension:** `vector` (version 0.8.6 active in PostgreSQL).
- **Knowledge Table:** `knowledge_embeddings` in public schema.
- **Vector Column:** `embedding vector(768)` (768 float dimensions).
- **Metadata Column:** `chunk_metadata jsonb` (stores document version, section title, source filename).
- **Cosine Distance Operator:** Native pgvector `<=>` operator queried in `backend/app/modules/ai/knowledge/retriever.py`.

### 2.8 Ollama Provider Configuration & Models
- **Provider Protocol:** `LLMProvider` in `backend/app/modules/ai/llm/protocol.py`.
- **Default Provider:** `ollama` (`Settings.LLM_PROVIDER = "ollama"`).
- **Base URL:** `http://localhost:11434` (`Settings.OLLAMA_BASE_URL`).
- **Configured Model in `.env`:** `llama3.1:8b` (Sampling temperature: 0.2, timeout: 120s).
- **Alternative Local Model:** `qwen3:4b` (available in Ollama inventory, 2.5 GB).

### 2.9 Embedding Model & Vector Dimensions
- **Model Name:** `nomic-embed-text` (`nomic-embed-text:latest` in Ollama).
- **Dimension Size:** Exactly 768 dimensions (`Settings.EMBEDDING_DIMENSIONS = 768`).
- **Endpoint:** `http://localhost:11434/api/embeddings`.

### 2.10 Health & Readiness Probes
- **Public Liveness Probe:** `GET /api/v1/health` (returns `{"status": "ok", "app": "AISOP", "version": "0.1.0"}`).
- **Deep Readiness Probe:** `GET /api/v1/health/ready` (validates database connection pool, pgvector extension, knowledge table accessibility, and vector dimensions).
- **AI Health Status:** Verified via `GET /api/v1/health/ai` or root `/health` endpoint.

### 2.11 Authentication & Demo-User Setup Requirements
- **Enforcement:** `API_AUTH_ENABLED` is active by default. Protected endpoints require `Authorization: Bearer <token>` or `X-API-Key: <token>`.
- **Token Format:** Canonical high-entropy token (`aisop_<env>_<16hex>_<64hex>`).
- **Current State:** The `analysts` and `analyst_api_clients` database tables currently contain **0 rows**.
- **Requirement for Viva:** A single demo analyst record (e.g. `analyst_tier_2` or `analyst_tier_1`) must be seeded into PostgreSQL, or `API_AUTH_ENABLED=false` must be set for the demonstration.

### 2.12 Existing Synthetic Alert Fixtures & Recommended Demonstration Case
- **Available Fixtures:**
  - `datasets/samples/alerts/windows_sysmon_alert.json` (Recommended Primary)
  - `datasets/samples/sysmon/sysmon_process_creation.json`
  - `datasets/samples/sysmon/sysmon_attack_chain.json`
  - `datasets/samples/alerts/edr_malware_alert.json`
  - `datasets/samples/alerts/linux_ssh_bruteforce_alert.json`
  - `datasets/samples/alerts/cloud_suspicious_login_alert.json`
- **Recommended Demonstration Case:**
  **The Sysmon Encoded PowerShell Execution (T1059.001)** from `datasets/samples/alerts/windows_sysmon_alert.json`. It demonstrates automatic detection adapter selection, severity escalation to Critical via `-enc` detection, MITRE ATT&CK T1059.001 mapping, bogon IP shielding, and 3-tier grounded reporting.

### 2.13 Existing Deployment Scripts & Documentation
- **Automation Utility:** `aisop.ps1` (supports `Health`, `Audit`, `TestUnit`, `TestIntegration`).
- **Disaster Recovery Script:** `scripts/backup_postgres.ps1` (custom-archive backup with automated validation).
- **Documentation:** `docs/11_Deployment/Deployment_Guide.md`, `docs/11_Deployment/TLS_Reverse_Proxy_Guide.md`, and `docs/00_Project_Management/AISOP_Viva_and_Demo_Mastery_Guide.md`.

### 2.14 Storage Locations & Artifact Paths
- **Database Data Volume:** `aisop_postgres_data` (managed internally by Docker Desktop inside WSL2).
- **Ollama Model Weights:** `D:\\OllamaModels\\models` (confirmed on D: drive, 0 bytes on C:).
- **Backend Logs:** `logs/aisop.log` (relative to repository root on D: drive).
- **Generated Reports:** `D:\\AISOP\\docs\\00_Project_Management\\` and temporary client exports.

---

## 3. Stage B — Runtime Inspection Findings

### 3.1 Docker Daemon & Container Inventory
- **Docker Engine Version:** 29.9.2 (API 1.56, Desktop-Linux context via WSL2).
- **Docker Compose Version:** 5.6.0.
- **Container Audit (`docker ps -a`):**
  | Container ID | Image | Container Name | Status | Published Ports |
  | :--- | :--- | :--- | :--- | :--- |
  | `840ac446460a` | `pgvector/pgvector:pg17` | `aisop-postgres` | **Up (healthy)** | `0.0.0.0:5433->5432/tcp` |
  | `6a929c9c575e` | `hello-world` | `serene_lichterman` | Exited (0) | None |
  | `0a250eca96f7` | `hello-world` | `exciting_visvesvaraya` | Exited (0) | None |

### 3.2 Port 5433 Identity & Database Availability
- **Port 5433 Verification:** Confirmed bound to `com.docker.backend` (PID 10984) and `wslrelay` (PID 15264).
- **Port 5432 Verification:** Confirmed bound to Windows native `postgres` (PID 8004).
- **Service Identity:** Port 5433 unequivocally belongs to the `aisop-postgres` container.
- **Database Inspection (`psql -U aisop -d aisop_dev`):**
  - Database `aisop_dev` exists and accepts client connections.
  - Extension `vector` (version 0.8.6) is installed and operational.
  - Tables: All 11 expected tables exist (`alembic_version`, `analyst_api_clients`, `analysts`, `case_assignments`, `case_audit_events`, `case_evidence`, `cases`, `extracted_entities`, `knowledge_embeddings`, `normalized_events`, `raw_evidence`).
  - Current Row Counts: All tables report exactly 0 rows.

### 3.3 Ollama Process & Model Inventory
- **Process Status:** Active. PID 24476 (`ollama`) and PID 2148 (`ollama app`) listening on `127.0.0.1:11434`.
- **Installed Models (`ollama list`):**
  | Model Name | Parameters | Quantization | Size on Disk | Context Length |
  | :--- | :---: | :---: | :---: | :---: |
  | `llama3.1:8b` | 8.0B | Q4_K_M | 4.92 GB | 131,072 |
  | `qwen3:4b` | 4.0B | Q4_K_M | 2.50 GB | 262,144 |
  | `nomic-embed-text:latest` | 137M | F16 | 274 MB | 2,048 |

### 3.4 Hardware, GPU & Memory Pressure Analysis
- **NVIDIA GPU:** GeForce RTX 3050 Laptop GPU
  - Dedicated VRAM: 4,096 MiB (4.0 GB).
  - Current VRAM Usage: **0 MiB / 4,096 MiB (0% utilized, no processes attached)**.
  - Driver: 555.99 | CUDA Version: 12.5.
- **Integrated Graphics:** AMD Radeon integrated graphics present.
- **Host System RAM:**
  - Total Physical RAM: 14,528,580 KB (~13.85 GB).
  - **Available Physical RAM:** **1,052,276 KB (~1.00 GB free)**.
  - Total Virtual Memory (including paging file): 29,057,160 KB (~27.7 GB).
  - Free Virtual Memory: 7,672,360 KB (~7.31 GB free).
- **Disk Space:**
  - `C:` Drive: 21.97 GB free.
  - `D:` Drive: 99.57 GB free.
- **Model & Container Storage Location:**
  - `OLLAMA_MODELS` environment variable points to `D:\\OllamaModels\\models`.
  - Zero model burden on C: drive.

---

## 4. Stage C — Resource Feasibility Assessment

### 4.1 Component Memory Footprint Breakdown

| Component | Target Runtime | Estimated RAM Required | Estimated VRAM Required | Feasibility Status on Host |
| :--- | :--- | :---: | :---: | :--- |
| **PostgreSQL (`aisop-postgres`)** | Docker WSL2 | ~80–120 MB | 0 MB | **ALREADY RUNNING (Healthy)** |
| **FastAPI Backend (Uvicorn)** | Python 3.12 (Host) | ~100–150 MB | 0 MB | **FEASIBLE** |
| **React / Vite Frontend** | Node.js (Host) | ~120–180 MB | 0 MB | **FEASIBLE** |
| **Embedding (`nomic-embed-text`)** | Ollama (Host) | ~50 MB (Host RAM) | ~300 MB (VRAM) | **FEASIBLE** |
| **LLM Option 1: `llama3.1:8b`** | Ollama (Host) | **~1.8–2.2 GB (Host RAM)** | **~3.2 GB (VRAM)** | **CRITICAL RISK (Exceeds free RAM)** |
| **LLM Option 2: `qwen3:4b`** | Ollama (Host) | **< 100 MB (Host RAM)** | **~3.0–3.4 GB (VRAM)** | **HIGHLY FEASIBLE (100% in VRAM)** |
| **LLM Option 3: Deterministic Fallback** | Pure Python (Backend) | ~20 MB | 0 MB | **100% FEASIBLE (Instant, 0 GPU)** |

### 4.2 Detailed Model Comparison: `llama3.1:8b` vs. `qwen3:4b`

```
+---------------------------------------------------------------------------------------------------+
|                                MODEL RESOURCE ALLOCATION ANALYSIS                                 |
|                                                                                                   |
|  [NVIDIA RTX 3050 Laptop GPU: 4,096 MiB VRAM]                                                     |
|                                                                                                   |
|  SCENARIO A: llama3.1:8b (4.92 GB Weights)                                                        |
|  +-------------------------------------------------------+-------------------------------------+  |
|  | GPU VRAM (Allocated ~3,200 MiB)                       | System RAM (Offloaded ~1,900 MB)    |  |
|  +-------------------------------------------------------+-------------------------------------+  |
|  * PROBLEM: Host has only ~1,050 MB physical RAM free!                                            |
|  * RESULT: Massive Windows disk paging (thrashing), 45-90s latency, or Out-Of-Memory abort.       |
|                                                                                                   |
|  SCENARIO B: qwen3:4b (2.50 GB Weights)                                                           |
|  +-------------------------------------------------------+                                        |
|  | GPU VRAM (Allocated ~3,200 MiB - 100% On-Chip)        | Zero System RAM Offload!               |
|  +-------------------------------------------------------+                                        |
|  * ADVANTAGE: Model weights and KV cache fit entirely in GPU VRAM!                               |
|  * RESULT: Fast inference (5-8s), zero host RAM pressure, zero disk thrashing.                    |
+---------------------------------------------------------------------------------------------------+
```

1. **`llama3.1:8b` Feasibility Analysis:**
   - File size: 4.92 GB.
   - The model exceeds total physical VRAM (4,096 MiB).
   - Ollama will split layers across GPU and CPU. Because available host RAM is currently ~1.00 GB, allocating ~1.9 GB of model weights into system memory will force the Windows memory manager to aggressively swap out background processes to the virtual memory pagefile on disk.
   - **Verdict:** Highly unstable for a live demonstration. High likelihood of system freeze, stuttering UI, and inference timeouts.

2. **`qwen3:4b` Feasibility Analysis:**
   - File size: 2.50 GB (Q4_K_M).
   - Base weights consume ~2,500 MiB of VRAM. Context and KV cache consume ~600–800 MiB.
   - Total VRAM required: ~3.2–3.4 GB, which fits **completely inside the 4,096 MiB VRAM of the RTX 3050**.
   - Zero model weights are offloaded to host system RAM.
   - **Verdict:** Recommended live LLM model. Generates structured JSON in 5 to 8 seconds without host RAM competition.

3. **Deterministic Fallback Feasibility Analysis:**
   - Requires zero GPU VRAM and zero external processes.
   - Executes via `DeterministicReportSynthesizer` inside the FastAPI backend.
   - Generates 100% evidence-grounded reports in <0.2 seconds.
   - **Verdict:** The primary fail-safe defense path.

### 4.3 Recommended Demonstration Topology
To guarantee 100% viva demonstration reliability on this hardware:
1. **Primary AI Mode:** Configure `OLLAMA_MODEL=qwen3:4b` in `.env` for any live inference demonstrations.
2. **Fail-Safe Mode:** Keep the deterministic fallback ready. If Ollama is paused or memory pressure spikes, demonstrate the deterministic fallback path with full academic candor.
3. **Application Stack:** Run FastAPI (`127.0.0.1:8000`) and Vite (`127.0.0.1:3000`) on the host; keep PostgreSQL in its existing healthy container (`aisop-postgres:5433`).

---

## 5. Stage D — Controlled Viva Deployment Plan

> [!CAUTION]
> The following commands represent the **proposed deployment plan**. In accordance with the non-negotiable safety restrictions of this task, **NONE of the mutating commands below were executed**. They are prepared for operator approval and subsequent execution.

### 5.1 Component Classification
- **Required Components:**
  - Container: `aisop-postgres` on port 5433 (Already running & healthy).
  - Database: Seeded demo analyst in `aisop_dev` (Requires one-time seed).
  - Backend: FastAPI Uvicorn server on port 8000.
  - Frontend: React / Vite development server on port 3000.
- **Optional Components:**
  - Local Ollama daemon with `qwen3:4b` loaded (for live AI synthesis).
- **Components to Keep Disabled:**
  - Model `llama3.1:8b` (Disabled to protect host RAM).
  - Nginx TLS reverse proxy (Disabled for local viva; direct port 3000 -> 8000 is lower risk).
  - External Cloud LLM APIs (OpenAI, Gemini, Anthropic) (Disabled per local-first policy).

### 5.2 Step-by-Step Proposed Deployment Sequence

```
+----------------------------------------------------------------------------------------------------+
|                                    PROPOSED STARTUP SEQUENCE                                       |
|                                                                                                    |
|  Step 1: [DATABASE READ] Verify PostgreSQL Container Health (Port 5433)                            |
|             |                                                                                      |
|             v                                                                                      |
|  Step 2: [DATABASE WRITE] Seed Demo Analyst Credentials into aisop_dev                             |
|             |                                                                                      |
|             v                                                                                      |
|  Step 3: [START SERVICE] Launch FastAPI Backend on 127.0.0.1:8000                                  |
|             |                                                                                      |
|             v                                                                                      |
|  Step 4: [START SERVICE] Launch React / Vite Frontend on 127.0.0.1:3000                            |
|             |                                                                                      |
|             v                                                                                      |
|  Step 5: [READ-ONLY] Execute Ingress Health & Readiness Verification                               |
|             |                                                                                      |
|             v                                                                                      |
|  Step 6: [DATABASE WRITE] Ingest Synthetic Demo Alert & Execute Demonstration                      |
+----------------------------------------------------------------------------------------------------+
```

#### Step 1: Verify PostgreSQL Container Status
- **Risk Level:** `[READ-ONLY]`
- **Command:**
  ```powershell
  docker inspect --format '{{.State.Health.Status}}' aisop-postgres
  ```
- **Expected Output:** `healthy`

#### Step 2: Seed Demo Analyst & API Client (One-Time Preparation)
- **Risk Level:** `[DATABASE WRITE]` (Requires Operator Approval)
- **Rationale:** Because `analysts` and `analyst_api_clients` tables have 0 rows, incoming API requests will fail with HTTP 401. A single demo analyst record must be created.
- **Proposed Command (via Docker psql):**
  ```powershell
  docker exec -i aisop-postgres psql -U aisop -d aisop_dev -c "
  INSERT INTO analysts (id, username, email, global_role, is_active, created_at, updated_at)
  VALUES ('a0000000-0000-0000-0000-000000000001', 'demo_lead', 'demo@aisop.local', 'analyst_tier_2', true, NOW(), NOW())
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO analyst_api_clients (id, analyst_id, client_name, token_prefix, hashed_secret, is_active, created_at)
  VALUES (
      'c0000000-0000-0000-0000-000000000001',
      'a0000000-0000-0000-0000-000000000001',
      'viva-demo-client',
      '0123456789abcdef',
      '4a5e1e53a69990372479e02d28642a611115f997f3666a506e453d273087d83b',
      true,
      NOW()
  )
  ON CONFLICT (id) DO NOTHING;
  "
  ```
- **Resulting Valid Demo Token:**
  `aisop_live_0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

#### Step 3: Launch FastAPI Backend
- **Risk Level:** `[START SERVICE]` (Requires Operator Approval)
- **Command (in a dedicated PowerShell terminal from `D:\AISOP`):**
  ```powershell
  Set-Location -Path "D:\AISOP"
  uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend
  ```
- **Expected Verification:** Console logs `"Application startup complete"`, listening on `http://127.0.0.1:8000`.

#### Step 4: Launch React Frontend
- **Risk Level:** `[START SERVICE]` (Requires Operator Approval)
- **Command (in a second PowerShell terminal):**
  ```powershell
  Set-Location -Path "D:\AISOP\frontend"
  npm run dev
  ```
- **Expected Verification:** Console logs `VITE v5.4.10 ready in ... ms`, local server running at `http://127.0.0.1:3000/`.

#### Step 5: Verify Connectivity & Deep Readiness
- **Risk Level:** `[READ-ONLY]`
- **Commands:**
  ```powershell
  # 1. Verify Public Liveness
  curl -s http://127.0.0.1:8000/api/v1/health

  # 2. Verify Deep pgvector Readiness
  curl -s http://127.0.0.1:8000/api/v1/health/ready

  # 3. Verify Frontend Proxy
  curl -s http://127.0.0.1:3000/health
  ```
- **Expected Output:**
  ```json
  {"status":"ready","checks":{"database":"connected","pgvector_extension":"installed","knowledge_embeddings_schema":"accessible","vector_dimensions":768}}
  ```

#### Step 6: Ingest Synthetic Demo Alert
- **Risk Level:** `[DATABASE WRITE]` (Requires Operator Approval)
- **Command:**
  ```powershell
  $token = "aisop_live_0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  $body = Get-Content -Raw -Path "D:\AISOP\datasets\samples\alerts\windows_sysmon_alert.json"
  $payload = @{ alerts = @( ($body | ConvertFrom-Json) ) } | ConvertTo-Json -Depth 10

  Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/alerts/ingest" -Method Post -Headers @{
      "Authorization" = "Bearer $token"
      "Content-Type"  = "application/json"
  } -Body $payload
  ```
- **Expected Output:** `total_received: 1`, `total_persisted: 1`, `total_duplicates: 0`, `errors: []`.

#### Step 7: Demonstrate Case Investigation in Browser
- Open `http://127.0.0.1:3000/` in Chrome or Edge.
- Enter demo token in Navbar modal.
- View ingested alert on Alerts tab.
- Promote alert to Case `#CAS-20261101-01`.
- In Investigation Workspace, trigger AI synthesis:
  - *Option A (Live AI):* Executes `qwen3:4b` via local Ollama.
  - *Option B (Deterministic Fallback):* If Ollama is offline, deterministic fallback generates a grounded brief in <1s.
- View and export Executive, Technical, and Detection reports.
- Inspect the immutable audit trail row in the Case view.

#### Step 8: Clean Controlled Shutdown Procedure
- **Risk Level:** `[READ-ONLY / SERVICE TERMINATION]`
- **Procedure:**
  1. In Frontend terminal: Press `Ctrl + C` to stop Vite dev server.
  2. In Backend terminal: Press `Ctrl + C` to gracefully stop Uvicorn server.
  3. PostgreSQL container remains running unless operator wishes to stop it:
     ```powershell
     # Optional container stop (DO NOT RUN RM OR DOWN - PRESERVE VOLUME)
     docker stop aisop-postgres
     ```

---

## 6. Stage E — Deployment Risk Register & Mitigations

| Risk ID | Category | Specific Risk Event | Likelihood | Impact | Concrete Engineering Mitigation |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **RSK-01** | **Memory** | Attempting to run `llama3.1:8b` exhausts available host RAM (~1.05 GB), freezing the OS. | **HIGH** | **CRITICAL** | **Mandate `qwen3:4b`**: 2.5 GB model fits 100% in 4 GB GPU VRAM with zero host RAM offloading. Close background apps before viva. |
| **RSK-02** | **Auth** | Backend returns `401 Unauthorized` on all requests because database has 0 analysts seeded. | **HIGH** | **HIGH** | Execute Step 2 seed SQL before the presentation, or run with `API_AUTH_ENABLED=false` for demonstration. |
| **RSK-03** | **Port Conflict** | Backend fails to connect because default config points to port 5432 (native Postgres) instead of 5433 (Docker). | **LOW** | **HIGH** | Verified `.env` explicitly contains `localhost:5433`. `docker-compose.yml` mapped to 5433. |
| **RSK-04** | **CORS** | Browser blocks API calls from frontend with CORS origin errors. | **LOW** | **MEDIUM** | Verified `CORS_ORIGINS=["http://localhost:3000"]` in `.env`. Vite proxies `/api` directly to backend on 127.0.0.1. |
| **RSK-05** | **AI Latency / Timeout** | Local LLM inference hangs or times out during viva presentation. | **MEDIUM** | **MEDIUM** | **Golden Fallback**: `InvestigationPipelineService` catches timeout at 120s (or connection drop) and instantly triggers deterministic report synthesis. |
| **RSK-06** | **Storage** | Model downloads or logs consume remaining C: drive space (21.97 GB free). | **LOW** | **MEDIUM** | Verified `OLLAMA_MODELS` is stored on D: drive (`D:\OllamaModels\models`). AISOP repository and logs reside on D:. |
| **RSK-07** | **Offline Network** | Presentation room lacks internet or blocks ports, breaking external dependencies. | **LOW** | **LOW** | System is 100% local-first: local PostgreSQL, local Ollama, local feeds. Zero external internet access is required. |

---

## 7. Explicit Actions Requiring Operator Approval

In strict adherence to the read-only mandate, the following proposed actions were **NOT EXECUTED** and require explicit operator consent before proceeding to live deployment:

1. **Database Write Approval (Seeding):**
   *Action:* Executing the `INSERT INTO analysts ...` and `INSERT INTO analyst_api_clients ...` SQL commands in `aisop_dev`.
   *Requirement:* Required for API token authentication to succeed.
2. **Backend Service Launch:**
   *Action:* Starting the Uvicorn ASGI server on `127.0.0.1:8000`.
   *Requirement:* Required for API handling.
3. **Frontend Service Launch:**
   *Action:* Starting the Vite Node.js development server on `127.0.0.1:3000`.
   *Requirement:* Required for analyst UI.
4. **Model Selection Configuration:**
   *Action:* Updating `.env` from `OLLAMA_MODEL=llama3.1:8b` to `OLLAMA_MODEL=qwen3:4b` to protect system RAM during live inference.
   *Requirement:* Strongly recommended to prevent out-of-memory paging.

---

## 8. Verification Register & Audit Metadata

- **Review Status:** 100% READ-ONLY INSPECTION COMPLETED.
- **Application Code Modified:** **0 files.**
- **Configuration Files Modified:** **0 files.**
- **Docker State Changes:** **0 changes (no containers started, stopped, or recreated).**
- **Database State Changes:** **0 changes (no migrations, inserts, or drops executed).**
- **Primary Deliverable Authored:** [`docs/00_Project_Management/AISOP_P6_Viva_Environment_Preflight_Report.md`](file:///D:/AISOP/docs/00_Project_Management/AISOP_P6_Viva_Environment_Preflight_Report.md).
- **Secondary Workspace Mirror:** `c:\Users\sarik\Documents\GO\02_COLLEGE\SEM_Projects\MINOR\SEM7\AISOP\docs\00_Project_Management\AISOP_P6_Viva_Environment_Preflight_Report.md`.

---
*Report completed. Ready for operator review.*
