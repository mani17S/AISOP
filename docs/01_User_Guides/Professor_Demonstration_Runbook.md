# AISOP — Professor Demonstration Runbook
## Repeatable, Offline Academic Demonstration of Local-First Security Operations

> **Document Type:** Evaluator Runbook / Demonstration Script  
> **Target Audience:** Academic Evaluators, Capstone Reviewers, Systems Professors  
> **Platform Target:** Windows 10/11 x64, Python 3.12, Docker Desktop (PostgreSQL 17 + pgvector), Ollama  
> **Operating Cost:** ₹0 Additional Cost (No cloud APIs, no external subscriptions, 100% offline-capable)  
> **Dataset:** Synthetic Sysmon Multi-Stage Telemetry (`datasets/samples/sysmon/sysmon_attack_chain.json`)

---

## 1. Executive Summary & Evaluation Boundaries

This runbook provides an instructor-led, deterministic walkthrough of the core operational capabilities implemented in AISOP (AI Security Investigation & Operations Platform).

### What This Demonstration Proves (Verified Capabilities)
1. **Local-First Telemetry Ingestion:** Direct REST submission of raw Windows Sysmon JSON telemetry batches via `POST /api/v1/evidence/ingest`.
2. **Cryptographic Chain of Custody:** Automatic canonical SHA-256 hashing of incoming payloads to guarantee forensic integrity and auditability.
3. **Idempotent Replay Deduplication:** Ingestion rejects duplicate evidence hashes without failing the batch, preventing telemetry pollution and state inflation.
4. **Canonical Event Normalization:** Automatic mapping of raw Sysmon events into structured, typed canonical schemas:
   - EventID 1: Process Creation (`powershell.exe`)
   - EventID 22: DNS Query (`c2.apt-simulated.org`)
   - EventID 3: Network Connection (`192.168.10.105:443 -> 198.51.100.45:443`)
   - EventID 11: File Creation (`C:\Users\Public\mimikatz.exe`)
5. **Atomic Entity Extraction:** Resolution of atomic indicators of compromise (IOCs)—including processes, usernames, hostnames, IP addresses, domains, and file hashes—into indexed relational records (17 entities extracted from the 4-event attack chain).
6. **Privacy-Preserving Threat Intelligence Shielding:** The `PrivateNetworkShield` evaluates observables in memory, classifies RFC1918 private IPs (`192.168.10.105`) and internal hostnames as shielded (`UNKNOWN` verdict), and blocks them at the dispatch boundary from external lookup (SSRF and data-leakage defense).
7. **Forensic Evidence Retrieval by Cryptographic Hash:** Lookup of raw evidence records and their associated canonical events by SHA-256 digest via `GET /api/v1/evidence/by-hash/{sha256_hash}`.
8. **Health & Readiness Telemetry:** Comprehensive monitoring of local vector database connections, schema migrations, and local Ollama inference models.

### What This Demonstration Does NOT Prove (Explicit Out-of-Scope)
- **Live SIEM Ingestion:** This demonstration utilizes a **synthetic, replayed telemetry sample**. It does not connect to a live corporate SIEM (Splunk, Elastic, Sentinel).
- **Automated Case & Report Generation:** The autonomous investigation and case-reporting modules (`cases/` and `reports/`) are scaffolded; their endpoints are unmounted in FastAPI pending core acceptance gates.
- **Graphical Analyst Dashboard:** The `frontend/` directory is an unbuilt scaffold. The platform interacts strictly via **Swagger UI (`http://localhost:8000/docs`)** and **PowerShell / curl CLI**.
- **Production Network Security:** The API currently has **no authentication or RBAC middleware**; it is designed strictly for evaluation on `localhost`.

---

## 2. Prerequisites & Preflight Checklist

Before beginning the demonstration, ensure the following components are ready on the host machine:

| Component | Required Version | Verified Configuration | Status Check Command |
|---|---|---|---|
| **Operating System** | Windows 10/11 x64 | PowerShell 7 (`pwsh`) | `$PSVersionTable.PSVersion` |
| **Python** | 3.12.x | Virtual environment at `.venv` | `.\.venv\Scripts\python.exe --version` |
| **PostgreSQL + pgvector** | PostgreSQL 17 + pgvector 0.8.0 | Docker container `aisop-postgres` | `docker ps --filter "name=aisop-postgres"` |
| **Host Database Port** | `5433` (isolated) | Mapped to container `5432` | `Test-NetConnection -ComputerName 127.0.0.1 -Port 5433` |
| **Ollama Inference Engine** | Local Windows Daemon | Listening on port `11434` | `curl.exe -s http://localhost:11434/api/tags` |
| **Embedding Model** | `nomic-embed-text:latest` | 768 dimensions (mandatory) | Listed in Ollama tags |
| **Reasoning Model** | `qwen3:4b` or `llama3.1:8b` | Local LLM inference | Configured in `.env` (`OLLAMA_MODEL`) |

---

## 3. Step-by-Step Demonstration Script

### Step 1: Database & Host Port Isolation Audit
AISOP isolates its database from any existing native PostgreSQL instances on the evaluator's machine by using host port **5433**.

Run the following in PowerShell:
```powershell
# 1. Verify container is running
docker ps --filter "name=aisop-postgres" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# 2. Test TCP port connectivity to port 5433
Test-NetConnection -ComputerName 127.0.0.1 -Port 5433
```

**Expected Output:**
```text
TcpTestSucceeded : True
```

Verify that migrations are up to date:
```powershell
.\.venv\Scripts\alembic.exe current
```
**Expected Output:**
```text
0003_source_scoped_chunks (head)
```

---

### Step 2: Ollama Local Model Readiness Verification
Verify that local AI models are loaded and accessible with zero cloud dependencies:

```powershell
curl.exe -s http://localhost:11434/api/tags
```

**Expected Output:**
A JSON response listing local models, crucially including `nomic-embed-text:latest` (768d embedding) and either `qwen3:4b` or `llama3.1:8b`:
```json
{
  "models": [
    {"name": "nomic-embed-text:latest", ...},
    {"name": "qwen3:4b:latest", ...}
  ]
}
```

---

### Step 3: Launch FastAPI Backend & Execute Health Probes

#### 3.1 Start the Application Server
On Windows, run the backend using Python's Selector event loop policy to ensure compatibility with `psycopg` async operations:
```powershell
.\.venv\Scripts\python.exe -c "import asyncio, sys, uvicorn; sys.platform == 'win32' and asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy()); uvicorn.run('app.main:app', app_dir='backend', port=8000, loop='none')"
```

#### 3.2 Liveness Probe
Open a second PowerShell terminal and test the basic health endpoint:
```powershell
curl.exe -s http://localhost:8000/api/v1/health
```

**Expected Output (HTTP 200):**
```json
{
  "status": "ok",
  "app": "AISOP",
  "version": "0.1.0",
  "environment": "development"
}
```

#### 3.3 Readiness Probe (Deep Dependency Inspection)
Test the readiness probe to inspect database and LLM subsystem status:
```powershell
curl.exe -s http://localhost:8000/api/v1/health/ready
```

**Expected Output (HTTP 200):**
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
      "latency_ms": 280.32
    }
  }
}
```
*(Note: If `checks.llm_provider.status` reports `degraded`, confirm that the model configured in `.env` under `OLLAMA_MODEL` matches an installed Ollama model tag).*

---

### Step 4: Ingest Synthetic Sysmon Attack Telemetry

We use a synthetic multi-stage attack dataset located at:
`datasets/samples/sysmon/sysmon_attack_chain.json`

This synthetic telemetry models a 4-stage intrusion sequence on workstation `CORP-FIN-WS01`:
1. **EventID 1 (Process Execution):** Obfuscated PowerShell execution (`powershell.exe -Enc SUVY...`, Parent: `explorer.exe`, User: `CORP\victim_user`).
2. **EventID 22 (DNS Resolution):** PowerShell querying C2 domain `c2.apt-simulated.org` resolving to `198.51.100.45`.
3. **EventID 3 (C2 Network Connection):** PowerShell connecting outbound from `192.168.10.105` to destination `198.51.100.45:443`.
4. **EventID 11 (Payload Staging / File Creation):** PowerShell creating executable `C:\Users\Public\mimikatz.exe`.

#### 4.1 Construct IngestRequest & Submit Payload
The ingestion endpoint requires an `IngestRequest` envelope specifying `source_type`, `source_identifier`, and an `events` array.

Run the following in PowerShell:
```powershell
# Read and parse raw sample events
$rawEvents = Get-Content -Raw datasets\samples\sysmon\sysmon_attack_chain.json | ConvertFrom-Json

# Construct valid IngestRequest payload
$payload = @{
    source_type = "sysmon"
    source_identifier = "CORP-FIN-WS01"
    events = $rawEvents
} | ConvertTo-Json -Depth 5

# Submit batch to ingestion endpoint
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/evidence/ingest" -Method Post -ContentType "application/json" -Body $payload | ConvertTo-Json -Depth 4
```

**Expected Output (HTTP 200):**
```json
{
  "batch_id": "<UUID>",
  "source_type": "sysmon",
  "total_received": 4,
  "total_normalized": 4,
  "total_entities_extracted": 17,
  "total_skipped_duplicates": 0,
  "existing_evidence_ids": [],
  "errors": []
}
```
**Evaluation Milestone:** All 4 events are cryptographically hashed, normalized into canonical schemas, and decomposed into 17 atomic security entities across the relational schema.

---

### Step 5: Verify Idempotent Deduplication (Replay Attack Defense)

In a live SOC or unstable network, telemetry forwarders frequently re-transmit identical logs. AISOP utilizes deterministic SHA-256 payload hashing to prevent duplicate database ingestion.

Re-submit the exact same batch:
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/evidence/ingest" -Method Post -ContentType "application/json" -Body $payload | ConvertTo-Json -Depth 4
```

**Expected Output (HTTP 200):**
```json
{
  "batch_id": "<UUID>",
  "source_type": "sysmon",
  "total_received": 4,
  "total_normalized": 0,
  "total_entities_extracted": 0,
  "total_skipped_duplicates": 4,
  "existing_evidence_ids": [
    "<UUID-1>",
    "<UUID-2>",
    "<UUID-3>",
    "<UUID-4>"
  ],
  "errors": []
}
```
**Evaluation Milestone:** The platform skips all 4 duplicate payloads (`total_skipped_duplicates: 4`), extracts 0 duplicate entities, and returns the existing evidence UUIDs without database mutation.

---

### Step 6: Query Ingested Telemetry & Entity Resolution

#### 6.1 Query Normalized Events
Retrieve the normalized events associated with workstation `CORP-FIN-WS01`:
```powershell
$eventsResponse = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/evidence/events?source_identifier=CORP-FIN-WS01"
$eventsResponse | ConvertTo-Json -Depth 4
```

**Expected Output (HTTP 200):**
A paginated envelope containing 4 items ordered by timestamp descending:
- EventID 11: `file_create` (`mimikatz.exe`)
- EventID 3: `network_connection` (`192.168.10.105 -> 198.51.100.45:443`)
- EventID 22: `dns_query` (`c2.apt-simulated.org`)
- EventID 1: `process_creation` (`powershell.exe`)

#### 6.2 Query Extracted Security Entities (Atomic IOCs)
Examine the atomic entities extracted across the telemetry:
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/evidence/entities?limit=20" | ConvertTo-Json -Depth 4
```

**Expected Output (HTTP 200):**
A paginated envelope (`total: 17`) containing extracted atomic indicators:
- **Domains:** `c2.apt-simulated.org` (role: `queried_domain`)
- **Files:** `mimikatz.exe` (role: `target`)
- **File Hashes:** `17565fe8a1553835b19fa865befa0df85fa3ec04b9741d8b4d445f0f5cc054d6` (role: `file_hash`), `a697368b25a0b7ec9aebee3fece92ce9d0e76f4b84bbda5701fea28a6635a33d` (role: `process_hash`)
- **Hosts:** `CORP-FIN-WS01` (role: `endpoint`)
- **IPs:** `192.168.10.105` (role: `source`), `198.51.100.45` (role: `destination`)
- **Processes:** `powershell.exe` (role: `executed`)

---

### Step 7: Verify Threat Intelligence Privacy Shield & Dispatch Boundary

AISOP contains a built-in `PrivateNetworkShield` that inspects observables before external threat-intelligence lookups. RFC1918 private IPs, loopback, and internal hostnames are classified as shielded (`UNKNOWN` verdict) and blocked at the code dispatch boundary from being queried against external network providers (SSRF and internal telemetry leakage defense).

Find the Event ID of the network connection event (Sysmon Event ID 3):
```powershell
$events = (Invoke-RestMethod -Uri "http://localhost:8000/api/v1/evidence/events?source_identifier=CORP-FIN-WS01").items
$netEvent = $events | Where-Object { $_.event_id -eq "3" }
$netEventId = $netEvent.id

# Query with Threat Intelligence enrichment enabled
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/evidence/events/$netEventId?enrich_threat_intel=true" | ConvertTo-Json -Depth 5
```

**Expected Output (HTTP 200):**
The response includes the normalized event, extracted entities, and `threat_intel` findings:
- Source IP `192.168.10.105` is an RFC1918 private address. It is evaluated against the `PrivateNetworkShield`.
- The shield blocks external dispatch, synthesizing an `unknown` verdict (never `benign`).
- When external providers and local feeds are uninitialized, the dispatch boundary guarantees safe fallback without external network egress.

---

### Step 8: Forensic Chain of Custody & Hash Lookup

Each raw evidence record is uniquely indexed by its canonical SHA-256 digest.

#### 8.1 Dynamically Retrieve Hash from Event Record
```powershell
# 1. Fetch single event detail to obtain parent raw evidence SHA-256 hash
$eventDetail = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/evidence/events/$netEventId"
$sha256 = $eventDetail.raw_sha256_hash
Write-Host "Discovered Evidence SHA-256: $sha256"

# 2. Look up raw evidence directly by cryptographic digest
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/evidence/by-hash/$sha256" | ConvertTo-Json -Depth 4
```

For the network connection payload (EventID 3), the precomputed SHA-256 digest is:
`55c634f79327662bd8cc433791e5d0e6c7528c6fd99b957d90932cf4a19ecf51`

*(Other sample event digests: EventID 1: `ec6b654b3fa2a14ea765bbe1c4213c98cca08798551b46bc426e1cc45a43a4e7`; EventID 22: `b3c2c769fa48293a76bce8b684caa0b5b9df3c3c9eda911d20405b19185eb5d9`; EventID 11: `aa95bf6e7dd4d56977b106c589b8c8ea907d5ac797085ca5520e38838bdb476f`).*

**Expected Output (HTTP 200):**
```json
{
  "id": "<RAW_EVIDENCE_UUID>",
  "source_type": "sysmon",
  "source_identifier": "CORP-FIN-WS01",
  "sha256_hash": "55c634f79327662bd8cc433791e5d0e6c7528c6fd99b957d90932cf4a19ecf51",
  "ingested_at": "2026-10-22T...",
  "raw_payload": {
    "EventID": 3,
    "UtcTime": "2026-09-09 14:15:22.800",
    "ProcessId": 5412,
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "SourceIp": "192.168.10.105",
    "DestinationIp": "198.51.100.45",
    "DestinationPort": 443,
    "Protocol": "tcp",
    "Computer": "CORP-FIN-WS01"
  },
  "normalized_events": [
    {
      "id": "<NORMALIZED_EVENT_UUID>",
      "event_id": "3",
      "event_type": "network_connection",
      "event_timestamp": "2026-09-09T14:15:22.800000Z",
      "severity": "informational",
      "action": "connected",
      "outcome": "success"
    }
  ]
}
```
**Evaluation Milestone:** The platform retrieves the immutable raw evidence payload and its associated canonical events using only the cryptographic hash, proving forensic integrity and chain of custody.

---

## 4. Teardown & Isolation Cleanup

Once the demonstration is complete:

1. **Stop the FastAPI Server:** Press `Ctrl+C` in the terminal running Uvicorn.
2. **Leave Docker Container Intact:** The PostgreSQL container `aisop-postgres` can remain running for subsequent tests, or stopped via:
   ```powershell
   docker compose stop postgres
   ```
3. **Database Integrity Note:** Ingestion writes raw records to the database specified in `.env`. The protected databases `aisop_dev` and `aisop_test` remain clean and untouched when running in isolated test targets.

---

## 5. Professor Review Checklist & Evidence Summary

| Capability Demonstrated | Verified Endpoint / Command | Academic Significance |
|---|---|---|
| **Liveness & Readiness** | `GET /api/v1/health/ready` | Proves local health monitoring without cloud telemetry. |
| **Telemetry Ingestion** | `POST /api/v1/evidence/ingest` | Demonstrates high-throughput batch normalization (4/4 parsed). |
| **Cryptographic Provenance** | `GET /api/v1/evidence/by-hash/{sha256}` | Forensically auditable chain of custody via SHA-256. |
| **Idempotent Deduplication** | `POST /api/v1/evidence/ingest` (replayed) | Prevents denial-of-service via telemetry replay (4/4 skipped). |
| **Entity Extraction** | `GET /api/v1/evidence/entities` | Automatically maps unstructured logs to 17 relational indicators. |
| **Privacy Shielding** | `GET /api/v1/evidence/events/{id}?enrich_threat_intel=true` | In-memory evaluation and blocking of private/internal RFC1918 IPs. |
| **Interactive API Documentation** | `http://localhost:8000/docs` | Standardized OpenAPI 3.0 contract. |

---

## 6. Troubleshooting Demonstration Issues

- **Issue: `psycopg.InterfaceError: ProactorEventLoop`**  
  *Cause:* Modern async psycopg on Windows requires the selector event loop.  
  *Fix:* Launch Uvicorn using the exact Python command provided in Step 3.1.
- **Issue: Readiness reports `llm_provider: degraded`**  
  *Cause:* The configured model in `.env` (`OLLAMA_MODEL`) has not been pulled.  
  *Fix:* Run `ollama pull qwen3:4b` or update `.env` to match installed tags.
- **Issue: Ingestion returns HTTP 422 Unprocessable Entity**  
  *Cause:* Sending the raw JSON array file directly instead of wrapping it in an `IngestRequest` dictionary (`source_type`, `source_identifier`, `events`).  
  *Fix:* Use the PowerShell snippet provided in Step 4.1.
- **Issue: Port 5433 connection refused**  
  *Cause:* Docker container `aisop-postgres` is stopped.  
  *Fix:* Run `docker compose up -d postgres`.
