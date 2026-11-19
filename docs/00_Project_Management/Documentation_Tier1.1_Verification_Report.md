# AISOP — Tier 1.1 Documentation Verification & Demonstration Correction Report
## Review, Ingestion Schema Correction, and Hash Lookup Alignment

**Document Reference:** `AISOP-DOC-TIER1.1-VERIFY-001`  
**Execution Date:** 23 October 2026 (00:07 IST)  
**Milestone:** Documentation Tier 1.1 — Independent Verification & Demonstration Runbook Correction  
**Working Repository:** `D:\AISOP`  
**Active Branch:** `main`  
**HEAD Commit:** `c4e877cf06056bce32f5a3f893a82261b850ff85`  
**Python Runtime:** Python 3.12.0 (`D:\AISOP\.venv\Scripts\python.exe`)  
**Auditor:** Senior Defensive Security Systems Reviewer & Backend Architect  
**Final Verdict:** **VERIFIED & CORRECTED (100% Schema and Execution Alignment)**

---

## 1. Executive Summary

This report establishes the findings, corrections, and empirical verification of the Tier 1 documentation suite:
- [README.md](file:///D:/AISOP/README.md)
- [docs/01_User_Guides/Professor_Demonstration_Runbook.md](file:///D:/AISOP/docs/01_User_Guides/Professor_Demonstration_Runbook.md)

Following review against `backend/app/schemas/ingest.py`, `backend/app/services/ingestion_service.py`, `backend/app/api/v1/endpoints/evidence.py`, and live execution against the isolated disposable database (`aisop_p2h3_disposable` on port 5433), two primary operational discrepancies and several response schema mismatches were identified and comprehensively remediated in the demonstration runbook.

---

## 2. Inconsistencies Found & Remediations Applied

| Category | Initial Document State | Technical Reality & Implementation Finding | Applied Remediation |
|---|---|---|---|
| **Ingestion Payload Schema (Step 4)** | Runbook posted raw JSON array from sample file directly: `Invoke-RestMethod ... -Body (Get-Content -Raw sysmon_attack_chain.json)` | `datasets/samples/sysmon/sysmon_attack_chain.json` is a JSON array (`list[dict]`). The endpoint `POST /api/v1/evidence/ingest` validates an `IngestRequest` dictionary requiring `source_type: str`, `source_identifier: str`, and `events: list[dict]`. Direct raw array submission fails with HTTP 422 Unprocessable Entity. | Corrected Step 4 in the runbook with a PowerShell snippet that parses the sample and wraps it in a valid `IngestRequest` envelope before submission. |
| **Ingestion HTTP Status Code** | Runbook documented `HTTP 201 Created` | `POST /api/v1/evidence/ingest` returns standard `HTTP 200 OK` upon successful ingestion and deduplication. | Corrected expected HTTP status code from 201 to 200 in both Step 4 and Step 5. |
| **Evidence SHA-256 Digest (Step 8)** | Hard-coded arbitrary mock digest: `d30ca74a58b6fb128d50b441f3e790a61f2f814987019f993d0d82997f7481ba` | The hard-coded digest did not correspond to any record generated from `sysmon_attack_chain.json`. The actual canonical SHA-256 digest of Event 3 (Network Connection) is `55c634f79327662bd8cc433791e5d0e6c7528c6fd99b957d90932cf4a19ecf51` (and Event 1 is `ec6b654b3fa2a14ea765bbe1c4213c98cca08798551b46bc426e1cc45a43a4e7`). | Step 8 was converted to a dynamic two-step workflow: first retrieving the actual parent `raw_sha256_hash` directly from `GET /api/v1/evidence/events/{event_id}`, then performing the lookup by that exact digest via `GET /api/v1/evidence/by-hash/{sha256}`. The precomputed canonical digests are also listed. |
| **Sample Attack Chain Events** | Runbook text described Event 2 as lateral movement via `wmic.exe` | The actual sample file `sysmon_attack_chain.json` contains: EventID 1 (Process Execution: `powershell.exe`), EventID 22 (DNS Resolution: `c2.apt-simulated.org`), EventID 3 (Network Connection: `192.168.10.105:443 -> 198.51.100.45:443`), and EventID 11 (File Creation: `mimikatz.exe`). | Updated Section 1 and Step 4 descriptions to accurately state the 4 events present in the sample. |
| **Readiness Response Schema (Step 3.3)** | Runbook documented a flat dictionary: `{"status": "ready", "database": "ok", "llm_provider": "healthy", ...}` | Implemented schema in `backend/app/schemas/health.py` returns nested dictionary: `{"status": "ok", "app": "AISOP", "version": "0.1.0", "checks": {"database": {"status": "ok"}, "llm_provider": {"status": "healthy", "provider": "ollama", "model": "qwen3:4b", ...}}}` | Aligned expected JSON response in Step 3.3 with actual runtime schema. |
| **Network Egress Boundary Claims** | Previous draft stated "Zero external network packets leave the machine." | Packet-level sniffing was not performed; claim was overly broad. | Narrowed claim to verified behavior: "The `PrivateNetworkShield` evaluates observables in memory, classifies RFC1918 private IPs (`192.168.10.105`) and internal hostnames as shielded (`UNKNOWN` verdict), and blocks them at the dispatch boundary from external lookup (SSRF and internal telemetry leakage defense)." |

---

## 3. Exact Files Changed

1. **[docs/01_User_Guides/Professor_Demonstration_Runbook.md](file:///D:/AISOP/docs/01_User_Guides/Professor_Demonstration_Runbook.md):**
   - Corrected Step 4 ingestion command to construct an `IngestRequest` dictionary wrapping the sample file.
   - Corrected HTTP status codes from 201 to 200.
   - Replaced static/invalid SHA-256 hash in Step 8 with a dynamic lookup procedure (`GET /api/v1/evidence/events/{id}` -> `raw_sha256_hash` -> `GET /api/v1/evidence/by-hash/{sha256}`) along with verified canonical digests for all 4 events.
   - Accurately described the 4 events in `datasets/samples/sysmon/sysmon_attack_chain.json` (EventIDs 1, 22, 3, 11).
   - Corrected readiness probe response structure to reflect nested `checks` object.
   - Narrowed network egress claims to code-level dispatch boundary blocking.
2. **[README.md](file:///D:/AISOP/README.md):**
   - Removed Unicode emoji character that triggered encoding errors under Windows `cp1252` console environments.
   - Confirmed all internal markdown links and architecture references resolve accurately.
3. **[docs/00_Project_Management/Documentation_Tier1.1_Verification_Report.md](file:///D:/AISOP/docs/00_Project_Management/Documentation_Tier1.1_Verification_Report.md):**
   - Authored this report.

---

## 4. Actual Commands Executed & Verified Results

All commands were executed in `D:\AISOP` using the local virtual environment `.venv\Scripts\python.exe` against the containerized PostgreSQL instance on port `5433` and Ollama daemon on port `11434`:

| Step / Command | Subsystem Tested | Actual Execution Result | Verification Status |
|---|---|---|---|
| `GET /api/v1/health` | Backend Liveness | HTTP 200: `{"status": "ok", "app": "AISOP", "version": "0.1.0", "environment": "development"}` | **VERIFIED** |
| `GET /api/v1/health/ready` | Backend Readiness | HTTP 200: `{"status": "ok", "checks": {"database": {"status": "ok"}, "llm_provider": {"status": "healthy", "model": "qwen3:4b"}}}` | **VERIFIED** |
| `POST /api/v1/evidence/ingest` (Initial Batch) | Ingestion & Normalization | HTTP 200: `total_received: 4, total_normalized: 4, total_entities_extracted: 17, total_skipped_duplicates: 0, errors: []` | **VERIFIED** |
| `POST /api/v1/evidence/ingest` (Replay Batch) | Cryptographic Deduplication | HTTP 200: `total_received: 4, total_normalized: 0, total_entities_extracted: 0, total_skipped_duplicates: 4, existing_evidence_ids: [4 UUIDs]` | **VERIFIED** |
| `GET /api/v1/evidence/events?source_identifier=CORP-FIN-WS01` | Normalized Events Query | HTTP 200: 4 canonical events returned in paginated envelope ordered by timestamp descending | **VERIFIED** |
| `GET /api/v1/evidence/entities?limit=25` | Atomic Entity Resolution | HTTP 200: 17 atomic indicators returned across domains, files, hashes, host, IPs, and process | **VERIFIED** |
| `GET /api/v1/evidence/events/{net_id}?enrich_threat_intel=true` | Threat Intelligence Shield | HTTP 200: Event returned; destination and source IPs evaluated. `192.168.10.105` shielded with `UNKNOWN` verdict; zero external dispatch triggered. | **VERIFIED** |
| `GET /api/v1/evidence/by-hash/{sha256}` | Forensic Hash Lookup | HTTP 200: Raw evidence record returned matching SHA-256 digest `55c634f79327662bd8cc433791e5d0e6c7528c6fd99b957d90932cf4a19ecf51` with associated canonical events | **VERIFIED** |

---

## 5. Which Runbook Steps Were Successfully Verified

Every single step in [Professor_Demonstration_Runbook.md](file:///D:/AISOP/docs/01_User_Guides/Professor_Demonstration_Runbook.md) was live-verified:
- **Step 1 (Port & Database Isolation):** Verified container `aisop-postgres` listening on port `5433` (isolated from host `5432`); Alembic head at `0003_source_scoped_chunks`.
- **Step 2 (Local Model Readiness):** Verified `nomic-embed-text:latest` (768d) and `qwen3:4b` installed and responsive.
- **Step 3 (FastAPI Launch & Probes):** Verified Windows Selector event loop launch command; liveness and readiness probes return HTTP 200 `ok`.
- **Step 4 (Synthetic Telemetry Ingestion):** Verified that wrapping the 4 sample events in `IngestRequest` results in HTTP 200 with 4 normalized events and 17 extracted entities.
- **Step 5 (Idempotent Deduplication):** Verified that exact batch re-transmission skips all 4 events with 0 new entities and returns existing evidence UUIDs.
- **Step 6 (Query & Entity Resolution):** Verified retrieval of normalized events and atomic IOCs via REST query endpoints.
- **Step 7 (Privacy Shielding):** Verified that private address `192.168.10.105` is shielded with safe fallback and zero external provider dispatch.
- **Step 8 (Forensic Hash Lookup):** Verified dynamic hash retrieval from event detail and successful lookup of raw evidence by SHA-256 digest.

---

## 6. Remaining Documentation Inaccuracies or Runtime Blockers

1. **Uvicorn ProactorEventLoop Trap on Windows:**
   - *Behavior:* On Windows Python 3.12, executing default `uvicorn app.main:app` uses `ProactorEventLoop`, which crashes with `psycopg.InterfaceError` upon the first async database transaction.
   - *Status:* Remediated. Both `README.md` and `Professor_Demonstration_Runbook.md` explicitly mandate the exact launcher command setting `WindowsSelectorEventLoopPolicy` and `loop='none'`.
2. **Missing Frontend UI:**
   - *Behavior:* The `frontend/` directory is an unbuilt scaffold.
   - *Status:* Remediated. Both documents clearly state that AISOP operates strictly as a headless REST API and CLI platform.
3. **Unmounted Case & Report Endpoints:**
   - *Behavior:* Autonomous case investigation and report generation routes are scaffolded but unmounted in FastAPI.
   - *Status:* Remediated. The runbook explicitly limits the demonstration to implemented capabilities (ingestion, deduplication, normalization, entity extraction, privacy shielding, and hash lookup).

---

## 7. Security Limitations for Untrusted Networks

The demonstration environment is strictly designed for **local-only evaluation on `localhost`**. The following security limitations make it unsuitable for exposure to an untrusted or corporate network:

1. **Zero API Authentication / Authorization:** The REST API possesses no authentication, API key validation, or RBAC middleware. Any network entity with TCP connectivity to port 8000 can ingest telemetry or view historical forensic records.
2. **Missing Ingestion Rate Limiting:** While individual payloads are capped at 64 KB per event and 2,000 events per batch, no rate-limiting middleware is mounted on the ingestion route.
3. **Localhost Binding Mandatory:** The FastAPI backend must remain bound to `127.0.0.1`.
4. **Plaintext Secrets in Local Config:** Database credentials reside in `.env`.
