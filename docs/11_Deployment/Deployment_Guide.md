# AISOP Deployment, Backup & Disaster Recovery Guide
## Operational Runbook for On-Premises & Private Network Deployments

- **Target System:** AISOP (AI-Assisted Security Operations Platform)
- **Database Engine:** PostgreSQL 17 with `pgvector` extension
- **Container Infrastructure:** Docker Compose (`aisop-postgres` service)
- **Standard Host Port:** `5433` (mapped to container port `5432`)
- **Default Database:** `aisop_dev`
- **Reference Milestone:** Post-P4-GOV Engineering Hardening (REQ-3.7)
- **Status:** **OPERATIONAL GOVERNANCE & RUNBOOK DELIVERABLE**

---

## 1. Architecture & Deployment Overview

AISOP is a local-first, privacy-preserving defensive security workbench. All security alerts, forensic evidence hashes, case dossiers, multi-audience reports, and audit trails reside within PostgreSQL. Semantic search over playbook knowledge documents is powered by `pgvector` (768-dimensional cosine distance embeddings).

```mermaid
flowchart TD
    subgraph "Host Environment"
        App["AISOP Backend / Frontend"]
        BackupScript["scripts/backup_postgres.ps1"]
        BackupStore["backups/ (Host Directory)"]
    end
    subgraph "Docker Container: aisop-postgres"
        PG["PostgreSQL 17.x Engine"]
        Ext["pgvector Extension (768-dim)"]
        AuditTrg["Immutable Audit Triggers"]
        Vol[("/var/lib/postgresql/data Volume")]
    end
    App -->|Host port 5433| PG
    BackupScript -->|docker exec pg_dump -Fc| PG
    PG --> Vol
    BackupScript -->|docker cp| BackupStore
```

---

## 2. Backup Strategy & Procedures

### 2.1 Backup Format & Technical Rationale
AISOP utilizes PostgreSQL's **Custom Archive Format** (`pg_dump -Fc`):
- **Binary Compressed:** Compresses table data, schema definitions, and vector embeddings with zlib.
- **Granular Restoration:** Allows `pg_restore` to selectively restore schemas, specific tables, or data only.
- **Dependency Reordering:** Automatically resolves table dependencies, foreign keys, and indexes during restoration, preventing constraint ordering failures.
- **Full Metadata Preservation:** Preserves PostgreSQL functions (`fn_prevent_case_audit_events_mutation()`), triggers (`trg_case_audit_events_immutable`), indexes (HNSW vector indexes, partial unique indexes), and table ownership constraints.

### 2.2 Backup Prerequisites
1. Docker daemon is running and accessible from the terminal.
2. The `aisop-postgres` container is healthy and running (`docker inspect --format '{{.State.Running}}' aisop-postgres` returns `true`).
3. Sufficient free host disk space in the target backup directory (minimum 5x the current database size recommended).
4. PowerShell 7 (`pwsh`) is available for running the automation utility.

### 2.3 Executing a Database Backup
To create a timestamped backup with automated integrity verification, execute:

```powershell
pwsh -File .\scripts\backup_postgres.ps1
```

#### Optional Parameters:
- `-BackupDir <Path>`: Specify an alternate host destination directory (Default: `<repo_root>\backups`).
- `-CustomTag <String>`: Append an operational tag (e.g., `pre-upgrade`, `weekly-snapshot`).
- `-DryRun`: Validate parameters and container health without invoking `pg_dump`.

#### Example Invocation:
```powershell
pwsh -File .\scripts\backup_postgres.ps1 -BackupDir "D:\backups\aisop" -CustomTag "milestone-p4c"
```

### 2.4 Generated Artifacts
Every successful backup execution emits three synchronized artifacts:
1. **Custom Dump File:** `aisop_<dbname>_<tag>_<timestamp>.dump` (Binary custom archive).
2. **SHA-256 Checksum:** `aisop_<dbname>_<tag>_<timestamp>.dump.sha256` (Standard format: `<hash> *<filename>`).
3. **Audit Metadata:** `aisop_<dbname>_<tag>_<timestamp>.meta.json` (Structured JSON record containing database identifier, container name, engine version, file size, format, timestamp, and checksum).

### 2.5 Backup Integrity Verification
Immediately following backup creation, verify the artifact on the host:

```powershell
# Verify SHA-256 checksum matches
$dumpFile = "backups\aisop_aisop_dev_20261101_002500.dump"
$expectedHash = (Get-Content "$dumpFile.sha256").Split(" ")[0]
$actualHash = (Get-FileHash -Path $dumpFile -Algorithm SHA256).Hash.ToLowerInvariant()

if ($expectedHash -eq $actualHash) {
    Write-Host "[VERIFIED] SHA-256 Checksum Matches: $actualHash" -ForegroundColor Green
} else {
    Write-Error "[CORRUPT] Hash Mismatch! Expected $expectedHash, got $actualHash"
}
```

---

## 3. Disaster Recovery & Restore Runbook

> [!CAUTION]
> **RESTORE TARGET ISOLATION INVARIANT:**
> Never execute a restore against the live, running `aisop_dev` database during operational testing or verification.
> Always restore into a dedicated, disposable recovery database (e.g. `aisop_recovery_disposable`) to validate data integrity without risking live production state.

### 3.1 Restore Prerequisites
1. Target PostgreSQL instance is running with `pgvector` pre-installed (`pgvector/pgvector:pg17`).
2. An isolated target recovery database has been created.
3. The custom backup archive (`.dump`) and its verified `.sha256` checksum are present.
4. Administrative credentials to connect to the database container via `docker exec`.

### 3.2 Step-by-Step Restoration Procedure

#### Step 1: Create an Isolated Disposable Recovery Database
Connect to the PostgreSQL container and create a clean recovery database:

```bash
docker exec -t aisop-postgres psql -U aisop -d postgres -c "CREATE DATABASE aisop_recovery_disposable;"
```

#### Step 2: Ensure pgvector Extension is Initialized
While `pg_dump -Fc` includes extension registration statements, pre-initializing the extension ensures that vector data types are recognized immediately during table creation:

```bash
docker exec -t aisop-postgres psql -U aisop -d aisop_recovery_disposable -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

#### Step 3: Copy Backup Archive into the Container
Copy the verified `.dump` file into the container's temporary directory:

```bash
docker cp "backups/aisop_aisop_dev_20261101_002500.dump" aisop-postgres:/tmp/restore_candidate.dump
```

#### Step 4: Execute `pg_restore`
Run `pg_restore` into the isolated recovery database using `--no-owner` and `--no-privileges`:

```bash
docker exec -t aisop-postgres pg_restore \
    -U aisop \
    -d aisop_recovery_disposable \
    --no-owner \
    --no-privileges \
    --verbose \
    /tmp/restore_candidate.dump
```

*Flags Explanation:*
- `-d aisop_recovery_disposable`: Directs output into the disposable recovery database.
- `--no-owner`: Prevents restoration failures if role ownership names differ between environments.
- `--no-privileges`: Prevents access privilege conflicts on restored objects.
- `--verbose`: Emits detailed object restoration logs.

#### Step 5: Clean Up Container Temporary File
```bash
docker exec -t aisop-postgres rm -f /tmp/restore_candidate.dump
```

---

## 4. Multi-Tier Restore Validation Checklist

Disaster recovery readiness requires rigorous validation across three distinct tiers:

```mermaid
flowchart LR
    TierA["Tier A:<br/>Backup File Integrity<br/>(Size, Hash, Header)"] --> TierB["Tier B:<br/>Restore Schema & Data<br/>(Tables, Vectors, Triggers)"]
    TierB --> TierC["Tier C:<br/>Application Reconnection<br/>(API, Queries, Auth)"]
```

### Tier A: Backup File Validation (Host Level)
- [ ] Backup file exists on host disk and is non-empty (`Length > 0`).
- [ ] Computed SHA-256 matches the companion `.dump.sha256` sidecar.
- [ ] Companion `.meta.json` file is present and contains complete audit metadata.
- [ ] File header inspection: First 5 bytes match PostgreSQL custom format magic bytes (`PGDMP`).

### Tier B: Restore Database Integrity Validation (SQL Level)
Execute the following verification queries against the restored recovery database:

#### 1. Alembic Migration History Parity
Verify that the restored database reflects the complete migration lineage:
```sql
SELECT version_num FROM alembic_version;
-- Expected output: Latest revision ID (e.g. 0004_p3h2_rbac_case_scoping)
```

#### 2. Core Relational Tables Existence
Verify that all core application tables are present:
```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
-- Expected: alembic_version, analyst_api_clients, analysts, canonical_events,
--           case_assignments, case_audit_events, case_evidence, cases,
--           evidence_entities, evidence_events, knowledge_embeddings
```

#### 3. Vector Embeddings & Vector Index Presence
Verify that `knowledge_embeddings` contains 768-dimensional vectors and active indexes:
```sql
-- Check vector column dimensions
SELECT column_name, data_type, udt_name
FROM information_schema.columns
WHERE table_name = 'knowledge_embeddings' AND column_name = 'embedding';
-- Expected: embedding, USER-DEFINED, vector

-- Check vector row count
SELECT count(*) AS total_chunks FROM knowledge_embeddings;

-- Check vector index definition
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'knowledge_embeddings';
```

#### 4. Audit Immutability Trigger Protection
Verify that the tamper-prevention trigger was restored and is actively enforcing append-only invariants:
```sql
-- Attempt an unauthorized update on an audit record (must be rejected)
DO $$
BEGIN
    UPDATE case_audit_events SET action = 'tampered' WHERE id = (SELECT id FROM case_audit_events LIMIT 1);
    RAISE EXCEPTION 'SAFETY TEST FAILED: Audit event was successfully modified!';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'SAFETY TEST PASSED: Trigger blocked audit mutation: %', SQLERRM;
END $$;
```

#### 5. Case and Evidence Relational Constraints
Verify that foreign key relationships between cases, evidence, and analysts remain intact:
```sql
SELECT c.case_number, count(ce.id) AS evidence_count
FROM cases c
LEFT JOIN case_evidence ce ON ce.case_id = c.id
GROUP BY c.case_number;
```

### Tier C: Full Application Recovery Validation (Service Level)
To test full application recovery against the restored database:
1. Temporarily configure `.env`:
   ```bash
   DATABASE_URL=postgresql+psycopg://aisop:aisop@localhost:5433/aisop_recovery_disposable
   ```
2. Start the backend application:
   ```bash
   uv run uvicorn app.main:app --port 8000
   ```
3. Probe application health:
   ```bash
   curl -s http://localhost:8000/api/v1/health/ready
   # Expected: {"status":"ok", "checks":{"database":{"status":"ok","engine":"postgresql","pgvector":{"status":"ok","installed":true},"schema":{"status":"ok","dimension":768}}, ...}}
   ```
4. Query cases and verify report synthesis operates against restored records.
5. Once validated, drop the disposable database:
   ```bash
   docker exec -t aisop-postgres psql -U aisop -d postgres -c "DROP DATABASE aisop_recovery_disposable;"
   ```

---

## 5. Recovery Limitations & Operational Boundaries

To maintain engineering honesty, the following operational boundaries must be understood:

1. **Logical vs. Physical Backup:** `pg_dump -Fc` is a logical export of database objects. It does not include:
   - Host filesystem evidence (e.g. raw captured `.pcap`, external sample logs in `datasets/`).
   - Application configuration (`.env` files, TLS certificates).
   - Python virtual environments or frontend distribution bundles.
   - Ollama LLM weight models (`llama3.1:8b`, `nomic-embed-text` weights reside in Ollama's volume).
2. **Point-in-Time Recovery (PITR):** Point-in-time recovery to a specific minute is **NOT SUPPORTED** at the current project scope. PITR requires continuous Write-Ahead Log (WAL) archiving (e.g. pgBackRest, WAL-G) and dedicated archive storage, which are deferred.
3. **Backup Schedule:** Backups must be scheduled periodically (e.g. daily via Windows Task Scheduler or cron) and immediately before applying Alembic schema migrations.

---

## 6. Emergency Disaster Recovery Runbook (Host Failure Scenario)

In the event of complete container or volume destruction:

1. Recreate the Docker container and volume:
   ```bash
   docker compose down -v
   docker compose up -d
   ```
2. Wait for container health:
   ```bash
   docker inspect --format '{{.State.Health.Status}}' aisop-postgres
   # Wait until output is 'healthy'
   ```
3. Locate the most recent verified backup file and sidecar checksum in `backups/`.
4. Validate the SHA-256 checksum:
   ```powershell
   Get-FileHash -Path "backups\<filename>.dump" -Algorithm SHA256
   ```
5. Follow Section 3.2 to restore the database.
6. Run Section 4 validation checklist to certify service resumption.

---

## 7. Hardened Private LAN TLS Reverse Proxy (REQ-9.3)

For private network and on-premises deployments, AISOP includes an inactive, pre-hardened Nginx reverse proxy template:
- **Configuration Template:** [`deploy/nginx/nginx.conf`](../../deploy/nginx/nginx.conf)
- **Comprehensive Runbook & Architecture:** [`docs/11_Deployment/TLS_Reverse_Proxy_Guide.md`](TLS_Reverse_Proxy_Guide.md)

### Key Architectural Invariants:
1. **Persistence exposure (corrected 2026-11-14):** the proxy template exposes only the application. The shipped `docker-compose.yml` publishes PostgreSQL as `5433:5432` without a host-IP binding, so it listens on all host interfaces and is limited only by the host firewall; Ollama listens wherever its own configuration says (AISOP does not start or configure it). Neither is isolated by AISOP itself. See section 8 for the recommended independent restrictions.
2. **TLS 1.2/1.3 Termination:** High-security AEAD ciphers with canonical HTTP-to-HTTPS 301 redirection.
3. **Spoofed Header Protection:** Nginx enforces `proxy_set_header X-Forwarded-For $remote_addr;` to prevent client IP spoofing against the backend rate limiter.
4. **Header Deduplication:** Nginx coordinates with FastAPI [`SecurityHeadersMiddleware`](../../backend/app/middleware/security_headers.py) to prevent duplicate response headers.

---

## 8. Local-First LLM Configuration, Endpoint Locality and Network Egress (Task 2, accepted 2026-11-14)

Every statement below is checked against the code (`backend/app/core/config.py`, `modules/ai/llm/manager.py`, `locality.py`, `inert.py`) and the shipped `docker-compose.yml`.

### 8.1 Provider selection
- `LLM_PROVIDER` is the only provider selector. Default `ollama`. API keys or other environment variables (OpenAI, Anthropic, Gemini, Azure and so on) never select or activate a provider.
- Only one provider implementation exists today: `ollama` (local adapter). Any other value fails closed with "Unsupported LLM provider". There is no fallback to another provider, and no cloud LLM provider is implemented.
- `LLM_ENABLED=false` turns AI assistance off: no provider client is built, and no chat, health or embedding call is made. Readiness reports the LLM as `disabled` (not degraded). Deterministic ingestion, correlation, evidence, ATT&CK mapping, sufficiency and reporting continue, and the AI status is `disabled`.
- With AI enabled but the local daemon or model unavailable, calls are bounded (`OLLAMA_MAX_RETRIES`, default 3, and `OLLAMA_TIMEOUT_SECONDS`, default 120), end in a typed error, and the deterministic result stays available (`fallback:*`). No model is downloaded automatically.

### 8.2 Ollama endpoint locality
- Default `OLLAMA_BASE_URL=http://localhost:11434`. Accepted without opt-in: `localhost`, `127.0.0.0/8` and `::1` (a syntactic check; no DNS lookup, no connection).
- Any other host is refused by default (typed `LLMConfigurationError`; the AI status becomes `fallback:LLMConfigurationError` and deterministic work continues).
- `LLM_ALLOW_NON_LOCAL_ENDPOINT=true` is an explicit operator trust decision. It permits a configured non-loopback **Ollama** endpoint only. It does not select or enable a cloud provider and does not add any fallback.
- Credentials inside the URL (`http://user:password@host`) are always rejected, with or without the flag. Error messages never echo the URL.
- The flag is an application-level allow decision, not a firewall or isolation control. A non-loopback endpoint is not necessarily a cloud endpoint (it may be another machine or container on a private network), and it must still be treated as an explicit trust relationship: prompts and evidence context are sent to it.

### 8.3 Docker networking implications
- The shipped `docker-compose.yml` defines a single `postgres` service (`aisop-postgres`, host port `5433` mapped to container `5432`). It defines no Ollama service, no backend or frontend container and no custom network; the backend and Ollama run on the host. No Compose-based Ollama hostname exists in this repository, so none is documented here.
- Generic Docker facts that matter if an operator containerizes the backend themselves (not a supported or shipped configuration): inside a container `localhost` and `127.0.0.1` are that container's own network namespace, not the Windows host and not another container, so a host-side Ollama is not reachable as `localhost`. A host alias (such as Docker Desktop's `host.docker.internal`) or a Compose service name is a non-loopback hostname and needs `LLM_ALLOW_NON_LOCAL_ENDPOINT=true`.
- A private Docker network is not the same as an internet-facing service, but it is still a network boundary.

### 8.4 Independent network egress restrictions (recommended; none is enforced or shipped by AISOP)
- Apply host firewall or container egress rules independently of AISOP; allow only the destinations required (the database, and the Ollama endpoint if non-loopback) and deny the rest.
- Keep Ollama on loopback or a private/internal network and do not publish its port beyond what is needed.
- Consider binding the PostgreSQL publish to loopback (`127.0.0.1:5433:5432`) if no other machine needs it. This is a recommendation only; the shipped compose file was not changed.
- Keep optional threat-intelligence egress separate from LLM egress. At present no concrete remote threat-intelligence provider exists in the code (only an abstract base).
- Audit browser traffic separately. The production frontend contains no CDN, remote script, remote font, analytics or service worker in source or build output, and its Content-Security-Policy limits connections to `self` plus `127.0.0.1:8000` and `localhost:8000`. Source and build inspection was supplemented on 2026-11-14 by one bounded headless-Edge load of the built UI with no backend running: every page request stayed same-origin and no service worker or WebSocket appeared. That run did not exercise an investigation workflow and did not record CSP violation reports; Edge itself also attempted its own Microsoft/Bing service calls, which were blocked by a resolver rule.

### 8.5 What the automated tests do and do not establish
Tests establish that the covered Python `httpx` and DNS paths make no prohibited outbound requests under the tested default and AI-disabled scenarios. They do not prove process-wide or host-wide isolation: browser traffic, raw sockets, other HTTP libraries, subprocesses, proxy environment variables and OS-level traffic are outside the guard, and redirect hops are invisible to a guard installed at `httpx send` (the application itself never enables `follow_redirects`). Do not describe AISOP as air-gapped or network-isolated on the basis of these tests.

### 8.6 Runtime tests (PostgreSQL and Ollama)
Marked tests are excluded from the default run (`-m "not postgres and not ollama"`). Exact node IDs, prerequisites and the controlled-run procedure are in the Task 2 acceptance report (`D:\AISOP-Backups\AISOP_Task2_Acceptance_2026-11-14_1800\01_POSTGRES_OLLAMA_TEST_INVENTORY.md`) and in `docs/Project_Management/Stage7B_PostgreSQL_Verification_Plan.md`. As of 2026-11-14 the two live Ollama embedding tests were executed and passed; the 37 PostgreSQL-marked tests were NOT executed, and a residual validation pass on 2026-11-14 confirmed they remain blocked (environment and approved disposable target not available to the assistant; see `AISOP_Task2_Residual_Validation_2026-11-14_2100`). Packet-level capture also remains not done.
