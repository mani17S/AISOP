# AISOP — Viva Demo Identity Provisioning & Operations Runbook

**Document Identifier:** AISOP-DOC-VIVA-RUNBOOK-2026-001  
**Milestone:** Post-P4-GOV Engineering Hardening / Phase 6  
**Audience:** Academic Viva Examiners, Platform Operators, Demonstrator  
**Classification:** Operational Guide (Internal / Academic Demonstration)

---

## 1. Overview & Trust Architecture

AISOP is a local-first, evidence-first, human-in-the-loop security operations platform. To prepare the platform for an academic viva demonstration without disabling authentication, weakening RBAC, or bypassing case-level authorization, two distinct identities must be provisioned:

| Identity | Username | Global Role | Associated Client | Purpose & Scope |
| :--- | :--- | :--- | :--- | :--- |
| **Demo Analyst** | `viva_analyst` | `analyst_tier_1` | `viva-tier1-workstation` | Human analyst session. Authorized for alert triage, case creation, evidence linking, and AI investigation synthesis. **Blocked from raw ingestion and administrative case closure.** |
| **Ingestion Sensor** | `viva_sensor` | `ingest` | `viva-sysmon-forwarder` | Machine-to-machine service client. Authorized strictly for raw alert and telemetry ingestion via `POST /api/v1/alerts/ingest`. **Blocked from analyst triage, case management, and reports.** |

```
[ SIEM / Sensor Egress ]
          |
          | (Token: viva_sensor)
          v
[ POST /api/v1/alerts/ingest ] ──(can_ingest_telemetry == True)──> [ PostgreSQL + pgvector ]
                                                                             |
[ React Analyst Frontend ]                                                   |
          |                                                                  v
          | (Token: viva_analyst)                                    [ Case Scoping & RBAC ]
          v                                                                  |
[ GET /api/v1/alerts | POST /api/v1/cases ] ──(can_access_global_event_triage)──+
```

---

## 2. Step 1: Provisioning Demo Identities

The provisioning script [`backend/scripts/provision_demo_identities.py`](file:///D:/AISOP/backend/scripts/provision_demo_identities.py) generates high-entropy canonical credentials, computes their SHA-256 digests, checks for database collisions, and commits the records atomically.

### Command Execution
Open a PowerShell terminal in `D:\AISOP` within the activated Python environment:

```powershell
Set-Location -Path "D:\AISOP"
.\.venv\Scripts\Activate.ps1

python backend/scripts/provision_demo_identities.py --expires-in-hours 48
```

> [!NOTE]
> The utility prompts the operator for interactive confirmation before performing database writes. To run in automated or non-interactive environments, append `--yes` or `-y`.

### One-Time Credential Output
The script prints the newly generated credentials directly to terminal stdout:

```text
========================================================================================
  AISOP DEMO IDENTITY PROVISIONING - SECURE ONE-TIME CREDENTIAL OUTPUT
========================================================================================
  WARNING: Plaintext credentials are displayed EXACTLY ONCE and cannot be
  recovered from the database. Copy and store them securely for the viva.
----------------------------------------------------------------------------------------
  Identity:    Demo Security Analyst (Tier-1 Triage & Investigation)
  Username:    viva_analyst
  Global Role: analyst_tier_1
  Client Name: viva-tier1-workstation
  Token Prefix:<16-hex-prefix>
  API TOKEN:   aisop_live_<16-hex-prefix>_<64-hex-secret>
----------------------------------------------------------------------------------------
  Identity:    System Ingest Identity (Sysmon / SIEM Forwarder)
  Username:    viva_sensor
  Global Role: ingest
  Client Name: viva-sysmon-forwarder
  Token Prefix:<16-hex-prefix>
  API TOKEN:   aisop_live_<16-hex-prefix>_<64-hex-secret>
========================================================================================
```

> [!CAUTION]
> The plaintext tokens are **never stored** in the database. The database persists only `token_prefix` and the cryptographic SHA-256 digest `hashed_secret`. Copy the printed tokens immediately.

---

## 3. Step 2: Configure the Analyst Frontend

1. Ensure the backend and frontend are running:
   - Backend: `http://127.0.0.1:8000`
   - Frontend: `http://127.0.0.1:3000`
2. Open `http://127.0.0.1:3000` in a browser.
3. Observe the initial state: metric cards display `"Auth Required"`, and the case table displays `"Authentication required. Configure your API key to load case data."`
4. Click **Set API Key** in the top navigation bar.
5. Paste the generated `viva_analyst` token into the modal input field.
6. Click **Save Key**.
7. **Verification**: The Dashboard immediately reloads. The metric cards transition from `"Auth Required"` to numeric counts (`0`), and the table placeholder updates to `"No active cases found in current assignment scope."`

---

## 4. Step 3: Ingest Synthetic Telemetry via Sensor Identity

Use the `viva_sensor` token to submit a synthetic vendor alert batch to the ingestion endpoint:

```powershell
$SensorToken = "aisop_live_<viva_sensor_token_here>"

curl.exe -s -X POST http://127.0.0.1:8000/api/v1/alerts/ingest `
  -H "X-API-Key: $SensorToken" `
  -H "Content-Type: application/json" `
  -d @datasets/samples/alerts/edr_crowdstrike_malware.json
```

### Expected JSON Response
```json
{
  "batch_id": "<uuid>",
  "source_type": "edr_malware",
  "total_received": 1,
  "total_normalized": 1,
  "total_skipped_duplicates": 0,
  "total_entities_extracted": 6,
  "alert_ids": ["<uuid>"],
  "errors": []
}
```

---

## 5. Step 4: Verify Case Scoping and RBAC Separation

### A. Verify Ingestion Boundary Enforcement
Demonstrate that the sensor identity is strictly quarantined from analyst triage operations:

```powershell
# Ingestion identity attempts to query alerts triage queue -> HTTP 403 Forbidden
curl.exe -s -i -H "X-API-Key: $SensorToken" http://127.0.0.1:8000/api/v1/alerts

# Ingestion identity attempts to create an incident case -> HTTP 403 Forbidden
curl.exe -s -i -H "X-API-Key: $SensorToken" -X POST http://127.0.0.1:8000/api/v1/cases `
  -H "Content-Type: application/json" -d '{"title":"Unauthorized"}'
```

### B. Verify Analyst Triage and Case Escalation
1. In the browser (`http://127.0.0.1:3000`), navigate to the **Alerts** tab.
2. The ingested CrowdStrike malware alert appears in the triage queue with canonical MITRE ATT&CK tags and extracted observables.
3. Click on the alert row to open the detail inspection modal.
4. Click **Promote to Case** to create a new security incident case.
5. In the **Cases** tab, click the newly created case row to open the **Investigation Workspace**.
6. Demonstrate human-in-the-loop AI investigation synthesis by clicking **Run AI Synthesis**.

---

## 6. Step 5: Credential Rotation (In-Place Token Renewal)

### Initial Provisioning vs. Credential Rotation

| Operation | Command | When to Use | Database Behavior |
| :--- | :--- | :--- | :--- |
| **Initial Provisioning** | `python backend/scripts/provision_demo_identities.py` | First-time viva setup when identities do not yet exist. | **Inserts** new records in `analysts` and `analyst_api_clients`. Fails closed if records already exist. |
| **Credential Rotation** | `python backend/scripts/provision_demo_identities.py --rotate` | Rehearsal completed, credential exposed, or refreshing token window before examination. | **Updates in-place** `token_prefix`, `hashed_secret`, and `expires_at`. **Strictly preserves** analyst UUIDs, client UUIDs, case assignments, creation timestamps, and audit history. |

### When to Execute Rotation
- Prior to the live viva if a rehearsal was conducted with previous credentials.
- If a demo credential was accidentally shared or printed in an insecure environment.
- To re-enable demo identities after a previous revocation (`--revoke`) without destroying existing test cases.

### Rotation Execution Command
```powershell
Set-Location -Path "D:\AISOP"
.\.venv\Scripts\Activate.ps1

python backend/scripts/provision_demo_identities.py --rotate --expires-in-hours 48
```

> [!NOTE]
> The rotation command requires interactive confirmation (`yes`) before committing changes to the database. Use `--yes` or `-y` to bypass prompts in automation scripts.

### Operator Actions After Rotation
1. Immediately copy the new `viva_analyst` canonical token from the stdout output.
2. In the React frontend (`http://127.0.0.1:3000`), click **Key Configured** (or **Set API Key**) in the navigation header.
3. Replace the old token with the new rotated token and click **Save Key**.
4. Existing cases, case assignments, and triage history remain accessible without interruption.
5. All subsequent requests using old tokens will immediately receive `HTTP 401 Unauthorized`.

---

## 7. Step 6: Post-Viva Credential Revocation

Immediately upon concluding the examination, deactivate both demo credentials without altering audit history or evidence records:

```powershell
python backend/scripts/provision_demo_identities.py --revoke --yes
```

### Verification of Revocation
Attempt to access any protected endpoint with either token:

```powershell
curl.exe -s -i -H "X-API-Key: $AnalystToken" http://127.0.0.1:8000/api/v1/cases
# Expected Output: HTTP/1.1 401 Unauthorized ("Invalid authentication credentials.")
```

### Inspection Utility
To verify identity status at any time without modifying database records:

```powershell
python backend/scripts/provision_demo_identities.py --status
```

