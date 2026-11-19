# AISOP — Alert Retrieval & Triage API Specification

**Document Version:** 1.1.0  
**Date:** 2026-10-31  
**Status:** IMPLEMENTED & TEST-VERIFIED (18/18 UNIT TESTS PASSING)  
**Target Module:** `backend/app/api/v1/endpoints/alerts.py`  
**Governing Architecture:** ADR-007 (Vendor-Neutral Alert Ingestion) & Decision 1A (Sanitized Projections)  

---

## 1. Overview & Architectural Motivation

This specification defines the backend API contract for retrieving, filtering, and inspecting persisted security alerts in AISOP.

### Problem Statement
The current API exposes `POST /api/v1/alerts/ingest` and `GET /api/v1/alerts/adapters`. However:
1. There is no `GET /api/v1/alerts` endpoint for the frontend triage queue (`Alerts.tsx`).
2. The existing telemetry endpoint `GET /api/v1/evidence/events` returns `SanitizedNormalizedEventSummary`, which strips the alert title, description, category, triage status, MITRE tactics, observables, and vendor attributes.
3. Direct unscoped event detail retrieval via `GET /api/v1/evidence/events/{event_id}` is disabled with `HTTP 403 Forbidden`.

To unblock Phase 4A frontend development without weakening security boundaries, AISOP requires two dedicated alert retrieval endpoints.

---

## 2. API Endpoint 1: List Alerts for Triage Queue

### 2.1 Route Definition
- **HTTP Method:** `GET`
- **Path:** `/api/v1/alerts`
- **Tags:** `["Alerts & Multi-Source Ingestion"]`
- **Summary:** `Paginated list of security alerts for SOC triage queue`

### 2.2 Security & Authorization
- **Authentication:** Mandatory HTTP `Authorization: Bearer <token>` or `X-API-Key: <token>`.
- **Enforcing Dependency:** `client: AuthenticatedClient = Depends(verify_api_key)`.
- **RBAC Policy:** Requires human analyst identity (`client.analyst is not None`) and `can_access_global_event_triage(client.analyst.global_role)`:
  - Permitted: `analyst_tier_1`, `analyst_tier_2`, `security_admin`.
  - Rejected: Machine tokens (`HTTP 403`), Ingest tokens (`HTTP 403`).

### 2.3 Query Parameters

| Parameter | Type | Required | Default | Constraints | Description |
|:---|:---|:---:|:---:|:---|:---|
| `page` | `integer` | No | `1` | `ge=1` | 1-indexed page number |
| `limit` | `integer` | No | `20` | `ge=1, le=100` | Number of alerts per page |
| `source_type` | `string` | No | `None` | Max 50 chars | Filter by vendor source adapter (`sysmon`, `edr_malware`, `windows_security`, etc.) |
| `severity` | `string` | No | `None` | Canonical severity | Filter by `critical`, `high`, `medium`, `low`, `informational` |
| `category` | `string` | No | `None` | Canonical category | Filter by alert category (`malware`, `credential_access`, `execution`, etc.) |
| `status` | `string` | No | `None` | `new, triaged, investigating, closed` | Filter by triage lifecycle status |
| `start_time` | `datetime` | No | `None` | ISO 8601 UTC | Filter alerts observed on or after timestamp |
| `end_time` | `datetime` | No | `None` | ISO 8601 UTC | Filter alerts observed on or before timestamp |
| `search` | `string` | No | `None` | Max 200 chars | Case-insensitive search on title and description |
| `source_identifier` | `string` | No | `None` | Max 255 chars | Filter by endpoint or sensor hostname |

### 2.4 Response Contract (`AlertSummaryResponse`)

```json
{
  "items": [
    {
      "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "source_alert_id": "SEC-EVT-4625-FAILED-LOGIN-9912",
      "source_type": "windows_security",
      "provider": "microsoft_windows",
      "title": "Multiple Failed Logon Attempts (Event ID 4625)",
      "description": "An account failed to log on due to bad credentials",
      "category": "credential_access",
      "severity": "high",
      "vendor_severity": "High",
      "status": "new",
      "timestamp": "2026-10-31T09:30:00Z",
      "ingested_at": "2026-10-31T09:35:12Z",
      "source_identifier": "DC01.corp.local",
      "mitre_attack": [
        {
          "tactic_id": "TA0006",
          "tactic_name": "Credential Access",
          "technique_id": "T1110.001",
          "technique_name": "Password Guessing"
        }
      ],
      "top_observables": [
        {
          "type": "ip",
          "value": "192.168.1.105",
          "relevance": "suspicious"
        }
      ],
      "has_case": false
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 20,
  "total_pages": 1,
  "has_next": false,
  "has_previous": false
}
```

---

## 3. API Endpoint 2: Get Alert Detail for Triage Modal

### 3.1 Route Definition
- **HTTP Method:** `GET`
- **Path:** `/api/v1/alerts/{alert_id}`
- **Tags:** `["Alerts & Multi-Source Ingestion"]`
- **Summary:** `Get complete canonical alert detail for triage inspection`

### 3.2 Security & Authorization
- **Authentication:** Mandatory HTTP `Authorization: Bearer <token>` or `X-API-Key: <token>`.
- **RBAC Policy:** `can_access_global_event_triage` (`analyst_tier_1`, `analyst_tier_2`, `security_admin`).
- **Data Protection:** Returns full canonical alert structure, entities, observables, MITRE tactics, and unmapped custom vendor fields. **Strictly excludes `raw_payload`** (raw evidence payloads remain accessible only via case-scoped evidence investigations or security admin audit).

### 3.3 Response Contract (`AlertDetailResponse`)

```json
{
  "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "source_alert_id": "SEC-EVT-4625-FAILED-LOGIN-9912",
  "source_type": "windows_security",
  "provider": "microsoft_windows",
  "title": "Multiple Failed Logon Attempts (Event ID 4625)",
  "description": "An account failed to log on due to bad credentials",
  "category": "credential_access",
  "severity": "high",
  "vendor_severity": "High",
  "status": "new",
  "timestamp": "2026-10-31T09:30:00Z",
  "ingested_at": "2026-10-31T09:35:12Z",
  "source_identifier": "DC01.corp.local",
  "raw_ref": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "mitre_attack": [
    {
      "tactic_id": "TA0006",
      "tactic_name": "Credential Access",
      "technique_id": "T1110.001",
      "technique_name": "Password Guessing"
    }
  ],
  "entities": [
    {
      "entity_type": "user",
      "entity_value": "Administrator",
      "role": "target",
      "attributes": { "domain": "CORP" }
    },
    {
      "entity_type": "ip",
      "entity_value": "192.168.1.105",
      "role": "attacker",
      "attributes": { "port": 49152 }
    }
  ],
  "observables": [
    {
      "type": "ip",
      "value": "192.168.1.105",
      "relevance": "suspicious"
    }
  ],
  "host": {
    "hostname": "DC01.corp.local",
    "ip_addresses": ["192.168.1.10"]
  },
  "user": {
    "username": "Administrator",
    "domain": "CORP"
  },
  "custom_fields": {
    "LogonType": "3",
    "Status": "0xc000006d",
    "SubStatus": "0xc000006a"
  },
  "associated_case_ids": []
}
```

---

## 4. Proposed Pydantic Schemas (`app/schemas/alert_query.py`)

```python
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.alert import AlertCategory, AlertObservable, AlertSeverity, AlertStatus, MitreAttackReference
from app.schemas.entities import DnsEntity, FileEntity, HostEntity, NetworkEntity, ProcessEntity, RegistryEntity, UserEntity


class AlertSummaryItem(BaseModel):
    """Sanitized projection of a security alert for the triage queue."""
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(description="Normalized event UUID (serves as evidence_id)")
    source_alert_id: str = Field(description="Upstream vendor alert ID")
    source_type: str = Field(description="Source adapter type")
    provider: str = Field(description="Vendor provider name")
    title: str = Field(description="Alert headline")
    description: str | None = Field(default=None, description="Alert description")
    category: AlertCategory = Field(description="Canonical category")
    severity: AlertSeverity = Field(description="Canonical severity")
    vendor_severity: str | None = Field(default=None, description="Original vendor severity")
    status: AlertStatus = Field(default="new", description="Triage status")
    timestamp: datetime = Field(description="Occurrence timestamp (UTC)")
    ingested_at: datetime = Field(description="Ingestion timestamp (UTC)")
    source_identifier: str | None = Field(default=None, description="Endpoint/host identifier")
    mitre_attack: list[MitreAttackReference] = Field(default_factory=list)
    top_observables: list[AlertObservable] = Field(default_factory=list)
    has_case: bool = Field(default=False, description="Whether alert is associated with at least one case")


class AlertDetailResponse(BaseModel):
    """Detailed canonical alert structure for triage inspection."""
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(description="Normalized event UUID")
    source_alert_id: str = Field(description="Upstream vendor alert ID")
    source_type: str = Field(description="Source adapter type")
    provider: str = Field(description="Vendor provider name")
    title: str = Field(description="Alert title")
    description: str | None = Field(default=None, description="Alert description")
    category: AlertCategory = Field(description="Canonical category")
    severity: AlertSeverity = Field(description="Canonical severity")
    vendor_severity: str | None = Field(default=None, description="Original vendor severity")
    status: AlertStatus = Field(default="new", description="Triage status")
    timestamp: datetime = Field(description="Occurrence timestamp (UTC)")
    ingested_at: datetime = Field(description="Ingestion timestamp (UTC)")
    source_identifier: str | None = Field(default=None, description="Host/sensor identifier")
    raw_ref: str = Field(description="Cryptographic SHA-256 digest of raw alert payload")
    mitre_attack: list[MitreAttackReference] = Field(default_factory=list)
    entities: list[dict[str, Any]] = Field(default_factory=list)
    observables: list[AlertObservable] = Field(default_factory=list)
    host: HostEntity | None = None
    user: UserEntity | None = None
    process: ProcessEntity | None = None
    network: NetworkEntity | None = None
    file: FileEntity | None = None
    dns: DnsEntity | None = None
    registry: RegistryEntity | None = None
    custom_fields: dict[str, Any] = Field(default_factory=dict)
    associated_case_ids: list[uuid.UUID] = Field(default_factory=list)
```

---

## 5. Security & Governance Invariants

1. **Anti-Tampering:** Neither `GET /api/v1/alerts` nor `GET /api/v1/alerts/{alert_id}` mutates database state.
2. **Denial of Raw Payload Exposure:** In strict adherence to Decision 1A and the principle of least privilege, `RawEvidence.raw_payload` is **NEVER** returned by alert query endpoints. Only canonical normalized representations and cryptographic `raw_ref` hashes are emitted.
3. **Fail-Closed Permissions:** Machine clients without an authenticated human analyst identity receive `HTTP 403 Forbidden`. Ingest-only tokens receive `HTTP 403 Forbidden`.
4. **Anti-XSS & Break-Word Rendering:** All textual fields (titles, paths, command lines, hashes) returned by the API must be safely escaped by frontend consumers and formatted with CSS word-break rules (`break-all`).

