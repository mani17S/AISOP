# ADR-007: Vendor-Neutral Security Alert Ingestion Architecture & Adapter Registry

| Field | Value |
|---|---|
| **ID** | ADR-007 |
| **Status** | APPROVED |
| **Date Proposed** | 2026-10-31 |
| **Date Approved** | 2026-10-31 |
| **Decision Maker** | Project Owner & AISOP Architecture Team |
| **Supersedes / Extends** | Extends ADR-004 (Initial Telemetry Ingestion Scope) |

---

## 1. Context

In ADR-004, AISOP established a dual ingestion principle: define a canonical normalized schema first, and implement Microsoft Sysmon as the first concrete telemetry parser. While this satisfied Phase 1 requirements, the authoritative AISOP product vision mandates that AISOP operate as a **vendor-neutral, AI-assisted security operations platform** across heterogeneous security ecosystems (SIEM, EDR, Network IDS, Cloud Audit, and Email Gateways).

Relying exclusively on Sysmon or Windows-specific assumptions creates severe architectural limitations:
1. **Telemetry vs. Alert Conflation:** Low-level event observations (e.g. Sysmon Event ID 1 process creation) were treated identically to high-level detection findings (e.g. CrowdStrike EDR detections, Suricata network alerts, or AWS GuardDuty findings).
2. **Ecosystem Lock-In:** SOC teams utilize heterogeneous security stacks; a platform restricted to Windows endpoint events cannot investigate multi-stage, cloud, network, or identity-based attacks.
3. **Evidence Integrity:** Ingested alerts must preserve original vendor payloads verbatim with cryptographic SHA-256 integrity digests, preventing normalization data loss while enabling deterministic downstream correlation.

---

## 2. Industry Standards Evaluation

Before defining AISOP's canonical alert schema, four major cybersecurity industry standards were evaluated:

| Standard | Architectural Strengths | Limitations for AISOP Local-First MVP | AISOP Design Adoption |
|---|---|---|---|
| **OCSF (Open Cybersecurity Schema Framework)** | Deep taxonomy for security findings, system, and network activity; vendor-agnostic class hierarchy. | Deeply nested, verbose JSON structures with heavy schema overhead; cumbersome for lightweight local-first database operations. | Adopted OCSF finding classification categories (`category`, `severity`, `confidence`, `status`, `provider`). |
| **ECS (Elastic Common Schema)** | Widespread adoption in open-source SIEM; intuitive dot-notation (`host.*`, `user.*`, `process.*`, `threat.*`). | Strongly tied to Elasticsearch document models; flat dot-notation requires extensive indexing considerations in relational PostgreSQL. | Adopted ECS entity naming conventions for endpoint, network, and process objects. |
| **ASIM (Microsoft Sentinel)** | Normalized schema views for authentication, network, process, web, and DNS events. | Designed primarily for KQL query-time parsing in Azure Sentinel; proprietary operational conventions. | Adopted ASIM authentication failure and network session field mappings. |
| **STIX 2.1** | Industry standard for threat intelligence exchange; rich graph representations (SDOs, SCOs, SROs). | Graph-centric serialization is overly verbose for streaming SIEM alert ingestion; STIX is a threat intelligence exchange format, not a real-time SIEM alert schema. | Adopted STIX 2.1 observable types (`ip-addr`, `domain-name`, `file:hashes`, `process`) for IOC extraction. |

---

## 3. Decision

1. **Establish Canonical Alert Contract (`CanonicalAlert`):**
   AISOP defines a dedicated Pydantic v2 `CanonicalAlert` schema in `app.schemas.alert` that captures upstream detection findings, normalized severities (`informational`, `low`, `medium`, `high`, `critical`, `unknown`), standard alert categories (aligned with MITRE ATT&CK enterprise tactics), and structured observables.

2. **Differentiate Telemetry, Alert, Evidence, and Investigation:**
   - **Security Alert:** A detection finding produced by an upstream detection engine or security tool.
   - **Raw Telemetry:** Low-level underlying logs (e.g. Sysmon, Linux auditd, network flows).
   - **Evidence:** Cryptographically hashed (SHA-256) immutable artifact stored in the platform with chain-of-custody.
   - **Investigation:** A case-scoped container binding alerts, evidence, entities, threat intelligence, timeline, and AI-synthesized findings.

3. **Implement Extensible Adapter Registry (`AlertAdapterRegistry`):**
   New log/alert formats are integrated via the `BaseAlertAdapter` protocol without altering core pipeline components. A default registry (`get_default_registry()`) provides built-in support for 8 canonical source categories:
   - `SysmonAlertAdapter`: Microsoft Sysmon event logs (Event IDs 1, 3, 7, 10, 11, 22).
   - `WindowsSecurityAdapter`: Windows Security Event IDs 4624, 4625, 4688, 4720, 1102.
   - `LinuxAuthAdapter`: Linux authentication, sshd brute-force, and sudo privilege escalation.
   - `EdrMalwareAdapter`: EDR detections (CrowdStrike Falcon, Microsoft Defender, SentinelOne).
   - `NetworkIdsAdapter`: Network intrusion detection systems (Suricata EVE-JSON, Snort, Zeek).
   - `CloudAuditAdapter`: Cloud IAM and suspicious logins (AWS GuardDuty, CloudTrail, Azure Entra ID, GCP Audit).
   - `EmailPhishingAdapter`: Email security gateways (Proofpoint TAP, Defender for O365).
   - `GenericSiemAdapter`: Enterprise SIEM correlation alerts (Splunk ES Notable Events, Microsoft Sentinel Incidents, Elastic Security).

4. **Zero-Breaking-Change Persistence via `to_canonical_event()`:**
   To maintain 100% backward compatibility with AISOP's existing `NormalizedEventModel`, `ExtractedEntityModel`, `CaseEvidenceModel`, and `ContextBuilder`, every `CanonicalAlert` seamlessly projects into a `CanonicalEvent`.

5. **Cryptographic Provenance & Full Fidelity:**
   The original raw alert payload is preserved verbatim in `RawEvidence.raw_payload` with a SHA-256 digest (`raw_ref`). Unmapped vendor attributes are preserved in `custom_fields`.

---

## 4. Consequences

### Positive
- **Vendor-Neutrality:** Ingestion is decoupled from any single operating system or security product.
- **Immediate Ecosystem Coverage:** Built-in adapters for endpoint, network, cloud, identity, and email alert types.
- **Architectural Stability:** Downstream AI investigation, context assembly, and reporting require zero modifications.
- **Strict Deduplication:** Automatic SHA-256 deduplication across batches and database transactions with zero orphaned records.

### Negative / Trade-Offs
- Adapters require maintenance if upstream vendors introduce breaking changes to their proprietary export formats.
- High-volume alert streams require indexing on `event_type` and `event_timestamp` in PostgreSQL (already implemented in P1-H5).

