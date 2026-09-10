# ADR-004: Initial Telemetry Ingestion Scope

| Field | Value |
|-------|-------|
| **ID** | ADR-004 |
| **Status** | APPROVED |
| **Date Proposed** | 2026-09-09 |
| **Date Approved** | 2026-09-09 |
| **Decision Maker** | Project Owner |

---

## Question

Which security telemetry format(s) should AISOP's first parser implementation
target, and how should the normalization interface be designed?

## Context

AISOP's core value proposition is: ingest security telemetry → normalize →
correlate → investigate with AI assistance → report. Without an ingestion
pipeline that can parse at least one real-world log format, the platform
cannot demonstrate its intended value.

This decision shapes:

- The **normalization schema** — the common data model all evidence conforms
  to.
- The **entity types** extracted — determining what the correlation engine can
  link.
- The **MITRE ATT&CK coverage** — which techniques can be automatically
  mapped.
- The **test data availability** — whether we can build meaningful, realistic
  test suites with publicly available attack datasets.
- The **academic/demonstration value** — for project evaluation and
  demonstration.

AISOP Master Prompt references:

- §28: *"Do not attempt to build entire SOC, entire SIEM. Instead build a
  strong CORE that can evolve."*
- §6: SOC / Blue Team / Security Investigation remains the PRIMARY product
  focus.
- §3: The intended positioning sits between SIEM/Logs/Telemetry and the
  Analyst.

## Options Considered

### Option A: Windows Security Event Logs / Sysmon (JSON Exports)

Support Sysmon events (Event IDs 1, 3, 7, 8, 10, 11, 22, etc.) and Windows
Security events (Event IDs 4624, 4625, 4688, 4720, 4732, etc.) exported as
JSON.

Entity types extracted: process name, command line, PID/PPID hierarchy, user
account, source/dest IP, source/dest port, file hash, file path, registry
key, DNS query, image loaded.

MITRE ATT&CK coverage: Extremely high — directly covers Execution,
Persistence, Privilege Escalation, Defense Evasion, Credential Access,
Lateral Movement, Discovery, and C2 technique categories.

### Option B: Network Telemetry (Zeek / Suricata JSON)

Support Zeek connection/DNS/HTTP/SSL logs and Suricata EVE JSON alert/flow
logs.

Entity types extracted: source/dest IP, port, protocol, DNS queries, HTTP
host/URI, TLS certificate details, flow metadata, Suricata signature details.

MITRE ATT&CK coverage: Strong for network-observable techniques (C2,
Exfiltration, Initial Access, Discovery), but blind to endpoint-level
techniques (process injection, credential dumping, registry modification).

### Option C: Generic Normalized Security JSON (ECS/OCSF-Inspired Schema)

Define an AISOP-internal normalized event schema inspired by Elastic Common
Schema (ECS) or Open Cybersecurity Schema Framework (OCSF). Build the parser
interface to accept pre-normalized events conforming to this schema. Specific
log format parsers then become adapters transforming raw logs into the
normalized format.

Entity types: format-agnostic, defined by the schema. MITRE ATT&CK coverage:
depends on the source data feeding into it.

## Trade-Off Analysis

| Criterion | Option A: Sysmon | Option B: Zeek/Suricata | Option C: Generic |
|-----------|-----------------|------------------------|-------------------|
| Local-First Deployment | Strong | Adequate | Strong |
| Open-Source Extensibility | Strong | Adequate | Adequate |
| Modularity | Strong | Strong | Strong |
| Security | Strong | Strong | Adequate |
| Maintainability | Strong | Strong | Strong |
| Scalability | Adequate | Adequate | Adequate |
| Developer Experience | Strong | Adequate | Adequate |
| Testing | Strong | Adequate | Adequate |
| Operational Complexity | Adequate | Adequate | Strong |

Key insight: Option C defines the interface (architectural contract), while
Option A provides the first high-value implementation of that interface.
They are complementary, not competing.

## Recommendation

Combined Option A + C was recommended:

1. Design the AISOP Normalized Event Schema first (Option C — the interface
   contract).
2. Implement the Sysmon/Windows Event Log parser as the first concrete
   implementation (Option A — the first adapter).

This gives immediately testable, real-world value while establishing the
modular parser architecture that allows future formats to be added without
redesigning the core.

## Decision (Project Owner — 2026-09-09)

**APPROVED: Canonical normalized event schema first (Option C), followed by
Sysmon as the first concrete parser (Option A).**

The canonical event schema is the architectural contract. All parsers produce
normalized events conforming to this schema. All downstream consumers
(correlation, AI, reporting) depend only on this schema.

Sysmon is the first implementation target because AISOP's primary focus is
SOC/Blue Team investigation and Sysmon provides the richest endpoint
telemetry for this domain.

The ingestion architecture must remain extensible so future sources (Windows
Event Logs, Zeek, Suricata, generic JSON, SIEM exports) can be added without
redesigning AISOP Core.

## Architectural Consequences

1. A **Normalized Event Schema** must be designed as a Pydantic model before
   any parser implementation. This schema becomes a foundational data
   contract for the entire platform.
2. The schema should be inspired by ECS/OCSF naming conventions but remain
   AISOP-specific and pragmatic — not a full ECS reimplementation.
3. Entity extraction produces strongly typed objects: `IPAddress`, `HostName`,
   `UserAccount`, `FileHash`, `ProcessExecution`, `NetworkConnection`.
4. A `Parser` protocol/interface is defined, and `SysmonParser` is the first
   concrete implementation.
5. Adding Zeek/Suricata later is a bounded task: implement the parser
   interface for the new format, add format-specific tests.
6. Test suites should use real-world Sysmon attack datasets (e.g.,
   EVTX-ATTACK-SAMPLES, Mordor/Security Datasets).
7. The `datasets/` directory structure (raw, processed, samples, ground_truth)
   aligns well with this approach — raw Sysmon JSON samples and expected
   normalized outputs for test validation.

## Risks

1. **Risk (Medium): Sysmon Field Variability.** Different Sysmon
   configurations enable different event types and fields. The parser must
   handle missing optional fields gracefully. **Mitigation:** Pydantic models
   with `Optional` fields; test against multiple Sysmon configurations and
   export tools.
2. **Risk (Low): XML vs. JSON Representation.** Raw Sysmon logs are Windows
   Event Log XML. The JSON representation varies by export tool.
   **Mitigation:** Target the JSON export format specifically; document the
   expected export procedure; consider supporting both XML and JSON ingestion
   in a future iteration.
3. **Risk (Low): Schema Evolution.** As new log formats are added, the
   normalized schema may need new fields or entity types. **Mitigation:**
   Design the schema with explicit versioning and optional extension fields
   from the start.
