# AISOP Threat Intelligence Architecture Specification — Milestone TI-3B: Provider-Neutral Multi-Source Orchestration

**Document Version:** 1.0.0  
**Date:** 2026-10-22  
**Status:** Approved for Implementation (Design Gate Pass)  
**Workspace:** `D:\AISOP`  
**Target Milestone:** TI-3B — Multi-Provider Threat Intelligence Orchestration  
**Preceding Verification:** TI-3A Remediation Verification (`TI-3A_Remediation_Report.md`) — PASS  
**Cost Compliance Status:** ₹0 Cost / 100% Local-First / Zero Cloud Dependencies / Zero Destructive DB Operations  

---

## 1. Executive Summary & Architectural Mission

The mission of **Milestone TI-3B** is to transition AISOP from a purely local threat-intelligence lookup engine into a **provider-neutral, fault-tolerant, privacy-preserving multi-source intelligence orchestrator (`ThreatIntelOrchestrator`)**.

### Core Architecture Principles
1. **Local Intelligence First:** Offline local feeds and local memory caches are always evaluated first with 0ms network latency and ₹0 financial cost. High-confidence local matches short-circuit unnecessary external queries.
2. **Strict Privacy & OPSEC Guardrails:**
   - External provider lookups are **disabled globally by default** (`ENABLE_EXTERNAL_THREAT_INTEL = False`).
   - Every external query requires an **explicit per-request opt-in** (`allow_external_lookup = True`).
   - **Mandatory Private Network Shielding:** Internal enterprise observables (RFC 1918, link-local, loopback, multicast, `.internal`/`.corp` domains) are intercepted and shielded—they are **never** transmitted to external providers.
3. **Data Minimization:** Only the normalized observable value (e.g. `198.51.100.1`) and its type are transmitted to external adapters. Raw telemetry, process arguments, hostnames, usernames, event IDs, and evidence hashes are strictly withheld.
4. **Resilience & Fault Isolation:** External lookups execute concurrently via bounded workers (`asyncio.Semaphore`), strict per-provider timeouts (2.5s), token-bucket rate limiters, and three-state circuit breakers (`CLOSED`, `OPEN`, `HALF_OPEN`). A failure, timeout, or rate-limit trip in one provider cannot abort or degrade lookups from other providers.
5. **Deterministic Conflict Resolution:**
   - Hierarchy: `MALICIOUS` > `SUSPICIOUS` > `BENIGN` > `UNKNOWN`.
   - A single provider's `BENIGN` rating can **never** override another provider's `MALICIOUS` detection.
   - Complete multi-source provenance (individual verdicts, reputation scores, reference links, and freshness timestamps) is preserved in `sources: list[dict]`.
6. **Zero-Cost & Contract Testing:** All external provider adapters are verified against verified free-tier terms. The test suite operates 100% offline using synthetic mock adapters without live network requests or real API keys.

---

## 2. Component Architecture & Request Flow

```text
                           Extracted Entity from Telemetry
                                       │
                                       ▼
                     [ Private Network & Internal Shield ]
             (Is RFC 1918 / RFC 4193 / Link-Local / Corp Domain?)
                                │               │
                           [YES]│               │[NO]
                                ▼               ▼
                    Return SHIELDED_INTERNAL   Tier 1: LocalThreatIntelEngine
                     (Zero External Egress)    (0ms, Offline, In-Memory Cache)
                                                       │
                                     ┌─────────────────┴─────────────────┐
                                     ▼                                   ▼
                          Definitive Local Match?               No Local Match / Unlisted
                          (e.g. MALICIOUS C2)                            │
                                     │                                   ▼
                                     │                  External Lookups Globally Enabled?
                                     │                  (ENABLE_EXTERNAL_THREAT_INTEL=True)
                                     │                  AND Request Opt-In Granted?
                                     │                  (allow_external_lookup=True)
                                     │                                   │
                                     │                        ┌──────────┴──────────┐
                                     │                   [NO] │                [YES]│
                                     │                        ▼                     ▼
                                     │                  Return Local          Tier 2: External
                                     │                   Findings               Orchestrator
                                     │                                              │
                                     │                                ┌─────────────┼─────────────┐
                                     │                                ▼             ▼             ▼
                                     │                           AbuseIPDB     VirusTotal      OTX
                                     │                           (Rate Limit:  (Rate Limit:   (Rate Limit:
                                     │                            1000/day)     4/min)         10/sec)
                                     │                                │             │             │
                                     │                                └─────────────┬─────────────┘
                                     │                                              ▼
                                     │                                Deterministic Multi-Source
                                     │                                   Verdict Synthesis
                                     │                                              │
                                     └───────────────────────┬──────────────────────┘
                                                             ▼
                                                 ThreatIntelFindingItem
                                                (Full Source Provenance)
```

---

## 3. Privacy, OPSEC & Data Protection Specifications

### 3.1 Private Network Shielding (`PrivateNetworkShield`)
Any observable matching internal private infrastructure represents confidential enterprise network topology. Inadvertently querying public multi-scanners leaks active security incident details to third parties.

The `PrivateNetworkShield` executes before any external adapter is invoked:

#### Blocked IP Ranges
- **RFC 1918 Private IPv4:**
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- **RFC 3927 Link-Local IPv4:** `169.254.0.0/16`
- **Loopback IPv4:** `127.0.0.0/8`
- **RFC 5737 Documentation IPv4:** `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
- **RFC 2544 / RFC 6815 Benchmark IPv4:** `198.18.0.0/15`
- **Multicast / Broadcast IPv4:** `224.0.0.0/4`, `255.255.255.255/32`
- **RFC 4193 Unique Local IPv6:** `fc00::/7`
- **RFC 4291 Link-Local IPv6:** `fe80::/10`
- **Loopback IPv6:** `::1/128`

#### Blocked Domain Patterns
- **Reserved Top-Level Domains (RFC 2606 / RFC 6761):** `.test`, `.example`, `.invalid`, `.localhost`.
- **Special-Use & Local Network Suffixes:** `.local`, `.internal`, `.corp`, `.lan`, `.home`, `.arpa`.
- **Single-Label Unqualified Hostnames:** Hostnames lacking dots (e.g. `DC-01`, `FILESRV`, `localhost`).

#### Shield Action
When an observable matches the shield:
- Status: `ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE`
- Verdict: `ThreatVerdict.UNKNOWN`
- State: `InvestigationFindingState.SHIELDED_INTERNAL`
- Error Message: `"Observable belongs to private/internal network; external lookups blocked for OPSEC protection."`
- **Zero network requests** are dispatched.

### 3.2 Data Minimization Rule
When querying an approved external provider:
- **Transmitted Data:** Only `observable.normalized_value` and its HTTP query parameter or URL path (e.g. `/api/v3/ip_addresses/{ip}`).
- **Withheld Data:** Raw Sysmon payloads, process command lines, parents, paths, usernames, workstation hostnames, event timestamps, internal IP addresses, and AISOP event UUIDs.

---

## 4. Provider Adapter Specifications & Cost Terms Audit

In accordance with AISOP's non-negotiable **₹0 cost constraint**, all candidate providers have been audited against official published developer documentation:

| Provider | Supported Types | Free Tier Limits | Terms & Constraints | OPSEC Risk | Approval Status |
|:---|:---:|:---|:---|:---:|:---:|
| **Local Feeds (Feodo / Tor)** | `ip` | Unlimited (Local memory) | CC0 / Public Domain. 100% offline. | **None** | **APPROVED (Default)** |
| **abuse.ch (URLhaus / ThreatFox)** | `domain`, `ip`, `file_hash` | Generous community API | Free for non-profit security research. | **Low** | **APPROVED (Tier 2)** |
| **AbuseIPDB** | `ipv4`, `ipv6` | 1,000 checks / day | Free for individual / non-commercial use. Key required. | **Medium** | **APPROVED (Tier 2)** |
| **AlienVault OTX** | `ip`, `domain`, `file_hash` | Community soft cap ~10k/day | Free community account. Key required. | **Medium** | **APPROVED (Tier 2)** |
| **VirusTotal (Google)** | `ip`, `domain`, `file_hash` | 4 req/min, 500 req/day | Strictly non-commercial. Samples shared with partners. | **High** | **APPROVED (Strict Opt-In)** |
| **Shodan / Censys / GreyNoise** | `ip` | Requires credit card or paid subscription | Commercial paywalls; academic verification needed. | **High** | **UNAPPROVED (Disallowed)** |

---

## 5. Concurrency, Timeouts, Rate Limits & Circuit Breakers

### 5.1 Concurrency Bounding
External lookups run concurrently via `asyncio.gather(*tasks, return_exceptions=True)`. Global concurrency is bounded using an `asyncio.Semaphore(max_concurrent=5)` to prevent socket exhaustion and local resource contention.

### 5.2 Strict Per-Provider Timeouts
Each individual provider call is wrapped in a strict timeout:
```python
res = await asyncio.wait_for(provider.lookup(request), timeout=2.5)
```
If a provider exceeds 2.5 seconds, it raises `asyncio.TimeoutError` and maps to:
- Status: `ThreatIntelLookupStatus.PROVIDER_FAILURE`
- State: `InvestigationFindingState.TIMED_OUT`
- Error Message: `"Provider 'virustotal' timed out after 2.5s"`
- The remaining providers continue execution without interruption.

### 5.3 Per-Provider Token-Bucket Rate Limiter
Every provider adapter maintains an in-memory token bucket rate limiter:
- **VirusTotal:** 4 tokens per 60 seconds (burst: 4).
- **AbuseIPDB:** 1000 tokens per 86,400 seconds (1 day quota tracking).
- **AlienVault OTX:** 10 tokens per second.
- **abuse.ch:** 10 tokens per second.

When a bucket is exhausted:
- Status: `ThreatIntelLookupStatus.PROVIDER_FAILURE`
- State: `InvestigationFindingState.RATE_LIMITED`
- Error Message: `"Provider 'virustotal' rate limit exceeded (4 req/min); lookup skipped."`
- Does not block or stall the request thread.

### 5.4 Circuit Breaker Pattern
Each provider adapter is guarded by a 3-state circuit breaker:
- **CLOSED (Normal):** Requests pass through. Failure counter tracks consecutive errors/timeouts.
- **OPEN (Tripped):** Tripped when 3 consecutive errors or timeouts occur. All requests fail fast with `PROVIDER_CIRCUIT_OPEN` for 60 seconds without dispatching network calls.
- **HALF_OPEN (Trial):** After 60 seconds, 1 trial request is permitted. If successful, state resets to `CLOSED`; if failed, state returns to `OPEN` for another 60 seconds.

---

## 6. Deterministic Result Synthesis & Provenance

When multiple sources (local and external) return results for an observable, the orchestrator executes deterministic conflict resolution:

### 6.1 Conflict Resolution Hierarchy
```text
1. If ANY source reports MALICIOUS  ──► Synthesized Verdict: MALICIOUS
2. Else if ANY source reports SUSPICIOUS ──► Synthesized Verdict: SUSPICIOUS
3. Else if ALL sources report BENIGN      ──► Synthesized Verdict: BENIGN
4. Else                                   ──► Synthesized Verdict: UNKNOWN
```

### 6.2 Immutable Safety Rules
1. **Malicious Dominance:** A `BENIGN` report from VirusTotal or AbuseIPDB can **never** override a `MALICIOUS` detection from local Feodo Tracker or AlienVault OTX.
2. **Suspicious Context:** An indicator flagged as an anonymization relay (e.g. Tor exit node) remains `SUSPICIOUS` unless corroborated as `MALICIOUS` by another feed.
3. **Allowlist Corroboration:** `BENIGN` is returned only when explicit benign evidence is observed with zero malicious/suspicious flags.
4. **Absence is Unknown:** If no sources match, or if all sources fail/time out, the verdict is `UNKNOWN`. It is never assumed clean.
5. **Incomplete Evidence Invariant (Phase 1.2 Security Gate):** If any external provider experiences an error, timeout, rate limit, or circuit break, a synthesized verdict of BENIGN is strictly forbidden and downgrades to UNKNOWN. A benign verdict requires full unanimous consensus and zero provider failures.

### 6.3 Source Lineage Preservation
All provider responses are preserved in `finding.sources`:
```json
{
  "sources": [
    {
      "source_provider": "local_feeds",
      "source_feed": "feodo_tracker",
      "verdict": "malicious",
      "confidence": 100.0,
      "threat_category": "botnet_c2",
      "malware_family": "QakBot",
      "retrieved_at": "2026-10-22T10:00:00Z"
    },
    {
      "source_provider": "abuseipdb",
      "verdict": "malicious",
      "confidence": 85.0,
      "abuse_confidence_score": 85,
      "total_reports": 42,
      "reference": "https://www.abuseipdb.com/check/198.51.100.1"
    }
  ]
}
```

---

## 7. Caching Policy & Invalidation Strategy

To prevent redundant API consumption and respect free rate limits:

| Result Category | TTL | Rationale |
|:---|:---:|:---|
| **Local Feed Matches** | 3,600s (1h) | Automatic cache eviction triggered by feed updates via invalidation callbacks. |
| **External Positive Match (`MALICIOUS`)** | 86,400s (24h) | Malicious infrastructure remains hostile; protects rate limits. |
| **External Negative Match (`NOT_FOUND`)** | 600s (10m) | Short negative cache ensures newly reported IOCs are caught promptly. |
| **Provider Failure / Timeout / Rate Limit** | **0s (No Cache)** | Transitive errors are never cached; retried on subsequent requests. |
| **Private Network Shielded Observables** | 86,400s (24h) | RFC 1918 classification never changes during runtime. |

---

## 8. Test Strategy & Mock Provider Contract Suite

All TI-3B unit and integration tests must run **100% offline with zero live network calls**:

### Test Suites to Implement
1. **`test_threatintel_private_shield.py`:**
   - Tests private IPv4 (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16), documentation IPs, multicast, unique local IPv6 (`fc00::/7`), and internal domain names (`.corp`, `.internal`, `.local`, unqualified hosts).
   - Verifies that external adapters are never invoked for shielded observables.
2. **`test_threatintel_orchestrator_concurrency.py`:**
   - Tests `asyncio.gather` bounded by semaphore.
   - Tests that 1 slow provider (simulated 5s delay) times out after 2.5s without delaying faster providers.
   - Tests that 1 crashing provider (raising `ConnectionError`) does not abort other providers.
3. **`test_threatintel_circuit_breaker.py`:**
   - Simulates 3 consecutive provider failures; verifies transition from `CLOSED` to `OPEN`.
   - Verifies that requests during `OPEN` state fail fast with `PROVIDER_CIRCUIT_OPEN`.
   - Simulates 60s timeout travel; verifies `HALF_OPEN` trial request.
4. **`test_threatintel_rate_limiter.py`:**
   - Tests token-bucket exhaustion and immediate `RATE_LIMITED` reporting without blocking.
5. **`test_threatintel_verdict_synthesis.py`:**
   - Conflicting verdict matrix:
     - Local `MALICIOUS` + External `BENIGN` -> `MALICIOUS` (Benign cannot override malicious).
     - Local `UNKNOWN` + External `SUSPICIOUS` -> `SUSPICIOUS`.
     - All `BENIGN` -> `BENIGN`.
     - All `UNKNOWN` / `NOT_FOUND` -> `UNKNOWN`.
6. **`test_threatintel_opt_in_toggle.py`:**
   - Tests that when `allow_external_lookup=False` or `ENABLE_EXTERNAL_THREAT_INTEL=False`, zero external adapters are invoked.

---

## 9. Implementation Roadmap & Verification Gates

### Phase 1: Core Orchestrator Infrastructure
- Implement `PrivateNetworkShield` in `backend/app/modules/threatintel/shield.py`.
- Implement token-bucket rate limiter and 3-state circuit breaker in `backend/app/modules/threatintel/resilience/`.
- Implement `ThreatIntelOrchestrator` in `backend/app/modules/threatintel/orchestrator.py`.
- Add unit tests for shield, rate limiters, circuit breakers, and synthesis hierarchy.

### Phase 2: Mock External Provider Adapters
- Implement base HTTP client with timeout and mock interceptor in `backend/app/modules/threatintel/adapters/base.py`.
- Implement `AbuseIPDBAdapter` (API v2 schema) with offline test fixtures.
- Implement `VirusTotalAdapter` (API v3 schema) with offline test fixtures.
- Implement `AlienVaultOTXAdapter` with offline test fixtures.
- Add contract test suite verifying offline behavior against recorded fixtures.

### Phase 3: Investigation Service & API Opt-In Integration
- Add `allow_external_lookup: bool = Query(default=False)` to `GET /api/v1/evidence/events/{event_id}`.
- Update `InvestigationQueryService` to query `ThreatIntelOrchestrator`.
- Add HTTP integration tests verifying opt-in behavior and end-to-end response schemas.

---

## 10. Design Gate Verdict

**Verdict:** **APPROVED FOR IMPLEMENTATION**

The TI-3B architectural specification satisfies all defensive constraints:
- Local intelligence remains primary.
- External lookups are strictly opt-in and disabled by default.
- Private enterprise networks are shielded from external disclosure.
- Bounded concurrency, timeouts, rate limits, and circuit breakers ensure resilience.
- Deterministic conflict policy prevents benign false negatives.
- Zero-cost policy and offline mock testing guarantee ₹0 financial commitment.

*Execution stopped. Awaiting explicit user authorization before starting Phase 1 implementation of TI-3B.*
