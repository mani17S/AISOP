# AISOP Comprehensive Security Verification Matrix & Engineering Architecture

| Attribute | Value |
|:---|:---|
| **Document ID** | AISOP-SEC-VERIF-MATRIX-001 |
| **Status** | APPROVED ARCHITECTURAL BASELINE |
| **Date** | 2026-10-31 |
| **Governing ADRs** | [ADR-001](../03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md), [ADR-002](../03_System_Design/ADR/ADR-002_Vector_Database.md), [ADR-003](../03_System_Design/ADR/ADR-003_Python_3.12_and_Typing.md), [ADR-004](../03_System_Design/ADR/ADR-004_Sysmon_Telemetry_Scope.md), [ADR-005](../03_System_Design/ADR/ADR-005_Headless_Architecture.md), [ADR-006](../03_System_Design/ADR/ADR-006_SDLC_and_DevSecOps_Strategy.md) |
| **Standards Baselines** | OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP ASVS 5.0, OWASP GenAI LLM Top 10:2026 |

---

## 1. RAG & pgvector Security Threat Model

AISOP utilizes PostgreSQL 17 with `pgvector` for semantic knowledge retrieval (MITRE ATT&CK frameworks, detection rules, and security runbooks). The vector layer operates across specific trust boundaries:

| Threat ID | Threat Scenario | Attack Vector & Impact | Implemented Control | Automated Verification | Status |
|:---|:---|:---|:---|:---|:---:|
| **RAG-01** | Unauthorized Vector Retrieval | Attacker queries embeddings belonging to another tenant or restricted case. | All vector queries enforce explicit tenant and case scoping filters in the SQL `WHERE` clause prior to HNSW traversal. | `test_postgres_case_scoping.py` | **Implemented (Tested & Passed)** |
| **RAG-02** | Cross-Case Vector Leakage | Investigation synthesis includes knowledge chunks from a different restricted investigation. | Context assembly resolves evidence and knowledge strictly through `case_id` bound session factories. | `test_case_synthesis_api.py::test_08_evidence_from_another_case_cannot_enter_prompt_context` | **Implemented (Tested & Passed)** |
| **RAG-03** | Document & Embedding Poisoning | Adversary injects malicious markdown documents with manipulated attack definitions or prompt injection. | Path traversal validation (`..` blocked), extension whitelist (`.md` only), deterministic `content_hash` computation. | `test_knowledge_loader_and_chunker.py::test_loader_path_traversal_defense` | **Implemented (Tested & Passed)** |
| **RAG-04** | Similarity Search Abuse & Threshold Bypass | Adversary crafts queries to retrieve irrelevant knowledge or flood context window. | Explicit SQL distance threshold bounding (`WHERE distance <= 1.0 - min_similarity`) prevents low-similarity chunks from displacing valid evidence. | `test_knowledge_ingestion_and_retrieval.py` | **Implemented (Tested & Passed)** |
| **RAG-05** | Chunk Boundary Manipulation | Attacker formats document to split sensitive sentences across boundaries to evade filters. | Deterministic sliding window (512-word target, 64-word overlap) with SHA-256 chunk hashing. | `test_knowledge_loader_and_chunker.py` | **Implemented (Tested & Passed)** |
| **RAG-06** | Stale Knowledge & Version Drift | Outdated MITRE ATT&CK chunks remain indexed after update. | Atomic document replacement lifecycle: all chunks for a `source_document` are deleted and re-inserted within a single transaction. | `test_knowledge_ingestion_and_retrieval.py` | **Implemented (Tested & Passed)** |
| **RAG-07** | Vector Dimension Corruption | Defective or malicious model outputs wrong vector dimension, corrupting the HNSW index. | Strict assertion `len(embedding) == 768` in `OllamaEmbedder`; raises `EmbeddingDimensionError` immediately. | `test_ollama_embedder.py::test_embedding_dimension_assertion` | **Implemented (Tested & Passed)** |
| **RAG-08** | Tampered Content Hashes | Stored chunk content altered directly in database. | Read-back integrity verification against SHA-256 `content_hash`. | `test_knowledge_models.py` | **Implemented (Tested & Passed)** |

---

## 2. LLM Security & Hallucination Evaluation Architecture

AISOP operates an advisory AI investigation pipeline. Under `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001`, all inference is executed locally through Ollama (`llama3.1:8b`) with zero cloud data transmission.

### 2.1 Core AI Security Boundaries
1. **Untrusted Data Axiom:** Telemetry payloads, Sysmon fields, command lines, and retrieved RAG chunks are categorized as **UNTRUSTED EVIDENCE**. XML delimiters (`<evidence>`, `<retrieved_knowledge>`) are treated as formatting aids, not cryptographic boundaries.
2. **Zero Tool Invocation / Autonomous Containment:** The LLM receives zero shell access, zero containment tools, and zero operating system execution capabilities.
3. **Pre-Inference Connection Release:** To prevent database pool exhaustion during long LLM generation cycles, the database session is released before calling Ollama and re-acquired with fresh context validation.
4. **Authoritative Model Provenance:** Model responses cannot spoof their identity; the provider model tag (`llama3.1:8b`) strictly overrides any persona generated in output content.

### 2.2 Hallucination Evaluation Suite
The ground-truth evaluation framework (`EvaluationReplayRunner`) measures investigation fidelity against 19 approved threat scenarios:

| Metric | Target Standard | Evaluation Logic | Verification Method |
|:---|:---:|:---|:---|
| **Evidence Grounding Rate** | $\ge 0.85$ | Claims must cite valid event UUIDs present in the context item set. | `test_ai_evaluation_framework.py::TestGroundingAndMitreEvaluation` |
| **Unsupported Claim Penalization** | $< 0.15$ | Claims lacking supporting context evidence are categorized as `unsupported_claim` and penalized. | `test_ai_evaluation_framework.py::test_08_unsupported_and_contradicted_claims` |
| **IOC Precision & Recall** | Macro $F_1 \ge 0.80$ | Observable extraction (IPs, hashes, files) evaluated against curated scenario truth with negation filtering. | `test_ai_evaluation_framework.py::test_09_ioc_precision_recall` |
| **MITRE ATT&CK Mapping** | Tolerance Bounds | Parent technique tolerance allowed; sibling sub-techniques strictly rejected. | `test_ai_evaluation_framework.py::test_10_mitre_evaluation_and_subtechnique_tolerance` |
| **Output Schema Validity** | $1.00$ (100%) | Structured output must parse into `StructuredInvestigationOutput` Pydantic model. | `test_ai_evaluation_framework.py::test_06_schema_validity_checking` |
| **Expression of Uncertainty** | Explicit | When telemetry is incomplete, deterministic fallback triggers inconclusive disposition rather than fabricating facts. | `test_reporting_pipeline.py::test_post_reports_synthesize_fallback_inconclusive` |

---

## 3. API Security & Ingress Abuse Defense (P3-H4)

```
Incoming Request
      │
      ▼
┌────────────────────────────────────────┐
│      SecurityHeadersMiddleware         │  Injects CSP, HSTS, X-Frame-Options: DENY,
│                                        │  X-Content-Type-Options: nosniff
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│         RateLimitMiddleware            │  Token-bucket per API Key / IP.
│                                        │  Exhaustion -> HTTP 429 Too Many Requests
└──────────────────┬─────────────────────┘  (Exempts /health, /docs)
                   │
                   ▼
┌────────────────────────────────────────┐
│     RequestCorrelationMiddleware       │  Binds X-Request-ID to request and logger
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│       API Ingress Authentication       │  verify_api_key (Bearer / X-API-Key)
│                                        │  Constant-time secret comparison
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│       RBAC & Case Authorization        │  require_case_role(LEAD, INVESTIGATOR)
│                                        │  Anti-enumeration (404 on unassigned)
└──────────────────┬─────────────────────┘
                   │
                   ▼
       Protected Route Handler
```

### Verified API Security Controls:
* **Token-Bucket Ingress Rate Limiting:** `RateLimitMiddleware` enforces burst capacities (`burst_capacity=60`) and steady-state limits (`120 req/min`). Returns HTTP 429 with RFC 6585 `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining` headers.
* **Perimeter Payload Boundaries:** `MAX_BATCH_SIZE=2000`, `MAX_EVENT_PAYLOAD_BYTES=65536` (64 KB), `MAX_PAGE_SIZE=200`. Requests exceeding bounds fail-fast with HTTP 422 before database transaction acquisition.
* **Anti-Enumeration:** Requests targeting unassigned cases return HTTP 404 instead of HTTP 403, preventing attackers from mapping active investigation UUIDs.
* **Private Network Egress Shielding:** `PrivateNetworkShield` validates all threat intelligence observables, strictly preventing SSRF targeting RFC 1918, loopback, or cloud metadata endpoints.

---

## 4. Local Security Testing Toolchain

To maintain zero recurring cost and strict local execution, AISOP establishes a tiered automated testing strategy:

| Tool | Category | Purpose in AISOP | Execution Command | CI/CD Integration Tier |
|:---|:---|:---|:---|:---:|
| **pytest** | Test Automation | Unit, integration, security regression, and property tests. | `uv run pytest -m "not postgres and not ollama"` | Tier 1 (Every Commit) |
| **pip-audit** | Software Supply Chain | Scans virtual environment packages against PyPA Advisory DB for known CVEs. | `uv run pip-audit` | Tier 1 Pre-Commit Gate |
| **Bandit** | Python AST Security | Static AST linter for common Python security flaws (asserts in prod, hardcoded passwords, unsafe bindings). | `uv run bandit -r backend/app` | Tier 1 PR Gate |
| **Semgrep** | SAST Rules | Pattern matching for SQL injection, insecure deserialization, and logging leakage. | `semgrep scan --config p/security-audit` | Tier 1 PR Gate |
| **Gitleaks** | Secret Detection | Pre-commit git hook scanning staged files for accidental API keys, tokens, or private keys. | `gitleaks detect --source .` | Tier 1 Pre-Commit Gate |
| **OWASP ZAP** | DAST Scanner | Automated baseline scan against local FastAPI test instance on port 8000. | `zap-baseline.py -t http://127.0.0.1:8000` | Tier 3 Staging Gate |
| **PentAGI** | Multi-Agent Red Team | Autonomous penetration testing in an isolated, air-gapped testbed VM. | *Evaluated in PentAGI_Evaluation.md* | Tier 4 Specialized Gate |

---

## 5. Agile Security Acceptance Criteria

For every development iteration, the following acceptance criteria must be satisfied prior to milestone sign-off:

1. **Input Validation:** All new route parameters and request bodies are bounded by explicit Pydantic V2 models (`extra="forbid"`, bounded string lengths, regex sanitization).
2. **Access Control:** Route handlers are protected by `verify_api_key` and role dependencies (`require_case_role`); zero unprotected routes outside public health probes.
3. **Query Parameterization:** All database interactions utilize SQLAlchemy 2.0 select/insert statements; zero raw SQL string concatenation.
4. **Error Sanitization:** Unhandled exceptions emit sanitized HTTP 500 error envelopes without exposing database schemas, SQL statements, or traceback details.
5. **Logging Safety:** Log messages pass through Loguru's recursive secret sanitizer; full raw event bodies are never logged at INFO level.
6. **Regression Gate:** Full offline test suite must pass with 100% pass rate and zero regressions (`1,089 passed`).

---

## 6. Final Deployment Security Checklist

Prior to production or restricted-user deployment:

- [x] API Ingress Authentication enabled by default (`API_AUTH_ENABLED=True`).
- [x] Ingress Rate Limiting enabled (`RATE_LIMIT_ENABLED=True`, 120 req/min).
- [x] Security headers middleware enabled (CSP, HSTS, X-Content-Type, X-Frame-Options).
- [x] CORS origin restricted to explicitly configured localhost or trusted domain (`CORS_ORIGINS`).
- [x] Debug mode disabled (`DEBUG=False`).
- [x] Swagger / ReDoc docs disabled or authenticated in production environment.
- [x] Database credentials loaded exclusively via environment variables with zero plaintext secrets in git.
- [x] PostgreSQL least-privilege role configured; superuser banned from application connection pool.
- [x] Private network egress shield active; external calls to RFC 1918 / loopback rejected.
- [x] Local Ollama daemon locked to loopback (`127.0.0.1:11434`) with zero WAN exposure.
- [x] Model output guardrails active; unsupported claims rejected from formal scorecards.
- [x] Full offline regression suite verified (1,089 tests passing).

