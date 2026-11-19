# AISOP Technical Evaluation: PentAGI Autonomous Penetration Testing Platform

| Attribute | Specification |
|:---|:---|
| **Document ID** | AISOP-SEC-EVAL-PENTAGI-001 |
| **Status** | EVALUATION COMPLETE & ARCHITECTURAL DISPOSITION ISSUED |
| **Date** | 2026-10-31 |
| **Evaluated System** | PentAGI (vxcontrol/pentagi) — v0.2.x+ |
| **Repository** | `https://github.com/vxcontrol/pentagi` |
| **Official Documentation** | `https://pentagi.com/docs/` |
| **Governing Charters** | `AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001`, ADR-001, ADR-006 |

---

## 1. Executive Summary & Architectural Disposition

**PentAGI** is an open-source (MIT Licensed), self-hosted autonomous multi-agent penetration testing platform. It orchestrates automated vulnerability discovery, exploitation planning, tool invocation, and reporting via coordinated LLM agents.

### Architectural Disposition for AISOP
* **Adoption Status:** **REJECTED AS A RUNTIME COMPONENT; CONDITIONALLY APPROVED AS AN ISOLATED ADVERSARIAL RED-TEAM TEST SYSTEM ONLY.**
* **Core Rationale:** 
  1. PentAGI requires Docker socket (`/var/run/docker.sock`) integration to spawn Kali Linux worker containers, which represents a **root-equivalent host privilege elevation**.
  2. Direct autonomous agent execution against untrusted targets risks prompt injection leading to host takeover or unconstrained lateral network scanning.
  3. AISOP's defensive architectural charter mandates zero recurring cost, local-first execution, and advisory-only operation (no autonomous destructive tools).
  4. For developer-side regression testing, deterministic scanners (OWASP ZAP, Semgrep, Bandit, pytest) provide faster, 100% reproducible, zero-hallucination verification without container escalation risks.
  5. However, PentAGI can be safely leveraged in a **strictly isolated, air-gapped testbed VM** using local Ollama (`llama3.1:8b`) to stress-test AISOP's defensive perimeter and rate limiting.

---

## 2. Technical Assessment of PentAGI

### 2.1 System Architecture
PentAGI is structured as a decoupled microservices architecture deployed via Docker Compose:
* **Backend API & Orchestrator:** Developed in **Go**, providing high-concurrency event loops, GraphQL/REST APIs, and agent workflow coordination.
* **Frontend Web Console:** Developed in **React** and **TypeScript**, exposing real-time task progression, terminal session streaming, and vulnerability graphs (default TLS port `8443`).
* **Database & Vector Memory:** Utilizes **PostgreSQL 17** with the **`pgvector`** extension for episodic memory, research embeddings, and historical attack pattern retrieval. (Optionally integrates Neo4j for semantic knowledge graphs).
* **Execution Sandbox:** Spawns dynamic worker containers from a pre-configured Kali Linux image containing 20+ penetration testing utilities (`nmap`, `sqlmap`, `metasploit`, `hydra`, `nikto`, `gobuster`).

### 2.2 License and Third-Party Compliance
* **Core License:** **MIT License** (`github.com/vxcontrol/pentagi/blob/main/LICENSE`).
* **Permissibility:** The MIT license is fully permissive and compatible with AISOP's academic and open-source licensing.
* **Third-Party Caveats:** Bundled Kali Linux tools carry individual GPL and proprietary licenses. Using PentAGI externally or commercially requires license adherence for each invoked binary.

### 2.3 Docker Execution Model & Privilege Boundaries
* **Docker Socket Requirement:** PentAGI's core backend container requires read/write access to `/var/run/docker.sock` to orchestrate sibling and child worker containers.
* **Security Criticality:** Mounting `/var/run/docker.sock` inside a container is **inherently root-equivalent**. An adversary or prompt-injected LLM capable of controlling container creation parameters can mount the host filesystem (`/`) and achieve complete host takeover.
* **Hardening Requirements:**
  - Mandatory use of **Rootless Docker** or a dedicated disposable Virtual Machine (VM) if executed.
  - Utilization of `DOCKER_INSIDE_HOST` proxying or capability dropping (`--cap-drop=ALL --cap-add=NET_RAW`).
  - Strict network namespace isolation with host loopback binding prohibited.

### 2.4 Local LLM Compatibility (Ollama Integration)
* **Local-First Feasibility:** PentAGI natively supports local LLM providers via **Ollama** and vLLM.
* **Configuration:** Configured via YAML provider specifications (e.g. `examples/configs/ollama-llama318b.provider.yml`).
* **Hardware Footprint:** Coordinating a multi-agent hierarchy (Orchestrator, Researcher, Coder, Executor) with `llama3.1:8b` locally requires substantial GPU VRAM (12–16 GB) and generates high context overhead.
* **Paid Service Bypass:** While PentAGI defaults to Tavily/Google for external web search, offline test scenarios against local endpoints can be configured without external search APIs.

---

## 3. Evaluation for Testing AISOP

### 3.1 Comparison: PentAGI vs. Deterministic Toolchain

| Evaluation Dimension | PentAGI (Autonomous Multi-Agent) | Deterministic Toolchain (OWASP ZAP, Bandit, Semgrep, pytest) |
|:---|:---|:---|
| **Reproducibility** | Non-deterministic (stochastic LLM decision trees). | 100% deterministic (reproducible test runs and exit codes). |
| **Execution Speed** | Slow (minutes to hours per scenario). | Fast (seconds to minutes for full CI/CD regression). |
| **False Positive Rate** | Moderate to High (agent hallucination, false exploit claims). | Low (rule-based pattern matching and explicit assertion checks). |
| **Privilege Risk** | High (Docker socket access, automated shell execution). | Zero (runs as unprivileged user in isolated Python venv). |
| **Cost** | Zero (if configured strictly with local Ollama). | Zero (100% free open-source tools). |
| **Coverage Scope** | Emergent attack chaining, creative bypass attempts. | Complete coverage of known OWASP Top 10 rules and schemas. |

### 3.2 Applicable AISOP Attack Surfaces for PentAGI Testing
If deployed in a dedicated, isolated testbed VM, PentAGI can evaluate:
1. **API Ingress Boundary Testing:** Fuzzing `/api/v1/evidence/ingest`, `/api/v1/cases`, and `/api/v1/cases/{case_id}/synthesize`.
2. **Authentication & RBAC Bypass:** Attempting horizontal object access (BOLA) and role privilege escalation.
3. **Ingress Throttling & Slowloris Resistance:** Validating that rate limiting middleware correctly returns HTTP 429 and isolates excessive client requests.
4. **Injection Fuzzing:** Automated submission of complex SQLi, command injection, and template payloads in Sysmon fields.

---

## 4. Strict PentAGI Operating Invariants & Restrictions

To ensure the safety, privacy, and integrity of the AISOP repository and host environment, the following non-negotiable restrictions apply:

1. **NO Direct Host Installation:** PentAGI must NEVER be installed directly on the primary host machine or within the AISOP repository tree.
2. **NO Production or Shared Network Exposure:** PentAGI must only run in a segmented virtual machine with firewall boundaries blocking access to LAN, RFC1918 subnets, and cloud metadata services (`169.254.169.254`).
3. **NO External Targets:** Testing must be strictly constrained to dedicated, synthetic AISOP test instances (`aisop_test`).
4. **NO Paid APIs:** External paid LLMs (OpenAI, Anthropic) or metered search APIs must remain disabled in favor of local Ollama (`llama3.1:8b`).
5. **NO Source Code Ingestion:** PentAGI source code must never be merged into the AISOP codebase.

