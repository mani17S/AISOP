# AISOP Private LAN TLS Reverse Proxy Architecture & Operational Guide
## Hardened Ingress Preparation & Security Boundary Specification (REQ-9.3)

- **Target System:** AISOP (AI-Assisted Security Operations Platform)
- **Component:** Private Network Ingress Reverse Proxy (`deploy/nginx/nginx.conf`)
- **Reference Milestones:** Post-P4-GOV Engineering Hardening (Step 4)
- **Primary Governance Requirement:** REQ-9.3 (Hardened Private TLS Reverse Proxy Template)
- **Status:** **CONFIGURATION TEMPLATE DELIVERABLE — INACTIVE PENDING OPERATOR ACTIVATION**

---

## 1. Executive Summary & Core Principle

> **Engineering Principle:** *A secure reverse proxy is a controlled trust boundary, not simply an HTTPS configuration file.*

In an on-premises, local-first defensive security workbench, human security analysts authenticate using Bearer tokens and API keys. If the platform is accessed over a local area network (LAN) without TLS termination, all authorization tokens, forensic evidence hashes, alert payloads, and investigation dossiers are transmitted across the physical network in cleartext.

The AISOP reverse proxy architecture establishes an authenticated, encrypted trust boundary terminating TLS 1.2/1.3 at the network edge, sanitizing client headers, enforcing defense-in-depth HTTP security headers, and strictly isolating internal persistence services (PostgreSQL + pgvector) from direct network exposure.

---

## 2. Intended Deployment Topology

```mermaid
flowchart TD
    subgraph "Analyst Workstation / LAN"
        Browser["Analyst Web Browser / REST Client"]
    end

    subgraph "Ingress Boundary (DMZ / Private LAN Entry)"
        Nginx["Hardened Nginx Reverse Proxy (Port 443 / 80)"]
    end

    subgraph "AISOP Application Services (Isolated Host / Docker Network)"
        Frontend["Frontend SPA (Port 3000 / Static HTML)"]
        Backend["FastAPI Backend Engine (Port 8000)"]
    end

    subgraph "Internal Persistence Tier (Zero LAN Exposure)"
        DB[("PostgreSQL 17 + pgvector (Port 5432 / Container Internal)")]
        Ollama[("Local Ollama Daemon (Port 11434 / Localhost Only)")]
    end

    Browser -->|HTTPS :443 (TLS 1.2/1.3)| Nginx
    Browser -.->|HTTP :80 (Plaintext)| Nginx
    Nginx -.->|301 Redirect to HTTPS| Browser

    Nginx -->|Proxy Pass /| Frontend
    Nginx -->|Proxy Pass /api/, /health, /docs| Backend
    Backend -->|Internal Session Pool| DB
    Backend -->|Loopback HTTP| Ollama

    style DB fill:#f9f,stroke:#333,stroke-width:2px
    style Ollama fill:#bbf,stroke:#333,stroke-width:2px
```

### Trust Boundary Rules:
1. **Perimeter Boundary:** The Nginx reverse proxy is the **sole entry point** permitted to listen on external/LAN network interfaces (`0.0.0.0:443` and `0.0.0.0:80`).
2. **Application Boundary:** The FastAPI backend (`127.0.0.1:8000`) and Vite frontend (`127.0.0.1:3000`) must bind exclusively to `localhost` or communicate within an isolated Docker bridge network.
3. **Database Boundary:** PostgreSQL with `pgvector` must **NEVER** be bound to `0.0.0.0:5433` or exposed to the LAN. In production, Docker Compose port mappings should bind only to `127.0.0.1:5433:5432` or omit host port publishing entirely.
4. **LLM Boundary:** The Ollama inference daemon binds exclusively to `127.0.0.1:11434` and accepts traffic only from the local backend application.

---

## 3. Threat Model & Security Controls

| Threat Scenario | Vulnerability Without Proxy | Reverse Proxy Mitigation in `deploy/nginx/nginx.conf` |
| :--- | :--- | :--- |
| **LAN Eavesdropping / Sniffing** | Cleartext Bearer tokens and case dossiers intercepted via ARP spoofing or promiscuous capture. | Enforces TLS 1.2 and TLS 1.3 with modern AEAD cipher suites (ECDHE-RSA/ECDSA with AES-GCM and ChaCha20-Poly1305). Plaintext HTTP is canonically redirected via HTTP 301. |
| **Host Header Injection / Cache Poisoning** | Malicious clients send manipulated `Host` headers to elicit cache poisoning or SSRF. | Default catch-all server block drops unrecognized hostnames and direct IP scans with HTTP 444 (connection closed without response). |
| **Client IP Spoofing (Rate Limit Bypass)** | Malicious clients spoof `X-Forwarded-For: 127.0.0.1` to bypass rate limiting or impersonate trusted clients. | Nginx explicitly overwrites `proxy_set_header X-Forwarded-For $remote_addr;`, guaranteeing that the backend receives the genuine TCP remote IP. |
| **Telemetry Denial of Service (Oversized Payloads)** | Memory exhaustion via unbounded payload uploads. | `client_max_body_size 50M;` caps evidence batches while permitting legitimate Sysmon telemetry bundles. |
| **Clickjacking & Framing** | AISOP UI framed in malicious third-party site. | Injects `X-Frame-Options: DENY` and `frame-ancestors 'none'` in Content-Security-Policy. |
| **MIME-Type Confusion** | User-uploaded evidence executed as script by browser. | Injects `X-Content-Type-Options: nosniff`. |
| **Information Disclosure** | Server version banners advertise software vulnerabilities. | `server_tokens off;` suppresses Nginx version strings in headers and error pages. |

---

## 4. Security Header Analysis & Deduplication Matrix

AISOP incorporates defense-in-depth security header injection both at the reverse proxy tier and within FastAPI application middleware ([`backend/app/middleware/security_headers.py`](../../backend/app/middleware/security_headers.py)).

To prevent header duplication (which causes RFC 7230 syntax anomalies or browser warnings when multiple headers are received), Nginx coordinates header responsibilities:

| Header Name | FastAPI Middleware Value | Nginx Ingress Value | Routing Resolution in `nginx.conf` |
| :--- | :--- | :--- | :--- |
| **`Strict-Transport-Security`** | Injected only when `X-Forwarded-Proto == https` (`max-age=31536000; includeSubDomains`) | `max-age=31536000; includeSubDomains` | Nginx injects HSTS on the HTTPS server block. Redirection block (port 80) omits HSTS per RFC 6797. |
| **`X-Content-Type-Options`** | `nosniff` | `nosniff` | Nginx uses `proxy_hide_header X-Content-Type-Options;` for `/api/` locations to avoid duplication. |
| **`X-Frame-Options`** | `DENY` | `DENY` | Nginx uses `proxy_hide_header X-Frame-Options;` for `/api/` locations. |
| **`Referrer-Policy`** | `strict-origin-when-cross-origin` | `strict-origin-when-cross-origin` | Nginx uses `proxy_hide_header Referrer-Policy;` for `/api/` locations. |
| **`Permissions-Policy`** | `geolocation=(), camera=(), microphone=(), payment=()` | `geolocation=(), camera=(), microphone=(), payment=()` | Nginx uses `proxy_hide_header Permissions-Policy;` for `/api/` locations. |
| **`Content-Security-Policy`** | API-focused: `default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';` | Frontend UI-focused: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https:;` | Distinct policies: FastAPI sets strict API CSP on `/api/`; Nginx sets UI-compatible CSP on `/` static assets. |

---

## 5. Backend Trusted Proxy & Rate Limiting Integration

FastAPI's [`RateLimitMiddleware`](../../backend/app/middleware/rate_limit.py) enforces client request limits per IP/token. To prevent untrusted LAN clients from spoofing their IP address, the middleware only parses `X-Forwarded-For` if the connecting peer IP matches `RATE_LIMIT_TRUSTED_PROXIES`.

### Operational Prerequisite for Proxy Deployment:
1. When Nginx runs on the **same host** as FastAPI:
   - Nginx connects to FastAPI from `127.0.0.1`.
   - `RATE_LIMIT_TRUSTED_PROXIES` default value (`["127.0.0.1", "::1"]`) is already sufficient.
2. When Nginx runs in a **Docker container** or on a **dedicated reverse-proxy host**:
   - The operator must configure `.env` with the proxy's IP or container subnet:
     ```bash
     # Example: Docker bridge network or dedicated proxy host IP
     RATE_LIMIT_TRUSTED_PROXIES=["127.0.0.1", "172.20.0.5"]
     ```

---

## 6. Private PKI & Certificate Prerequisites

AISOP is designed for private on-premises networks. Public ACME / Let's Encrypt automated certificate issuance is **incompatible** with air-gapped or non-publicly routable IP spaces.

### Certificate Requirements:
1. **Issuing Authority:** Certificates should be signed by an enterprise internal Certificate Authority (e.g. Active Directory Certificate Services, HashiCorp Vault PKI, or an offline enterprise Root CA).
2. **Subject Alternative Name (SAN):** Modern browsers reject certificates that rely solely on the `CommonName` (CN). The certificate must include standard SAN entries matching the private DNS hostname:
   ```text
   DNS:aisop.secops.internal
   DNS:aisop.local
   IP:192.168.1.100  # If accessed via direct IP
   ```
3. **Key Specification:** RSA 3072/4096-bit or ECDSA (curve `prime256v1` / `secp384r1`).
4. **Renewal Cycle:** Establish operational runbooks to rotate certificates prior to expiration (typically 12-month or 90-day lifecycles).

---

## 7. Configuration Validation & Activation Runbook

The configuration template is located at [`deploy/nginx/nginx.conf`](../../deploy/nginx/nginx.conf). It is an **inactive template** that must be parameterized before deployment.

### Step 1: Parameterize Placeholders
Before activating, copy the template and replace the placeholders:
```powershell
# Copy template to active configuration directory
Copy-Item ".\deploy\nginx\nginx.conf" -Destination "C:\nginx\conf\nginx.conf"

# Replace placeholders:
# __AISOP_SERVER_NAME__      -> e.g. aisop.secops.internal
# __AISOP_TLS_CERT_PATH__    -> e.g. C:/nginx/ssl/aisop.crt
# __AISOP_TLS_KEY_PATH__     -> e.g. C:/nginx/ssl/aisop.key
# __AISOP_BACKEND_HOST__     -> 127.0.0.1
# __AISOP_BACKEND_PORT__     -> 8000
# __AISOP_FRONTEND_HOST__    -> 127.0.0.1
# __AISOP_FRONTEND_PORT__    -> 3000
```

### Step 2: Static Syntax Validation
Validate Nginx configuration syntax before binding ports:
```bash
nginx -t -c /path/to/parameterized/nginx.conf
# Expected output:
# nginx: the configuration file /path/to/nginx.conf syntax is ok
# nginx: configuration file /path/to/nginx.conf test is successful
```

### Step 3: Containerized Docker Compose Activation Example
To run Nginx alongside AISOP services in Docker, use a Compose overlay (`docker-compose.tls.yml`):
```yaml
services:
  nginx-proxy:
    image: nginx:1.27-alpine
    container_name: aisop-tls-proxy
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./deploy/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /path/to/certs:/etc/ssl/certs:ro
      - /path/to/keys:/etc/ssl/private:ro
    depends_on:
      - backend
      - frontend
```

### Step 4: Verification Checklist Post-Activation
1. **HTTP to HTTPS Redirection:**
   ```bash
   curl -I http://aisop.secops.internal/api/v1/health
   # Must return: HTTP/1.1 301 Moved Permanently -> Location: https://...
   ```
2. **TLS Handshake & Cipher Suite:**
   ```bash
   openssl s_client -connect aisop.secops.internal:443 -tls1_2
   openssl s_client -connect aisop.secops.internal:443 -tls1_3
   # Both must connect cleanly; TLS 1.0 and 1.1 must fail.
   ```
3. **Security Headers Verification:**
   ```bash
   curl -kI https://aisop.secops.internal/api/v1/health
   # Verify presence of: Strict-Transport-Security, X-Content-Type-Options: nosniff, X-Frame-Options: DENY
   ```
4. **Host Header Dropping:**
   ```bash
   curl -k -H "Host: malicious.attacker.com" https://<proxy_ip>/
   # Must return HTTP 444 or connection drop.
   ```
5. **PostgreSQL Network Boundary:**
   ```bash
   nc -zv <server_lan_ip> 5433
   # Connection must be refused or timed out from the external LAN.
   ```

---

## 8. Rollback Procedure

If reverse proxy deployment causes routing or authentication issues:
1. Immediately stop the proxy service (`docker compose stop nginx-proxy` or `Stop-Service nginx`).
2. Revert client connections to the direct local-only development URLs (`http://127.0.0.1:3000` / `http://127.0.0.1:8000`).
3. Ensure LAN firewall blocks external ingress to ports 8000, 3000, and 5433.

---

## 9. Operational Verification Status (Safety Boundaries)

In strict accordance with project safety constraints:
- **No live services were started, stopped, or restarted.**
- **No software (Nginx or Caddy) was installed.**
- **No live certificates or private keys were generated or placed on disk.**
- **No network ports (443, 80) were bound.**
- **No external LAN exposure was initiated.**
- **The deliverable is a validated configuration template and operational runbook.**

