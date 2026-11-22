# OWASP Top 10 (2021) checklist: web client, deployment, supply chain

Date: 2026-11-22. Scope: React frontend (`frontend/`), nginx templates (`deploy/nginx/`), `docker-compose.yml`, `render.yaml`, CI, dependencies, the Remotion video project, plus read-only inspection of the backend sinks that the web client depends on. Owner's own code, defensive review. Backend `core/`, `middleware/`, `api/`, `modules/`, `services/` were inspected read-only only; fixes there belong to the backend owner (see Open items).

Evidence legend:
- **RUN** = verified by executing a command or test in this session.
- **READ** = read-only inspection (no execution); weaker evidence.
- Result: **pass**, **fixed** (defect found, test written first and seen failing, fixed, test passes), **open** (residual, not fixed here).

Automated guards added by this review: `backend/tests/unit/test_owasp_web_deploy.py` (17 tests, offline, no services) and `frontend/tests/security_api_key.test.tsx` (16 tests, wired into `npm test`). Nothing here claims production readiness: nginx.conf and render.yaml are templates that have not been deployed or exercised against a live proxy (UNVERIFIED at runtime).

## Summary of defects found

| # | Item | Defect | Result |
|---|---|---|---|
| 1 | A05 | `nginx.conf`: the SPA `location /` declared `add_header Content-Security-Policy`, and a nested `location = /index.html` declared `add_header Cache-Control`. nginx drops every inherited `add_header` in a location that declares its own, so HSTS, nosniff, X-Frame-Options, Referrer-Policy and Permissions-Policy were silently missing from all SPA responses; `/api/` had no CSP | **fixed** (CSP and COOP moved to server level, `expires -1` replaces the Cache-Control `add_header`) |
| 2 | A05 | `nginx.conf` proxied `/docs` and `/redoc` to the backend (OpenAPI is a map of every endpoint) | **fixed** (404 at the proxy; the backend already disables docs outside development, verified by test) |
| 3 | A05 | `nginx.conf` CSP `connect-src 'self' https:` allowed exfiltration to any HTTPS host; no `form-action` | **fixed** (`connect-src 'self'`, `form-action 'self'`) |
| 4 | A05 | `frontend/public/_headers` (Cloudflare Pages) had no CSP and no HSTS. `frame-ancestors` is ignored in the `<meta>` CSP, so clickjacking protection relied on X-Frame-Options alone | **fixed** (header CSP with only the directives that do not fall back to `default-src`, so the build-time `connect-src` rewrite still works; HSTS; COOP) |
| 4b | A04 | `nginx.conf` had no ingress request-rate limit (the local template had one) | **fixed** (`limit_req_zone`, 30 r/s, burst 60, 429) |
| 5 | A05/A02 | `docker-compose.yml` healthcheck hardcoded `-U aisop -d aisop_dev`, so overriding `POSTGRES_USER`/`POSTGRES_DB` (the documented way to replace the default credentials) made the container permanently unhealthy | **fixed** (`$${POSTGRES_USER}` / `$${POSTGRES_DB}`, expanded in the container) |
| 6 | A02/A09 | API client: an error body that echoed the API key (for example in a validation message) passed the safe-text filter and would be shown to the user | **fixed** (`api.ts` scrubs the in-memory key and any AISOP-key-shaped string from error messages before they leave the client) |

Real third-party vulnerabilities: see A06.

## A01 Broken Access Control

| Module | Checked | How | Result | Evidence |
|---|---|---|---|---|
| Frontend role selector | The "View as" role is not trusted and never sent | RUN `security_api_key.test.tsx` "never sends a role, user or identity header" (header names are exactly accept, content-type, x-api-key; URL carries no role); READ `AuthContext.tsx` (role kept in React state and sessionStorage key `aisop_view_as`, used only by `canCreateCase()` etc. to show or hide buttons) | pass | A forged `sessionStorage.aisop_view_as` only changes what the UI shows. The server derives the principal from the key (`core/auth.py`, `core/rbac.py`, deny by default) |
| Frontend routes | No client-side route guard is a security control | READ `App.tsx`: tabs render only when `apiKey` is set; every data fetch needs the server to accept the key | pass | Hiding a tab does not grant or deny data |
| Backend v1 router | All routers except health sit under `verify_api_key` | READ `api/v1/__init__.py` | pass | Health probes are intentionally public |
| Case-scoped access (BOLA/IDOR) | Case objects checked against assignment | RUN `test_case_bola_security.py`, `test_api_auth.py` (part of 294 passed) | pass | existing suites |

Residual: UI-visible role is spoofable by design; its only effect is cosmetic. Auditors should not read "View as" as an access statement.

## A02 Cryptographic Failures

| Module | Checked | How | Result | Evidence |
|---|---|---|---|---|
| Browser key storage | Key only in memory and `sessionStorage`; never `localStorage`, URL, console, error text | RUN `security_api_key.test.tsx` (storage, URL, 8 status codes that echo the key, network error, console capture); RUN `test_frontend_never_uses_localstorage_or_logs_secrets` (static scan of `frontend/src`) | pass, plus fix #6 | |
| Threat model (document) | sessionStorage is readable by any script in the origin; it is not an XSS boundary. What protects it: tab scope (cleared on tab close), CSP `script-src 'self'` with no `unsafe-inline`/`unsafe-eval`, React escaping, zero HTML sinks (A03), server-side key hashing and revocation, `Clear key` removing it everywhere | READ + RUN as above | pass (documented) | An XSS that executes would read the key; the mitigation is preventing execution, not hiding the key. Residual: no idle timeout and no automatic clear on a 401 |
| TLS in `nginx.conf` | TLS 1.2/1.3 only, AEAD ciphers, no session tickets, HSTS 1 year, `server_tokens off` | RUN `test_nginx_tls_only_modern_protocols` (both templates), `test_nginx_production_template_has_hsts...` | pass | Never executed against a live nginx (UNVERIFIED at runtime). `nginx.local.conf` deliberately omits HSTS (localhost) |
| Secrets in compose | Only a default DB password `aisop`, overridable with `POSTGRES_PASSWORD`; port bound to `127.0.0.1` | RUN `test_compose_database_is_loopback_only_and_healthcheck_follows_overrides` | pass (accepted local default) | Defaults are acceptable only because the port is loopback. Any non-local run must set `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` and a matching `DATABASE_URL` |
| Secrets in `render.yaml` | No secret values; `DATABASE_URL` and `CORS_ORIGINS` are `sync: false`; no static `API_AUTH_KEYS` | RUN `test_render_blueprint_is_production_hardened_and_holds_no_secrets` | pass | |
| Default `aisop:aisop` in code | `Settings.DATABASE_URL` defaults to `aisop:aisop@127.0.0.1`; `.env.example` and docs use it | RUN grep | open | Production mode does not reject the default credentials (`core/config.py` `_validate_auth_invariants` only checks auth). A missing `DATABASE_URL` on Render fails to connect rather than connecting insecurely, so impact is low. Recommendation to the backend owner: refuse `ENVIRONMENT=production` with the default credentials |
| Secret files | `.env`, `opencode.json`, `viva-credentials.txt` ignored and untracked | RUN `git check-ignore`, `git ls-files` (read-only) | pass | Contents not read |
| Key at rest on server | hashed storage | READ only (`modules/authentication`) | not reviewed in depth | owned by backend agent |

## A03 Injection and XSS

| Module | Checked | How | Result | Evidence |
|---|---|---|---|---|
| Backend raw SQL | Every `text()`/`exec_driver_sql` argument is a static literal | RUN `test_raw_sql_text_calls_are_static_string_literals` (AST scan of `backend/app`, migrations excluded) | pass | Health probes are the only raw SQL; all literals |
| Backend dynamic execution | No `eval`, `exec`, `compile`, `os.system`, `subprocess`, `shell=True`, `pickle`, `marshal`, `yaml.load` | RUN `test_backend_has_no_dynamic_code_execution_or_unsafe_deserialization` (AST) | pass | |
| Path joins from user input | Dataset loader verifies resolved path stays under its base directory; ATT&CK file path is configuration, not user input | READ `evaluation/dataset_loader.py` (`_verify_path_safety`), `attack_reference/loader.py` | pass (read-only) | No HTTP parameter reaches a file path in the grep results |
| LLM prompt context | Evidence is XML-escaped before entering the prompt | READ `ai/context_builder` (`escape_xml_text`) | pass (read-only) | Prompt-injection suites are owned elsewhere |
| Frontend HTML sinks | No `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `javascript:` in code | RUN `test_frontend_source_has_no_html_injection_or_eval_sinks` (comments stripped) | pass | |
| Telemetry and report text rendering | Hostile strings render only as escaped text | RUN existing `hostile_render.test.tsx` (part of 256 `npm test` tests) | pass | Reports and alerts are rendered through JSX; there is no markdown-to-HTML renderer in the SPA (markdown is shown as text and downloaded as a file) |
| `href`/`src` built from data | Only `operator.contactUrl`, a compile-time `https://` constant | RUN `test_frontend_href_values_from_data_are_not_unvalidated` | pass | |
| Downloads | Blob built from server markdown with `type: text/markdown`, `download` attribute only; the filename is server supplied but browsers sanitize it | READ `ReportViewer.tsx`, `MultiSourcePanel.tsx` | pass (read-only) | Not rendered or opened in the browser, so no script context |
| Template injection | `jinja2` is a dependency | RUN grep of `Template(`/`render_template` in `backend/app` found none | pass | Used, if at all, with static templates |

Residual: `style-src 'unsafe-inline'` is kept because React inline styles need it. Style injection is far weaker than script injection, but it is a known relaxation.

## A04 Insecure Design (abuse cases)

| Abuse case | Control | How | Result | Evidence / residual |
|---|---|---|---|---|
| Evidence flooding | Per-path body limits (8 MiB domain import, 16 MiB alerts, 64 MiB telemetry), schema record caps, per-client rate limiter, new nginx `limit_req` | RUN `test_body_limit_regression.py`, `test_rate_limiting.py` (294 passed run); RUN `test_nginx_production_template_has_hsts_and_rate_limit...` | pass | nginx `client_max_body_size 50M` is below the 64 MiB backend telemetry limit: operators posting larger batches must split or raise it |
| LLM cost/latency DoS | LLM is optional (`LLM_ENABLED`; Render sets it false), local-first endpoint guard, timeout 120 s, retries 3, auth required, rate limiter | READ `core/config.py`, `render.yaml` | open (residual) | No global concurrency cap or queue on LLM calls: a few authenticated clients can occupy the single local model for minutes. Rate limiting is per client address. Recommend a process-wide semaphore (backend owner) |
| Hostile telemetry causing UI break | Error boundary, escaped rendering | RUN `hostile_render.test.tsx` | pass | |
| Deterministic path under LLM outage | Required by invariants | READ | pass | not re-tested here |

## A05 Security Misconfiguration

| Module | Checked | How | Result | Evidence |
|---|---|---|---|---|
| `index.html` CSP | `default-src 'self'`, `script-src 'self'`, no `unsafe-eval`, no wildcard, `connect-src` limited to self and the local backend, no third-party origins | RUN `test_index_html_csp_has_no_script_escape_hatches` | pass | Hosted builds rewrite `connect-src` to the single `VITE_API_BASE_URL` https origin (`vite.config.ts`) |
| `_headers` | nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy, HSTS, COOP, CSP `frame-ancestors 'none'` | RUN `test_pages_headers_file_carries_framing_and_transport_headers`; RUN `npm run build` then confirmed `dist/_headers` contains HSTS | fixed (#4) | Effect on a real Pages deployment UNVERIFIED |
| `nginx.conf` headers and inheritance | Every location, after nginx inheritance rules, carries HSTS, nosniff, XFO, Referrer-Policy, CSP | RUN `test_nginx_every_location_keeps_security_headers` (failed before, passes after) | fixed (#1) | |
| `nginx.conf` docs | `/docs`, `/redoc`, OpenAPI JSON return 404 | RUN `test_nginx_does_not_proxy_api_docs_or_openapi` | fixed (#2) | |
| Backend docs endpoints | Disabled when `ENVIRONMENT != development` | RUN `test_production_environment_disables_api_docs` (builds the app in production mode, no lifespan/DB) | pass | `nginx.local.conf` comment saying the backend exposes docs unconditionally is outdated (docs are gated now); the proxy block remains as defence in depth |
| CORS | Origins come from `CORS_ORIGINS` (default `http://localhost:3000`); methods and headers allow-listed; `allow_credentials=True` | READ `main.py`, `config.py` | pass with note | No origin validator rejects `*` in `CORS_ORIGINS`; with credentials enabled a wildcard would be unsafe. Set exact origins (Render blueprint documents a JSON list) |
| Docker ports | Postgres bound to `127.0.0.1:5433`; no `privileged`, no `network_mode` | RUN compose test | pass | Compose runs only Postgres; the container user is the upstream image's `postgres` user (not overridden) |
| Debug flags | `DEBUG` defaults False; Render sets production | RUN render test; READ config | pass | |
| Default creds | See A02 | | open (documented) | |
| Render start command | `--host 0.0.0.0` is required by the platform | READ | pass | `RATE_LIMIT_TRUSTED_PROXIES` is not set on Render, so behind Render's proxy all clients may share one rate-limit bucket (availability, not confidentiality). Set it once Render's proxy range is confirmed (UNVERIFIED) |

## A06 Vulnerable and Outdated Components

Verified by running `pip_audit` (installed into `.venv`; advisory data fetched) and `npm audit`.

| Project | Tool | Result |
|---|---|---|
| Backend `requirements.txt` | `pip_audit -r requirements.txt` | **No known vulnerabilities found** (also `backend/requirements.txt`) |
| `frontend/` | `npm audit` | 2 findings, **dev-tooling only**: `vite@5.4.21` (high, advisory range <=6.4.3: dev-server path traversal in optimized-deps `.map` handling GHSA-4w7w-66w2-5vf9, `server.fs` bypasses GHSA-rq7h-c2jc-7f22 and GHSA-fx2h-pf6j-xcff, cross-origin script execution via custom middleware GHSA-9jrq-w75r-8gcw, bundled `launch-editor` advisories) and `esbuild@0.21.5` (moderate, GHSA-67mh-4wv8-2f99: a website can send requests to the esbuild/Vite dev server and read the response). Fixed only in `vite@8.3.8`, a breaking major |
| `video/` | `npm audit` | 11 findings (10 high, 1 critical), all transitive under `@remotion/cli@4.0.441`: `loader-utils` 2.0.0 to 2.0.3 (critical: prototype pollution GHSA-76p3-8jx3-jpfq, ReDoS GHSA-3rfm-jhwj-7488, GHSA-hhq3-ff78-jv3g), `postcss` <=8.5.22 (high: XSS via `</style>` GHSA-qx2v-qp2m-jg93, arbitrary `.map` file read GHSA-6g55-p6wh-862q and related), `ws` 8.0.0 to 8.20.1 (high: uninitialized memory GHSA-58qx-3vcg-4xpx, fragment DoS GHSA-96hv-2xvq-fx4p), `zod` <4.6.6 (high: memory exhaustion GHSA-mrhx-c7xc-m3w5), plus `extract-zip`, `@remotion/{bundler,renderer,studio,studio-server,zod-types}`. npm reports a non-major fix: `@remotion/cli@4.0.545` |

Decisions:
- Frontend: **not upgraded**. The vulnerable code runs only in `npm run dev` / `npm test` (esbuild) / the build on the developer's machine; the dev server binds `127.0.0.1`. The production artefact is the static `dist/` with no vite or esbuild code. The fix is a major vite upgrade (5 to 8) that I did not judge safe to take blind; it needs its own task with the build, typecheck, tests and a browser check. Mitigation until then: do not open untrusted sites while `npm run dev` is running, and do not expose the dev server.
- Video: **not changed** (outside the edit scope of this task). `video/` is local rendering tooling, never deployed. Recommended: bump `remotion` and `@remotion/cli` together to `4.0.545` (exact pins), `npm ci`, render once. Open until done.
- Neither `pip_audit` nor `npm audit` finds a Python or deployed-bundle exposure. This is a point-in-time result (2026-11-22).

## A07 Identification and Authentication Failures

| Module | Checked | How | Result | Evidence |
|---|---|---|---|---|
| SPA session handling | Key held in memory and sessionStorage; no cookie, no JWT, so no CSRF surface for the SPA; custom header `X-API-Key` forces a CORS preflight for cross-origin calls | RUN `security_api_key.test.tsx`; READ `api.ts` | pass | |
| Logout / clear path | `Clear key` in the key dialog calls `setApiKey('')`, which clears memory and sessionStorage; `clearApiKey()` does the same | RUN tests "removes the key from memory and storage on clear" and "setting an empty key" | pass | |
| Input normalization | Whitespace and newlines stripped so a pasted key cannot inject a header | RUN test "strips whitespace" | pass | |
| Password-type input | Key field is `type=password` with `autoComplete="off"` | READ `Navbar.tsx` | pass | |
| Server auth | Bearer or `X-API-Key`; hashed DB tokens; legacy static keys off in Render | RUN `test_api_auth.py`, `test_owasp_api_auth.py` exists (other agent) | pass (existing suites) | |
| Idle timeout, 401 auto-clear | Not implemented | READ | open (low) | A rejected key stays in the tab until the user clears it or closes the tab |

## A08 Software and Data Integrity Failures

| Module | Checked | How | Result | Evidence |
|---|---|---|---|---|
| Lockfiles | `frontend/package-lock.json`, `video/package-lock.json`, `uv.lock` present; CI uses `npm ci` and `cache-dependency-path` | READ `ci.yml`, directory listing | pass | `requirements.txt` is exact-pinned but has no `--hash` entries (pip does not verify hashes); installs are not hash-locked. Open (low) |
| CI actions | `actions/checkout@v4`, `setup-python@v5`, `setup-node@v4` pinned to major tags, not commit SHAs | READ `ci.yml` | open (low) | Tag pins can move. Recommend SHA pins (`.github/` was outside my edit scope) |
| CI privileges | Top-level `permissions: contents: read`; triggers only push/PR to main and manual; no `pull_request_target`, no secrets used | READ `ci.yml` | pass | |
| CI audit coverage | Runs `pip-audit -r requirements.txt` (unpinned tool install); does not run `npm audit` | READ | open (low) | Add `npm audit --audit-level=high --omit=dev` for `frontend/` |
| ATT&CK data integrity | Pinned release with SHA-256 (and size) verified over the exact bytes before parsing; mismatch fails closed; no auto-update | READ `attack_reference/loader.py` (`ENTERPRISE_V20_1`, `HASH_MISMATCH`) | pass (read-only) | existing drift/loader tests belong to other suites; not re-run here |
| Model downloads | No code downloads models; embedder and provider only call a local Ollama endpoint; the missing-model error tells the operator to run `ollama pull` | RUN grep for `from_pretrained`, `urlretrieve`, `requests.get` in `backend/app` | pass | |
| Threat-intel feeds | Remote feeds are operator-configured, local files under `data/feeds` | READ `feeds/parsers.py` | pass (read-only) | |

## A09 Security Logging and Monitoring Failures

| Module | Checked | How | Result | Evidence |
|---|---|---|---|---|
| Logging and redaction | `redact_text` and `redact_sensitive_data` mask keys, passwords, tokens by key name and by value pattern; depth bounded | RUN `test_logging.py`, `test_diagnostic_logging.py` (in the 294 passed run) | pass | |
| Request IDs | Server-generated `X-Request-ID` per request, a client value only logged as a separate field; frontend only shows ids matching a strict pattern | READ `middleware/correlation.py`; RUN `test_error_contract.py` | pass | |
| Error text | Stable error envelope; client filter blocks SQL, paths, hosts, library names and (now) keys | RUN `error_presentation.test.tsx`, `security_api_key.test.tsx` | pass | |
| Client logging | Only `ErrorBoundary` calls `console.error` (error object and component stack, no key) | RUN static scan test; READ | pass | |
| Audit trail | Case audit events exist and are exposed to the UI (`CaseAuditEventItem`) | READ | pass (read-only) | Not tampering-resistant (no hash chain); residual |
| nginx access log | `aisop_combined` format logs the URL with query string and referrer; keys travel in headers, not URLs, so they are not logged | READ | pass | Alerts search text can appear in the query string of access logs; treat logs as sensitive |
| Alerting and monitoring | No alert on repeated 401/429 is configured in this repo (`infra/monitoring` not reviewed) | not verified | UNVERIFIED | |

## A10 Server-Side Request Forgery

| Module | Checked | How | Result | Evidence |
|---|---|---|---|---|
| Ollama base URL | Local-first guard: only localhost, 127.0.0.0/8, ::1; http(s) only; credentials in URL rejected; non-local needs explicit opt-in; syntactic check, no DNS | RUN `test_llm_endpoint_guard_rejects_non_local_hosts_credentials_and_metadata_addresses` (169.254.169.254, 10.x, IPv4-mapped metadata IPv6, look-alike `127.0.0.1.evil.example`, `file://`, `ftp://`, userinfo, empty) plus existing `test_local_first_controls.py` | pass | Hostname `localhost` is trusted without DNS resolution (a hosts-file change is out of scope). Operator opt-in `LLM_ALLOW_NON_LOCAL_ENDPOINT` deliberately bypasses the guard |
| AbuseIPDB provider | URL is a fixed constant plus `/check`; the observable is parsed with `ipaddress.ip_address` and sent as a query parameter, never as host or path | READ `threatintel/abuseipdb/provider.py` | pass (read-only) | `base_url` is a constructor argument, not request data |
| Other TI providers | Orchestrator applies a private-network shield before any address leaves the host; external lookups are off by default and need per-query opt-in | RUN `test_threatintel_private_shield.py` (in the 294 passed run); READ config | pass | |
| Webhooks | None found in `backend/app` | RUN grep (`httpx`, `requests`, `urllib`, `aiohttp`) | pass | Outbound HTTP exists only in the Ollama provider, the embedder and TI providers |
| Frontend `VITE_API_BASE_URL` | Build-time value, must be `https://`, rewritten into the CSP | READ `vite.config.ts` | pass | Not user data at runtime |

## Supply chain (Remotion video project and fonts)

| Item | Checked | How | Result | Evidence |
|---|---|---|---|---|
| Fonts | Geist, Newsreader, JetBrains Mono come from `@fontsource*` npm packages, bundled into `dist/assets`; no Google Fonts or CDN request; CSP `font-src 'self'` | RUN `npm run build`, grep of `dist/index.html` and CSS for external URLs (only `http://127.0.0.1` and `http://localhost` in the CSP meta); RUN `test_index_html_csp_has_no_script_escape_hatches` (no external `src`/`href`) | pass | Package integrity depends on npm's registry and the lockfile integrity hashes |
| Remotion project | `video/` has its own lockfile, exact pins (`remotion` and `@remotion/cli` 4.0.441), no remote fonts or URLs in `video/src`; `render` script uses the local Chrome path | READ `video/package.json`, grep `video/src` | pass with open advisories | 11 transitive advisories (see A06); local tooling only, never deployed. Its `render` script embeds a Windows Chrome path (not a secret) |
| Install scripts | Not audited for postinstall behaviour of the npm trees | not verified | UNVERIFIED | `npm ci --ignore-scripts` is recommended for CI if the build does not need scripts |

## Commands run (RUN evidence)

- `.venv\Scripts\python.exe -m pytest backend/tests/unit/test_owasp_web_deploy.py -q`: 6 failed before the fixes, 17 passed after.
- From `frontend/`: `npm run typecheck` (clean), `npm test` (256 passed, 0 failed; the 16 new tests in `security_api_key.test.tsx` initially failed for the key-echo case), `npm run build` (succeeded).
- Existing related backend suites (294 passed): `test_api_auth`, `test_case_bola_security`, `test_logging`, `test_security_headers`, `test_rate_limiting`, `test_body_limit_regression`, `test_threatintel_private_shield`, `test_error_contract`, `test_diagnostic_logging`.
- `.venv\Scripts\python.exe -m pip_audit -r requirements.txt` and `-r backend/requirements.txt`: no known vulnerabilities. `npm audit` in `frontend/` and `video/`: results above.
- `pip` was missing from `.venv`; it was restored with `ensurepip` and `pip-audit` was installed there (the only environment change).

## Open items and not verified

Open: vite/esbuild dev-server advisories (needs a vite major upgrade); video `@remotion/cli` advisories (bump to 4.0.545); production should refuse default DB credentials and a wildcard `CORS_ORIGINS` (backend `core/config.py`); no global LLM concurrency cap; CI actions on tags not SHAs and no `npm audit` step; `requirements.txt` without hashes; no idle timeout or 401 auto-clear for the SPA key; `style-src 'unsafe-inline'`.

Not verified: nginx and Pages header behaviour on a running server (static analysis of the configuration only); Render proxy rate-limit behaviour; Docker image user and healthcheck behaviour (Docker was not run); the video npm install scripts; server-side key storage and hashing beyond existing suites; monitoring and alerting under `infra/`.
