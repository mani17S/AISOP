# Security Test Findings (five-day plan, 2026-11-20)

Scope: the OWASP-mapped probe suite requested in brief 20, section 4. Data is synthetic. Targets are the local test harness and a disposable local PostgreSQL stack on 127.0.0.1 only. Status words follow the project convention: only what a saved log shows is called passed.

## How it was tested
| Layer | Test | Where it runs | Record |
|---|---|---|---|
| Offline | `backend/tests/unit/test_owasp_probe_suite.py` (33 test cases through the real FastAPI app, SQLite harness, no network) | pytest | `D:\AISOP-Backups\AISOP_Dev_Logs_20261120\day123_security_offline_probes.log` (33 passed) |
| Live | `backend/scripts/live_security_probe.py` against the running backend on PostgreSQL (`aisop_demo`) | HTTP on 127.0.0.1:8010 | `day123_security_live_probe_result.json` (18 of 18 probes passed, run as the non-superuser role) |

Mapping used: OWASP API Security Top 10:2023 (API1 BOLA, API2 authentication, API3 property exposure and mass assignment, API4 resource consumption, API5 function level authorization, API8 misconfiguration), OWASP Top 10 (injection, access control, security misconfiguration), OWASP LLM Top 10 (LLM02 information disclosure, LLM05 improper output handling, LLM06 excessive agency, locality of the model endpoint).

## Findings
| ID | Severity | Finding | Evidence | Status |
|---|---|---|---|---|
| SEC-F1 | Medium | The multi-source Markdown report wrote raw evidence text into table cells, so an alert whose rule name contains `<script>`, `<img onerror>` or a `[x](javascript:...)` link produced an exported report that a Markdown or HTML viewer could execute. The web UI shows the report in a `<pre>` block and does not use `innerHTML`, so the UI was not affected. | probe `test_xss_script_and_markup_in_evidence_text_is_not_rendered_active_in_the_report` failed before the fix | **Fixed** in `backend/app/modules/correlation/report.py` (`_cell` escapes `&`, `<`, `>`, `|`, backticks and breaks link and image syntax). Offline probe and 413 related tests pass; live probe check passes. |
| SEC-F2 | High for any non-lab use | The backend connected to PostgreSQL as the container superuser (`rolsuper`, `rolcreatedb`, `rolcreaterole` all true). | `pg_roles` query | **Fixed for the demo stack**: `scripts/demo_up.ps1` creates `aisop_app` (no superuser, no createdb, no createrole, DML only), and the full live E2E passes as that role. **Not changed** for the default `docker-compose.yml` and the `aisop_dev` database; disclosed. |
| SEC-F3 | Low | An `ingest` identity can call `GET /api/v1/cases` and receives 200 with an empty list (the endpoint lists cases assigned to the caller). No data is exposed. | probe `test_api5_bfla_roles_cannot_call_functions_outside_their_role` | Disclosed, no change. |
| SEC-F4 | Low | The analyst API key is kept in browser `sessionStorage` (documented in `frontend/src/services/api.ts`). Any script running in the page could read it. | source | Disclosed. Mitigations in place: strict CSP, no `innerHTML`, no third-party scripts. |
| SEC-F5 | Low | Rate limiting is in process memory (60 requests per minute observed on the live backend), so it does not span several workers. | live responses carry `x-ratelimit-limit: 60` | Disclosed. Run one worker, or enforce limits at a reverse proxy. |
| SEC-F6 | High (npm severity; development dependency) | `vite` 5.4.21 (range `<=6.4.3`) has advisories that affect the **Vite development server** (path traversal in optimized deps `.map` handling, `server.fs.deny` bypass on Windows alternate paths, cross origin script execution through custom middleware, and several `launch-editor` issues). | `npm_audit_full.log`, `npm_audit_full.json` (npm audit, 2026-11-20) | **Not fixed, by owner decision**: the fix is a breaking major upgrade (`vite@8`) and no dependency may change during the 5-day window. Not present in the production build (`dist` is static files). Mitigation: the dev server binds to 127.0.0.1 only (`vite.config.ts`). Do not expose the dev server to a network. Upgrade after the window. |
| SEC-F7 | Moderate (CVSS 5.3; development dependency) | `esbuild` `<=0.24.2` (transitive through vite): any website can send requests to the esbuild development server and read the response. | same audit | **Not fixed**, same reason and mitigation as SEC-F6. |
| SEC-F8 | None found | `pip-audit` on the pinned `requirements.txt` (52 pinned packages): "No known vulnerabilities found". Caveats: run with `--no-deps --disable-pip` (it audits the pinned list, not a resolved tree), requirements are not hash-pinned, and it reflects the vulnerability database on the run date only. | `pip_audit_full.log` (first attempt timed out and is kept as `pip_audit_attempt1_timeout.log`) | No action. |

## Passing probes (offline suite, grouped)
BOLA (another analyst cannot read or act on a case: 8 routes), function level authorization (analyst tokens cannot ingest, ingest identities cannot triage or create cases, a case viewer cannot link evidence or start an investigation), authentication (7 invalid credential shapes on 3 endpoints, deactivated analyst), SQL metacharacters in 6 filters and path ids, pagination and batch limits, mass assignment, security headers, CORS for a foreign origin, error bodies without internals, NUL bytes, tokens and raw command lines absent from investigation and audit responses, LLM endpoint must be loopback (3 loopback forms accepted, 7 other forms refused), AI disabled returns the inert provider, unknown or non-local providers fail closed, private and internal indicators are shielded from external threat intelligence lookups.

## Not done (stated, not hidden)
- Dependency upgrades: none made (owner decision for the 5-day window); SEC-F6 and SEC-F7 stay open.
- PentAGI: not authorized, not run. No statement of "pentested with PentAGI" may be made. The correct statement is "OWASP-mapped probe suite executed".
- Browser-level XSS check of the report view, and a keyboard and screen reader review.
- Prompt injection against a real model (existing tests use scripted providers), model-output rendering with a live model.
- Credential rotation for the hosted Neon database and tokens: owner action.
- Backup file permissions, TLS to the database (not applicable on loopback), retention and deletion.
