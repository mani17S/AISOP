# OWASP API Security Top 10 (2023) Review

Scope: the FastAPI backend (`backend/app`), all six routers in `backend/app/api/v1/endpoints/`, the middleware stack and the authentication core. Review date 2026-11-22. This is an owner-authorised defensive review of the project's own code on the owner's machine. It is a point-in-time review, not a certification, and not a production-readiness claim.

## How to read the evidence

| Label | Meaning |
|---|---|
| LIVE | Sent to the running backend (`http://127.0.0.1:8000`, disposable database `aisop_ui_review`, development environment) with real keys for four roles: tier-2 lead, tier-1 outsider assigned to nothing, security_admin, ingest. |
| TEST | Offline regression test, real FastAPI app on the SQLite harness. Test names are in `backend/tests/unit/test_owasp_api_auth.py` (`auth`) and `backend/tests/unit/test_owasp_api_hardening.py` (`hard`). |
| CODE | Read in source only; not exercised. |

Important caveat on LIVE results: the live server was started before this review's fixes. The LIVE probes therefore show the behaviour **before** the fixes. The fixes are verified by TEST only (and are not yet running in that server process until it is restarted).

Status values: pass (no defect), fixed (defect found, failing test written first, fixed, test passes), open (not fixed, see residual risk).

## Defects found and fixed

| # | Risk | Defect | Evidence before fix | Fix |
|---|---|---|---|---|
| F1 | API2 | No brute-force protection for invalid keys; the rate limiter keyed on the raw credential header, so each random key got a fresh bucket. 260 random invalid keys from one address were all answered 401 and never throttled. | LIVE (260 x 401, no 429); TEST `hard::test_api4_rotating_credentials_cannot_bypass_the_per_client_rate_limit` and `auth::test_many_invalid_keys_from_one_client_are_locked_out_with_429` failed first | New `backend/app/core/auth_throttle.py` (sliding window, lockout doubling to 15 min, per address and per address+prefix, never per prefix alone, so no account lockout DoS); wired in `backend/app/core/auth.py` (`locked_out`, `reject`); state on `app.state.auth_throttle` in `backend/app/main.py`; `rate_limit.py` now also charges a per-address aggregate bucket (4x the per-key bucket) to credentialed requests |
| F2 | API2 | Non-ASCII credentials in both headers caused HTTP 500 (`secrets.compare_digest` raises `TypeError` on non-ASCII `str`). Same latent defect in the legacy-key comparison. | LIVE (500 with INTERNAL_ERROR); TEST `auth::test_non_ascii_*` failed first | `backend/app/core/auth.py` `_equal()` compares UTF-8 bytes; legacy loop compares every configured key with no early exit |
| F3 | API2 | `analyst_api_clients.last_used_at` existed but was never written, so a stolen or dormant key could not be spotted. | Code read; TEST `auth::test_last_used_at_is_recorded_after_a_successful_authentication` failed first | `backend/app/core/auth.py` `_touch_last_used()`: best effort, at most one write per key per 5 minutes, after a successful verification only, never affects the auth outcome |
| F4 | API4/API8 | X-Forwarded-For was read from the left (client-controlled) once the peer was a trusted proxy (loopback is trusted by default), so a client could mint unlimited per-address buckets. | LIVE (130 anonymous requests with rotating XFF all 401, none throttled); TEST `hard::test_api4_forged_leftmost_forwarded_for_entries_do_not_create_new_buckets` failed first | `backend/app/middleware/rate_limit.py` `resolve_client_ip()`: walk the header from the right, first non-trusted valid IP wins, malformed entry falls back to the socket peer. Shared by auth and rate limit |
| F5 | API4/API6 | LLM-capable endpoints (case synthesize x3, multisource start, report export) had only the general 120/min per-key allowance: one key could queue up to 60 concurrent local-model inferences. | Code read; TEST `hard::test_api4_expensive_llm_capable_endpoints_...` failed first | `rate_limit.py` `EXPENSIVE_PATTERNS` plus a second per-credential bucket (`RATE_LIMIT_EXPENSIVE_PER_MINUTE`, default 20/min, burst 10) |
| F6 | API4 | No request-body cap on the small-JSON write endpoints. A 20 MiB `query_filter` to `/cases/{id}/synthesize` was accepted and parsed; the request had not finished after 30 s. | LIVE (client read timeout at 30 s); TEST `hard::test_api4_small_json_write_endpoints_have_a_request_body_cap` failed first | `backend/app/middleware/body_limit.py` `SMALL_BODY_LIMITS` (1 MiB; 8 MiB for `/reports/format`), applied by a second `BodySizeLimitMiddleware` instance in `main.py`. The existing `LIMITS` table is untouched |
| F7 | API8 | 429 responses were produced outside the security-headers middleware (no nosniff, CSP, frame headers). | Code read; TEST `hard::test_api8_throttled_429_responses_still_carry_the_security_headers` failed first | `main.py` middleware order: security headers now wrap the rate limiter |
| F8 | API8 | API responses (case and evidence JSON) carried no `Cache-Control`. | LIVE (header absent); TEST `hard::test_api8_api_responses_are_not_cacheable` failed first | `security_headers.py`: `Cache-Control: no-store` unless already set |
| F9 | API8 | HSTS was emitted on plain HTTP when a client sent `X-Forwarded-Proto: https`. | LIVE (HSTS header returned over http); TEST `hard::test_api8_hsts_is_only_sent_for_real_tls_...` failed first | `security_headers.py`: the header is honoured only from a configured trusted proxy; direct TLS still works |
| F10 | API8 | `GET /api/v1/health/ready` is unauthenticated and returned database engine, pgvector version, schema and dimension, LLM provider, model, latency and provider error text. | LIVE (full detail returned) | `backend/app/api/v1/endpoints/health.py:370`: the `checks` object is returned only in `development`; status and HTTP code are unchanged. TEST `hard::test_api8_unauthenticated_readiness_hides_infrastructure_detail_outside_development` |
| F11 | API8 | A wildcard `CORS_ORIGINS` with `allow_credentials=True` was accepted in any environment. CORS also allowed `PUT` and `DELETE`, which no route implements. | Code read; TEST `hard::test_api8_wildcard_cors_origin_is_refused_outside_development`, `..._cors_methods_are_limited_...` failed first | `backend/app/core/config.py` `_validate_cors_origins` (append-only); `main.py` allow-list trimmed to GET, POST, PATCH, OPTIONS |
| F12 | API8/API9 | `GET /` advertised `"docs": "/docs"` in staging and production, where docs are disabled. | Code read; TEST `hard::test_api8_root_does_not_advertise_docs_outside_development` failed first | `main.py`: key returned in development only |
| F13 | API2 | A canonical key placed in a URL path, query value or free text would be logged unredacted (the redaction patterns only matched `bearer ...` and `key=...` shapes). | TEST `auth::test_canonical_api_keys_are_redacted_wherever_they_appear_in_log_text` failed first | `backend/app/core/logging.py:48`: pattern for the canonical key format, shape kept (`aisop_live_[REDACTED]`) |
| F14 | API8 | Production could start with the shipped demo database credentials (`aisop:aisop`) or another trivially weak password. A wildcard `CORS_ORIGINS` was already refused by the Settings validator (F11). | TEST `hard::test_api8_production_settings_check_*` and `test_api8_application_refuses_to_start_in_production_with_default_database_credentials` failed first | `backend/app/core/config.py` `validate_production_settings()` and `ProductionConfigError` (append-only), called first in the `lifespan` in `backend/app/main.py`; the error names the problem and never the credential. Done at start-up, not in the Settings validator, so existing tests that build a production-environment app object keep working |

New settings (all default to safe values, in `backend/app/core/config.py`): `AUTH_BRUTE_FORCE_PROTECTION_ENABLED`, `AUTH_FAILURE_MAX_PER_IP` (20 rejected credentials per 5 minutes), `AUTH_LOCKOUT_SECONDS` (60, doubling), `RATE_LIMIT_EXPENSIVE_PER_MINUTE` (20).

## API1:2023 Broken Object Level Authorization

| Module / endpoint | Tested | Evidence | Status | Residual risk |
|---|---|---|---|---|
| Every `/cases/{case_id}/...` route (17 operations, probed live as 18 because two section names were tried: detail, patch, activity, assignments, lead, close, evidence link and list, domain import, multisource start, review, export, section, investigations/synthesize, synthesize, reports/synthesize, reports/export) as tier-1 outsider, security_admin outsider and ingest identity: existing-but-unassigned case versus random non-existent id | status and body (request id and UUIDs normalised) must be identical | LIVE: 0 differences across 54 pairs (3 roles x 18 probes, all 404, same body). TEST `hard::test_api1_unassigned_and_nonexistent_cases_are_indistinguishable_on_every_route` (3 roles) and `test_idor_matrix_covers_every_case_scoped_route` (a new route must be added to the matrix) | pass | None found |
| Same routes with a malformed body | does a 422 reveal that the case exists | LIVE and TEST `hard::test_api1_malformed_body_does_not_reveal_whether_the_case_exists`: dependencies run before body validation, both 404 | pass | None |
| `/evidence/events/{id}`, `/evidence/{id}`, `/evidence/by-hash/{hash}` | any role, real or random id | LIVE and TEST `hard::test_api1_unscoped_evidence_and_synthesis_routes_are_uniformly_disabled`: always 403 `UNSCOPED_ENDPOINT_DISABLED` | pass | None |
| `/alerts/{id}` | non-existent id | LIVE and TEST: 404 with a fixed message | pass | Alerts are a global triage pool by design (tier-1, tier-2, admin); not case-scoped |
| `/reports/format` with `case_id` | unassigned versus non-existent case | LIVE: both 422 (body validation first, identical); CODE: assignment check returns the shared 404 | pass | Only the 422 path was exercised live with a minimal body |
| Sub-resource id swap: an event from another case posted to `POST /cases/{B}/evidence` by a tier-1 who leads B | does ownership of the event matter | LIVE: 201, and the tier-1 then read the event's `normalized_payload` through `GET /cases/{B}/evidence` | **open (design)** | Any investigator or lead can link any existing event id to a case they control. Event ids are UUIDs, but they are listed to every tier-1 by the global triage views. This makes the "Decision 1A" rule (tier-1 sees full payloads only through a case) satisfiable by self-assignment. Not changed: it is the intended triage-to-case flow and a product decision. Recommendation: ADR proposing either lead approval or a case-claims-event rule for tier-1 |
| Same endpoint, non-existent event id | oracle | LIVE: 404 `EVIDENCE_NOT_FOUND` versus 201 for a real id | open (low) | Event-id existence oracle for investigators and leads only; 122-bit ids make enumeration impractical |
| Path variants: trailing slash, upper-case id, `%2e%2e`, `//`, braces, hyphenless, `;x=1` | auth bypass or alias | LIVE: trailing slash gives a 307 to the canonical URL (no auth bypass, same for assigned and unassigned), upper-case UUID resolves to the same object and is still authorised, all other variants 404 | pass | None |
| Method override headers (`X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`) and verbs DELETE, PUT, TRACE | override | LIVE: 405 with `Allow: GET`, headers ignored | pass | None |

## API2:2023 Broken Authentication and API key hardening

| Property | Finding | Evidence | Status |
|---|---|---|---|
| Generation | Canonical `aisop_<live\|test>_<16 hex prefix>_<64 hex secret>`: `secrets.token_hex(8)` prefix and `secrets.token_hex(32)` secret (256 bits), generated only by `backend/scripts/provision_demo_identities.py`, shown once, never logged | CODE; TEST `auth::test_token_generation_has_enough_entropy_and_hashes_are_stored_not_secrets` | pass |
| Storage | SHA-256 of the full token; no plaintext. SHA-256 (not a slow KDF) is appropriate for a 256-bit random secret | CODE | pass |
| Comparison | `secrets.compare_digest` on the digest, now on bytes (F2) | TEST | fixed |
| Lookup | Indexed unique prefix; wrong secret on a known prefix and an unknown prefix returned the same 401 body and header; median latency 25.3 ms versus 26.8 ms over 40 requests each (no measurable difference) | LIVE; TEST `auth::test_invalid_key_lookup_does_not_leak_whether_the_prefix_exists` | pass |
| Revoked, inactive, expired, deactivated analyst | All fail closed with the identical 401 `Invalid authentication credentials.` | TEST `auth::test_revoked_inactive_and_deactivated_keys_are_a_uniform_401`; expiry in CODE and the existing `test_api_auth.py` | pass |
| `last_used_at` | Was never written (F3) | TEST | fixed |
| Key in URL, log or error body | Keys in query strings (`api_key`, `X-API-Key`, `token`) are not accepted and not echoed; a key used as a path segment gives 422 with no echo (validation errors never echo input); log redaction now covers the canonical shape (F13). Correlation logging records method and path, never headers or query | LIVE (query variants 401); TEST `auth::test_a_key_sent_in_the_url_is_not_accepted_and_not_echoed` | fixed |
| Brute force | None (F1) | LIVE, TEST | fixed. In-memory and per process: lost on restart, not shared between workers |
| Conflicting or duplicate credentials | Bearer and X-API-Key must be equal | LIVE (401 `Conflicting authentication credentials provided.`) | pass |
| Legacy static keys | Disabled by default (`API_AUTH_ALLOW_LEGACY_KEYS=False`); when enabled they carry no analyst identity, so every analyst-scoped endpoint returns 403 and only the two ingest endpoints accept them (by design for sensors) | CODE; existing `test_api_auth.py` | pass. Residual: legacy keys have no hashing, expiry or revocation; keep them off outside local demos |
| `test` keys in staging and production | Rejected | CODE | pass |
| Unauthenticated access | Every one of the 35 operations returns 401 without credentials except `GET /`, `GET /api/v1/health`, `GET /api/v1/health/ready` | LIVE (full sweep) and TEST `hard::test_api9_every_registered_route_requires_authentication_except_the_public_probes` (enumerates the generated schema) | pass |
| Rotation and revocation | The only path is the operator script `backend/scripts/provision_demo_identities.py` (`--rotate` re-issues in place, `--revoke` deactivates the demo analysts and their clients without deleting rows). Setting `analyst_api_clients.is_active=false` or `analysts.is_active=false` takes effect on the next request (no cache). There is no HTTP admin API for keys and none was added: it would be a new privileged surface and is out of scope for this review | CODE | open (documented) |
| Key expiry | `expires_at` is honoured, but a key may be issued with no expiry; the demo script defaults to 48 h | CODE | open (policy) |

## API3:2023 Broken Object Property Level Authorization

| Module / endpoint | Tested | Evidence | Status | Residual risk |
|---|---|---|---|---|
| Case create and patch, assignments, lead transfer, close | Extra fields `lead_analyst_id`, `status`, `role`, `id`, `is_admin`, `severity` bypass, `case_role: lead` | LIVE and TEST `hard::test_api3_extra_fields_are_rejected_on_every_case_write_body`: all request models use `extra="forbid"`, 422 `extra_forbidden`; `case_role=lead` rejected by schema | pass | None |
| Response projections | Role-specific models: viewers get sanitised summaries (no `normalized_payload`, no `raw_evidence_id`); the global triage views are sanitised; raw payloads are never returned by the case or global routes | CODE; LIVE field list of the tier-1 case evidence response (no raw payload field) | pass | Investigators and leads receive `normalized_payload` by design |
| Error bodies | Validation errors never echo submitted values | CODE `core/errors.py`; LIVE | pass | None |

## API4:2023 Unrestricted Resource Consumption

| Module / endpoint | Tested | Evidence | Status | Residual risk |
|---|---|---|---|---|
| Pagination on cases, alerts, events, entities | `limit` 0, -1, 100000, abc, `page` 0, -5 | LIVE and TEST `hard::test_api4_pagination_and_offset_abuse_is_bounded`: all 422; `page=99999999999999999999` returns 200 with no 500 | pass | None |
| Rate limiting per IP and per key | Random-key rotation, XFF rotation (F1, F4); per-key buckets stay independent | TEST `hard::test_api4_*` | fixed | In-memory, per process |
| LLM-capable endpoints | Per-credential tighter bucket (F5) | TEST | fixed | Concurrency of in-flight inferences is still unbounded for a patient client (20/min); a semaphore around the provider would be the next step (outside the files this review may edit) |
| Request body size | F6; the explicit caps for domain import (8 MiB), alert ingest (16 MiB) and telemetry ingest (64 MiB) remain; streamed bodies without a truthful Content-Length are counted | LIVE (before), TEST `hard::test_api4_body_cap_counts_streamed_bytes_...` | fixed | `POST /cases/{id}/evidence` (a single UUID) is deliberately left without a cap because an existing regression test (`test_unlisted_paths_are_not_limited_by_this_middleware`) pins that behaviour |
| Server-side timeouts | Database pool timeout 10 s, Ollama client timeout 120 s with up to 3 retries, external TI timeouts. No application-level request timeout and no uvicorn slow-client limits configured here | CODE | open (deployment) | Set a reverse-proxy read timeout and uvicorn limits in the deployment; not a code change |

## API5:2023 Broken Function Level Authorization

Role by endpoint, as enforced in code (CODE) and probed with the real keys (LIVE) where noted. "assigned" means an active case assignment; unassigned and non-existent are both 404.

| Endpoint | ingest | tier-1 | tier-2 | security_admin | Case role needed | Verified |
|---|---|---|---|---|---|---|
| `POST /alerts/ingest`, `POST /evidence/ingest` | allow | 403 | 403 | 403 | none | CODE, existing tests |
| `GET /alerts`, `GET /alerts/{id}`, `GET /evidence/events`, `GET /evidence/entities` | 403 | allow | allow | allow | none (global triage, sanitised) | LIVE (alerts/{id}), CODE |
| `GET /alerts/adapters` | allow | allow | allow | allow | none | CODE. Static adapter and taxonomy list; any authenticated identity, no data exposure |
| `POST /cases` | 403 | allow | allow | allow | none | LIVE (tier-1 create 201), CODE |
| `GET /cases` | 200, empty | own | own | own | list is filtered to assignments | LIVE (ingest and admin got `total=0`) |
| `GET /cases/{id}`, `/activity`, `/evidence`, `/investigations/multisource/{section}`, `/reports/export` | 404 | 404 unless assigned | same | same | viewer, investigator or lead | LIVE (outsiders), CODE |
| `POST /cases/{id}/evidence`, `/evidence/domain`, multisource start and export | 404 | 404 unless assigned | same | same | investigator or lead | LIVE (outsiders), CODE |
| `PATCH /cases/{id}`, `/review`, `/lead` | 404 | 404 unless lead | same | same | lead | LIVE (outsiders), CODE |
| `POST /cases/{id}/assignments`, `/close` | 404 | lead is 403 (tier-1 cannot staff or close) | lead allowed | lead allowed | lead and tier-2 or admin | LIVE (tier-1 lead of own case got 403 on both) |
| `POST /cases/{id}/investigations/synthesize`, `/synthesize`, `/reports/synthesize` | 404 | assigned investigator or lead | same | same | investigator or lead (enforced in the service) | LIVE (outsiders), existing `test_case_synthesis_api.py` |
| Unscoped `POST /investigations/synthesize`, `/reports/synthesize`; `GET /evidence/{id}`, `/events/{id}`, `/by-hash/{h}` | 403 | 403 | 403 | 403 | n/a (disabled) | LIVE |
| `POST /reports/format` | 403 | allow | allow | allow | assigned if `case_id` is given | CODE |

Observed behaviour worth noting: an ingest identity gets `200` with an empty list from `GET /cases` rather than 403 (no data leak; pinned by the existing `test_owasp_probe_suite`). Security_admin has no case bypass (verified LIVE: 404 on every case route).

## API6:2023 Unrestricted Access to Sensitive Business Flows

| Flow | Control | Evidence | Status | Residual risk |
|---|---|---|---|---|
| Report export (outward-facing) | Multisource export is refused (409) unless the case lead approved the exact current result and the evidence is unchanged; every export is audited | CODE; existing multisource tests | pass | Role-tailored `reports/export` is deterministic and viewer-readable by design |
| Case creation and assignment churn | Per-key rate limit; tier-1 cannot staff or close | CODE, LIVE | pass | No per-analyst case quota |
| LLM investigation | Per-credential expensive bucket (F5); `use_llm=true` requires the synthesis role | TEST | fixed | See API4 |
| Evidence linking | Any investigator or lead can link any event id | LIVE | open (design), see API1 | |
| Telemetry and alert ingestion | Ingest role only, batch size and body caps, SHA-256 dedup | CODE | pass | A compromised sensor key can write evidence; keys are scoped to the ingest role only |

## API7:2023 Server Side Request Forgery

| Surface | Finding | Evidence | Status |
|---|---|---|---|
| User-supplied URLs | No endpoint accepts a URL, host or callback. Evidence text containing URLs is data and is never fetched | CODE (all request schemas) | pass |
| Ollama base URL | Operator setting only; must be loopback unless `LLM_ALLOW_NON_LOCAL_ENDPOINT=true`; credentials in the URL, non-http schemes and metadata addresses are refused | existing `test_owasp_probe_suite::test_llm_endpoint_must_be_loopback_unless_explicitly_allowed` | pass |
| External threat intelligence | Off by default (`TI_EXTERNAL_ENABLED=False`); the private-network shield blocks private, loopback, link-local and internal names; httpx clients do not follow redirects (default) and have explicit timeouts | CODE; existing `test_ssrf_*` | pass |

## API8:2023 Security Misconfiguration

| Item | Result | Evidence | Status |
|---|---|---|---|
| CORS | Explicit origin list (`http://localhost:3000`); foreign origins, `null` and a suffix-lookalike origin get 400 with no allow-origin header; methods now GET, POST, PATCH, OPTIONS; wildcard refused outside development | LIVE; TEST | fixed (F11) |
| Security headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP (`default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`), `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `X-XSS-Protection: 0`, `Cache-Control: no-store`; HSTS only over real TLS or a trusted proxy | LIVE (all but no-store and HSTS rule, which are TEST) | fixed (F7, F8, F9) |
| API docs and schema | `/docs`, `/redoc` and `/api/v1/openapi.json` served only in development (LIVE: 200, unauthenticated, development environment); staging and production return 404 | LIVE; TEST (existing and `hard::test_api8_staging_also_hides_docs_and_schema`) | pass. Note: the schema declares no security scheme, so the Swagger "Authorize" button does not work; documentation only |
| Debug and verbose errors | `DEBUG=False` default; 404, 405, 422 and 500 responses use the stable envelope; no stack trace, SQL, path or exception text in any probed response (invalid JSON, invalid UTF-8, bad UUID, bad datetime, short hash, unknown route) | LIVE; TEST existing `test_error_contract.py`, `test_owasp_probe_suite` | pass |
| Health | Liveness minimal; readiness detail now development-only (F10) | LIVE (before), TEST | fixed |
| `Server: uvicorn` banner | Present on every response | LIVE | open (low): start uvicorn with `--no-server-header`; not a code change |
| Redirect on trailing slash | 307 to the canonical URL built from the request Host | LIVE | open (info): no auth bypass; set `redirect_slashes=False` only if no client relies on it |
| 429 and 413 responses | Carry the stable envelope and now the security headers | TEST | fixed (F7) |

## API9:2023 Improper Inventory Management

| Item | Result | Status |
|---|---|---|
| Versions | One API version prefix, `/api/v1`. No `/v0`, `/v2`, `/internal`, `/debug` or unversioned business routes. TEST `hard::test_api9_no_unversioned_or_legacy_route_prefixes_exist` | pass |
| Deprecated surface | Five unscoped routes remain registered but are disabled and return 403 (`/evidence/events/{id}`, `/evidence/{id}`, `/evidence/by-hash/{h}`, `/investigations/synthesize`, `/reports/synthesize`). They are kept so old clients get an explicit, uniform error | pass (open question: delete them in a later cleanup) |
| Alias | `POST /cases/{id}/synthesize` aliases `/investigations/synthesize`; both are in the IDOR matrix | pass |
| Inventory guard | The IDOR matrix test fails if a new `/cases/{case_id}` route is added without being covered, and the unauthenticated sweep enumerates the generated schema | pass |

### Endpoint inventory (35 operations, all under `/api/v1` unless shown)

| Method | Path | Auth | Object id |
|---|---|---|---|
| GET | `/` | none | none |
| GET | `/health`, `/health/ready` | none | none |
| POST | `/alerts/ingest` | ingest role | none |
| GET | `/alerts`, `/alerts/adapters` | analyst or any key | none |
| GET | `/alerts/{alert_id}` | tier-1+ | alert (global pool) |
| POST, GET | `/cases`, `/cases` | analyst | none |
| GET, PATCH | `/cases/{case_id}` | assigned, lead for PATCH | case |
| GET | `/cases/{case_id}/activity` | assigned | case |
| POST | `/cases/{case_id}/assignments`, `/lead`, `/close` | lead | case |
| POST, GET | `/cases/{case_id}/evidence` | investigator+, viewer+ | case, event id in body |
| POST | `/cases/{case_id}/evidence/domain` | investigator+ | case |
| POST | `/cases/{case_id}/investigations/multisource` | investigator+ | case |
| POST | `/cases/{case_id}/investigations/multisource/review` | lead | case |
| GET | `/cases/{case_id}/investigations/multisource/export` | investigator+ | case |
| GET | `/cases/{case_id}/investigations/multisource/{section}` | viewer+ | case, enum section |
| POST | `/cases/{case_id}/investigations/synthesize`, `/synthesize`, `/reports/synthesize` | investigator+ | case |
| GET | `/cases/{case_id}/reports/export` | viewer+ | case |
| POST | `/evidence/ingest` | ingest role | none |
| GET | `/evidence/events`, `/evidence/entities` | tier-1+ | none |
| GET | `/evidence/events/{event_id}`, `/evidence/{evidence_id}`, `/evidence/by-hash/{sha256_hash}` | any analyst | disabled, 403 |
| POST | `/investigations/synthesize`, `/reports/synthesize` | any analyst | disabled, 403 |
| POST | `/reports/format` | analyst | optional case |

## API10:2023 Unsafe Consumption of APIs

| Upstream | Finding | Evidence | Status | Residual risk |
|---|---|---|---|---|
| Ollama (local LLM) | Loopback enforced; timeout and bounded retries; output is never trusted as evidence: it passes the claim-verification and sufficiency gates (a separate module not changed here); error text from the provider is not returned to API callers (stable envelope); the readiness route no longer returns provider error text outside development | CODE; existing tests | pass | The response body is read in full without a size cap (local, operator-controlled endpoint) |
| Threat-intelligence feeds | Local files, age-limited, off for external lookups by default; results are kept distinct from observed evidence | CODE | pass | Feed files are trusted operator input |
| Evidence text from sensors | Treated as untrusted: escaped in reports (existing XSS probe test), bounded by body and batch limits, never executed or fetched | existing `test_owasp_probe_suite` | pass | |

## What was verified live and what was only read

Verified live (before the fixes): unauthenticated access to every operation; IDOR matrix (3 outsider roles x 18 case probes x unassigned/non-existent); malformed-body ordering; sub-resource swap; mass assignment; method override and verbs; path variants; pagination abuse; bad-credential variants; key in URL; lookup timing; 260-key and 130-XFF flood; non-ASCII headers; headers, CORS, docs, health and error bodies; the 20 MiB body.

Verified by offline tests only: every fix; the role matrix for roles and routes not hit live (viewer and investigator behaviour, expiry, revocation); the security-header and HSTS rules; staging and production behaviour.

Read in code only: key generation, storage, redaction beyond the new pattern, the viewer and investigator gating in `CaseService`, external TI and Ollama handling, timeouts.

Not verified: behaviour behind a real reverse proxy and TLS; PostgreSQL-specific behaviour of the new `last_used_at` update (SQLite in tests; the live server was not restarted); multi-worker deployments (the throttle and rate limiter are per process); concurrent-load behaviour of the new lockout.

## Open items

1. API1/API6: any investigator or lead can link any event id to their own case (see API1). Decided: ADR-014 (approved 2026-11-22, Option A): the evidence pool is shared by design (single-tenant), every link is already audited, and the id-existence test is an accepted residual risk.
2. API2: no HTTP key-management API; rotation and revocation are operator-script only; keys can be issued without expiry.
3. API4: no application-level request timeout (the in-flight cap on model calls was added, see the follow-up below); the evidence-link body is uncapped by design of an existing test.
4. API8: `Server: uvicorn` header; trailing-slash 307 redirects; the throttle and rate limiter are in-memory per process.
5. API8: the development configuration still serves docs, the schema and full readiness detail unauthenticated; production settings (`ENVIRONMENT=production`) close all three.

## Follow-up 2026-11-22: cap on concurrent model calls

The earlier review left "no cap on in-flight LLM calls" open. `LLM_MAX_CONCURRENCY` (default 1, range 1 to 8) now limits model calls in flight per process, using one gate per event loop shared by every provider instance (`backend/app/modules/ai/providers/ollama/provider.py`). Extra callers wait for a slot; the request timeout starts only when the call is sent, so a queue no longer makes every caller time out together. Pinned by `backend/tests/unit/test_llm_concurrency.py` (four simultaneous calls reach the model one at a time; a higher limit is honoured). Offline-tested only. The limit is per process, like the other throttles.

