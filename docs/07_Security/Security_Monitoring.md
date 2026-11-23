# Security monitoring: what the server saw being done to it

Status: IMPLEMENTED and tested offline; live-checked on the local demo stack (PostgreSQL) on 2026-11-22. Not yet exposed on a public server.

## What it is

A **Security** page, visible and readable only to the `security_admin` role, that shows the suspicious requests the API server observed: rejected API keys, lockouts after repeated bad keys, rate limiting, requests for paths that do not exist (scanners probing for `/.env`, `/wp-login.php`), wrong HTTP methods, oversized or malformed requests, and role refusals. It shows totals by kind, an hourly bar chart, the busiest source addresses, the most requested paths and the most recent events.

It answers the hosting question: once the API is on the internet, scanners reach it within minutes, and this is where that becomes visible.

## How it works

| Part | File | Notes |
|---|---|---|
| Rules and counter | `backend/app/core/security_events.py` | `classify` decides what is suspicious; `SecurityEventBuffer` counts per (minute, kind, source, status, path), caps at 5 000 keys and counts what it dropped; `clean_text` strips control characters and truncates |
| Observation | `backend/app/middleware/security_events.py` | Pure ASGI, outside the rate limiter and size caps so their 429 and 413 answers are seen; reads the response status after the fact; any failure is swallowed so it can never change a response |
| Storage | `backend/app/models/security_event.py`, migration `0005_security_events` | One row is a count, not a request |
| Writing and summary | `backend/app/services/security_event_service.py` | Written every 10 seconds; a refused write puts the counts back; rows older than 30 days are deleted hourly; the overview aggregates in Python over at most 20 000 rows so PostgreSQL and SQLite behave alike |
| API | `GET /api/v1/security/overview?hours=1..168` | `security_admin` only; a key with no analyst behind it (legacy machine key) is refused |
| Page | `frontend/src/pages/Security.tsx` | Tab shown when the role preview is Security admin; the server enforces the role |

A missing record on a real route (404 on `/api/v1/cases/<unknown id>`) is **not** recorded: it is ordinary use and, with the anti-enumeration rule, indistinguishable from an unauthorised case. Identifiers in real routes are replaced (`/api/v1/cases/{id}`) so an id never becomes part of what is stored.

## What is never stored

API keys or any part of one, request bodies, headers other than a cleaned user agent. Control characters are removed from everything attacker-controlled before storage and the page escapes it on display. Tested in `backend/tests/unit/test_security_events.py`.

## Privacy

Source IP addresses can be personal data. The privacy page states what is kept, for how long (30 days) and who can read it.

## What it cannot do (say this plainly)

- It records what **this process** saw. Traffic dropped before it reached the application (a firewall, the host, a platform edge) is invisible. A quiet page does not prove nothing happened.
- It blocks nothing. Blocking is the lockout, the rate limits and the request size caps.
- Behind a proxy (Render, Cloudflare) the source address is the proxy's unless the proxy is configured as trusted (`RATE_LIMIT_TRUSTED_PROXIES`); the existing client-address function reads `X-Forwarded-For` from the right and ignores client-controlled entries. **Not yet verified on the hosted service.**
- Counts waiting in memory are lost if the process is killed before the next write (at most about 10 seconds); a failed write is retried.
- It is not a SIEM, has no alerting and no correlation across sources.
- Under a large flood new keys are dropped and the page says how many events were not recorded.
- The free hosted tier restarts and sleeps the service; the database keeps what was written.

## Operating notes

- A new table needs privileges for a least-privilege runtime role: `GRANT SELECT, INSERT, DELETE ON security_events TO aisop_app;` (the setup script `scripts/demo_up.ps1` grants on all tables after migrating; an already-built database needs the grant once). Found when the first live read returned a permission error that SQLite tests could not show.
- To produce visible, labelled traffic for a demonstration: `.venv\Scripts\python.exe backend\scripts\demo_probe_traffic.py --base http://127.0.0.1:8010`. Every request carries a User-Agent saying it is demonstration traffic. Run it against a server you own, and not repeatedly within a few minutes (it triggers the lockout by design).

## Verified and not verified

Verified: 31 offline tests for the rules, the buffer, the middleware, role enforcement, cleaning, retention and the overview; a live read on PostgreSQL with 20 labelled requests showing the correct kinds, counts, sources and paths; the page rendered at 1425 px and 375 px without horizontal overflow; 8 page tests including escaping of hostile text.

Not verified: behaviour behind a real proxy and TLS; load (a sustained flood); the hosted database; multi-process deployments (each process keeps its own buffer and lockout state).
