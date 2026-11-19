# Route Body-Limit Inventory

Date: 2026-11-12. Status: inventory IMPLEMENTED (generated from the running application); the **global default is a PROPOSAL, not implemented**. No deployment configuration was changed.

## 1. Method
* Operations and request bodies: `app.openapi()` of `app.main.app` (FastAPI 0.141.1) -> **33 operations, 16 accept a request body, 17 are body-less (GET)**.
* Authorization column: parsed from the endpoint source (`Depends(...)` names and role checks), because the framework wraps included routers and hides them from direct route introspection. Stacked-decorator aliases can be mis-parsed by the script; the one mis-parse found (`/investigations/synthesize`) was corrected by reading `cases.py`.
* Limit column: matched against `app/middleware/body_limit.py::LIMITS` (`BodySizeLimitMiddleware`, innermost user middleware, applied before authentication and routing).
* Machine-readable copy: `D:\AISOP-Backups\Reference_Research_2026-11-12\logs\routes.json`.

## 2. Operations that accept a body
| # | Method | Path | Authorization (from source) | Body limit today | Recommended |
|---|---|---|---|---|---|
| 1 | POST | `/api/v1/alerts/ingest` | api_key,can_ingest | 16 MiB | explicit exception (existing) |
| 2 | POST | `/api/v1/cases` | analyst | none | global default 1 MiB |
| 3 | PATCH | `/api/v1/cases/{case_id}` | case_role(LEAD),analyst | none | global default 1 MiB |
| 4 | POST | `/api/v1/cases/{case_id}/assignments` | case_role(LEAD),analyst | none | global default 1 MiB |
| 5 | POST | `/api/v1/cases/{case_id}/close` | case_role(LEAD),analyst,can_close | none | global default 1 MiB |
| 6 | POST | `/api/v1/cases/{case_id}/evidence` | case_role(INVESTIGATOR,LEAD),analyst,can_link_evidence | none | global default 1 MiB |
| 7 | POST | `/api/v1/cases/{case_id}/evidence/domain` | case_role(INVESTIGATOR,LEAD),analyst,can_link_evidence | 8 MiB | explicit exception (existing) |
| 8 | POST | `/api/v1/cases/{case_id}/investigations/multisource` | case_role(INVESTIGATOR,LEAD),analyst,can_synthesize | none | global default 1 MiB |
| 9 | POST | `/api/v1/cases/{case_id}/investigations/synthesize` | case_role + analyst (stacked alias of `/{case_id}/synthesize`; verified by reading `cases.py`, parse artefact showed `-`) | none | global default 1 MiB |
| 10 | POST | `/api/v1/cases/{case_id}/lead` | case_role(LEAD),analyst | none | global default 1 MiB |
| 11 | POST | `/api/v1/cases/{case_id}/reports/synthesize` | analyst | none | explicit exception: 4 MiB (to be measured) |
| 12 | POST | `/api/v1/cases/{case_id}/synthesize` | analyst | none | global default 1 MiB |
| 13 | POST | `/api/v1/evidence/ingest` | api_key,can_ingest | 64 MiB | explicit exception (existing) |
| 14 | POST | `/api/v1/investigations/synthesize` | api_key | none | global default 1 MiB |
| 15 | POST | `/api/v1/reports/format` | api_key | none | explicit exception: 4 MiB (to be measured) |
| 16 | POST | `/api/v1/reports/synthesize` | api_key | none | explicit exception: 4 MiB (to be measured) |

Body-less operations (GET): `/`, `/api/v1/health`, `/api/v1/health/ready`, alerts list/detail/adapters, cases list/detail/activity/evidence/reports export, multisource section reads, evidence reads (`by-hash`, `entities`, `events`, `{evidence_id}`). They carry no body and are outside this policy (a GET with a body is not read by these handlers).

## 3. Findings
1. Only **3 of 16** body-accepting operations are limited (alerts ingest 16 MiB, evidence ingest 64 MiB, domain import 8 MiB). Verified on the wire for the two ingest paths and the import path (`Stage6_Post_Implementation_Verification_Addendum.md`).
2. The other 13 accept JSON bodies with no application-level cap; behind the repository's nginx a global `client_max_body_size 50M` applies (`deploy/nginx/nginx.conf:58`), a direct-to-uvicorn deployment has none. Pydantic limits (field `max_length`) apply only **after** the whole body is parsed.
3. Legitimate sizes for the 13: case create/update/assign/close/lead and evidence link bodies are bounded by schema fields (`max_length` 200 to 2000 characters, a UUID) so well under 10 KiB; the synthesize/multisource option bodies are a handful of scalar fields. Two exceptions are structurally large: `POST /reports/format` takes a whole `InvestigationValidationResult` plus an optional `InvestigationContext` (up to `MAX_CONTEXT_EVENTS = 200` events with attributes), and `/reports/synthesize` carries similar structures. **Their real maximum has not been measured**.

## 4. Recommendation (PROPOSED; no limit values were changed in this task)
| Policy element | Value | Rationale |
|---|---|---|
| Global default for `POST`, `PUT`, `PATCH` on `/api/` not listed below | **1 MiB** | about 100 times the largest legitimate small body; cheap to reject; protects every present and future route by default instead of by memory |
| Explicit exception: `/alerts/ingest` | 16 MiB (keep) | batch of up to 1000 alerts, about 16 KiB each; tunable |
| Explicit exception: `/evidence/ingest` | 64 MiB (keep; flagged) | schema allows 2000 x 64 KiB = about 125 MiB; 64 MiB is below the theoretical maximum and above any real Sysmon batch; owner to confirm |
| Explicit exception: `/cases/{id}/evidence/domain` | 8 MiB (keep) | 500 records, per-record cap 1 MiB; typical batches are far smaller |
| Explicit exception: `/reports/format`, `/reports/synthesize` | **4 MiB, provisional** | must be sized by serialising a maximum-size validation result and context before approval (UNMEASURED) |
| Mechanism | extend the existing `LIMITS` table with a default entry and a method filter; keep one module; keep 413 with the fixed body; keep the streamed-body rewrite (measured necessary) | one place to review; no second middleware |
| Not recommended | raising any existing limit; per-route values scattered in endpoint code | arbitrary increases and drift |
| Out of scope here | `root_path` / path-prefix deployments (the patterns are anchored at `/api/v1`), HTTP/2, slow-body timeouts, reverse-proxy settings: UNVERIFIED; no deployment configuration was changed |

## 5. Required tests before enabling the default
Each of the 13 unlimited operations rejects a 2 MiB body with 413 and accepts a normal small body; the three explicit exceptions keep their limits; `/reports/format` accepts a measured maximum-size valid request; the existing 1530-test unit suite and 85 integration tests stay green; streamed and declared oversize both yield 413 (already covered by `test_body_limit_regression.py` for the three limited paths).
