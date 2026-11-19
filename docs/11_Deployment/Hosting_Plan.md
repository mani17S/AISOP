# AISOP Hosting Plan, zero cost (PROPOSED, nothing deployed)

Status: PROPOSED. Revised 2026-11-19 for a student budget of zero and no dependence on a personal laptop being on.
Nothing has been registered, signed up for or published. Facts come from vendor pages fetched on 2026-11-19 and the free-for-dev list.

## 1. Chosen stack (all free tiers)

| Part | Service | Verified free terms | Notes |
|---|---|---|---|
| Frontend | Cloudflare Pages | 500 builds per month, 20,000 files, 25 MiB per file, 100 custom domains; unknown paths such as `/privacy` fall back to `index.html` unless a `404.html` exists | Gives a free `<project>.pages.dev` address with HTTPS and no domain purchase. |
| Database | Neon (free Postgres) | Permanent plan, no credit card, 1 GB per project, 100 CU-hours per month, compute suspends after 5 minutes idle and wakes on the next query; pgvector available on every plan | The first request after idle is slower. |
| Backend API | Render free web service | 750 instance hours per month, spins down after 15 minutes without traffic, about 1 minute to wake, ephemeral filesystem | Card requirement not stated on the page, confirm at sign up. Docker support on the free tier not confirmed; a native Python start command is the safe route. |
| Language model | None hosted | Ollama cannot run on any of the free tiers above | The deterministic path works with the LLM disabled. Hosted deployment runs without AI synthesis. |

Rejected:
- Render free Postgres: expires 30 days after creation, then deleted.
- Koyeb: requires a credit card ($29 pre-authorisation hold per its FAQ), and only 512 MB RAM.
- Supabase: 500 MB database, pause rules not verified.
- Oracle Always Free: page returned 403, terms not read; it normally needs a card for sign up.
- Anything that needs your laptop running.

## 2. Domain

- **No cost, no registration:** the `*.pages.dev` address from Cloudflare Pages. It sits on a reputable shared suffix and cannot be reclaimed by a third party.
- **Custom domain, optional:** a free subdomain from free-for-dev. RIPE NCC issues IP addresses only, so it is not a source.
  - FreeDNS: shared domains "may disappear next week" and are not indexed by Google by default.
  - DNSHE: free subdomains on third-party suffixes, one-year term, free renewal within 180 days before expiry, can be reclaimed. Terms page not read.
  - DigitalPlat and pp.ua: unverified.
  - Free suffixes are often rated poorly by email and web filters, which matters for a security product.
- A subdomain can stay on external DNS: associate it in the Pages dashboard first, then add a CNAME to `<project>.pages.dev` (CNAME first gives a 522 error). An apex domain needs Cloudflare nameservers.
- Record the final address in `deploy/DOMAIN.txt` so `npm run prelaunch` can pass.

## 3. Wiring

1. Create a Neon project, run `CREATE EXTENSION vector;`, then `alembic upgrade head` against it (owner supplies the connection string as a secret; never commit it).
2. Deploy the backend to Render with `ENVIRONMENT=production`, `API_AUTH_ENABLED=true`, `DATABASE_URL` set to the Neon string, LLM disabled, and `CORS_ORIGINS` set to the exact frontend origin only.
3. Create the first analyst and token directly in the database; there is no public sign-up.
4. In Cloudflare Pages use root directory `frontend`, build command `npm run build`, output directory `dist`, and set the build variable `VITE_API_BASE_URL` to the Render https address. The build then allows only that origin in the page's Content-Security-Policy (verified locally). `frontend/public/_headers` adds the security headers.

Deploy files prepared in the repository: `render.yaml` (backend blueprint, secrets left to the dashboard) and `frontend/public/_headers`.

The backend also needs a Windows-specific event-loop launcher only on Windows; Render runs Linux and does not.

## 4. Safety rules for a public student deployment

- Public data must be synthetic or sample data only. Do not ingest real telemetry, real alerts or real personal data.
- The API stays behind token authentication. Treat all issued tokens as secrets and rotate them if shared.
- Rate limiting and brute-force protection on the API are UNVERIFIED and must be checked before launch.
- Free tiers can change or disappear. Do not rely on them for anything with a deadline without a backup copy of the database (`scripts/backup_postgres.ps1` produces one).
- Expect a slow first load after idle: Render takes about a minute to wake and Neon a moment after 5 idle minutes. The interface will show Degraded until the backend answers.

## 5. Launch gate

Run `npm run prelaunch` in `frontend/`. Launch is blocked until every check passes. Failing now:
- operator name, contact email, governing law and effective date in `frontend/src/legal/operator.ts` (owner supplies them)
- `deploy/DOMAIN.txt`
- a build made with `VITE_API_BASE_URL` set to the https API address

Also required and not scriptable: review of the Privacy Policy and Terms of Service by someone qualified, and an independent security review.

## 5a. Sources fetched 2026-11-19

developers.cloudflare.com (Pages limits, serving pages, custom domains); neon.com (pricing, pgvector); render.com/docs/free; koyeb.com/docs/faqs/pricing; supabase.com billing docs; freedns.afraid.org; dnshe.com; free-for-dev README (local copy). Failed or unread: oracle.com free tier (403), domain.digitalplat.org (403), nic.ua pp.ua terms.
