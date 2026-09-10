# ADR-005: Frontend Technology Stack

| Field | Value |
|-------|-------|
| **ID** | ADR-005 |
| **Status** | APPROVED |
| **Date Proposed** | 2026-09-09 |
| **Date Approved** | 2026-09-09 |
| **Decision Maker** | Project Owner |

---

## Question

What JavaScript framework and build tooling should AISOP's frontend
investigation workspace use?

## Context

AISOP's investigation workspace — where analysts view timelines, explore
entity relationships, confirm or reject AI hypotheses, and generate reports —
requires a web-based dashboard. The frontend must render:

- Investigation timelines (chronologically ordered events with expandable
  detail)
- Entity relationship graphs (hosts ↔ users ↔ processes ↔ connections)
- Evidence detail panels (raw log display, normalized fields, AI annotations)
- AI hypothesis cards (confidence indicators, evidence links, confirm/reject)
- Case management views (case list, status, assignment, priority)
- Role-tailored report previews (SOC, IR, Detection Engineering, Executive)
- Dark-mode cybersecurity aesthetic (industry standard for SOC tools)

The frontend communicates with the FastAPI backend exclusively via REST API
(`/api/v1/*`). There is no public internet audience, no SEO requirement, and
no need for server-side rendering.

AISOP Master Prompt references:

- §4: Local deployment, self-hosting, workstation deployment.
- §11: *"Avoid unnecessary abstractions."*
- §26: *"Every major dependency should answer: Why do we need it?"*
- §27: *"Reproducible development environment."*

## Options Considered

### Option A: React 19 + Vite + Vanilla CSS / CSS Modules

Initialize a React single-page application with Vite as the build tool.
Styling via Vanilla CSS (CSS custom properties for theming) or CSS Modules.
State management via React hooks + Context API (or Zustand if complexity
warrants). Routing via React Router.

`npm run build` produces a static `dist/` folder that can be served by
FastAPI (`StaticFiles`), nginx, or opened from disk. Zero additional server
runtime.

### Option B: Next.js (App Router)

Full-stack React framework with server-side rendering, API routes, file-based
routing, and built-in optimization. Requires a Node.js server runtime in
production.

## Trade-Off Analysis

| Criterion | Option A: React + Vite | Option B: Next.js |
|-----------|----------------------|-------------------|
| Local-First Deployment | Strong | Weak |
| Open-Source Extensibility | Strong | Adequate |
| Modularity | Strong | Weak |
| Security | Adequate | Adequate |
| Maintainability | Strong | Adequate |
| Scalability | Adequate | Adequate |
| Developer Experience | Strong | Adequate |
| Testing | Strong | Adequate |
| Operational Complexity | Strong | Weak |
| Future LLM Flexibility | N/A | N/A |

Key differentiator: Next.js's core value proposition — server-side rendering
for SEO and initial page load — is entirely irrelevant for AISOP. AISOP is a
local investigation dashboard accessed by authenticated analysts, not a
public-facing website. SSR adds operational complexity (a Node.js server),
architectural confusion (two backends), and maintenance burden (Next.js
upgrade treadmill) without providing any benefit.

React + Vite produces static files servable by FastAPI directly, resulting in
a single-container or two-container deployment (backend + postgres) instead
of three.

## Recommendation

Option A (React 19 + Vite + Vanilla CSS) was recommended.

## Decision (Project Owner — 2026-09-09)

**APPROVED: React 19 + Vite (Option A) — static SPA architecture.**

Use a static SPA architecture for the initial frontend.

Next.js shall not be introduced unless a future approved requirement
demonstrates a concrete need for server-side/SSR functionality.

## Architectural Consequences

1. `frontend/` becomes a self-contained React SPA.
2. `npm run build` produces `frontend/dist/` with static HTML/CSS/JS.
3. The FastAPI backend can serve `dist/` via
   `app.mount("/", StaticFiles(directory="frontend/dist"))`.
4. In Docker, a multi-stage build copies `dist/` into the backend image.
   Single container serves both API and UI.
5. All API communication is explicit `fetch()` / `axios` calls to
   `/api/v1/*`.
6. Component library: custom cybersecurity-themed components (timeline, entity
   graph, evidence card) with Vanilla CSS for full control over dark-mode
   aesthetic.
7. State management starts with React Context + hooks; can evolve to Zustand
   if the investigation workspace state becomes complex.
8. The empty `frontend/package.json` will be replaced by a Vite-initialized
   project during an approved implementation phase.

## Risks

1. **Risk (Low): Complex State Management.** A full investigation workspace
   may eventually require sophisticated state management beyond React
   Context. **Mitigation:** Zustand (~2KB) or Jotai can be added
   incrementally without architectural changes.
2. **Risk (Low): Entity Relationship Graph Rendering.** Interactive node-link
   diagrams may require a specialized library (D3.js, React Flow, vis.js).
   **Mitigation:** Evaluate graph visualization libraries during the UI
   implementation phase. This doesn't affect the framework choice.
3. **Risk (Low): Real-Time Updates.** If AISOP adds real-time alert streaming
   (WebSocket), the SPA architecture supports this natively — no SSR needed.
   **Mitigation:** FastAPI has built-in WebSocket support; React handles
   WebSocket state via hooks.
