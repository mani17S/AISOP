# Phase 4: Investigation Report Bundle Viewer Implementation Report

**Document ID:** AISOP-DOC-PHASE4-REPORT-VIEWER-001  
**Classification:** Frontend Security & Application Architecture  
**Author:** Senior Application Security Engineer, Full-Stack Engineer, Frontend Design Engineer  
**Date:** 2026-10-31  
**Status:** IMPLEMENTED, TESTED & VERIFIED  

---

## 1. Executive Summary

Phase 4 of the AI-Assisted Security Operations Platform (AISOP) introduces the **Investigation Report Bundle Viewer**, an integrated, role-tailored reporting experience for security operations center (SOC) analysts, incident responders, detection engineers, and executive leadership.

The implementation consists of:
- **`frontend/src/pages/Reports.tsx`**: Owns case selection, authorized report orchestration, synthesis parameter configuration, and lifecycle states (idle, synthesizing, rendered, error).
- **`frontend/src/components/ReportViewer.tsx`**: Owns structured, high-density, multi-audience presentation:
  1. *Executive Brief*: Leadership overview, business risk statement, severity justification, evidenced affected assets, key confirmed findings, threat intelligence context.
  2. *Technical Incident Response Report*: Grounded timeline with chronological events, confirmed findings (`VALIDATED_REFERENCE`), hypotheses/inferences (`ANALYST_REVIEW_REQUIRED`), refuted claims audit, MITRE ATT&CK technique mappings, investigation gaps, and advisory analyst actions.
  3. *Detection Engineering Guidance*: Observables with provenance attribution (IPs, hashes, executables, command lines), MITRE coverage targets, candidate hunting pseudocode, recommended telemetry sources, and false-positive considerations.
  4. *Deterministic Markdown & JSON Export*: Role-gated, safe client-side file export for all generated reports.

---

## 2. Real Backend Contracts & Verification

The frontend implementation was developed exclusively against the real, active backend contracts:
- **Active Endpoint:** `POST /api/v1/cases/{case_id}/reports/synthesize`
  - Input: `CaseInvestigationSynthesizeRequest` (`time_window_start`, `time_window_end`, `root_event_id`, `query_filter`, `model_override`)
  - Output: `InvestigationReportBundle` (`executive_brief`, `technical_report`, `detection_report`, `provenance`, `markdown_executive`, `markdown_technical`, `markdown_detection`)
- **Format Endpoint:** `POST /api/v1/reports/format`
  - Input: `ReportFormatRequest` (`validation_result`, `context`, `case_id`)
  - Output: `InvestigationReportBundle`
- **Deprecated Unscoped Routes:** `POST /api/v1/investigations/synthesize` and `POST /api/v1/reports/synthesize` remain permanently blocked with HTTP 403 Forbidden to enforce case-level authorization.

---

## 3. Security Architecture & Threat Mitigations

1. **Anti-Enumeration & BOLA/IDOR Enforcement:**
   - Case selection is restricted to server-returned authorized cases (`api.getCases()`).
   - If a caller probes an unauthorized case, the backend returns HTTP 404 (`"Case not found or access denied."`), preventing resource enumeration.
2. **Zero `dangerouslySetInnerHTML`:**
   - All narrative texts, summaries, commands, hashes, and observables are rendered using native React JSX text nodes, guaranteeing complete HTML entity escaping.
   - Verified via automated tests: raw unescaped `<script>` and `<img>` tags are completely neutralized.
3. **Epistemic Segregation of Facts vs. Inferences:**
   - Observed facts backed by verified telemetry are explicitly tagged as `VALIDATED_REFERENCE`.
   - AI-generated inferences are labeled `ANALYST REVIEW REQUIRED`.
   - Refuted claims are preserved in an audit section with confidence scores and reasoning.
4. **Human-in-the-Loop Operational Policy:**
   - Recommended actions are prominently marked as advisory recommendations.
   - Zero automated remediation, endpoint isolation, account locking, or firewall configuration actions are executed by the interface.
5. **Zero Secret Disclosure:**
   - No API keys, Bearer tokens, or raw authorization headers are printed to browser console or telemetry.

---

## 4. Design Constitution Compliance

The Report Viewer adheres strictly to `docs/08_Frontend/AISOP_Website_Design_Constitution.md`:
- Deep dark-mode neutrals (`#0a0e17`, `#121826`, `#182234`) with high-contrast text.
- Tabular, high-density telemetry displays with monospace fonts for hashes, UUIDs, and commands.
- Zero purple gradients, zero pill buttons, zero emojis as interface icons, zero em dashes in copy.
- Zero fabricated metrics, fake customer counts, or simulated threat statistics.

---

## 5. Verification Evidence

1. **Frontend Typecheck (`npm run typecheck`):**
   - 0 errors (`tsc --noEmit`).
2. **Frontend Production Build (`npm run build`):**
   - Clean Vite production bundle in 722ms (`193.39 kB` JS, `18.82 kB` CSS).
3. **Frontend Component & Security Tests (`npm test`):**
   - 11/11 tests passed in 133ms (verifying XSS mitigation, fallback badges, empty states, timeline rendering, observables, and markdown export).
4. **Backend BOLA/IDOR Regression (`test_case_bola_security.py`):**
   - 47/47 tests passed in 5.71s.
5. **Existing Auth & Case Suites:**
   - 135/135 tests passed in 14.29s.
6. **Full Offline Backend Suite (`pytest -m "not postgres and not ollama"`):**
   - 1,144 passed, 28 deselected in 42.83s.

