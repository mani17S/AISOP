# Frontend Analyst-Experience Review (manual, Impeccable-guided)

Date: 2026-11-12. Scope: `frontend/src/components/{MultiSourcePanel,DomainEvidencePanel}.tsx`, `frontend/src/styles/index.css`. Status: **PARTIAL review.**

**Degraded method, stated up front.** Impeccable's critique protocol requires (A) a design review and (B) a deterministic detector run, as two isolated sub-agents, plus browser inspection. None of (B), the browser step or sub-agents was done: the detector engine is a downloaded binary that was deliberately not fetched (see `REFERENCE_REPOSITORY_ENGINEERING_REVIEW.md` section C), and no live browser check was authorized. This is therefore a **single-context, source-level critique**; every finding below was read from code or computed, none was observed on screen. Impeccable advice is subordinate to `frontend/AGENTS.md`, accessibility and the AISOP design constitution.

## 1. What the analyst can already tell (verified by code and render tests)
Observed vs. inferred vs. external vs. analyst vs. AI are labelled in separate sections (`EvidenceTable` trust column, `GraphSection`, `IntelligenceSection`, `AnalystStatements`, AI claim labels); source system, collection method, adapter, time status and SHA-256 prefix are shown per record; weak correlations read "Context only"; undated and unclassified records are labelled; contradictions use `role="alert"`; AI skipped/abstained/limit states are distinguished; API failures are shown, not hidden.

## 2. Findings (severity = reviewer judgement)
| # | Finding | Evidence | Severity | Suggested change (not implemented) |
|---|---|---|---|---|
| U1 | No responsive rules at all | `index.css`: 0 `@media` rules; the 10-column evidence table relies on `.table-container { overflow-x:auto }` | Medium | Stack the key columns on narrow widths; keep horizontal scroll as fallback |
| U2 | No visible keyboard-focus style for buttons, links or file input | `index.css`: only 2 `:focus` rules (inputs), 0 `:focus-visible`; the import file input and "Start/Force" buttons rely on browser defaults on a dark theme | Medium (accessibility) | Add a `:focus-visible` outline using an existing accent colour |
| U3 | Tables have no `<caption>` and no `scope` on headers | grep: 0 `<caption>`, 0 `scope=` in both panels | Medium (accessibility) | Add captions and `scope="col"`; screen-reader users currently get 8 anonymous tables |
| U4 | No reduced-motion handling | 0 `prefers-reduced-motion` | Low (few animations observed) | Add a guard when animations are introduced |
| U5 | Import progress is silent | `DomainEvidenceImport` disables the input while `busy` but renders no "importing" status text | Low-Medium | Add `role="status"` text during the call |
| U6 | Validation errors are codes, not explanations | quarantine list shows `FIELD_INVALID:ip` | Medium (the brief asks for understandable errors) | Map fixed codes to plain-language sentences client-side (codes remain visible) |
| U7 | "What is missing" is not shown as an action | sufficiency shows reason codes, but nothing says what evidence would raise the verdict | Medium (analyst action) | Derive from reason codes (e.g. `UNCORROBORATED_QUESTION` -> "a second independent source sharing a specific artefact") |
| U8 | Contradictions are an alert box inside the graph section; the verdict banner itself does not mention them | `GraphSection`; the report text has a notice (added at closure) but the banner does not | Medium | Show a contradiction line in or next to the verdict banner until the contradiction-aware verdict exists |
| U9 | Large evidence lists have no sort, filter or search | `EvidenceTable` renders all (up to 500) rows | Low-Medium | Client-side filter by classification, source, time status |
| U10 | Graph is tabular only | `GraphSection` lists edges; the node list the API returns is not shown | Low | Optional: grouped entity view; a node-link drawing is not justified for incident-sized graphs |
| U11 | `<pre>` report block is raw Markdown text | `MultiSourcePanel` renders `report_markdown` in `<pre>` | Low | Acceptable (no `dangerouslySetInnerHTML`); a safe Markdown renderer would need a dependency decision |
| U12 | Import control is shown to every role | backend returns 403/404 and the error is displayed | Low (backend enforces) | Optionally hide by role as convenience only |

## 3. Measured, not assumed
Colour contrast of the secondary text colour: `#8b9bb4` on card `#182234` = **5.65:1**, on page `#0a0e17` = **6.84:1** (WCAG AA body text needs 4.5:1): passes. Other colours (badges, severity red `#ef4444` on dark, amber `#f59e0b`, teal `#14b8a6`) were not measured.

## 4. Priority for Stage 9 (frontend and operational hardening)
1. U2 focus styles and U3 table semantics (accessibility, small, low risk).
2. U8 and U7 (analyst understanding of verdict and gaps), after the contradiction-aware verdict exists.
3. U6 plain-language validation messages.
4. U1 responsive layout; U5, U9, U10 as time allows.
Each change needs a render test and, once authorized, a live-browser check.
