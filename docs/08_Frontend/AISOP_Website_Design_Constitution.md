# AISOP Website and Frontend Design Constitution

**Document ID:** AISOP-CONST-DESIGN-2026-001  
**Classification:** Mandatory Architectural & UI/UX Design Policy  
**Scope:** Universal across all AISOP frontend surfaces (Dashboard, Cases, Evidence, Reports, Investigation views, Modals, Navigation, Forms, Visualizations, Settings, and Future Landing Pages).  
**Effective Date:** 2026-10-31  

---

## 1. Guiding Principle & Product Truth

AISOP is a serious, defensive, privacy-preserving cybersecurity engineering platform operating under local-first execution with zero recurring service costs. 

The frontend must reflect authentic cybersecurity engineering craft. It is designed for Security Operations Center (SOC) Tier-1/Tier-2 analysts, incident responders, detection engineers, and security auditors who depend on fast, readable, high-density, accurate telemetry and verified investigative evidence.

**AISOP is an operational command tool, not a generic vibe-coded AI SaaS landing page.**

---

## 2. Strictly Prohibited Visual Patterns

The following patterns are **permanently prohibited** from all AISOP frontend interfaces:

### 2.1 Color, Lighting & Geometry Bans
- **Banned:** Purple gradients, purple-to-blue SaaS gradients, and vibrant neon pastel overlays.
- **Banned:** Pill-shaped buttons (border-radius > 8px on buttons) and excessively rounded, bubbly containers.
- **Banned:** Unnecessary glassmorphism (`backdrop-filter: blur()`) that impairs contrast or readability.
- **Banned:** Cards nested arbitrarily inside cards without functional information hierarchy.
- **Banned:** Excessive glowing drop-shadows (`box-shadow: 0 0 25px rgba(...)`) or pulsing borders around static cards.

### 2.2 Animation & Motion Bans
- **Banned:** Cursor-following particles, floating ambient bubbles, and custom animated cursor trails.
- **Banned:** Excessive scroll-triggered layout shifts, parallax wobbles, or unprompted rotational transforms.
- **Allowed:** Purposeful, subtle transitions (<= 150ms `ease-in-out` on hover, focus, or modal open).

### 2.3 Fake Content & Fabricated Metric Bans (CRITICAL)
- **Banned:** Fake customer reviews, fabricated user testimonials, and fabricated corporate logos ("Trusted by Fortune 500").
- **Banned:** Fake user counters ("10,000+ SOC teams protected"), fake activity tickers, or simulated live customer feeds.
- **Banned:** Fabricated security metrics (e.g. "99.9% automated threat catch rate", "1,420 threats neutralized this week").
- **Banned:** Fabricated terminal output, fake incident streams, or hardcoded mock alert feeds in production views.
- **Banned:** Fabricated MITRE ATT&CK coverage percentages or synthesized confidence scores not backed by actual database models.
- **Banned:** Unnecessary "Made with AI", "Powered by Magic", or generic generative AI marketing badges.

### 2.4 Typography, Copywriting & Icon Bans
- **Banned:** Emoji icons used as user interface controls or section headers (e.g., 🛡️, 🚀, 🤖, ⚠️, 🔍). Use professional SVG icons or clean semantic badges.
- **Banned:** Em dashes (`—`) in website and user interface copy.
- **Banned:** Generic AI marketing slogans, including:
  - "Revolutionizing cybersecurity."
  - "Next-generation AI security."
  - "Unleash the power of AI."
  - "The future of threat intelligence."
  - "Autonomous AI defending your enterprise."
- **Required:** Plain, technically defensible, concise language describing actual capabilities.

---

## 3. Mandatory Visual & Architectural Standards

### 3.1 Color Palette
- **Backgrounds:** Deep dark-mode neutrals (`--bg-primary: #0a0e14`, `--bg-secondary: #0f141c`, `--bg-card: #151b24`, `--bg-input: #1a2332`).
- **Borders & Separators:** Subtle, high-contrast borders (`--border-color: #232d3f`, `--border-subtle: #1c2534`).
- **Typography:** 
  - Primary text: Crisp neutral off-white (`--text-primary: #f0f4f8`).
  - Secondary/metadata text: Muted slate (`--text-secondary: #94a3b8`).
  - Monospace telemetry/hashes: Modern tabular monospace (`--font-mono: 'JetBrains Mono', 'Fira Code', monospace`).
- **Status & Severity Accents (Restrained Semantic Colors):**
  - Informational / Active: Solid engineering cyan/blue (`#0284c7`).
  - Critical / High Severity: Crimson / Red (`#dc2626`).
  - Medium Severity: Amber / Orange (`#d97706`).
  - Low Severity / Notice: Muted Slate (`#64748b`).
  - Verified / Safe: Forest Emerald (`#059669`).

#### 3.1.1 Accessible Text Tones (Amendment A1, 2026-11-13, owner-approved in Phase 2.1)
The accent and severity fills above do not reach 4.5:1 as small text on the dark surfaces (for example `#0284c7` on `--bg-card` is 4.22:1 and `#dc2626` is 3.58:1). Two lighter tones of the SAME semantic families are therefore defined for **text and text-bearing foregrounds only**. They do not replace the fills, and they do not change what any colour means.

| Token | Value | Family | Purpose | Never use for |
|---|---|---|---|---|
| `--accent-text` | `#60a5fa` | Informational / Active (`#0284c7` family) | Active navigation and tab labels, links, informational counts, and the keyboard focus ring (`--focus-ring`) | Severity meaning, fills behind white text, success states |
| `--severity-critical-text` | `#f87171` | Critical / High (`#dc2626` family) | Critical or destructive text on dark surfaces (danger button label, critical badge text) | Backgrounds, borders that must carry 3:1 on their own, or any non-critical status |

Measured contrast (WCAG 2.1 relative luminance, computed 2026-11-13; script and raw output kept with the Phase 2.1 report):

| Foreground | `--bg-primary` | `--bg-secondary` | `--bg-card` | `--bg-input` |
|---|---|---|---|---|
| `#60a5fa` on constitution surfaces (`#0a0e14`, `#0f141c`, `#151b24`, `#1a2332`) | 7.61 | 7.26 | 6.80 | 6.21 |
| `#f87171` on constitution surfaces | 6.99 | 6.68 | 6.25 | 5.71 |

On the surfaces currently implemented in `frontend/src/styles/index.css` (`#0a0e17`, `#121826`, `#182234`, `#1f2c42` hover, `#0d131f`) `#60a5fa` measures 7.59, 6.97, 6.27, 5.52, 7.31 and `#f87171` measures 6.98, 6.41, 5.76, 5.07, 6.72. On tinted fills `#f87171` on `rgba(239,68,68,0.2)` over `--bg-card` is 4.71:1 and on `rgba(239,68,68,0.15)` is 5.02:1; `#60a5fa` on `rgba(59,130,246,0.2)` is 4.81:1.

Approved pairings (measured above, normal-size text, at least 4.5:1): each tone on the four surfaces in the table, and the tinted fills listed. Rules:
- This table is a record of measured pairings, not a claim that every combination is accessible. A pairing not listed here must be measured before use.
- Severity is never conveyed by colour alone; the word (Critical, High, and so on) or an icon with a text label must accompany it.
- The Informational / Active and Critical / High fills keep their meanings and are still used for fills, borders and badges.
- The muted-text and primary-action tokens are recorded in 3.1.2 (Amendment A2).

#### 3.1.2 Muted Text and Action Tokens (Amendment A2, 2026-11-13, owner-approved in Phase 2.2)
Two further stylesheet tokens are recorded. Neither is a blanket approval for every background: each is approved only for the pairings in the tables, and every other pairing must be measured first.

| Token | Value | Purpose | Approved use | Disallowed use |
|---|---|---|---|---|
| `--text-muted` | `#8795ad` | Tertiary text only: timestamps, metadata, secondary labels, empty-state hints | Text of at least 12px on `--bg-primary`, `--bg-secondary`, `--bg-card`, `--bg-input` (and on `--bg-hover` with the stated limit below); 11px only for dense technical identifiers (see Muted_Text_12px policy below) | Primary content, anything the analyst must read to act, severity or status meaning, disabled-looking controls, text on any surface not listed, text over images or tinted fills without measuring |
| `--accent-action` (hover `--accent-action-hover`) | `#2563eb` (hover `#1d4ed8`) | Fill of the primary interactive control (primary button, brand badge) carrying white text | White text on the fill; the fill on `--bg-primary`, `--bg-secondary`, `--bg-card`, `--bg-input` | Text colour on dark surfaces (3.08:1 on `--bg-card`, fails), a replacement for `--accent-text` or for the informational `#0284c7`, severity or status colour, a universal blue |

Measured contrast (WCAG 2.1 relative luminance, computed 2026-11-13; script and raw output kept with the Phase 2.2 report):
| Pairing | Ratio | Result |
|---|---|---|
| `#8795ad` on `--bg-primary` | 6.38 (constitution `#0a0e14`), 6.37 (implemented `#0a0e17`) | pass, normal text |
| `#8795ad` on `--bg-secondary` | 6.10 (`#0f141c`), 5.85 (`#121826`) | pass |
| `#8795ad` on `--bg-card` | 5.71 (`#151b24`), 5.26 (`#182234`) | pass |
| `#8795ad` on `--bg-input` | 5.21 (`#1a2332`), 6.13 (`#0d131f`) | pass |
| `#8795ad` on `--bg-hover` (`#1f2c42`, implemented only) | 4.63 | pass, minimum margin; do not use smaller than 12px here |
| White on `#2563eb` | 5.17 | pass, normal text |
| White on hover `#1d4ed8` | 6.70 | pass |
| `#2563eb` fill against `--bg-primary` / `--bg-secondary` / `--bg-card` / `--bg-input` (non-text boundary) | 3.74 / 3.57 / 3.35 / 3.05 (constitution surfaces); 3.73 / 3.43 / 3.08 / 3.60 (implemented) | pass, at least 3:1 |
| `#2563eb` fill against `--bg-hover` | 2.71 | does not meet 3:1: do not rely on the fill edge there; the label (5.17:1) identifies the control |
| Hover fill `#1d4ed8` against surfaces | 2.09 to 2.88 | does not meet 3:1: the hover state is identified by its label (6.70:1) and the focus ring, not by the fill edge |
| `#2563eb` as text on `--bg-card` / `--bg-primary` | 3.08 / 3.73 | fails 4.5:1: disallowed |
| Focus ring `--focus-ring` (`#60a5fa`) on `--bg-card` / `--bg-primary` | 6.27 / 7.59 | pass, at least 3:1; the 2px ring sits 2px outside the control, so it is measured against the surface, not the fill (against the fill it would be 2.03) |
| `--text-muted` against `--text-secondary` (hierarchy check on `--bg-card`) | 5.26 vs 5.65 | the two remain close in value; hierarchy relies on size, weight and position as well as colour |

Rules: do not infer accessibility from one ratio; text smaller than 12px in `--text-muted` is permitted only for the documented technical-identifier exception; hover and focus states must be measured separately (see the Phase 2.2 populated-UI review).

#### 3.1.3 Case-file direction (Amendment A4, 2026-11-20, owner instruction in the current task)
The owner asked that the interface stop resembling common SIEM and SOAR consoles. The following are adopted; every earlier prohibition still applies.
- Navigation is a top bar, not a left sidebar. Content is a centered column (1120px for reading pages, 1320px for wide data pages).
- Page and section titles use a serif face (Newsreader, self-hosted). Interface text stays Geist, identifiers and hashes stay JetBrains Mono.
- The primary action is an off-white fill with dark text. The blue `--accent-action` token is retained for focus, links and informational state but is no longer the default primary fill.
- Severity and status are a square marker plus the word, never a filled pill. Tables are ledgers: a single rule above, hairlines between rows, no frame or header fill.
- Each evidence record carries a short exhibit reference (`E-` plus the first four hex characters of its own identifier) wherever it appears. It is a label only; the full UUID remains the identifier.
Contrast tokens in 3.1.1 and 3.1.2 are unchanged.

#### 3.1.4 Surface, border, radius, spacing and control-height tokens (Amendment A5, 2026-11-21, owner-approved)
The owner approved the token set in `docs/08_Frontend/UI_Token_Proposal_2026-11-21.md` for a minimal, professional black interface. This amendment is limited to the rows below. Nothing else in this constitution changes: A1 to A4, every prohibition in section 2, the semantic status colours, the typography and the accessible text tones remain as written. Existing token names stay as aliases of the new ones, so no component depends on a removed name.

| Token group | Old value (stylesheet before A5; constitution 3.1 where it differs) | New value | Reason |
|---|---|---|---|
| Surfaces | `--bg-primary #0b0d12` (constitution `#0a0e14`), `--bg-secondary #0f1116` (`#0f141c`), `--bg-card #14171d` (`#151b24`), `--bg-hover #272c37`, `--bg-input #0d0f14` (`#1a2332`): five or four near-identical levels | Three levels: `--surface-0 #0b0d12` (page), `--surface-1 #14171d` (cards, panels, inputs, navigation), `--surface-2 #1a1e26` (hover, selected, menus). `--bg-primary` aliases surface-0; `--bg-secondary`, `--bg-card`, `--bg-input` alias surface-1; `--bg-hover` aliases surface-2 | Fewer, clearer levels; the old hover value was a large jump |
| Borders | `--border-color #262b35` (constitution `#232d3f`), `--border-subtle #1b1f27` (`#1c2534`); measured 1.26:1 and 1.09:1 against the card | `--line-hairline #1b1f27` (separators), `--line-default #262b35` (card and table edges), new `--line-strong #5f6a80` (input and control boundaries, selected state); `--border-color` and `--border-subtle` alias the first two | Input and control boundaries must reach 3:1: `#5f6a80` measures 3.57 on the page, 3.30 on the card, 3.07 on surface-2 and 3.52 on the old input surface |
| Radii | 4, 6 and 8 px used without a rule | `--radius-control 6px` (buttons, inputs, selects), `--radius-container 8px` (cards, tables, dialogs). Square status markers (A4) and the 8 px cap on buttons (section 2.1) are unchanged | One rule for the two kinds of object |
| Spacing | 4px and 8px grid (section 3.2) | Scale 4, 8, 12, 16, 24, 32 px as tokens `--space-1` to `--space-6` | Same grid, named values |
| Control height | about 33 px (8 px padding, 13 px text) | `--control-height 40px` on desktop; 44px when the pointer is coarse or the window is narrower than 768px | Owner request; 44 px follows the touch-target guidance reviewed for this change |

Measured pairings added by this amendment (WCAG 2.1, computed 2026-11-21): primary text `#eceef2` on surface-1 15.45:1; muted `#8795ad` on surface-2 5.51:1; off-white button fill with `#0b0d12` label 16.73:1 (hover `#ffffff` 19.43:1, active `#d5d9e0` 13.73:1); focus ring `#60a5fa` on surface-1 7.06:1 and on the page 7.64:1; critical text `#f87171` on surface-1 6.49:1. The A1 and A2 tables remain the record for the pairings they list; any pairing not listed in A1, A2 or here must be measured before use.

#### 3.1.5 Display typeface (Amendment A6, 2026-11-21, owner instruction)
The owner found that the serif title face made the interface look like a common AI-assistant product and asked for it to change. Amendment A4 (serif page and section titles in Newsreader) is superseded for typography only; everything else in A4 stands.

| Item | Old | New | Reason |
|---|---|---|---|
| Page, section and table titles, wordmark | Newsreader (serif), weight 500 | Geist (already installed), weight 600, letter-spacing -0.015em; wordmark 18px, weight 600, letter-spacing 0.14em | Owner request; no new dependency |
| Interface text | Geist | unchanged | |
| Identifiers, hashes, telemetry | JetBrains Mono | unchanged; tabular figures added for table data | |
| Font loading | Newsreader loaded in `main.tsx` | not loaded; the `@fontsource-variable/newsreader` package remains in `package.json` until the owner approves removing it | removing a dependency is the owner's decision |

#### 3.1.6 Interface typeface (Amendment A7, 2026-11-25, owner instruction)
The owner asked for the typography to be reworked so the product does not look like a generic AI or developer-tool site. Geist, the interface face in A6, is the same face many AI products use. It is replaced by IBM Plex Sans (SIL Open Font License 1.1, self-hosted through `@fontsource/ibm-plex-sans`, pinned at 5.3.0, weights 400, 500 and 600, Latin subset only, no external font request). A6 stands otherwise: titles use the interface face at weight 600; identifiers, hashes and telemetry stay JetBrains Mono.

| Item | Old (A6) | New (A7) | Reason |
|---|---|---|---|
| Interface text, titles, wordmark | Geist | IBM Plex Sans, 400 / 500 / 600 | Designed for technical documentation; distinct from the Geist/Inter family; reads as a record rather than a marketing page |
| Identifiers, hashes, telemetry | JetBrains Mono | unchanged | Constitution 3.1 |
| Dependency | `@fontsource-variable/geist` loaded | not loaded; the package stays in `package.json` until the owner approves removing it | Removing a dependency is the owner's decision |
| Revert | | Restore the Geist import in `main.tsx` and put `"Geist Variable"` first in `--font-sans` | One-line rollback |

Checked 2026-11-25: typecheck and build pass, 307 of 307 frontend tests pass, and the responsive audit at 1440 and 390 px reports the same overflow and target-size counts as before (screenshots in `D:\AISOP-Backups\AISOP_UI_Audit_20261125_plex`). Not checked: contrast was not re-measured (text colours are unchanged); no user testing. The landing page's preview image is a screenshot taken before this change and still shows the old face until it is recaptured.

### 3.2 Spacing, Density & Layout
- Use a disciplined 4px / 8px grid (padding: 8px, 12px, 16px, 24px).
- Maintain high information density suitable for SOC workflows without clutter.
- Maintain WCAG 2.1 AA compliant contrast ratios (>= 4.5:1 for body text, >= 3:1 for large headers).
- **Minimum size for muted and secondary text (Amendment A3, Phase 2.2):** 12px for ordinary muted metadata and secondary labels. 11px is retained only for (a) monospace technical identifiers and values (hashes, digests, UUID lists), (b) compact badges, pills and tags that carry a word label, (c) uppercase table column headers, and (d) code and JSON blocks and truncated audit-detail cells. Each exception must meet 4.5:1 and be checked at 1024px; the 10px uppercase classification badges already in the stylesheet are retained as compact badges. Every retained exception is listed in the Phase 2.2 12px audit.
- Fully responsive across desktop (1920x1080, 1440x900) and laptop/tablet screens (>= 1024px).

### 3.3 Data Grounding & Epistemic Honesty
- Every displayed metric, count, timestamp, and entity MUST originate from actual application state or backend API responses.
- If a value or metric is not supplied by the backend:
  1. Omit the element entirely, OR
  2. Display a clearly explained, neutral empty state (e.g., `"No MITRE ATT&CK techniques mapped to this case."`), OR
  3. Explicitly label the field as `"Unavailable"`.
- Never invent placeholder numbers or mock classifications to make an empty screen appear populated.
- Synthetic fixtures must be strictly quarantined within automated test suites.

### 3.4 Evidence Provenance & Claim Distinctions
In all investigation and report views:
- Explicitly differentiate between **Observed Facts** (direct cryptographic telemetry, raw event payloads) and **Inferred Hypotheses** (LLM synthesis).
- Grounding status labels (such as `VERIFIED`, `INFERENCE`, or `REFUTED`) may only be displayed when that explicit status is returned by the backend schema.
- All observables (IPs, hashes, domains, commands) must link directly to their source evidence identifier.

---

## 4. Frontend Security & Trust Boundaries

1. **Zero Client Privilege Trust:** UI visibility guards (`RoleGuard`) are presentation conveniences only. The server is the sole source of authorization truth.
2. **Strict XSS Defense:**
   - Permanent ban on `dangerouslySetInnerHTML`.
   - Zero unsanitized HTML interpolation.
   - Textual rendering of all observables, commands, file paths, and LLM text using native React JSX string escaping.
3. **Zero Secret Logging:**
   - No API keys, Bearer tokens, or raw authorization headers in `console.log` or error alerts.
4. **Human-in-the-Loop Constraint:**
   - The frontend is strictly an investigative and reporting cockpit. No destructive containment, endpoint isolation, account deletion, or external firewall modification actions may be executed automatically or from report viewer components.

---

## 5. Design Verification Protocol

Before any frontend pull request, milestone review, or deployment sign-off:
1. Run Impeccable audit checks (`/impeccable audit`).
2. Verify zero prohibited patterns (no purple gradients, no emojis, no em dashes, no fake metrics).
3. Validate keyboard accessibility and focus management on forms and modals.
4. Verify TypeScript compilation (`npm run typecheck`) and production bundling (`npm run build`).
5. Confirm all displayed values trace to genuine API schemas.

