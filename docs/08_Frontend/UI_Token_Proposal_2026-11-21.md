# UI Token Proposal for Owner Review (NOT APPLIED)

Written 2026-11-21 in response to the owner's redesign request (minimal, professional, black background; buttons, cards, borders). **No CSS or component was changed.** The constitution (`AISOP_Website_Design_Constitution.md`) and `frontend/AGENTS.md` override this proposal on any conflict; the items that conflict are listed in section 4 and need an owner decision (a constitution amendment) before they can be applied.

## 1. Where the UI is today (read from `frontend/src/styles/index.css`)
- It is already near-black and restrained: surfaces `#0b0d12`, `#0f1116`, `#14171d`, `#272c37` (hover), `#0d0f14` (input); borders `#262b35` and `#1b1f27`; one blue accent family used for focus, links and the older primary fill; semantic status colours; Newsreader, Geist and JetBrains Mono.
- Amendment A4 (2026-11-20) already adopted a case-file direction: top bar, serif titles, off-white primary button, square status marker plus word, ledger tables, exhibit references.
- What is inconsistent: **five surface values** where three would do; **two border values that are almost invisible on cards** (measured 1.09:1 and 1.26:1 against `#14171d`); **three radii mixed** (4, 6, 8 px) without a rule; the default button padding gives a height of about 33 px (8px padding, 13px text), below the 40 px the owner asked for; and the stylesheet has both an older blue `.btn-primary` rule near line 271 and the A4 off-white direction, so which one wins in each place must be checked before changing it (I have not verified the cascade).

## 2. Proposed token set
Three surface levels, one border system with a hairline and a strong value, two radii, a 4 px spacing scale. Existing names stay as aliases so no component has to change in the first pass.

| Token | Value | Replaces or maps | Measured contrast (WCAG 2.1) |
|---|---|---|---|
| `--surface-0` (page) | `#0b0d12` | `--bg-primary` | text `#eceef2` on card 15.45:1 |
| `--surface-1` (cards, panels, inputs) | `#14171d` | `--bg-card`, `--bg-secondary`, `--bg-input` | muted text `#8795ad` 5.51:1 on the raised level below |
| `--surface-2` (hover, selected, menus) | `#1a1e26` | `--bg-hover` (`#272c37` is a large jump) | |
| `--line-hairline` | `#1b1f27` | `--border-subtle` | 1.09:1 on card. Decorative separators only, never the only cue |
| `--line-default` | `#262b35` | `--border-color` | 1.26:1 on card. Card and table edges; the content, not the line, carries meaning |
| `--line-strong` | `#5f6a80` | new | 3.57 page, 3.30 card, 3.07 raised, 3.52 input. Meets 3:1 for input and control boundaries, selected rows and focus context |
| `--focus-ring` | `#60a5fa` (unchanged) | same | 7.06 on card, 7.64 on page |
| Primary button | fill `#eceef2`, label `#0b0d12` | A4 direction | 16.73:1; hover fill `#ffffff` 19.43:1; active `#d5d9e0` 13.73:1 |
| Destructive text | `#f87171` (unchanged) | `--severity-critical-text` | 6.49:1 on card |
| Status colours | existing success, warning, error; used only for status, always with an icon or the word | | `#10b981` 7.08, `#f59e0b` 8.36 on card |
| `--radius-control` | 6px | buttons, inputs, selects | within the constitution cap (8px on buttons) |
| `--radius-container` | 8px | cards, tables, dialogs | |
| `--radius-marker` | 2px | status squares, badges | A4: square markers |
| Spacing | 4, 8, 12, 16, 24, 32 | all gaps and padding | 4px grid |
| `--control-height` | 40px (desktop), 44px under a coarse pointer or width below 768px | buttons, inputs | see note on touch size below |

Contrast figures were computed on 2026-11-21 with the WCAG 2.1 relative-luminance formula. A pairing not in this table must be measured before use.

## 3. Components
- **Buttons:** one primary (off-white fill, dark label), one secondary (transparent, 1px `--line-strong`, primary text), one destructive (transparent, 1px critical border and `#f87171` text; filled only in the confirm step). All: 40px height, 6px radius, 150ms transitions, hover one surface step, active one step darker, `:focus-visible` 2px `--focus-ring` with 2px offset, disabled at reduced emphasis with `disabled` semantics and no pointer.
- **Cards:** flat, `--surface-1`, 1px `--line-default`, 16 to 20px padding, no shadow, no nesting unless it carries information hierarchy.
- **Evidence classes (not by colour alone):** each statement carries a text label and a distinct square-or-shape marker for **Observed, Inferred, External, Analyst, AI-generated**, placed in the card header, so the five stay distinct in greyscale and for colour-blind users. Border-left stripes wider than 1px are not used (Impeccable craft floor).
- **Inputs and selects:** `--surface-1` fill, 1px `--line-strong` border (meets 3:1), focus replaces the border with the ring.

## 4. Conflicts and decisions needed from the owner
1. **Palette values.** The constitution fixes `--bg-primary #0a0e14`, `--bg-secondary #0f141c`, `--bg-card #151b24`, `--bg-input #1a2332`. The stylesheet already differs from it, and this proposal merges four surfaces into three. Changing the recorded palette needs an amendment (A5). Alternative: keep every current value and only add `--line-strong` and the radius, spacing and height tokens.
2. **`--line-strong` `#5f6a80`** is a new border value; it is the smallest change that makes input and control boundaries meet 3:1.
3. **Control height:** the owner asked for at least 40px. The UI UX Pro Max guidance lists 44 (Apple) and 48 (Material) as touch minimums; its rules file says its tables target native and mobile UI, and its web quick reference repeats those figures. Proposal: 40px for mouse and keyboard on desktop, 44px when the pointer is coarse or the window is narrow. Confirm.
4. **Em dashes** stay banned in interface copy (AGENTS rule 4). No gradients, glows, pill buttons, emoji icons or purple tints (constitution 2.1, 2.4).

## 5. Plan once approved (tokens first, 6 hours, demo path only)
1. Before screenshots of dashboard, alerts, case, multi-source panel and report (headless browser, loopback, synthetic key). Memory note: free RAM was 0.8 of 13.9 GB at the last check; a headless browser needs several hundred MB, so free memory first.
2. Tokens in `frontend/src/styles/index.css`, old names kept as aliases.
3. Buttons, then cards, then borders; touch components only where a class must change.
4. No change to data fetching, auth, the API key flow (including its recent fix) or any text describing what evidence means.
5. Checks: WCAG AA for text and borders, keyboard-only pass, a narrow window, `npm run typecheck`, `npm test` (193 tests at the last run; changed tests listed with the reason), `npm run build`.
6. After screenshots and before/after pairs saved under `D:\AISOP-Backups\AISOP_Dev_Logs_20261120\`. If time runs long, stop after tokens, buttons and cards.

## 6. References read for this proposal
`frontend/AGENTS.md` (in full); the design constitution (sections 1 to 3.1.3 and the start of 3.2 read; the remainder not read); the current stylesheet (tokens and the button, card, badge, dialog and border rules); Unslop `SKILL.md` (direction, Spacing, Color, Copy, Details sections); Impeccable `reference/craft-floor.md` and `clarify.md` (lines 1 to 70); UI UX Pro Max `SKILL.md` priority table, `references/pro-rules.md` (touch, state and border lines) and `references/quick-reference.md` (contrast, focus, touch and elevation lines). Not read: the upstream source folder under `D:\REPO _TO_BE_LOOKEDAT`, Unslop `tokens.md` for this task, Impeccable files beyond those listed. No script was run.
