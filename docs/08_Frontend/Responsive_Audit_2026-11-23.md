# Responsive and touch audit (2026-11-23)

Method: `scripts/ui_audit.mjs` drives real headless Chrome over the DevTools protocol (no extra dependencies), at 11 viewport sizes, over the landing page, the two legal pages and every workbench tab (dashboard, alerts, cases, evidence, reports, security), logged in with local demo keys that are never printed or stored in the report. For each page it measures horizontal overflow, elements that extend past the right edge, interactive elements under 44 x 44 CSS px and under 24 x 24, text under 12 px, and unreachable navigation items, and saves a full-page screenshot. Screenshots and JSON are in `D:\AISOP-Backups\AISOP_UI_Audit_20261123_*` (outside the repository).

Scope and limits: one browser engine (Chromium), emulated viewports and emulated touch, the local demo data (no real devices, no Safari or Firefox, no screen-reader session, no usability test with people). Elements that scroll by design, ellipsised chips, screen-reader-only text and inline links inside a sentence are excluded from the "sticks out" and "target size" counts (the WCAG 2.5.8 inline exception); the script reports deliberate scroll regions separately.

## What the first run found (before)
| Finding | Measured |
|---|---|
| Main navigation tabs 36 px tall on touch screens | 217 occurrences across sizes up to 820 px |
| Short footer, landing and legal links under 44 px; the role-strip disclosure under 24 px | 36 + 22 + 11 occurrences under 24 px |
| Text under 12 px (`observable-type-tag`, 10 and 11 px) | 25 per size |
| Alerts table (1,220 px) and evidence table (847 px) scrolled sideways inside a phone screen, showing about three columns | scroll regions 358 < 1220 and 358 < 847 at 390 px |
| Role strip repeated the account name the header already shows | seen in screenshots |
No page overflowed the viewport.

## What was changed
- Tablets count as touch: 44 px controls and navigation below 1024 px and on any coarse pointer; the landing button follows it.
- Short links get a real target (44 px tall; 44 px wide for one-word links); the role-strip disclosure is a full-size target.
- Text at 12 px or larger everywhere (the observable chip and its type tag).
- Alerts, evidence and cases tables become stacked cards below 1024 px, each cell carrying a `data-label`, the header row kept for screen readers. A first attempt overlapped rows because an older rule fixed every cell at 44 px height; found in a screenshot and fixed.
- The role strip now says "Your role: ..." and no longer repeats the account name; "Set by the server from your API key" moved inside the detail.
- Tests: `frontend/tests/responsive_layout.test.tsx` (8 tests) pins the labels, the stylesheet rules and the role-strip wording; `identity.test.tsx` updated for the new wording. Frontend suite 298 of 298; typecheck and build clean.

## Result (after), all 11 sizes
| Viewport | Overflow pages | Under 44 px | Under 24 px | Text under 12 px | Sticks out |
|---|---|---|---|---|---|
| 320, 360, 375, 390, 430 (phones) | 0 | 0 | 0 | 0 | 0 |
| 768, 820 (tablets) | 0 | 0 | 0 | 0 | 0 |
| 1024, 1280, 1440, 1920 (laptop and desktop) | 0 | 107, 76, 76, 76 | 0 | 0 | 0 |
Before, on the same widths: 59 to 65 under 44 px at phone and tablet sizes, 139 and 108 at 1024 and 1440, 25 text items under 12 px, and horizontally scrolling tables on every phone and tablet size. At 1024 px and above the pointer is a mouse; the 44 px touch size is not required there, and the 24 px minimum is met everywhere.

## Not done, not claimed
- No real-device test, no other browsers, no assistive-technology test, no peer usability test.
- Accessibility beyond target size, text size and overflow (contrast, focus order, announcements) was not re-audited here; earlier phases tested contrast in the unit suite.
- The header still stacks into several rows on phones; it fits but it is tall. A compact mobile header is future work.
- Dense tables on tablets show one card per row at full width; a two-column card grid at 600 to 1023 px would use space better.
