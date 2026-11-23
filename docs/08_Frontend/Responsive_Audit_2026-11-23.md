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
- The header still stacks into several rows on phones; it fits but it is tall (a first compaction is in the second pass below; a full redesign is future work).
- Tablet cards were one per row at full width in the first pass; the second pass below puts them in two columns from 640 px.

## Second pass (same day): header, tablet grid and a defect the first pass left
- **Where the content starts.** Measured as the distance from the top of the page to the main content: 264 px on a 390 px phone (31% of an 844 px screen) and 268 px at 768 px before; 240 px on a 390 px phone after (the live UTC clock is hidden on phones because the time-zone selector beside it already names the zone, and "Signed in as" stays for screen readers only). At 768 px it is unchanged at 268 px. Final values by width: 284 px at 320 and 360, 240 px at 375, 390 and 430, 268 px at 768 and 820, 174 px at 1024, 122 px at 1280 and above. This is a modest gain, not a redesign; the header still takes four rows on a phone.
- **Two-column card grid** for stacked tables between 640 and 1023 px, so tablets use their width.
- **A defect found by looking at a zoomed screenshot, not by a number.** The dashboard's "All cases" button looked clipped on phones. The cause was the right-edge fade added earlier to tell a reader that a wide table scrolls; it applied to every table container, including ones that hold no scrolling table. It now applies only to a container that holds a table which really scrolls (`:has(table:not(.table-stack))`). The automated audit could not see this, which is a limit of the method: a fade over a control is not overflow, not a target-size failure and not small text.
- Tests: three more rules pinned in `frontend/tests/responsive_layout.test.tsx` (11 tests in that file; frontend suite 301 of 301).
- Final audit at all 11 sizes: 0 pages overflowing, 0 targets under 24 px, 0 text under 12 px, and 0 targets under 44 px at every phone and tablet width.
