# UI direction: how AISOP should differ from an XDR, EDR or Wazuh-style console

Status: PROPOSED by the owner's request (2026-11-25). Nothing here is implemented except the typeface change (constitution A7). Comparisons to other products are the author's general impression of the category, not measurements, and name no vendor feature. Verify any vendor claim before using it in the defence.

## 1. The point
A detection console answers "what is happening on my estate". AISOP answers "can I defend this conclusion, and what exactly is it resting on". The interface should make that second question the first thing anyone sees. Today it does not: the screens (Overview, Alerts queue, Cases) look like a generic dark dashboard with a table, which is what most consoles look like.

## 2. What is already different and under-used (all exists in the product today)
| Real capability | Where it shows now | Direction |
|---|---|---|
| Evidence-sufficiency verdict (sufficient, limited, insufficient) with reasons | inside the case view only | Make it the primary status of every case, ahead of severity, in the Cases list and the case header |
| Evidence classes kept apart (observed, tool-asserted, threat intelligence, derived, model inference, analyst-confirmed) with distinct glyph shapes | small markers in the evidence table | Use the same glyph vocabulary everywhere a claim appears (report, findings, alert detail) so a reader can tell observed from inferred at a glance |
| Generated versus ingested time, with "Late: arrived 10 d 4 h after it was generated" | alert queue | Keep; this is honest in a way most queues are not. Extend to the case timeline |
| Raw record, SHA-256 and source beside each claim | evidence detail | Show a short hash and source on every claim line, in the monospace face |
| AI optional and clearly separated | AI explanation box | Keep a permanent visual boundary: model text never shares a container with observed evidence |
| Role comes from the key, not a selector | navbar "Signed in as" | Keep; drop the "View as" preview when a key is present (already done) |

## 3. Visual principles (apply within the constitution; no new colours, no gradients, no glow)
1. A case reads like a case file: a header with number, verdict, window and owner, then claims in numbered rows, each with its evidence reference. Fewer cards, more ruled sections.
2. Typography carries the identity: IBM Plex Sans for reading, JetBrains Mono for anything verifiable (ids, hashes, times). Hierarchy by size and weight, not colour.
3. Severity colour stays on the small severity marker only. The sufficiency verdict uses shape plus word, not a new hue, consistent with amendment A4.
4. Empty states say what is missing and why (for example "no case assigned to your role"), never a blank page. The Tier-2, admin and sensor keys currently see an empty Cases screen; that should explain assignment scoping.
5. No decorative charts and no invented numbers (constitution 2.3).

## 4. Proposed order of work (each item small, tested, then screenshotted)
1. Cases list: add a sufficiency column and sort by it. Needs the API to return the verdict per case; check what `GET /cases` returns before designing (not verified).
2. Case header and report: apply the class glyphs and the hash-and-source line to every claim row.
3. Empty-state wording for roles with no assigned cases.
4. Recapture the landing page's preview image so it shows the current face.
5. Stress test the screens with worst-case data (long hostnames, huge counts, non-Latin text) using the project's own harness, after reading any third-party skill for it first.

## 5. Not done and not claimed
No user testing, no accessibility re-run with a screen reader, no contrast re-measurement after the typeface change, no comparison against any real product's console.
