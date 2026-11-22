# MITRE D3FEND integration (optional reference)

Status: IMPLEMENTED and unit-tested (synthetic fixtures plus the real pinned file). Not wired to any endpoint other than the deterministic incident report. Not a production-readiness claim.

## What it is

AISOP maps ATT&CK techniques only from evidence-backed rules. The D3FEND reference is shown beside that mapping, never instead of it: for each technique the rules mapped, the incident report lists related MITRE D3FEND defensive techniques (id, name, category) as reference suggestions for the analyst.

## Source

| Item | Value |
|---|---|
| Publisher | The MITRE Corporation, https://d3fend.mitre.org |
| Release | D3FEND ontology 1.6.0 (website UI 0.26.1) |
| Retrieved | 2026-11-22 |
| Mapping file | https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend-full-mappings.csv, 14,751,588 bytes, SHA-256 `2B86A5A19DE143560B75FB2B443A7AC60335D60DFB6B08A7A6E9A53A052AD79F` |
| Technique list | https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend.csv, 38,047 bytes, SHA-256 `979C5B82324893DD3F3C6BB2ACBCD6B2A14B49566CBFB2052564665DE13506C6` |
| Local copy | `D:\AISOP-Reference-Data\MITRE-D3FEND\1.6.0\` |
| License | D3FEND Terms of Use (https://d3fend.mitre.org/tou): non-exclusive, royalty-free licence to use D3FEND for research, development and commercial purposes, provided MITRE's copyright designation and the licence are reproduced in copies; warranties disclaimed. Content is marked "Approved for Public Release; Distribution Unlimited". ATT&CK content stays under the ATT&CK terms. Broader redistribution is not explicitly addressed, so the data files are not copied into the repository. |
| Stability | The ontology is versioned by folder (1.6.0, 1.5.0, ...), so a pinned release is stable. The REST API (`/api/...`) is documented by MITRE as an alpha version and is not used. |

The hashes are locally calculated identity records, not MITRE signatures. The SHA-256 values are pinned in `backend/app/modules/defense_reference/loader.py` (`D3FEND_1_6_0`). Adopting a new release needs a reviewed code change and a new pinned record; nothing updates automatically.

The "ATT&CK mitigations to D3FEND" mapping (a different artifact) and the JSON-LD/OWL/TTL ontology files were not downloaded or used.

## Behaviour

- Setting `DEFENSE_REFERENCE_PATH` (directory containing the two files above). Unset: no section, behaviour unchanged. Offline, lazy, loaded once per process (about 1 second).
- The loader refuses a file whose size or SHA-256 differs from the pin, before parsing. It validates only the needed columns through strict Pydantic models, rejects duplicate D3FEND ids or names, rejects a mapped technique missing from the technique list or listed under another tactic, and keeps only a bounded definition (500 characters maximum). Only `ATTACKEnterpriseTechnique` rows are used (ICS and SPARTA rows are skipped).
- Lookup is by exact ATT&CK id. A sub-technique is not resolved through its parent, because the pinned mapping does not define that inheritance; a technique without mapping gets an explicit "no D3FEND technique is mapped" line.
- Categories shown are the D3FEND tactics: Harden, Detect, Isolate, Deceive, Evict, Restore and Model (Model is a real D3FEND tactic and is kept).
- If configured but the files fail verification, the report states the reference is unavailable (with the error code) and shows no defensive techniques.
- The section "4a. Defensive countermeasures (MITRE D3FEND reference)" is rendered deterministically by `defense_reference/section.py`; the LLM does not author or edit it.

## What is and is not claimed

Claimed: MITRE's published mapping relates the listed D3FEND techniques to the ATT&CK technique (through shared digital artifacts), at the pinned release.

Not claimed: that any control is missing, disabled or failed; that a listed technique would have prevented or detected the activity; completeness, ranking or relevance to this environment; that the list is observed evidence or corroboration. It does not influence correlation, sufficiency verdicts, severity or ATT&CK mapping.

## Results for the intrusion scenario (release 1.6.0)

| ATT&CK | D3FEND techniques returned |
|---|---|
| T1110 | none (no mapping) |
| T1078 | 7 (Harden 2, Isolate 1, Evict 1, Restore 2, Model 1) |
| T1059.001 | none (exact id absent; parent T1059 has 15 techniques but is not applied) |
| T1027 | none (no mapping) |
| T1564.003 | 14 (Harden 2, Detect 2, Isolate 5, Deceive 1, Evict 1, Restore 2, Model 1) |
| T1071 | 23 (Harden 1, Detect 12, Isolate 7, Deceive 1, Evict 1, Restore 1) |

The artifact-based inference can be coarse (for example T1564.003 maps mostly to file-oriented techniques); analysts should read the list as prompts, not conclusions.

## Tests

`backend/tests/unit/test_defense_reference.py`: pinned-hash refusal, tamper refusal, size mismatch, missing path, duplicates, inconsistent mapping, oversized definition, unknown technique, unconfigured no-op, load-once, section present and labeled, section absent without mapped techniques, section absent when unconfigured in a full incident report.
