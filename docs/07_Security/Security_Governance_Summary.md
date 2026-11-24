# Security and governance summary for AISOP (for a CISO, DPO and risk committee)

Written 2026-11-24. Each row states what is implemented and tested, what is partial, and what is missing. "Supports" is not "compliant": no certification, audit or framework assessment has been performed. Control themes follow the six functions of NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover); verify any category mapping against the framework text before presenting it.

## 1. AISOP's own security
| Theme | Implemented and tested | Partial or missing |
|---|---|---|
| **Govern** | Written invariants (`CLAUDE.md`), 17 decision records (`docs/03_System_Design/ADR/`), a claims list of what must not be said | ADRs 008 to 011, 015, 016 and 017 awaiting or just given owner decisions; no risk register owner |
| **Identify** | Assets and data flows drawn from source (`docs/03_System_Design/Architecture_Diagrams.md`); SBOM of 221 components (`docs/07_Security/sbom/`) | No formal data classification scheme |
| **Protect: access** | API keys stored only as hashes, with expiry, lockout and a revoke script; global roles and case roles enforced on the server; case-creation cap; `/docs` disabled outside development | **No MFA or session lifecycle** (ADR-015 proposed); no row-level security; throttles are per process |
| **Protect: data** | Local-first; raw evidence kept verbatim with SHA-256; secrets only in the backend and never in a response, log or the browser bundle (checked by pattern search and tests); a repository scan on 2026-11-24 (tracked files, untracked files and the commit history, patterns for common token, key and connection-string formats plus long literal assignments to secret-named variables) found only synthetic test values and one fixture key with a repeated-character body, no real credential (the patterns cannot see every provider's token format, so this is a screen, not proof); hosted model opt-in, synthetic data only | No encryption at rest beyond the database host's; no key management service; retention policy only for security events (30 days) |
| **Protect: platform** | Security headers and CSP; input validation and body limits; stable error responses; parameterised queries (static SQL only in code) | Container images and an application Dockerfile do not exist; the compose database still has a default password fallback (loopback only) |
| **Protect: supply chain** | SBOM; known-advisory check against the public OSV database: 71 runtime components, none with a published advisory; development-only advisories in vite and esbuild; no copyleft package flagged (LGPL and MPL used unmodified) | Lookup of published advisories only; model licences not reviewed; no signed builds |
| **Detect** | Security Events page: probes, failed keys, lockouts, unknown paths, new-address use of a valid key, case-creation bursts; separate from analyst telemetry | No notification channel; events not append-only; no metrics or tracing |
| **Respond** | Revoke script; case-creation cap; audit trail | No incident runbook for AISOP itself |
| **Recover** | Logical backup and an isolated restore drill (recorded); migrations tested | No point-in-time recovery; downgrade safety not verified |

## 2. What AISOP supports in the company's programme
| Company need | How AISOP supports it | Limit |
|---|---|---|
| Consistent, explainable investigation | Fixed rules with reason codes; every verdict states why | ATT&CK rules scored on public third-party captures (about a third of documented techniques recovered); the sufficiency rules are validated on synthetic and metamorphic data only |
| Evidence integrity for audit or legal review | Hashes, hash-chained ledger, approved-export gate, case audit trail | Tamper-evident since submission, not immutable |
| Logging gap visibility | Management summary lists absent telemetry types and what to collect | Describes supplied evidence only |
| AI governance | Model optional, labelled and checked; human approval; no model output counts as evidence; no silent cloud fallback | Hosted option sends evidence text to a third party when on |

## 3. Data handling (for the data protection officer)
- **What is stored:** raw evidence as supplied (kept verbatim), normalised events and entities (hosts, users, addresses, hashes), case records, audit events, security events (source address, key prefix, route, status), embeddings of a curated knowledge base. No passwords or API keys are stored in clear.
- **Where:** a PostgreSQL database controlled by the operator. Nothing leaves the environment unless the hosted model option is switched on by the operator, in which case prompt and retrieval text go to the provider.
- **Who can see it:** global roles (security admin, tier 2, tier 1, ingest) and case roles (lead, analyst, viewer); the Security page is for the security admin only.
- **Retention:** security events 30 days; no policy yet for evidence and reports (the operator must set one).
- **Personal data:** user names, host names and addresses appear in evidence; a pilot must sanitise before export.

## 4. Known gaps a risk committee should record
No MFA; per-process throttles; no row-level security; no notification channel; no independent penetration test; no real-data validation; no human-labelled accuracy; the hosted deployment not live; a per-run limit of 1,000 evidence rows, so larger exports must be split.
