# AISOP Next-Phase Roadmap

Date: 2026-11-12. Status: **PROPOSED**; ordering is a recommendation to be confirmed by the Project Owner. It does not change the Stage 6 decision (CONDITIONALLY CLOSED). Effort figures are my planning estimates in focused working days for one engineer with the existing test infrastructure; they are not measurements and exclude owner waiting time. Design context: `docs/Architecture/AISOP_ARCHITECTURE_EVOLUTION_PLAN.md`.

## Ordering and why (dependencies, not the brief's list order)
1. **Stage 6A first**: Detection Engineering and every later export or tool must not build on an investigation whose verdict ignores contradictions.
2. **Stage 7 next**, starting with DE-0: Detection Engineering is the stated next capability and the academic differentiator; DE-0 (process-creation observation) is independent of Stage 8.
3. **Stage 8 before Stage 9**: ledger vocabulary is a prerequisite for typed tools and export; UX hardening is best done once verdict semantics (contradictions, missing evidence) are final, but its small accessibility fixes (U2, U3) can be done any time.
4. If submission time is short, **Stage 6A + Stage 7 up to DE-4 is the defensible core**; Stages 8 and 9 are optional extensions.

## Stage 6A: close outstanding correctness and security gaps
| Item | Status now | Effort | Depends on | Acceptance |
|---|---|---|---|---|
| 6A-1 Contradiction-aware sufficiency (ADR-013, `suff-v4`) | PROPOSED; 5 passing + 5 strict-xfail specification tests exist | 3 to 5 days | Owner approval of ADR-013 | all xfail markers removed; 1509+ existing tests pass except documented version/hash updates; dataset delta report; labels untouched |
| 6A-2 Body-size limit on `/alerts/ingest` | **IMPLEMENTED** this stage (16 MiB via `middleware/body_limit.py`), tested (`test_stage6a_hardening.py`) | done | none | 413 before parse; normal batches unaffected |
| 6A-3 Domain evidence with existing case synthesis | **IMPLEMENTED (tested)**: endpoint works (200); unsupported mock claim demoted to `analyst_review_required`; observation: unsupported ATT&CK *hypothesis* is retained as a labelled hypothesis (existing validator behaviour) | done | none | recorded in test; hypothesis tightening moved to 8-3 |
| 6A-4 Concurrent import of the same record | **IMPLEMENTED (SQLite-simulated race)**: a lost insert race (unique `sha256_hash`) rolls the attempt back and retries once, which then takes the ordinary duplicate path (a first design using a savepoint was abandoned: it broke rollback semantics on SQLite and was caught by the existing persistence-failure test) | done; real multi-connection PostgreSQL race UNVERIFIED | PostgreSQL authorization for the real race | simulated race tests pass; PostgreSQL run later |
| 6A-5 Browser verification of Stage 6 UI | BLOCKED (needs a running stack; none was started) | 0.5 to 1 day after authorization | Owner authorization; running backend+frontend | live check of import, graph, verdict, errors, keyboard focus |
| 6A-6 Credential exposure (`opencode.json`, `viva-credentials.txt`) | OPEN owner action | owner | Owner | key rotated if live; both files git-ignored |
| 6A-7 PostgreSQL validation of Stage 5/6 storage | BLOCKED | 1 to 2 days after authorization | Owner authorization (also Stage 5 items) | marked tests run; U+0000, unique-hash race, JSON storage verified |
| 6A-8 Real-model prompt-injection validation | BLOCKED | 1 to 2 days | Owner authorization, local model available | recorded attack set with outcomes; no generalisation claimed |

## Stage 7: Detection Engineering foundation (ADR-012, roadmap DE-0 .. DE-8)
| Milestone | Effort | Depends on | Acceptance |
|---|---|---|---|
| DE-0 `endpoint.process_creation` observation + process-lineage ATT&CK rule | 2 to 3 days | Stage 6A-1 recommended | adapter, graph, ATT&CK tests; existing tests unchanged |
| DE-1 findings interface + opportunity identification with abstention | 2 days | DE-0 | refuses stale/INSUFFICIENT/contradicted/analyst-only findings |
| DE-2 rule model + deterministic Sigma serialiser | 2 days | DE-1 | round-trip and determinism; hostile values cannot change structure |
| DE-3 schema + log-source validators | 2 to 3 days | DE-2; Owner choice of validator approach | valid/invalid fixture corpus; unsupported fields flagged |
| DE-4 matcher + positive/negative fixtures + FP assessment (AiSOC-style: positive hits AND same-shape negative stays silent; self-test shows the check can fail) | 3 to 4 days | DE-3 | web-server-shell example passes; no benign corpus means NOT_ASSESSED |
| DE-5 versioning, provenance, review state machine, approval, export | 3 days | DE-4; persistence decision | export refuses unapproved/modified rules; RBAC and audit tests |
| DE-6 frontend | 2 to 3 days | DE-5 | render tests, typecheck, build; "validation is not effectiveness" shown |
| DE-7 optional LLM proposer | 2 days | DE-6 | candidate always re-validated; never auto-approved |
| DE-8 evaluation report | 1 day | DE-7 | honest results, no effectiveness claim |

## Stage 8: investigation intelligence
| Item | Effort | Depends on | Acceptance |
|---|---|---|---|
| 8-1 Ledger extension persisted in the audit row (plan section 11) | 3 days | none (6A-1 helps) | offline verification from stored row; no secrets; tamper tests |
| 8-2 Typed read-only tool registry + bounded loop (plan section 12) | 4 to 5 days | 8-1 | schema/injection/bound/timeout/audit tests; fallback intact |
| 8-3 Claim-support check and hypothesis tightening (demote ATT&CK hypotheses not supported by cited evidence) | 2 to 3 days | none | unsupported "authorized" claim cannot validate; unsupported hypothesis demoted |
| 8-4 Contradiction-aware reports | 1 day | 6A-1 | headline and banner show unresolved contradictions |
| 8-5 Investigation export bundle (deterministic bytes; optional signature) | 3 days | 8-1; Owner key decision | byte-identical re-export; independent offline verification |

## Stage 9: frontend and operational hardening
UX findings U2, U3 (focus, table semantics; about 1 day), U6, U7, U8 (messages and verdict banner; 2 days), U1, U5, U9, U10 (2 to 3 days); live-browser verification; reliability and deployment hardening tied to the Stage 5 owner actions. Depends on 6A-5 authorization.

## Not scheduled (deliberately)
Autonomous penetration testing; multi-agent frameworks; hosted infrastructure; GRC and compliance workflows; automatic rule deployment or case closure.

## Owner decisions needed to start
1. Approve ADR-011, ADR-012, ADR-013 (all PROPOSED).
2. Authorize PostgreSQL validation, browser verification and a local-model run (each separately).
3. Rotate and ignore the exposed credential files.
4. Choose the Sigma validator approach and persistence for rules.
5. Decide whether to download the Impeccable engine into a D: folder (or leave the detector off).

## Smallest technically sound next milestone
**6A-1: contradiction-aware sufficiency.** It is a bounded change to existing modules (correlator, gate, schemas, report), needs no dependency, no migration and no network, has its specification already written as executable tests, closes the most significant known correctness defect, and unblocks Detection Engineering safely. Estimated 3 to 5 days after ADR-013 approval.
