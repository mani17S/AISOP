# Limitations

Written 2026-11-21. Everything here is a limit of the current prototype, stated plainly. Items marked (logged) are supported by a saved log; the others come from reading the source.

## Evidence and data
- **Synthetic data only.** All samples and scenarios are author-built. No real vendor export has been run through any adapter. The adapters accept sample-shaped JSON; their support for the real formats of the vendors they name is unverified.
- **No measured accuracy.** There are no labels, no baseline comparison and no held-out run (`docs/10_Research/Evaluation.md`). No detection rate, false-positive rate or accuracy figure exists.
- **Small rule coverage.** ATT&CK mappings come from 13 evidence-backed rules. A mapping states that a rule fired on independent evidence, not that an attack occurred.
- **Class markers describe, they do not judge.** The marker states what kind of statement a record is (for example an analyst statement or AI inference). It says nothing about whether the record is correct.
- **Suricata EVE is synthetic-tested only.** The translator covers `alert`, `dns` and `flow` records; `http`, `tls`, `fileinfo`, `anomaly` and other event types are skipped, not interpreted. It was tested on hand-written records, not on output from a real Suricata sensor, and there is no live feed: a file is converted and imported on request.
- **Missing time is rejected, not guessed.** An alert with no usable event time is refused at ingest (logged: 13 tests). That keeps the timeline honest but means such alerts need fixing at the source.

## The AI layer
- **One provider.** The AI layer is pluggable (see `Adding_an_LLM_Provider.md`) but only local Ollama exists; no hosted provider has been written or tested, so nothing is claimed about one.
- **Optional and small.** One provider (a local Ollama model). With `qwen2.5:1.5b` on the demo laptop the AI explanation took about 8 s warm and 12 to 13 s cold for one case, and one of its two incidents fell back to the deterministic output because the model did not return valid structured output (logged: `AI_LATENCY_RECORD.md`). Real-model prompt-injection behaviour has not been tested.
- **No claim of AI quality.** The model benchmark has 0 of 19 scenarios captured.
- **Retrieval (RAG)** is verified on PostgreSQL with a 7-document corpus, but it runs inside case synthesis only when the analyst supplies a query filter, and not in the deterministic investigation, and the corpus files are not yet committed.
- **Threat intelligence** is not applied inside the multi-source investigation.

## Human control
- **Review record only, no export gate.** The case lead can approve or reject a stored multi-source investigation; the record is append-only, bound to the evidence it covered and goes stale if the evidence changes (tested offline and in 14 live checks on PostgreSQL, at API level). The multi-source report export is gated on an approved, unchanged result and each release is audited; the case-synthesis report path (client-side downloads in the report viewer) has no review step and is not gated. Nothing is sent outward automatically.

## Security and operations
- **Lab only.** Single process (in-memory rate limit and per-case locks), no queue, no metrics, no SSO, no retention policy, no restore drill, nothing deployed beyond the local demo.
- **Open advisories:** two development-server findings in the frontend toolchain (Vite high, esbuild moderate; the built site is not affected). `pip-audit` found none in the pinned Python list (logged).
- **Not penetration-tested.** The OWASP-mapped probes (33 offline, 18 live, logged) are a test suite, not an independent assessment.
- **Credential hygiene** for the hosted database is an owner action still open.
- **Stability of the demo host:** processes started from a tool session stopped silently at least twice on 2026-11-20 under memory pressure; the cause was not proven.

## What the prototype should not be used for
Real telemetry, real incidents, any production or enterprise claim, and any claim of novelty before the literature review in `docs/01_Project_Foundation/Research_Gap.md`.
