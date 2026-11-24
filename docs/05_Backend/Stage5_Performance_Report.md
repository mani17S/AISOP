# Stage 5 Performance Report - Deterministic Multi-Source Investigation

Date 2026-11-12. Bounded local measurements on synthetic data only. No production-scale claim is made or implied; no load test, no concurrency test, no PostgreSQL, no LLM.

## Environment
Windows 11 Home (10.0.26300), AMD64 family 25 (12 logical CPUs), CPython 3.12 from the project `.venv`, single process, in-memory SQLite for the API benchmark, no other load control (a developer machine, other applications running). Figures are medians of 5 repetitions (engine benchmark) or one run per cell (API benchmark); expect roughly +-20 % run-to-run variation.

## Method (reproducible)
* `backend/scripts/benchmark_investigation.py --sizes 10 100 500 1000 --reps 5`: engine only (`workflow.analyze`), stage timings taken by wrapping the functions the workflow calls; peak Python memory from a separate `tracemalloc` run; stored-result size is the JSON size of `build_payload`.
* `backend/scripts/benchmark_investigation_api.py`: the real app through httpx ASGI: ingestion in batches of 100, first start, repeat, status GET.
* Two data shapes, 10 events per synthetic intrusion chain (SIEM + Windows identity + Sysmon + DNS + firewall/IDS): **separate** = N/10 independent chains (many small incidents); **single** = all chains share one C2 domain/IP (one large incident, worst case for correlation).
Raw outputs: `logs/benchmark_final.json`, `logs/benchmark_api.json`.

## Engine measurements (median ms)
| Events | Shape | Total | Normalize | Correlate | Context | Sufficiency | Timeline | ATT&CK | Report | Clusters | Links | Incidents | Stored result | Peak mem |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 10 | separate | 3.0 | 0.93 | 0.47 | 0.69 | 0.47 | 0.09 | 0.07 | 0.15 | 10 | 33 | 1 | 19.7 KB | 0.2 MB |
| 100 | separate | 32.5 | 8.99 | 6.4 | 7.3 | 4.99 | 1.11 | 0.73 | 1.48 | 100 | 735 | 10 | 190 KB | 1.7 MB |
| 100 | single | 43.1 | 8.26 | 17.85 | 4.94 | 9.01 | 0.7 | 0.23 | 1.33 | 100 | 2,310 | 1 | 89 KB | 2.5 MB |
| 500 | separate | 300 | 41.8 | 100 | 39.6 | 61.2 | 8.9 | 3.5 | 27.0 | 500 | 12,675 | 50 | 532 KB | 13.6 MB |
| 500 | single | 708 | 39.7 | 594 | 11.2 | 29.6 | 4.3 | 0.4 | 17.3 | 500 | 55,550 | 1 | 174 KB | 40.4 MB |
| 1,000 | separate | 1,116 | 81.3 | 608 | 87.2 | 49.7 | 26.3 | 7.5 | 186 | 1,000 | 47,850 | 100 | 612 KB | 40.6 MB |
| 1,000 | single | 2,538 | 79.4 | 2,294 | 14.9 | 29.8 | 9.1 | 0.5 | 66.7 | 1,000 | 221,100 | 1 | 175 KB | 154 MB |
(10 events, single: 3.0 ms; the two shapes coincide at that size.) The stored-result column reflects the Stage 5 caps: before them the 1,000-event separate case stored 2.3 MB.

## API end-to-end (in-process, SQLite, seconds)
| Events | Shape | Ingest (all) | First start | Repeat (reuse) | GET status | Response |
|---|---|---|---|---|---|---|
| 10 | separate | 0.07 | 0.11 | 0.022 | 0.018 | 19 KB |
| 100 | separate | 0.16 | 0.15 | 0.029 | 0.023 | 183 KB |
| 500 | separate | 0.73 | 0.64 | 0.054 | 0.049 | 513 KB |
| 500 | single | 0.74 | 1.02 | 0.052 | 0.048 | 166 KB |
| 1,000 | separate | 1.55 | 2.49 | 0.095 | 0.163 | 591 KB |
| 1,000 | single | 1.45 | 3.30 | 0.091 | 0.087 | 167 KB |

## Bottlenecks and scaling
* **Correlation dominates and is quadratic**: 500 to 1,000 clusters multiplied the single-incident correlate time by 3.9 (594 to 2,294 ms) and memory by 3.8 (40 to 154 MB), because every cluster pair sharing any entity yields a link (221,100 links at 1,000). Many of those are WEAK links created by ubiquitous values (for example the process name `powershell.exe`). Weak links never merge incidents or corroborate, so they cost without adding evidence; discarding or capping them is a candidate optimisation (not applied: it changes link counts shown in reports; PROPOSED, would need a design decision).
* Report rendering grows with incident count (186 ms for 100 incidents).
* Normalization and sufficiency scale close to linearly in this range.
* Idempotent repeats and status reads stay at about 20 to 160 ms (they re-read the stored document and the case evidence).
* Consequence applied: refuse more than 1,000 evidence rows per investigation (413), cap stored incidents at 25, cap model invocations at 5 per run (the model cost is not measured here at all).

## Limitations
Synthetic, highly regular records (chains repeat structure); real telemetry will differ in entity overlap. SQLite in memory is not PostgreSQL; there is no network or disk latency, no concurrent clients, no authentication cost beyond one token check. Memory is Python allocation only (`tracemalloc`), not process RSS. Sizes above 1,000 events were deliberately not run (a 2,000-event single incident is extrapolated, not measured, at roughly 10 s and 600 MB).

## 2026-11-24 update: a hard-shaped input, and the fix
A shape not covered above (many separate incidents, every record on the same host, so nearly every pair of evidence units shares the host) took far longer than the figures in this report: 600 synthetic SSH-style records 34.7 s, 1,500 records 515.5 s, and 2,000 records of a real public SSH log 9.1 s. Profiling found three loops that rescanned every link once per incident or per lone component (cubic growth) plus repeated recomputation of the same entity's link strength. They were rewritten to give IDENTICAL output: `backend/evaluation_tools/pipeline_fingerprint.py` hashes the full result (events, clusters, links, incidents, verdicts, reason codes, assessment hashes) for the demo scenarios, the envelope scenarios, two synthetic logs, the real SSH log and the two real Windows files; all 14 hashes matched before and after.

| Input | Before | After |
|---|---|---|
| 600 synthetic records | 34.7 s | 2.95 s |
| 1,500 synthetic records | 515.5 s | 14.8 s |
| 2,000 real SSH lines | 9.06 s | 3.05 s |
| all 14 inputs together | 559.6 s | 21.2 s |

Pinned by `backend/tests/unit/test_pipeline_scaling.py` (the exact output of 10 inputs, plus a bound that 800 records finish within 60 s). The per-run limit of 1,000 evidence rows (ADR-010) is unchanged. The number of pairwise links itself still grows with the square of the number of evidence units that share an entity; this removed the extra factors, not that one.
