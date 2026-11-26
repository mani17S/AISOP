# Responsiveness during large investigations: profiling record and proposed fixes

Status: **OPEN.** (2026-11-26: the "polls received" percentages in this record were recalculated; see the correction in section 15. The worker-process setting `ANALYSIS_WORKER_PROCESSES` exists, defaults to 0 and is enabled only in the demo script.) Measurements and proposals only. No application code was changed for this record (the one earlier mitigation, `asyncio.to_thread(analyze, ...)` in `correlation/workflow.py`, is described in section 1). Panel criticism 5 (multiple alerts and large investigations) is **not** resolved until a repeatable benchmark shows the application stays responsive during large investigations (acceptance criteria, section 7).

All figures: one laptop (12 logical CPUs, Windows, Python 3.12.0), one uvicorn process, PostgreSQL 17.11 in Docker, LLM off, synthetic data, scratch database `aisop_loadtest`. Each controlled run is two repeats per size. Two repeats show consistency, not statistical confidence. Evidence is in `D:\AISOP-Backups\AISOP_LoadTest_20261125\` (nothing deleted; failed and partial runs kept).

## 1. What was measured

Tools added under `backend/scripts/` (measurement only, never used to serve users):
`live_load_probe.py` (first probe), `profile_investigation_server.py` (instrumented launcher: phase timers, event-loop lag, GC pauses, slow SQL; optional cProfile), `bench_investigation.py` (repeatable benchmark with real-server-process CPU and memory sampling through the Windows API, PostgreSQL wait-state sampling, result digests), `profile_verdict_lookup.py` (five-part breakdown of the verdict lookup).

Earlier probe (uninstrumented): no failures. One 1,000-alert batch stored in 16 s with no stall. A 1,000-record investigation froze the health check for 3.5 s before the first mitigation and 1.5 s after it.

Controlled runs (instrumented timers only, no profiler, benchmark server with the per-hour case-creation cap raised to 1,000 so repeated runs are not refused with 429; the cap is unchanged in the application):

| Run | Setting | Evidence folder |
|---|---|---|
| A | default thread switch interval (5 ms) | `cmp2_A_default` |
| B | switch interval 0.5 ms | `cmp2_B_switch0p5ms` |
| A2 | default again, run last (checks order and drift) | `cmp2_A2_default_repeat` |

Failed or partial attempts kept: `profile_run1_instrumented` (tool bug, server did not start), `profile_run2_instrumented` and `profile_run3_switch0p5ms` (cProfile on, so timings inflated, used only for attribution), `cmp_*` (stopped by the case-creation cap).

### Investigation of 1,000 records, both repeats
| Run, repeat | Duration s | Liveness polls got/expected | Liveness max ms | Auth-only DB poll max ms | Cases DB poll max ms | Server CPU s | CPU % of one core | RSS end / peak MB |
|---|---|---|---|---|---|---|---|---|
| A r0 | 3.55 | 8/35 | 1393 | 1724 | 2929 | 3.52 | 81 | 159 / 168 |
| A r1 | 3.54 | 11/35 | 1347 | 1268 | 2183 | 3.58 | 82 | 164 / 171 |
| A2 r0 | 3.54 | 11/35 | 779 | 1505 | 2131 | 3.59 | 83 | 163 / 168 |
| A2 r1 | 3.50 | 10/35 | 745 | 1856 | 1796 | 3.59 | 83 | 164 / 169 |
| B r0 | 6.44 | 49/64 | 185 | 219 | 256 | 8.77 | 121 | 166 / 169 |
| B r1 | 6.70 | 52/66 | 200 | 237 | 284 | 9.23 | 123 | 165 / 171 |

### Other scenarios (one run each)
| Scenario | A duration s / liveness max ms / CPU s | B duration s / liveness max ms / CPU s | A2 duration s / liveness max ms / CPU s |
|---|---|---|---|
| Investigation, 500 records (2 repeats: A 1.46 and 1.54 s, liveness max 1014 and 855 ms) | 1.5 / 855-1014 / 1.6 | 2.6-2.7 / 123-132 / 3.6-3.8 | 1.4-1.5 / 522-918 / 1.4-1.6 |
| Two investigations of 500 at once | 3.32 / 1203 / 3.05 | 16.69 / 212 / 35.86 | 3.40 / 1773 / 3.06 |
| Ingestion (4 x 100 alerts) during a 1,000-record investigation | 7.04 / 2121 / 6.48 | 15.05 / 260 / 22.69 | 6.99 / 1856 / 6.67 |
| Duplicate storm (8 clients, same 100 alerts) | 6.01 / 146 / 5.05 | 6.00 / 141 / 5.09 | 6.12 / 164 / 5.20 |
| Idle (6 s) | RSS 114 MB, 26% CPU | 114 MB, 30% | 115 MB, 30% |

Correctness in every run: identical result digest across the two repeats of each size; 400 of 400 concurrent alerts stored; the duplicate storm stored exactly 100 of 800 submissions; all statuses 200 or 201. (Digests differ between runs because each run seeds fresh alerts, so cross-version output equivalence must be proven by a differential test, section 5, not by this benchmark.)

Memory (real server process, found by listening port; the earlier "4 MB" reading was the launcher): idle 114 MB, peak 168-174 MB, end-of-run 164-166 MB after repeated investigations. No growth signal across runs; about +55 MB transient during a 1,000-record investigation.

PostgreSQL side: at most 1 active session (2 once) during investigations and 0 lock waiters. The duplicate storm shows 8 active and 7 lock waiters, which is the expected unique-constraint contention that the savepoint recovery handles.

## 2. Findings and root-cause assessment (confidence in brackets)

1. **CPU-bound analysis competing with the event loop for the Python GIL is the dominant cause of unresponsiveness. [High]** The investigation thread uses about 80-90% of one core (CPU seconds roughly equal wall seconds) while the health check receives only 23-31% of its expected polls. Cutting the thread switch interval to 0.5 ms raised liveness polls to about 78% of expected and cut the worst delays from 0.75-1.4 s to about 0.19-0.20 s (database checks from 1.3-2.9 s to 0.22-0.28 s). A and A2 agree, so the baseline is reproducible and not an ordering or warm-up effect.
2. **The switch interval is not a fix. [High]** It buys responsiveness by paying for scheduling: a 1,000-record investigation takes 6.4-6.7 s instead of 3.5 s, uses 8.8-9.2 CPU seconds instead of 3.5, two parallel investigations take 16.7 s instead of 3.3 s using 36 CPU seconds, and ingestion during an investigation takes 15 s instead of 7 s. This shows threads cannot solve the problem without a throughput penalty. It also supports the GIL explanation.
3. **Database locks or execution are not the cause. [High]** 0 lock waiters, at most 1-2 active sessions, and PostgreSQL executes the verdict queries in under 1 ms (item 6).
4. **The same stall delays database-touching requests. [Medium-High]** An auth-only database check (no verdict query) is delayed 1.3-1.9 s, nearly as much as the cases check (1.8-2.9 s). The extra delay on the cases check (roughly 0-1.2 s, inconsistent) is consistent with the verdict lookup's added round trips and decoding but is not the main cause.
5. **Result serialization is not a factor. [High]** FastAPI response serialization takes 2.5 ms at most. The result-building step (`build_payload`) takes 12-22 ms (one 185 ms outlier). Garbage-collection pauses: 23-24 events, longest 159-171 ms, which does not explain multi-second stalls. [Medium: GC measured under load]
6. **Loop-thread database steps are a smaller, real contribution. [Medium]** Loading 1,000 rows through the ORM (twice per investigation) takes about 0.2-0.3 s each on the loop thread; a few commits of the large result took 0.2-0.8 s as seen by the application, inflated by the GIL competition.
7. **Quadratic work inside the analysis exists and is confirmed. [High that it exists; Medium-Low on payoff]** `analyze()` alone: 2.8 s at 1,000 records, 1.2 s at 500. Outside the API cap (one investigation is limited to 1,000 records) the cost grows faster than linearly: 1,000 records 2.5 s, 2,000 records 7.6 s, 4,000 records 25.5 s (about 3.0x then 3.4x for each doubling). The profile shows about 2,000,000 UUID hash operations and the cause in section 3.
8. **The verdict lookup is a real but modest cost. [High on measurement]** Section 4.
9. **Memory is not a demonstrated problem. [Medium]** See above.

Probe-shape caveat: the synthetic data (20 hosts, TEST-NET addresses, one alert a minute) forms about 1,000 separate incidents of one event each (25 stored by the storage cap). A single large incident would stress different code (pair correlation). Not yet measured.

## 3. Optimisation 1: reuse of whole-run lookup tables in the analysis

Exact code (verified by reading; confirmed by the profile):
- `backend/app/modules/correlation/workflow.py`, `build_incident_context` (about line 173): `by_key = {e.event_key: e for e in result.events}` rebuilt for every incident. O(n) per incident, O(I x n) overall (1,000 x 1,000 = 1,000,000 UUID hashes).
- `backend/app/modules/correlation/timeline.py`, `build_timeline` (about line 23): the same dictionary again (second 1,000,000), plus the `conflicts` mapping over all contradictions (lines 25-28). Together the roughly 2,000,000 hashes in the profile.
- Not the cause: the sufficiency gate, which is a pure function of one incident (about 2.8 ms per call, per-call object validation, JSON and hashing, constant work at one event per incident). `events.index(m)` (`sufficiency_gate.py` about line 369) is quadratic only within a large incident; the witness search (about lines 574-587) runs only when corroborating evidence exists. Neither matters at one event per incident. Other whole-list scans per incident exist in `analyze()` for domain-envelope records only (observations, candidates, analyst observations; `graph.py` rebuilds); not exercised here.

Safe reuse (argued from the code): one `by_key` built from `corr.events` (the same sorted list, same order, same last-wins behaviour for duplicate keys, the same frozen event objects, read-only in both callees); one `conflicts` mapping built after the contradiction merge (`corr` is reassigned at about line 345); `unit_ids = list(members)` in the gate; an optional bounded memo for `entity_link_strength`. Must not be done: building `by_key` from the normalised events or from the correlator's own map (different order or duplicate behaviour); building `conflicts` before the contradiction merge; any module-level or `lru_cache` memo of the build functions (the analysis runs in worker threads); reusing the dummy-hash context object; caching or removing the second pass of the context hasher (it is a verification contract used by the validator and synthesizer).

Minimal change: `build_incident_context(..., by_key=None)` and `build_timeline(result, incident, by_key=None, conflicts=None)` each fall back to today's local build when not given; `analyze()` builds the two mappings once and passes them. Existing two-argument callers and tests stay valid.

Expected impact (ESTIMATE, not measured): the profile attributes about 2.0 of 6.4 profiled seconds to the rebuilds, but the profiler inflates Python-level hashing; the agent's estimate of the unprofiled saving is about 10-15% of analysis time (about 0.3-0.5 s of 2.8 s at 1,000 records). It does not touch the sufficiency gate, the largest remaining cost. Complexity afterwards: O(n) once plus O(sum of k).

Regression risks: wrong source or hoist position of the mappings (see above); current pins are thin: `pipeline_fingerprint` covers ids, event keys, verdicts, reasons and assessment hashes but not context hashes, timelines, the ledger head or ATT&CK output.

Tests proving identical output and provenance (new file; nothing existing edited): a differential test that runs the reference path (the new optional parameters switched off by monkeypatching the two build functions) and the optimised path on the same inputs (60 all-separate records, one 260-event incident that exercises the 200-event cap and the witness search, mixed shapes, duplicate and `None` event keys, tied timestamps, domain-envelope scenarios with analyst notes, a rejected-only batch) and asserts byte equality of: `summary()`, per incident `context` JSON, `context_sha256`, timeline rows, assessment JSON including `assessment_sha256` and `reason_codes`, trace, ATT&CK output, report markdown, the whole ledger, its head and `ledger_ok`. Provenance: every timeline row's `raw_sha256_prefix` equals the first 12 characters of the raw digest of the event with that key; every context item's raw digest equals the normalised event's digest (unique keys only; with duplicate keys assert old equals new). Existing tests that must stay green: `test_pipeline_scaling.py` (10 pinned fingerprints and the 800-record time bound), `test_multisource_workflow.py` (timeline, determinism, ledger chain, end-to-end), `test_evidence_domain_scenarios.py`, `test_evidence_domains.py`, the gate and independence suites, `test_context_hasher.py`.

## 4. Optimisation 2: the case-verdict lookup

Code (written for the Cases-list verdict feature): `backend/app/services/multisource_investigation_service.py`, `case_sufficiency_summaries` and `_case_sufficiency_from_row`, called from `case_service.py` `list_cases_for_analyst` and `get_case_detail`. It selects the latest investigation row per case with a window query and then loads each row's whole stored `details` JSON (about 0.5 MB each) to read one verdict.

Measured at idle, 20 cases with the largest stored investigations (page text 9.6 MB, 5.7 MB stored compressed), median of 7:
| Stage | Time |
|---|---|
| PostgreSQL execution, window query (EXPLAIN ANALYZE) | 0.15 ms |
| PostgreSQL execution, details fetch (EXPLAIN ANALYZE; does not include sending or de-compressing the value) | 0.49 ms |
| Transfer as raw text, no parsing (server de-compress, jsonb to text, network, driver) | 143 ms |
| JSON decoding of that text (pure Python-side work on the loop thread) | 78 ms |
| SQLAlchemy path with full `details` | 232 ms |
| SQLAlchemy path selecting a tiny JSON path value instead | 27 ms |
| The verdict reduction itself | 0.55 ms |
| Whole `case_sufficiency_summaries` as the application runs it | 226 ms |

So a 20-case page costs about 226 ms at idle, about 8x more than a compact read (about 27 ms, mostly statement overhead): 63% transfer, 35% decoding, nothing in database execution or reduction. For the dashboard check (limit 1) it is one row, roughly 10 ms at idle. This is a defect in my own change; its effect under load is amplified by the GIL stall because every wait needs the event loop.

Proposed minimal fix (Option 1 of four evaluated): at write time add one small top-level key to the stored result, `verdict_summary = {schema: 1, verdict, rule_version, truncated}`, derived from the assessments already in the same payload by the same reducer used on the read side (no evaluation, no gate call); read it with a portable SQLAlchemy JSON path (`details["verdict_summary"]`), so only about 100 bytes per case cross the wire. Rows written before the change lack the key: only those fall back to today's full read in a second query, with a small bounded in-process memo keyed by the immutable audit-row id. Nothing is back-filled or updated (the audit table is append-only and enforced by database triggers). No migration. Rejected: per-incident JSON paths (clumsy; the database may re-read the whole value for each path), a separate audit row or table (conflicts with append-only semantics and audit-count pins, needs a migration), generated columns or indexes (migration; PostgreSQL only).

Expected impact (ESTIMATE): bytes per 20-case page from about 9.6 MB to about 2-3 KB for new rows; time from about 226 ms to about 30-40 ms at idle; legacy rows unchanged until re-investigated or memoised (the 56 existing demo cases would not benefit until then).

Regression risks and tests: the POST and reuse responses gain one extra top-level key (the frontend reads typed fields and ignores unknown keys; verify in `MultiSourcePanel.tsx`); `section_view` and `activity_summary` build explicit dictionaries and ignore it; the evidence fingerprint does not hash `details`. Tests to add: for every existing fixture (worst-of reduction, batch-only, malformed, unknown verdict, truncation true and false) the result from `details + verdict_summary` equals the result from the full path; rows without the key resolve identically; a mixed page of old and new rows equals an all-old page, with statement counts one for all-new and two for mixed; assignment scoping unchanged (existing BOLA tests untouched); `evaluate_sufficiency` monkeypatched to raise proves the gate is never called on read or in `_compact_verdict`; `build_payload` output carries `verdict_summary` equal to the reducer's result, including with the incident storage cap lowered. Other full-`details` loaders (`list_case_activity`, `_latest`, section reads) are listed for a separate change.

## 5. The architectural question: where should large investigations run

Evidence that a thread cannot fix this (findings 1 and 2) and that algorithmic changes alone cannot either (finding 7: an estimated 10-15% reduction in analysis time while the loop still competes with a CPU-bound thread). The options evaluated:

| Option | Removes | Cost and regression risk |
|---|---|---|
| Keep `to_thread` and add the two optimisations above | Shorter stall window (CPU work shrinks) | Low risk. Does not remove the GIL competition; the stall remains proportional to analysis time |
| Smaller thread switch interval | Stall (measured) | Rejected: 1.8x duration, 2.5x CPU, 5x with two parallel investigations |
| Worker process for the deterministic analysis | The GIL competition (separate interpreter) | Windows spawn start-up and import cost, extra memory (+100-200 MB per worker, estimate), inputs and outputs must be picklable (the stored payload is about 0.6 MB; returning only the payload dictionary avoids pickling the full result objects), crash and cancellation handling, tests that monkeypatch the gate would not reach a child process, the model-assisted path needs result objects and the provider so it would stay in the server process. Needs a spike measuring start-up, pickling and memory before a decision |
| Background job with task tracking (202 and polling) | Request duration, not CPU contention | Larger: needs job state (a table, so a migration, or in-memory state lost on restart), a per-job session, a new PROPOSED ADR (ADR-010 defers it), and the current UI reads the result from the POST response. Evaluate only after the process spike; bounded concurrency and per-case isolation (the existing per-case lock) must live inside the job |
| Chunked incremental persistence | Almost nothing (stored result about 0.6 MB, tens of ms) | Needs a new table and breaks the one-audit-row-per-run assumption. Not justified by the data |

Recommendation (for owner review, not started): do optimisations 1 and 2 first (small, safe, testable, each measured with the same benchmark), then run a **spike** of a single bounded worker process for the deterministic analysis and result building, measuring start-up time, memory and pickling cost against this benchmark. Adopt it only if it meets the acceptance criteria without a throughput penalty like the switch-interval experiment. Do not introduce Celery, Redis or a job queue.

## 6. What is not established
Repeats per scenario are two, so differences smaller than the run-to-run spread are not conclusions. Instrumentation (small timers, a 5 ms lag ticker, SQL statement events) adds overhead; compare only instrumented runs with instrumented runs. Single machine, single process, synthetic one-event-per-incident data, LLM off. Not measured: sustained load over time, the LLM-enabled path, multi-process behaviour, a single very large incident, phase timings with the analysis thread idle (for the loop-thread database steps), real vendor data. The estimates in sections 3 and 4 are estimates.

## 7. Acceptance criteria (issue closes only when all hold, from at least three repeats per scenario)
Responsiveness, 1,000-record investigation: liveness polls received at least 90% of expected, worst liveness delay at most 250 ms, worst auth-only and cases database-check delay at most 300 ms; same for two parallel investigations of 500 and for ingestion during an investigation. Throughput: a single 1,000-record investigation no slower than 1.25x the current 3.5 s, two parallel 500-record investigations no slower than 1.5x the current single-500 time, total server CPU seconds no more than 1.25x the current. Verdict lookup: at most 50 ms for a 20-case page at idle with new rows. Correctness: differential test byte-identical (section 3), result digests identical across repeats, 0 lost alerts, exactly one record per duplicate, all existing suites green (the full backend unit suite, integration without live services, frontend tests), per-case isolation and error handling unchanged. Memory: server peak at most 200 MB (plus any worker) and no growth across repeated runs. Evidence: the benchmark and its results are committed with the change, and the unmodified original evidence folders remain.

## 8. Order of work proposed (nothing started)
P0 finish this record and get owner review; P0 optimisation 1 with its differential test; P0 optimisation 2 with its tests; P1 re-run the benchmark (three repeats, interleaved with a baseline) and the full test suite; P1 measure the loop-thread database steps and a single large incident; P2 process-worker spike if the criteria are still not met.

---

## 9. Results after the two optimisations (2026-11-26)

Implemented (uncommitted): lookup-table reuse in `analyze()` (`correlation/workflow.py`, `correlation/timeline.py`, one line in `sufficiency_gate.py`, all new parameters defaulting to the old behaviour) and the compact `verdict_summary` (`multisource_investigation_service.py`). Verification: full backend unit suite 4,011 passed, 2 skipped, 1 xfailed, 0 failed; integration without live services 85 passed, 39 deselected; frontend typecheck clean and 312 of 312 tests; the 10 pinned pipeline fingerprints unchanged; a 39-test differential file proves byte-identical output between the old and new code paths on 17 datasets with provenance checks. Not run: the PostgreSQL-marked and Ollama-marked tests.

Benchmark: two passes of the same benchmark on the new code, three repeats each (`new_N1_new_default`, `new_N2_new_default`), against the earlier two baseline passes with two repeats each (`cmp2_A_default`, `cmp2_A2_default_repeat`). Median over all repeats; worst values are the maximum over all repeats.

| Scenario | Duration, before | after | Liveness polls received, before | after | Worst liveness delay, before | after | Worst DB-check delay (cases), before | after | Server CPU s, before | after |
|---|---|---|---|---|---|---|---|---|---|---|
| Investigation, 500 | 1.48 s | 1.33 s | 45% | 60% | 1.01 s | 0.68 s | 1.22 s | 1.02 s | 1.56 | 1.33 |
| Investigation, 1,000 | 3.54 s | 2.67 s | 30% | 35% | 1.39 s | 1.12 s | 2.93 s | 2.65 s | 3.58 | 2.67 |
| Two investigations of 500 | 3.36 s | 2.95 s | 36% | 45% | 1.77 s | 1.30 s | 2.55 s | 1.94 s | 3.05 | 2.61 |
| Ingestion during a 1,000 investigation | 7.02 s | 6.00 s | 49% | 54% | 2.12 s | 1.72 s | 3.16 s | 2.36 s | 6.58 | 5.47 |

`analyze()` alone, in process, no server: 1,000 records 2.51 s to 1.77 s; 2,000 records 7.59 s to 4.54 s; 4,000 records 25.54 s to 12.09 s (28%, 40% and 53% lower: the saving grows with size, consistent with removing a quadratic term; the earlier estimate of 10 to 15% was too low). Correctness: result digests identical across repeats; 400 of 400 concurrent alerts stored; the duplicate storm stored exactly 100 of 800; memory peak unchanged (168 to 172 MB, no growth). The new runs' digests differ from the old runs' because each run seeds fresh alerts; old versus new output equality is proven by the differential test, not by the benchmark.

Verdict lookup (20-case page, real PostgreSQL scratch database, median of 7): rows written by the new code 23.5 ms (first call 30.9 ms) against 173 ms for the full-details path on the same rows; old rows (no summary) first call 237 ms (unchanged from the earlier 226 ms) and about 33 ms on repeat calls in the same process from the in-memory cache. The earlier estimate was 30 to 40 ms. Old rows only benefit after one slow load per process or after re-investigation.

Assessment against the acceptance criteria (section 7): the optimisations deliver real CPU and duration savings but **the responsiveness criteria are not met** (liveness polls received 35% against at least 90%; worst delay 1.1 s against at most 250 ms; database-check delay 2.7 s against at most 300 ms). The stall shrank only in proportion to the CPU work removed, as the GIL explanation predicts. **This issue remains OPEN.**

## 10. Worker-process spike (measurement only; no application code changed)

`backend/scripts/spike_process_worker.py` runs the application's own `analyze` and `build_payload` (unchanged) on the same synthetic records two ways inside a bare asyncio loop with a 5 ms lag ticker: in a worker thread (today) and in one spawned worker process that returns only the JSON-safe payload. Three repeats per size; results in `spike_process_worker.json`. No database, no HTTP, no LLM.

| Records | Mode | Wall s (median) | Worst loop lag | Loop ticks received | Parent CPU s | Worker CPU s | Parent RSS MB | Worker RSS MB |
|---|---|---|---|---|---|---|---|---|
| 500 | thread | 0.84 | 152 ms | 10% | 0.84 | n/a | 99 | n/a |
| 500 | process | 0.89 | 26 ms | 33% | 0.00 | 0.88 | 96 | 94 |
| 1,000 | thread | 1.86 | 245 ms | 10% | 1.84 | n/a | 120 | n/a |
| 1,000 | process | 1.91 | 27 ms | 32% | 0.05 | 1.89 | 116 | 107 |
| 2,000 | thread | 4.40 | 308 ms | 10% | 4.39 | n/a | 162 | n/a |
| 2,000 | process | 4.57 | 27 ms | 31% | 0.06 | 4.53 | 154 | 133 |
| 2 x 500 at once | thread | 1.79 | 323 ms | 8% | 1.80 | n/a | n/a | n/a |
| 2 x 500 at once | process (2 workers) | 0.87 | 26 ms | 34% | 0.05 | 1.72 | n/a | 92 and 92 |

Reading it: the loop lag in process mode is flat (about 27 ms) whatever the size, against 150 to 320 ms in thread mode. "Ticks received" is capped near 32% in process mode because Windows' default timer resolution (about 15.6 ms) cannot deliver a 5 ms tick; so process mode gets essentially all the ticks the platform can give, and thread mode only about a third of them. Throughput: 3 to 6% slower than the thread (no penalty like the 0.5 ms switch interval, which cost 83% more time and 2.5x the CPU); two concurrent investigations finish in half the time because they run on separate cores. The parent process does almost no CPU work (0.05 s against 1.84 s). One-time cost: worker start-up 2.3 s (spawn plus importing the application modules), worker idle memory 76 MB, 94 to 133 MB while working. Data movement is negligible: inputs 115 to 463 KB (2 to 8 ms to pickle), returned payload 280 to 729 KB (1.5 to 5 ms each way). Equality: the payload from the process path is byte-identical (canonical JSON hash) to the thread path in all 9 comparisons.

Limits of the spike: it excludes the database, ORM loading, response writing and the LLM path; a bare loop has far fewer awaits per request than the server, so the server's absolute delays (about 1 s) are larger than the spike's thread-mode lag (about 0.25 s). The direction and size of the effect are what transfer; the end-to-end figure must be measured with the real server and this benchmark.

## 11. Proposed integration (for owner approval; nothing implemented)

Why a process is justified: threads cannot remove the GIL competition (section 2, items 1 and 2); algorithmic savings are real but proportional (section 9); the spike shows a separate interpreter removes the stall at a 3 to 6% duration cost with identical output. It uses only the standard library (`concurrent.futures.ProcessPoolExecutor`, spawn): no Celery, Redis, queue or new service.

Design: a small executor abstraction used by the deterministic path of `MultiSourceInvestigationService._start_locked`. With a setting (proposed `ANALYSIS_WORKER_PROCESSES`, default 0 = today's thread behaviour, so nothing changes until enabled), the deterministic investigation (no model call) runs `analyze` plus `build_payload` in a bounded worker pool (size 1 or 2) and returns the JSON-safe payload; the evidence fingerprint, the per-case lock, the evidence-changed check, the audit write and the response stay in the server process unchanged. The model-assisted path (`use_llm=true`) keeps running in the server process because it needs the provider and result objects. Pool created lazily or at startup with a warm-up initializer and shut down with the application; if the pool breaks (a worker crash), fall back to the thread path for that request and rebuild the pool, so no investigation is lost. A new PROPOSED ADR would record the execution model (ADR-010 section 3C defers background jobs).

Regression risks and mitigations: worker start-up and memory (+76 to +133 MB per worker; warm at start); Windows spawn must re-import the application, so settings and logging must work in the child (pass the environment; verify); tests that monkeypatch the gate or other in-process objects keep using the default in-process path; the architecture test that forbids model calls outside the gate is unaffected (the worker never calls a model, and `analyze` already contains the single gate); no cancellation of a running job (it finishes). Correction from the 2026-11-26 independent review (section 19, finding 4): the per-case lock is NOT held until the worker job finishes. If the request is cancelled (for example a client disconnect) the semaphore and the per-case lock are released while the worker keeps running; the orphan job's result is discarded and no audit row is written for it. A retry of the same case starts a second job queued behind it, and queued work is not bounded by the semaphore. The pool size bounds how many jobs run at once; extra investigations queue.

Tests required: differential test that the process path payload equals the thread path payload byte for byte on the same 17 datasets; error propagation (an exception in the worker surfaces as the same fail-closed error); worker-crash fallback; shutdown; the existing multi-source, reliability and adversarial suites with the setting on and off; a benchmark run with the setting on (three repeats, interleaved with off) against section 7.

Expected outcome (estimate to be confirmed by benchmark): worst liveness delay in the low hundreds of milliseconds or less and at least 90% of achievable polls, duration within the 1.25x limit, parent CPU near zero during the analysis; the remaining delay would come from the loop-thread database steps (two ORM loads of about 0.2 to 0.3 s each), which the benchmark would then expose and which can be addressed next.

## 12. Order of work now
P0 owner decision on section 11 (and a new PROPOSED ADR if approved); P1 implement behind the default-off setting with the tests above; P1 benchmark with the setting on and off, three repeats each, interleaved; P2 loop-thread database steps if still above the criteria; P2 commit the measurement tools and this record when authorised.

---

## 13. Benchmark with the worker-process setting enabled (2026-11-26)

**Read section 15 with this section.** The "polls received" percentages below (and in sections 1, 9 and 10) used a biased calculation; the corrected poll rates are lower (1,000-record investigation with the worker on: 86%, not 96%), the statement that the criteria are "largely met" is withdrawn, and the latency findings stand.

Implemented behind `ANALYSIS_WORKER_PROCESSES` (default 0 = off, nothing changes until enabled): `backend/app/services/analysis_executor.py` (new), the setting in `core/config.py`, one branch in `MultiSourceInvestigationService._start_locked`, pool start and stop in the app lifespan, proposed `ADR-018_Analysis_Worker_Process.md` (PROPOSED, not adopted). The deterministic path only; the model-assisted path never leaves the server process; a crashed or unavailable pool falls back to a thread for that request. Verification before benchmarking: full backend unit suite 4,026 passed, 2 skipped, 1 xfailed, 0 failed (15 new tests: byte-identical payloads from the worker and the in-process path on 5 datasets, crash fallback with a rebuilt pool, exception parity, `use_llm` stays in process, setting 0 creates no pool, bounded concurrency, shutdown idempotent, evidence-changed protection still raises); integration without live services 85 passed; frontend 312 of 312. Not run: PostgreSQL-marked and Ollama-marked tests; a `uvicorn` command-line launch (only `backend/run_local.py` was used).

Benchmark: three passes in the order ON, OFF, ON on the same code and scratch database, three repeats each (`wk2_P1_workers_on`, `wk2_OFF3_workers_off`, `wk2_P2_workers_on`; the first two attempts failed on a benchmark-tool bug, a missing PowerShell path used to find worker processes, and are kept in `_failed_first_attempt`). Worker CPU and memory are measured on the real worker processes (found as descendants of the server). ON figures combine P1 and P2 (6 repeats for investigations, 2 for the single-run scenarios); OFF is one pass (3 repeats, 1 for single-run scenarios).

| Scenario | Setting | Duration (median) | Health polls received (median; worst repeat) | Worst health delay | Worst auth-only DB-check delay | Worst cases DB-check delay | Server CPU s | Worker CPU s | Server peak MB | Worker MB |
|---|---|---|---|---|---|---|---|---|---|---|
| Investigation, 500 | OFF | 1.39 s | 50%; 43% | 808 ms | 1,003 ms | 1,025 ms | 1.39 | 0 | 141 | 0 |
| Investigation, 500 | ON | 1.48 s | about 100%; 76% | 130 ms | 213 ms | 242 ms | 0.73 | 1.14 | 125 | 94 |
| Investigation, 1,000 | OFF | 2.70 s | 37%; 35% | 741 ms | 1,336 ms | 1,384 ms | 2.66 | 0 | 168 | 0 |
| Investigation, 1,000 | ON | 2.41 s | 96%; 79% | 247 ms | 347 ms | 416 ms | 0.99 | 1.86 | 136 | 109 |
| Two investigations of 500 | OFF | 2.56 s | 48% | 935 ms | 1,019 ms | 1,116 ms | 2.12 | 0 | 168 | 0 |
| Two investigations of 500 | ON | 2.59 s | 100% | 123 ms | 163 ms | 236 ms | 1.29 | 1.71 | 136 | 103 |
| Ingestion during a 1,000 investigation | OFF | 8.88 s | 45% | 2,644 ms | 3,287 ms | 3,305 ms | 8.25 | 0 | 173 | 0 |
| Ingestion during a 1,000 investigation | ON | 3.98 s | 82% | 135 ms | 240 ms | 282 ms | 3.50 | 1.94 | 136 | 110 |
| Duplicate storm (ingestion only) | OFF | 10.80 s | 61% | 215 ms | 271 ms | 424 ms | 8.20 | 0 | 173 | 0 |
| Duplicate storm (ingestion only) | ON | 5.78 s | 79% | 116 ms | 220 ms | 268 ms | 4.81 | 0 | 136 | 110 |

Correctness in all three passes: result digests identical across repeats at 500 and 1,000; 400 of 400 concurrent alerts stored; the duplicate storm stored exactly 100 of 800 submissions; all statuses 200 or 201. Output equality between the worker path and the in-process path is proven by the 15 new tests and by the spike, not by this benchmark.

Findings (confidence in brackets):
1. Moving the deterministic analysis into a worker process removes the stall during investigations. [High] Health polls received rose from 35-50% to about 96-100%; worst health delay fell from 0.7-0.9 s to 0.12-0.25 s; worst database-check delay from 1.0-1.4 s to 0.16-0.42 s; two parallel investigations went from 48% to 100% of polls. The server process's own CPU for a 1,000-record investigation fell from 2.66 s to 0.99 s (the work moved to the worker, 1.86 s).
2. There is no throughput penalty. [Medium-High] A single 1,000-record investigation took a median 2.41 s ON against 2.70 s OFF (the spread within OFF alone is 1.98 to 2.71 s, so a difference of this size is not a conclusion); total CPU (server plus worker) 2.85 s against 2.66 s (+7%).
3. One repeat was an outlier and the cause is not identified. In P2 the first 1,000-record repeat took 3.95 s with worker CPU 2.91 s (the other five repeats: 2.33 to 2.45 s and 1.78 to 1.88 s), worst health delay 247 ms, database checks 347 and 416 ms. Wall time and worker CPU rose together, which points at the worker getting less CPU than usual (background activity on the laptop is a candidate; not verified). Without it all investigation scenarios meet the criteria below.
4. Ingestion still runs inside the server's event loop. [High] In the ingestion-heavy scenarios the server uses 70-80% of a core and only 79-82% of polls are answered (worst delay stays at 116-135 ms). This is a different, remaining cause, not addressed by this change.
5. Memory: the server process peak fell from 168-173 MB to 136 MB; the worker adds 94-110 MB; combined about 245 MB against 168 MB, so the setting costs about 75 MB of total memory. [High]
6. System noise is large for ingestion-heavy scenarios: the same code with the setting off took 8.88 s and 10.8 s in this pass against about 6.0 s and 5.7 s in the earlier passes N1 and N2. Differences in ingestion timings between ON and OFF therefore must not be read as a speed-up from the worker. [High]

Assessment against the acceptance criteria (section 7), investigations only unless stated: at least 90% of polls received (met in the median for 500, 1,000 and two parallel; the worst repeat is 76% and 79%; not met for ingestion during an investigation at 82%); worst health delay at most 250 ms (met: 130, 247, 123 and 135 ms); worst database-check delay at most 300 ms (met in 11 of 12 investigation repeats; the outlier repeat reached 347 and 416 ms); duration within 1.25x (met); server memory peak at most 200 MB (met: 136 MB, worker separate); correctness (met). **Status: the investigation stall is largely resolved in this benchmark but the issue stays OPEN**: one outlier repeat is unexplained, the ingestion scenarios remain below the polling criterion, repeats are few, and this is one laptop with synthetic data and the LLM off. The code default of the setting stays 0; enabling it for a demo or deployment is the owner's decision (the owner has since approved it for the demo script, see section 14).

## 14. Remaining work
P0 decide whether to enable `ANALYSIS_WORKER_PROCESSES=1` for the demo (correction, 2026-11-26: the owner approved enabling it for the demo and `scripts/demo_backend.ps1` now sets `ANALYSIS_WORKER_PROCESSES=1`, so the demo runs with the worker; the code default is still 0); P1 more repeats to measure how often outliers occur and test whether they correlate with background load; P1 ingestion path (parsing and normalisation on the event loop) as the next responsiveness target; P2 adopt or reject ADR-018 after the owner reviews this evidence; P2 commit the measurement tools, the new code and this record when authorised.

---

## 15. Correction (2026-11-26): the "polls received" percentages in sections 1, 9, 10 and 13 were biased

An independent code review noticed, and I confirmed in `bench_investigation.py`, that "liveness polls got/expected" was computed wrongly: the pollers run for the work duration plus 0.8 s of extra idle polling (0.5 s before and 0.3 s after the work), while "expected" used the work duration alone and assumed a 0.1 s poll cycle, which is really about 0.12 s on Windows (timer rounding plus request time). Short scenarios were therefore flattered (some exceeded 100%). The worst-delay figures (maximum and 95th percentile latency), the database-check delays, CPU, memory and correctness results are not affected. The corrected metric is each scenario's poll rate relative to the same run's idle poll rate over the same measured window (idle reads 100% by construction); the benchmark summary now prints this. Recomputed for every earlier pass:

| Scenario | Workers off, old code (A/A2) | Workers off, optimised (N1/N2) | Workers off, optimised, same day as ON (OFF3) | **Workers on (P1+P2)**, median; worst repeat |
|---|---|---|---|---|
| Investigation, 500 | 36% | 44% | 37% | **83%**; 72% |
| Investigation, 1,000 | 30% | 33% | 35% | **86%**; 85% |
| Two investigations of 500 | 36% | 43% | 44% | **94%**; 91% |
| Ingestion during a 1,000 investigation | 54% | 59% | 51% | **86%**; 83% |
| Duplicate storm (ingestion only) | 86% | 89% | 70% | **87%**; 85% |

What changes in the conclusions:
1. The improvement from the worker process is real and large (investigation poll rate about 30-44% without it, 83-94% with it) but the earlier statement "96% of health checks answered" was wrong; the corrected figure for a 1,000-record investigation is **86%**.
2. The "at least 90% of polls" criterion in section 7 is **not met** for 500-record and 1,000-record investigations (83% and 86%) or for ingestion during an investigation (86%); it is met only for two parallel investigations (94%). Section 13's statement that the criteria are "largely met" is withdrawn: the latency criteria are met in most repeats, the poll-rate criterion is not.
3. The worst-delay and 95th-percentile figures with the worker on (health check 95th percentile 43 to 86 ms; maximum 116 to 247 ms; auth-only database check 95th percentile 87 to 140 ms) sit near this setup's own idle noise floor: the idle scenario alone shows health-check maxima of 115 to 291 ms and auth-check maxima of 309 to 452 ms in every pass. A 250 ms worst-delay limit is therefore at the measurement noise level on this laptop and cannot discriminate small differences; the 95th percentile is the more reliable latency figure.
4. The remaining gap during an investigation with the worker on (poll rate 83-86%, not 100%) is consistent with the work the server process still does itself: loading and decoding the case's evidence rows twice and writing the stored result (server CPU 0.9-1.0 s for a 1,000-record investigation). That is the "loop-thread database steps" item in section 14 and is the next candidate, but it is a hypothesis until profiled with the analysis off the server.
5. The pooled ingestion scenarios (duplicate storm 85-89% with or without workers) are unaffected by the worker, as expected.

Ingestion path, static analysis by an independent review (not yet measured): about 5 database round trips per new alert (savepoint, three inserts, release) all on the event loop; measured about 16 ms per alert wall time and an estimated 4 to 7 ms of server CPU per attempt, which suggests the dominant cost is the ORM unit-of-work, driver and greenlet work around those round trips and not the pure parsing (estimated under 10% of per-alert CPU), so moving only the parsing into a worker would gain little. Cheapest candidate first: cooperative yielding in the two loops without awaits and replacing an O(n squared) list membership test with a set (same output); then fewer savepoints (one per chunk with a per-alert fallback); then bulk inserts with `ON CONFLICT DO NOTHING` (largest gain, largest change). All need PostgreSQL-marked tests because the unit tests use a single shared synchronous session. Measurement plan: a standalone profile of `ingest_batch` against the scratch database, timing each stage per alert.

## 16. Order of work now (replaces section 14)
P0 owner review of this correction; P1 profile the server-process work that remains during an investigation (row loading, result persistence) with the analysis off the server, then decide; P1 profile `ingest_batch` per stage before changing it; P1 more repeats and a check whether background load explains the one slow outlier; P2 decide on ADR-018 after the corrected evidence; P2 commit when authorised.

---

## 17. What the server process still does during an investigation, and where ingestion spends its time (measured 2026-11-26; proposals only, nothing changed)

Tools added (measurement only): `backend/scripts/profile_fingerprint_load.py` and `backend/scripts/profile_ingest_batch.py`; results in `fingerprint_load_breakdown.json` and `ingest_batch_breakdown.json` under `D:\AISOP-Backups\AISOP_LoadTest_20261125\`. Both use the scratch database only. The ingest profile adds synthetic rows to it and deletes nothing.

### 17.1 The evidence-changed check and the first evidence load (investigation, workers on)

The phase logs of the two worker-on passes (`wk2_P1_workers_on`, `wk2_P2_workers_on`, 9 investigations each) show the server's own work per 1,000-record investigation is dominated by two ORM loads of the case's evidence (`MultiSourceInvestigationService._load_rows`): typically 130 to 300 ms each as seen by the application (up to 760 ms under load). Everything else on the server side is small: fingerprint about 5 ms, building the analysis inputs about 2 ms, response serialization at most 6 ms, a few commits of 60 to 195 ms, garbage-collection pauses up to 106 to 181 ms. The benchmark's own pollers account for most of the server's CPU in these scenarios (the idle scenario alone, with the three pollers, uses 27 to 30% of a core), so the investigation's real server-side cost is only a few hundred milliseconds, and the ORM loads are most of it.

Where the cost of an evidence load goes (case with 1,000 linked evidence items, 246 KB of raw payload text, idle server, median of 7):
| Way of reading the evidence | Time |
|---|---|
| A: current, ORM load (entities plus joined raw record) then `fingerprint` | 139 ms (the load alone 132 ms) |
| B: the same SELECT through Core, with payloads, no ORM entities | 26 ms |
| C: column-only SELECT of (event id, raw SHA-256) feeding the same `fingerprint` function | 21 ms |
| Fingerprint from A equals fingerprint from C | **True** |

About 80% of the current cost is the ORM building entity objects; the database, the transfer and the JSON decoding together cost about 26 ms. The second load in `_start_locked` and the load in `get_section` and `review` exist only to recompute the fingerprint (the evidence-changed and stale-evidence checks), which needs only the id and SHA-256 of each row.

Proposal A (small, low risk): add a column-only query for the fingerprint inputs and use it for the evidence-changed re-check after the analysis, for the stale check in `get_section`, and for `review`; build the fingerprint with the SAME `fingerprint` function (through light stand-in objects or a pairs overload) so the value is identical by construction. Optionally (Proposal A2) read the first load as a Core select of (event id, SHA-256, raw payload) in the same order instead of ORM entities, since `_inputs` uses only the payload, digest and id (preserve the outer-join semantics of `joinedload` for rows without a raw record). Expected effect (estimate from the idle measurements above): about 118 ms less loop-thread time per fingerprint check (139 to 21 ms), about 105 ms less for the first load; per 1,000-record investigation about 220 ms less loop-thread work; per workspace open, which reads about 9 sections, about 1 s less. Regression risks: ordering and duplicates (the fingerprint sorts, so row order does not matter), rows whose raw record is missing (digest `""` today; keep), visibility rules (the query must keep the join on `case_evidence.case_id` and nothing else; assignment checks happen before), the evidence-changed protection (the test that evidence changed during the run must still raise `EvidenceChanged`). Tests: a differential test that the fingerprint from the new query equals the old one on the datasets used by the multi-source tests including a case with a missing raw record, the existing `test_multisource_api`, `test_multisource_review`, `test_stage5_adversarial` suites, and a statement-count and rows-materialised check.

### 17.2 Ingestion (`AlertIngestionService.ingest_batch`), 1,000 generic_siem alerts, in process, three repeats each (source type named and `auto`)

| Measure | Result |
|---|---|
| Wall time per alert | 11.5 ms (1,000 alerts in 11.5 to 11.7 s) |
| Process CPU per alert | 6.1 to 6.6 ms, 54 to 57% of wall (the rest is waiting for PostgreSQL) |
| SQL statements per alert | 5.0 (savepoint, three inserts, release), as predicted |
| Event-loop lag during the batch (5 ms ticker) | maximum 11 ms in 5 of 6 runs, 27 and 89 ms in the others; ticks over 50 ms: 1 in all runs combined |
| Alerts stored, errors | 1,000 and 0 in every run |

Per-alert stage cost (milliseconds, timers around the application's functions): `session.flush` (three flushes) 8.9 ms (about 78% of wall time), adapter `adapt` 0.14, `session.add` 0.08, `to_canonical_event` 0.05, `extract_entities` 0.04, hash 0.01, adapter selection with `auto` 0.06, savepoint creation and commit under 0.01. The pure per-record work (parse, normalise, hash, entities) is therefore about 0.3 ms of about 6.4 ms of CPU per alert, roughly 5%. The cProfile run (300 alerts) shows the rest in SQLAlchemy's unit of work, psycopg and greenlet switching, with `select.select` (waiting for the database) the largest single entry.

Findings: (1) **Ingestion does not block the event loop**: it yields at each of its five database round trips per alert; the earlier "ingestion blocks the loop" explanation is refuted for a single batch. The lower poll rates seen during concurrent ingestion (79 to 89%) come from one process using more than half a core for the ORM, the driver and greenlet work, so concurrent clients queue behind each other, not from a long blocking step. [High, measured] (2) Moving the parsing into the worker pool would gain at most about 5% of CPU and is not recommended. [High, measured] (3) The dominant cost is the number of statements and the ORM flush machinery around them.

Proposals (nothing implemented), smallest first: (a) replace the O(n squared) list membership test in the duplicate classification (`ev_id not in existing_evidence_ids`) with a set plus the same ordered list; no database effect, output identical; (b) one savepoint per chunk of alerts with a per-alert fallback only after a failure (saves about 2 of 5 statements); (c) bulk operations: Core `INSERT ... ON CONFLICT (sha256_hash) DO NOTHING RETURNING` for raw records, then events and entities in bulk, one flush per chunk; the expected gain is the largest (a several-fold CPU reduction, an estimate to be measured) but it changes how per-record failures and races are isolated, `alert_ids` order and duplicate accounting must be preserved, and it needs the PostgreSQL-marked tests because the unit tests use one shared SQLite session and cannot show concurrency effects. API response fields (`total_normalized`, `total_skipped_duplicates`, `errors`, `alert_ids`, `existing_evidence_ids`) must not change. Acceptance for any of these: identical stored rows and response for the same input, the full unit and PostgreSQL ingestion tests green, and a measured reduction in statements per alert and CPU per alert.

## 18. Order of work now
P0 owner decision on Proposal A (evidence-load changes; recommended first: smallest, measured, identical by construction) and A2; P1 implement with the differential tests, re-run the worker-on benchmark (three repeats, interleaved with the current code) and compare the server's CPU and loop-thread busy time; P1 ingestion proposal (a) and (b) only after Proposal A, (c) only with PostgreSQL tests and a separate decision; P2 decide ADR-018; P2 commit when authorised.

---

## 19. Independent review of the change set (2026-11-26)

An independent, read-only review of the uncommitted responsiveness change set (worker process, lookup-table reuse, compact verdict, light fingerprint query, case verdict badge, adapter severity change) was made on 2026-11-26. The reviewer read the code; nothing was executed. Findings, and the planned action for each. "Planned" means not done: no fix is claimed here.

| # | Finding | Status | What happens | Planned action |
|---|---|---|---|---|
| 1 | Case verdict badge lost | CONFIRMED defect (fixed, see section 21) | After closing, updating the metadata of, or transferring the lead of a case, the response is built in `case_service.py` without the four verdict fields. The frontend replaces its case with that response, so the header shows "Not assessed" with a tooltip saying no investigation has been run, which is false. Also, the header badge is not refreshed after an investigation is started in the workspace until the page is reloaded | Code fix by other agents (include the verdict fields in those three responses; refresh the badge after an investigation). Not fixed at the time of this record |
| 2 | No deadline on a worker job | PLAUSIBLE (fixed, see section 21) | `analysis_executor` has no deadline. A hung job would hold the only worker (pool size 1), so later deterministic investigations queue behind it, and shutdown waits forever | Planned: a job deadline |
| 3 | Start-up failure of the worker | PLAUSIBLE (fixed, see section 21) | A worker that crashes at start-up (initializer failure) is re-spawned on every request (a spawn storm). No investigation is lost: each request falls back to a thread | Planned: a cool-down after a failure |
| 4 | Cancellation differs from sections 11 and 13 and ADR-018 | PLAUSIBLE (documentation corrected, see section 21) | A cancelled request (client disconnect) releases the semaphore and the per-case lock while the worker keeps running. The orphan job's result is discarded and no audit row is written for it. A retry of the same case starts a second job queued behind the first, and queued work is not bounded by the semaphore. The same new cancellation point exists on the thread path (`asyncio.to_thread` in `workflow.py`) | Statements in sections 11 and 13/14 and in ADR-018 corrected in this record. Code or design decision on bounding queued work: planned, not decided |
| 5 | Verdict badge covers at most 25 incidents | PLAUSIBLE (fixed, see section 21) | The badge reflects at most the 25 stored incidents. The truncation flag is shown only in a tooltip | Planned: show the truncation as visible text |
| 6 | Missing severity understated | PLAUSIBLE (still open, see section 21) | A missing alert severity is now stored as "unknown" by the adapters, but correlation and the persisted event map "unknown" to "informational". An alert with no severity therefore counts as the lowest severity inside an incident, and incident severity can be understated. This is derived, not invented, but it is a limitation. The re-pinned fingerprint in `test_pipeline_scaling.py` reflects it | Disclose (see `Panel_Criticism_Validation.md`). Whether published evaluation scores need recomputing after the adapter change was not checked: the evaluation dataset case files are frozen and hash-locked, which suggests they are unaffected, but this was not verified |
| 7 | Minor items | PLAUSIBLE | (a) A request arriving between `shutdown_pool` clearing the pool and finishing could build a new pool that is never shut down (unlikely, uvicorn drains requests first). (b) The first submit starts a process on the loop thread on Windows, a brief stall at start-up (the pool is pre-warmed). (c) The Geist font package is now unused but still listed in `package.json`; removal is the owner's decision, already recorded in constitution amendment A7 | No action planned beyond awareness; (c) waits for the owner |
| 8 | Gate-line equivalence, lookup-table reuse equivalence, thread safety of `analyze` (no module-level mutable state found), fingerprint equivalence (including the outer join and de-duplication), single verdict reducer, pickle and error-leak paths (the parent unpickles only its own worker's result), RBAC scoping of the verdict and of the light fingerprint query, audit table only inserted into and read, `CaseResponse` constructors and the extra `verdict_summary` key, spawn re-import safety (`run_local.py` guard; nothing at import time that must not run in a worker), semaphore across event loops | CLEARED (by reading, not executed) | No defect found | None |

Owner decision on the demo script: the reviewer doubted that enabling the workers in `scripts/demo_backend.ps1` was authorised. It was: the owner approved it ("GO AHEAD APPROVED") after the question about enabling it.

Planned tests for the gaps the reviewer listed (none written yet): the verdict is kept on the close, update and transfer responses; cancelling `run_deterministic` mid-job; an initializer failure over N requests; a hung job and shutdown; a badge with the truncation flag shows visible text; a case with 26 or more incidents where the unstored incident is the worst; changing the worker setting after the pool exists.

What the reviewer could not verify: pytest was not run, the live application was not run, the PostgreSQL execution of the verdict JSON-path read was not run, and real Windows spawn behaviour was not exercised. Everything marked CLEARED rests on reading the code only. Findings 2 to 7 are risks inferred from the code, not observed failures.

---

## 20. Result of Proposal A, the column-only evidence-changed check (2026-11-26)

Implemented (uncommitted) in `multisource_investigation_service.py`: a shared `fingerprint_from_pairs` function, a column-only `_load_fingerprint_pairs` query (event id and raw SHA-256 only, outer join, de-duplicated by event id), used for the evidence-changed re-check after the analysis, the stale check in `get_section`, `review` and `export_report`. The first evidence load (needed for the analysis inputs) is unchanged (Proposal A2 is still open). Verification: 17 new tests (old versus new fingerprint equal on several shapes, sensitivity to added, removed and re-hashed evidence, the evidence-changed protection still returns 409 with nothing stored, `_load_rows` runs once per investigation and never in section, review or export reads, the query selects two columns and creates no ORM entities); full backend unit suite 4,043 passed, 2 skipped, 1 xfailed, 0 failed; integration without live services 85 passed; frontend 312 of 312. Not run: PostgreSQL-marked and Ollama-marked tests.

Benchmark: two passes with the worker on after the change (`wk3_Q1_light_check_on`, `wk3_Q2_light_check_on`, three repeats each) against the two earlier worker-on passes (`wk2_P1_workers_on`, `wk2_P2_workers_on`, also three repeats each). The earlier passes ran hours earlier on the same code without this change, so the comparison is not a same-session interleave; drift cannot be excluded. Poll rate is the corrected metric of section 15 (relative to the same run's idle rate). Medians; worst values over all repeats.

| Scenario | Before (P1+P2) | After (Q1+Q2) |
|---|---|---|
| Evidence loads through the ORM per investigation (instrumented count over 18 investigations) | 36 | 18 |
| Median time of one ORM load | 130.6 ms | 135.1 ms (unchanged, as expected) |
| Investigation, 1,000 records: duration, poll rate, worst health delay, 95th percentile, worst DB-check delay (auth-only, cases) | 2.41 s, 86% (worst 85%), 247 ms, 86 ms, 347 and 416 ms | 2.30 s, 91% (worst 88%), 151 ms, 57 ms, 161 and 205 ms |
| Investigation, 500 records: duration, poll rate, worst health delay, worst DB-check delay | 1.48 s, 83% (worst 72%), 130 ms, 213 and 242 ms | 1.10 s, 80% (worst 80%), 50 ms, 111 and 148 ms |
| Two investigations of 500: poll rate, worst health delay, worst DB-check delay | 94%, 123 ms, 163 and 236 ms | 92%, 140 ms, 172 and 203 ms |
| Ingestion during a 1,000 investigation: poll rate, worst health delay, worst DB-check delay | 86%, 135 ms, 240 and 282 ms | 84%, 238 ms, 285 and 323 ms |
| Server process CPU, 1,000 records (median) | 0.99 s | 0.94 s |

Correctness in both passes: result digests identical across repeats at 500 and 1,000; 400 of 400 concurrent alerts stored; the duplicate storm stored exactly 100 of 800; all statuses 200 or 201.

Reading: the second ORM load per investigation is gone (36 to 18) and the 1,000-record investigation improved on the poll rate (86% to 91%), the worst health delay (247 to 151 ms) and the worst database-check delay (347 and 416 to 161 and 205 ms); the unexplained slow repeat of the earlier worker-on pass (section 13, finding 3) did not recur in these two passes, which supports (but does not prove) a background-load cause. The cost of one ORM load did not change, so the remaining server-side cost is the first load, about 135 ms for 1,000 records (up to 800 ms under load), plus the benchmark's own pollers. Ingestion scenarios and two parallel investigations are unchanged within noise. Against the section 7 criteria for investigations with the worker on: the 90% poll-rate criterion is met for 1,000 records (91%) and two parallel investigations (92%) and not for 500 records (80%, a short 1.1 s scenario where the 0.8 s of surrounding polling weighs more) or ingestion during an investigation (84%); the worst health delay of at most 250 ms is met everywhere (151, 50, 140 and 238 ms, with the idle noise floor of section 15 in mind); the database-check limit of 300 ms is met everywhere except the cases check during ingestion (323 ms); duration is within 1.25 times the setting-off run in every scenario; correctness holds. **The issue remains OPEN**: the criteria are met for large single investigations on this laptop with the worker on and the LLM off, but not for every scenario, two passes are few, and the ingestion path is a separate remaining target (section 17.2).

Open items from this step: Proposal A2 (read the first evidence load through Core instead of ORM entities, estimated 105 ms less per 1,000 records at idle; needs a decision because the row order feeds the analysis); the ingestion proposals of section 17.2; the findings of section 19 (fixes in progress at that time; see section 21 for the result).

---

## 21. Fixes for the review findings and live verification (2026-11-26)

The findings of section 19 were acted on. The statements "not fixed" and "planned" in section 19 describe the state when the review was written; this section gives the state afterwards.

| Finding | Status | What changed | How verified |
|---|---|---|---|
| 1. Verdict lost after close, update or transfer; header badge stale after an investigation | FIXED | Backend: `case_service.py` `update_case_metadata`, `transfer_lead` and `close_case` now return the stored verdict through the same read as the detail path. Frontend: the badge keeps a shown verdict when a response lacks the fields (pure helper `mergeCaseVerdict`; a null verdict from the server is accepted as a real "not assessed"); `MultiSourcePanel` has an optional `onInvestigationChanged` callback, called after a stored run or an AI run; the workspace re-fetches the case in place without a loading screen | 16 new backend tests (`test_case_verdict_write_paths.py`); with the three lines removed, 9 of the 16 fail. 7 new frontend tests (319 of 319 pass). Live on real PostgreSQL with the worker on (scratch database): a new case has no verdict; after an investigation the detail response, the metadata update response, the list row, the lead-transfer response and the close response (status closed) all show `limited` under `suff-v5`. In a real headless browser the header badge changed from "Not assessed" to "Limited" right after Start multi-source investigation, with no reload and no console errors (the two 404 requests seen are the panel asking for a stored investigation before the first run, existing behaviour) |
| 2. Hung job | FIXED | `analysis_executor.py`: setting `ANALYSIS_WORKER_TIMEOUT_SECONDS` (default 300, range 1 to 3600). On timeout the worker processes are killed (through a private CPython attribute, noted in a comment), the pool is discarded, a cool-down starts, one warning is logged and `AnalysisWorkerError('analysis timed out')` is raised (the generic 500; there is no thread fallback). With a pool larger than 1, a timeout also kills that pool's other in-flight jobs, which then fall back in process | Tests in `test_analysis_executor_hardening.py` (8 new tests for findings 2, 3 and 7 together) |
| 3. Start-up failure storm | FIXED | Setting `ANALYSIS_WORKER_COOLDOWN_SECONDS` (default 30, range 0 to 3600). After a pool failure (broken pool, spawn error, failed pre-warm, timeout), requests run in process without touching a pool until the cool-down ends, then one fresh pool is built. A value of 0 reproduces the old behaviour | Same 8 new tests |
| 4. Cancellation | FIXED (documentation) | Module docstring and records corrected: a cancelled request releases the semaphore while the worker finishes and its result is discarded. The code behaviour is unchanged; bounding queued work is still not decided | Read against the corrected text only |
| 5. Badge covers at most 25 incidents | FIXED (frontend) | The truncation is shown as visible text, such as "Limited (partial)", plus an `aria-label` and a title | Frontend tests (part of the 319 of 319) |
| 6. Missing severity counts as informational downstream | OPEN | Unchanged. It remains a disclosed limitation | None; see `Panel_Criticism_Validation.md` |
| 7. Minor items | PARTLY CHANGED | `shutdown_pool` now loops until no pool remains. A request that obtained the pool just before shutdown would still get a `RuntimeError` from submit (existed before, not changed) | Same 8 new tests |

Test totals after all fixes: backend unit 4,067 passed, 2 skipped, 1 xfailed, 0 failed; integration without live services 85 passed, 39 deselected; frontend 319 of 319; production build succeeds. Not run: PostgreSQL-marked and Ollama-marked tests. The demo stack was being restarted to load this code when this section was written.

What is still not verified: no crash caused by the analysis code itself inside a worker was provoked. The failure handling was tested as follows: the crash fallback by terminating a real spawned worker process from the test (so the fallback and the rebuilt pool ran against a genuinely dead worker); the start-up-failure cool-down with a stub pool that raises a broken-pool error; and the job deadline with a real pool running a sleeping stand-in job (a real analysis can finish faster than the one-second minimum deadline). No multi-hour run was made, so slow resource growth over many hours is unknown. The lead-transfer path was verified live only once. The PostgreSQL-marked test suite was not run (the live check used a scratch database by hand, which is not the same as the suite). Finding 6 is still open, and whether published evaluation scores need recomputing after the adapter change is still unchecked.

---

## 22. Evidence-load change A2, chunked ingestion and the garbage-collection finding (2026-11-26)

This section records three follow-up changes (all uncommitted), the measurements behind them, an independent review, and what is not verified. They are separate from the worker-process decision of ADR-018: chunked ingestion and the garbage-collection setting are not part of that ADR.

### 22.1 What changed

1. **Proposal A2 (evidence inputs through one column-only query).** `MultiSourceInvestigationService._load_inputs` now returns the records, digests, keys and fingerprint pairs from one Core select (event id, raw payload, SHA-256). The ordering is the same as the earlier ORM load (event timestamp ascending, then id ascending; the event timestamp is NOT NULL, so NULL ordering cannot arise), with an outer join and de-duplication by event id. `_start_locked` no longer calls `_load_rows`. 17 new tests. Three existing tests were retargeted only at their injection point, with assertions unchanged: the fingerprint light-check count test, the R08 read-failure test in `test_reliability_matrix.py`, and the executor service failing-analysis test (which now drives the failure through the data, records `None`).
2. **Chunked ingestion.** `AlertIngestionService` has a chunked fast path in front of the old per-alert path (constructor flag `chunked=True`). The old path is kept as the fallback and as the reference. Phase 1 does the pure steps for a chunk with no database access. Phase 2 does one savepoint and three flushes per chunk. Any chunk failure rolls the savepoint back and re-processes that chunk through the old per-alert code. The list membership test that was O(n squared) is now a set plus an ordered list. Rejected records never reach the database. 40 new equivalence tests (SQLite; 36 at first, 4 added after the review).
3. **Chunk size and a garbage-collection setting.** `FAST_CHUNK_SIZE` is set to 20. A new opt-in setting `GC_FREEZE_AT_STARTUP` (default False) runs `gc.collect()` and then `gc.freeze()` once after start-up and logs the frozen count. It never blocks start-up; a failure only logs a warning.

### 22.2 Ingestion on real PostgreSQL (in process, 1,000 alerts, same session)

| Variant | Wall time | CPU | SQL statements per alert | Worst event-loop lag (5 ms ticker) |
|---|---|---|---|---|
| Per-alert path (old) | 11.2 to 11.6 s | 5.7 to 6.3 s | 5.0 | usually 11 ms |
| Chunk 50 | 1.9 to 2.3 s | 1.3 to 1.6 s | 0.1 | 57 to 89 ms (89 ms in the run used for the garbage-collection comparison) |
| Chunk 50, garbage collection disabled (diagnostic only) | 1.75 to 1.99 s | 1.12 to 1.16 s | 0.1 | 27 to 42 ms |
| Chunk 50 with `gc.freeze()` | 1.80 to 2.07 s | 1.17 to 1.28 s | 0.1 | 42 to 57 ms |
| Chunk 20 with `gc.freeze()` | 2.1 to 2.3 s | 1.38 to 1.42 s | 0.25 | 11 to 27 ms |
| Chunk 10 with `gc.freeze()` | 2.7 to 2.9 s | 1.50 to 1.95 s | 0.5 | 11 to 27 ms |

All 1,000 alerts were stored in the runs. Database integrity after about 6,000 alerts: 43,212 raw rows, 43,212 distinct hashes, no orphaned events, raw records or entities.

### 22.3 The tuning story in plain words

The server benchmark showed that chunked ingestion was much cheaper in total, but the worst latency seen while ingesting during an investigation got worse, not better (table in 22.5). The first explanation was chunk size: a bigger chunk holds the event loop for longer. A sweep did not support that. The worst lag at chunk 10, 20 and 50 was 57 to 89 ms regardless of size, whereas the per-alert path usually showed 11 ms. Disabling garbage collection cut the chunk-50 lag from 89 ms to 27 to 42 ms, so Python full collections account for about half of the stall. Calling `gc.freeze()` once after start-up (which moves the objects that exist at that point out of later collections) gave: chunk 50, 42 to 57 ms; chunk 20, 11 to 27 ms with a wall time of 2.1 to 2.3 s; chunk 10, 11 to 27 ms with a wall time of 2.7 to 2.9 s. Chunk 20 was chosen as the smaller stall without the longer wall time of chunk 10. The asyncio slow-callback diagnostic was tried and was not informative: it names only the outermost task, and debug mode distorts timing (the per-alert run took 31 s). The freeze is opt-in and off by default because its effect on the real server is not yet measured (see 22.7).

### 22.4 Independent review of the chunked ingestion and A2

A read-only review, by reading; nothing was executed. No confirmed defect. Nothing outside the chunk savepoint is mutated before a failure; a failed flush's savepoint rollback expunges the chunk's new objects; one raw row per hash remains after a concurrent writer; `alert_ids` and the counters keep input order; the `_load_inputs` ordering is identical to the old load. Plausible risks it raised and what happened:

- The synchronous stall per chunk grows with chunk size: confirmed by the measurements above.
- The fallback warning lacked the batch id: fixed. It now logs the batch id, the chunk range and the exception class name only.
- Repeated fallbacks can cost up to about 1 to 2 times the old path when a concurrent writer makes every chunk fail once: not changed; accepted as a limit.
- Test gaps it listed: failure after the real second and third flush (added, parametrised N=2 and N=3), fallback logging (added), commit failure parity (added); a PostgreSQL two-session race and `_load_inputs` equivalence on PostgreSQL (see 22.5 and 22.7).

### 22.5 Race script and server benchmark

The PostgreSQL two-session race is covered by `backend/scripts/verify_ingest_race_pg.py` (scratch database only), not by a postgres-marked test. Results at chunk 50 and then chunk 20:

| Scenario | Result |
|---|---|
| S1 overlap race | B stored 0 and skipped 50; one row per hash; chunked equals per-alert |
| S2 partial overlap | 25 stored and 25 skipped; one row per hash |
| S3 reversed order (a deliberate lock cycle between two sessions) | Chunked: B's chunk fell back and counted the duplicates with no error. Per-alert: the deadlock victim batch reported an error. Both end with exactly one row per hash and no orphans |
| S4 chunk boundary | 119 stored, 1 skipped; chunked equals per-alert |
| S5 integrity | No orphans or duplicates |

Overall PASS at chunk 50 and at chunk 20 (6 fallbacks at chunk 20). The first S3 chunked run timed out because the script held session A's locks until after both batches had finished, while B (retrying after the deadlock) waited on A's uncommitted row. The script was changed so that A commits as soon as its own batch ends, which is what a real batch does. This is a script correction, not a change of the service; the rerun passed.

Server benchmark with all changes at chunk 50, worker on (passes R1 and R2, three repeats each) against the previous passes Q1 and Q2 of section 20 (corrected poll-rate metric, medians; worst values in brackets). Not a same-session interleave; drift cannot be excluded.

| Scenario | Before (Q1, Q2) | After (R1, R2) |
|---|---|---|
| Investigation, 1,000 records: poll rate | 91% (worst 88%) | 94% (worst 92%) |
| Investigation, 1,000 records: worst health delay | 151 ms | 46 ms |
| Investigation, 1,000 records: worst database-check delay (auth-only, cases) | 161 and 205 ms | 63 and 76 ms |
| Two investigations: poll rate, worst health delay | 92%, 140 ms | 96%, 20 ms |
| Investigation, 500 records: poll rate | 80% | 82% |
| Ingestion during a 1,000 investigation: duration | 4.01 s | 3.19 s |
| Ingestion during a 1,000 investigation: server CPU | 3.55 s | 1.46 s |
| Ingestion during a 1,000 investigation: 95th percentile health delay | 39 ms | 219 ms |
| Ingestion during a 1,000 investigation: worst health delay | 238 ms | 301 ms |
| Ingestion during a 1,000 investigation: worst database-check delay | 285 and 323 ms | 606 and 719 ms |
| Ingestion during a 1,000 investigation: poll rate | not restated here (84% in section 20) | 84% (worst 81%) |
| Duplicate storm, 8 clients x 100 alerts: poll rate | 88% | 81% |
| Duplicate storm: 95th percentile health delay | 88 ms | 134 ms |
| Duplicate storm: alerts stored | exactly 100 of 800 | exactly 100 of 800 |

Correctness in R1 and R2: result digests identical across repeats, 400 of 400 concurrent alerts stored, statuses 200 or 201. The server log showed 14 chunk fallbacks in pass R1 in the duplicate storm, so the race path was exercised on PostgreSQL.

Reading: investigations are now clearly better on every health and database-check measure (the 90% poll-rate criterion of section 7 is met for 1,000 records and for two investigations, and still not for 500 records at 82%). Ingestion during an investigation uses less than half the server CPU and finishes sooner, but its tail latency is worse (95th percentile health delay 39 to 219 ms, worst database-check delay up to 719 ms against the 300 ms limit). That is the stall described in 22.3, and it is the reason for chunk 20 and the freeze setting. The R1 and R2 passes ran at chunk 50, before that change, so they do not show the effect of chunk 20. **The issue remains OPEN.**

### 22.6 Test totals (at chunk 20)

Backend unit 4,129 passed, 2 skipped, 1 xfailed, 0 failed; integration without live services 85 passed, 39 deselected; frontend 319 of 319. Not run: PostgreSQL-marked and Ollama-marked test suites.

### 22.7 Not verified

- The PostgreSQL-marked test suite was not run. The race was checked by a script against a scratch database, which is not the same as a test in the suite.
- `_load_inputs` equivalence on PostgreSQL is covered only by the benchmark digests (identical across repeats), not by a dedicated test.
- All measurements are from one laptop with synthetic data, with other processes possibly running. The in-process tuning numbers come from a few runs each, not a statistical sample.
- The benefit of `gc.freeze()` on the real server is not yet measured. The in-process figures above are not a server result, and the server passes R1 and R2 ran at chunk 50 without the freeze.
- Memory effects of the freeze and long-running behaviour are unknown.
- The independent review was by reading only.

### 22.8 Server benchmark of chunk 20 with the freeze off and on

Server benchmark of chunk 20 with the worker on, garbage-collection freeze off (`wk5_S1_chunk20_freeze_off`) and on (`wk5_S2_chunk20_freeze_on`), one pass each (three repeats for single investigations, one for the other scenarios), beside the chunk-50 passes R1 and R2. Poll rate is relative to the same run's idle rate. Values: poll rate; 95th percentile and worst health delay; worst DB-check delay (auth-only, cases).

| Scenario | Chunk 50 (R1+R2) | Chunk 20, no freeze (S1) | Chunk 20, freeze (S2) |
|---|---|---|---|
| Investigation, 500 | 82%; 38 / 72 ms; 86, 131 ms | 77%; 19 / 19 ms; 48, 68 ms | 77%; 11 / 33 ms; 56, 74 ms |
| Investigation, 1,000 | 94%; 20 / 46 ms; 63, 76 ms | 89%; 24 / 105 ms; 80, 126 ms | 100%; 13 / 47 ms; 57, 75 ms |
| Two investigations of 500 | 96%; 15 / 20 ms; 38, 53 ms | 91%; 14 / 32 ms; 127, 146 ms | 100%; 9 / 18 ms; 38, 44 ms |
| Ingestion during a 1,000 investigation | 84%; 219 / 301 ms; 606, 719 ms | 78%; 171 / 200 ms; 487, 583 ms | 95%; 98 / 111 ms; 291, 364 ms |
| Duplicate storm (ingestion only) | 81%; 134 / 175 ms; 412, 489 ms | 69%; 139 / 239 ms; 253, 409 ms | 85%; 83 / 94 ms; 230, 220 ms |

Correctness in S1 and S2: result digests identical across repeats; 400 of 400 concurrent alerts stored; the duplicate storm stored exactly 100 of 800; statuses 200 or 201; the S2 server log confirms the freeze ran.

Limits of this comparison: S1 ran in a visibly slower period (server CPU for a 1,000-record investigation 1.27 s against 0.71 s in R1 and R2 and 0.88 s in S2, although the change does not touch that path), so S1 against S2 overstates what the freeze does. One pass per setting is thin. The controlled in-process measurement above is the stronger evidence that the freeze shortens stalls.

Criteria with chunk 20 and the freeze (S2), investigations and ingestion during an investigation: worst health delay at most 250 ms is met in every scenario (111 ms at most); poll rate of at least 90% is met for 1,000 records, two parallel investigations and ingestion during an investigation, and not for 500 records (77%; this short scenario reads 77 to 82% in every configuration, which points at the metric rather than the server, not verified) or for the ingestion-only duplicate storm (85%); the 300 ms database-check limit is met everywhere except the cases check during ingestion (364 ms). The issue remains OPEN: not every criterion is met and the passes are few.
