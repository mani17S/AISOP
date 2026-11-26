# ADR-018: Analysis Worker Process for Large Multi-Source Investigations

| Field | Value |
|---|---|
| **ID** | ADR-018 |
| **Status** | **PROPOSED.** On 2026-11-26 the project owner approved building the code behind a default-off setting (`ANALYSIS_WORKER_PROCESSES=0`). This record is not adopted: adoption waits for the owner to accept the benchmark evidence with the setting enabled (the benchmark has since been run, see the Evidence section; the criteria are only partly met). |
| **Date** | 2026-11-26 (proposed) |
| **Relates to** | ADR-008 (sufficiency gate), ADR-010 section 3C (background jobs deferred), ADR-011 (evidence domains), `docs/05_Backend/Investigation_Responsiveness_Profiling_2026-11-25.md` (sections 2, 5, 9, 10, 11) |
| **Does not change** | The sufficiency gate and its single entry point, the deterministic path and fallback, claim verification, the audit-row persistence of ADR-010, the API response shape, or the local-first default |

## Context
A panel criticism said the application crashes or becomes unresponsive when several alerts or a large investigation are handled. Profiling on 2026-11-25 and 2026-11-26 (one laptop, 12 logical CPUs, Windows, Python 3.12.0, one uvicorn process, PostgreSQL 17.11 in Docker, LLM off, synthetic data) found no crash and no lost data, but a real responsiveness problem. A 1,000-record investigation keeps the single server process mostly unresponsive for about 3 seconds: during a 3.5 s run the health check received 8 to 11 of 35 expected polls, with a worst delay of 745 to 1393 ms, and database checks were delayed 1.3 to 2.9 s.

The dominant cause is CPU-bound analysis competing with the event loop for the Python GIL (confidence High in the profiling record). The evidence:
- The analysis thread uses about 80 to 90% of one core (CPU seconds roughly equal wall seconds) while the health check receives only 23 to 31% of its expected polls.
- Switch-interval experiment: cutting the thread switch interval from 5 ms to 0.5 ms raised liveness polls to about 78% of expected and cut the worst delay to about 0.19 to 0.20 s, which is what the GIL explanation predicts.
- Database locks and execution are not the cause: 0 lock waiters, at most 1 to 2 active sessions, and PostgreSQL executes the verdict queries in under 1 ms.
- Result serialization (2.5 ms at most) and garbage collection (longest pause 159 to 171 ms) do not explain multi-second stalls.

The two algorithmic optimisations done first (lookup-table reuse in `analyze()` and the compact `verdict_summary`) were measured on 2026-11-26. For a 1,000-record investigation, duration fell from 3.54 s to 2.67 s, but liveness polls received rose only from 30% to 35%, the worst liveness delay fell from 1.39 s to 1.12 s and the worst cases database-check delay from 2.93 s to 2.65 s. The responsiveness criteria (section "Acceptance criteria") are not met, so panel criticism 5 stays open.

A spike (`backend/scripts/spike_process_worker.py`, measurement only, no application code changed, no database, no HTTP, no LLM) ran the application's own `analyze` and `build_payload` in one spawned worker process and compared it with a worker thread. For 1,000 records, worst loop lag was 27 ms in process mode against 245 ms in thread mode; wall time was 1.91 s against 1.86 s.

## Decision (proposed)
Add an optional, bounded pool of worker processes that runs the deterministic analysis and result building (`analyze` plus `build_payload`) for the deterministic path of `MultiSourceInvestigationService._start_locked`.
- Standard library only: `concurrent.futures.ProcessPoolExecutor` with the `spawn` start method (the only method that works on Windows). No Celery, no Redis, no queue, no new service.
- New setting `ANALYSIS_WORKER_PROCESSES`, **default 0 (off)**. At 0 the behaviour is exactly today's `asyncio.to_thread` path. Proposed pool size when enabled: 1 or 2.
- The worker returns only the JSON-safe payload dictionary (about 0.6 MB), not the full result objects.
- Staying in the server process, unchanged: the model-assisted path (`use_llm=true`, which needs the provider and result objects), the evidence fingerprint, the per-case lock, the evidence-changed check, the audit write and the response.
- If a worker fails or the pool breaks, that request falls back to the in-process path and the pool is rebuilt, so no investigation is lost. The fallback returns the same payload by the same code.
- The pool is started lazily or at startup with a warm-up initializer, and shut down with the application. The pool size bounds concurrency: extra investigations queue.

## Constraints this decision must respect
1. One evidence-sufficiency gate. The worker calls the same `analyze`, which already contains the single gate. The worker never calls a model, and no second gate is added.
2. The deterministic path stays independent of any LLM.
3. Byte-identical results: the process path payload must equal the thread path payload byte for byte.
4. No lost and no duplicate records: ingestion, the duplicate-storm behaviour and the one-audit-row-per-run rule are unchanged.
5. Per-case isolation: the existing per-case lock stays in the server process. It is held while the request waits for the worker. If the request is cancelled (for example a client disconnect), the lock and the semaphore are released while the worker keeps running (see Consequences, cancellation limits; corrected after the 2026-11-26 review).
6. Local-first: nothing leaves the machine; no network, no external service.
7. Windows: spawn must re-import the application, so settings and logging must work in the child (the environment is passed on; to be verified in tests).
8. Evidence text stays untrusted input: only the already-bounded records and payloads cross the process boundary, as data, never executed.

## Alternatives considered
| Option | Measured or stated reason |
|---|---|
| Keep `to_thread` and add the algorithmic fixes | Done. 25% less time at 1,000 records (3.54 s to 2.67 s) but the responsiveness criteria are still unmet (35% of polls against at least 90%; worst delay 1.12 s against at most 250 ms; database-check delay 2.65 s against at most 300 ms). The stall shrank only in proportion to the CPU work removed. Kept as a complement, not a fix. |
| Smaller thread switch interval | Rejected. It fixes the lag but a 1,000-record investigation takes 6.4 to 6.7 s instead of 3.5 s (about 1.8x), uses 8.8 to 9.2 CPU seconds instead of 3.5 (about 2.5x), and two parallel investigations of 500 take 16.7 s instead of 3.3 s using 36 CPU seconds (about 5x). |
| Background job with 202 and polling | Deferred, as in ADR-010 section 3C. It needs a job table (a migration) or in-memory state lost on restart, a per-job session, and the current UI reads the result from the POST response, so the UI would break. It also reduces request duration, not CPU contention. Evaluate only after this ADR. |
| Chunked incremental persistence | Rejected. The stored result is only about 0.6 MB (tens of ms to write), so there is almost no gain; it needs a new table and breaks the one-audit-row-per-run assumption. |

## Measured in the spike (2026-11-26, three repeats per size, bare asyncio loop with a 5 ms lag ticker)
| Records | Mode | Wall s (median) | Worst loop lag | Parent CPU s |
|---|---|---|---|---|
| 1,000 | thread | 1.86 | 245 ms | 1.84 |
| 1,000 | process | 1.91 | 27 ms | 0.05 |
| 2,000 | thread | 4.40 | 308 ms | 4.39 |
| 2,000 | process | 4.57 | 27 ms | 0.06 |
| 2 x 500 at once | thread | 1.79 | 323 ms | 1.80 |
| 2 x 500 at once | process (2 workers) | 0.87 | 26 ms | 0.05 |

The payload from the process path was byte-identical (canonical JSON hash) to the thread path in all 9 comparisons. Data movement was negligible: inputs 115 to 463 KB (2 to 8 ms to pickle), returned payload 280 to 729 KB (1.5 to 5 ms each way). Process-mode "ticks received" is capped near 32% only because the default Windows timer resolution (about 15.6 ms) cannot deliver a 5 ms tick.

Limits of the spike: it excludes the database, ORM loading, response writing and the LLM path, and a bare loop has far fewer awaits per request than the server. The direction and size of the effect transfer; the end-to-end figure is **to be confirmed by the benchmark** with the real server and the setting enabled.

## Consequences
- Memory: +76 to +133 MB per worker as measured in the spike (76 MB idle, 94 to 133 MB while working). The server's own peak criterion (at most 200 MB) excludes the workers.
- Start-up: 2.3 s one time per worker (spawn plus importing the application modules); a warm-up at start hides it from the first investigation.
- Duration: a single investigation is 3 to 6% longer in the spike. Two concurrent investigations finish in half the time (0.87 s against 1.79 s) because they run on separate cores. Parent CPU is near zero during analysis (0.05 s against 1.84 s at 1,000 records).
- Expected (estimate, **to be confirmed by the benchmark**): worst liveness delay in the low hundreds of milliseconds or less and at least 90% of achievable polls. The remaining delay would then come from the loop-thread database steps (two ORM loads of about 0.2 to 0.3 s each at 1,000 records), which the benchmark would expose and which are a separate change.
- Complexity: a second process, pool lifecycle, crash handling and a fallback path to keep tested.
- Cancellation limits (corrected after the independent review of 2026-11-26, which replaced an earlier statement that the per-case lock is held until the worker finishes): a running worker job cannot be cancelled; it finishes. A cancelled request (client disconnect) releases the semaphore and the per-case lock while the worker keeps running. The orphan job's result is discarded and no audit row is written for it. A retry of the same case starts a second job queued behind the first, and queued work is not bounded by the semaphore. The same new cancellation point exists on the thread path (`asyncio.to_thread` in `workflow.py`). Whether to bound queued work is not decided.
- Hung job (plausible risk found by the review; not observed). Mitigation implemented 2026-11-26: a job deadline, set by `ANALYSIS_WORKER_TIMEOUT_SECONDS` (default 300, range 1 to 3600). Without it, a hung job would hold the only worker (pool size 1), later deterministic investigations would queue behind it, and shutdown would wait forever. On timeout the worker processes are killed (through a private CPython attribute, noted in a comment in the code), the pool is discarded, a cool-down starts, one warning is logged and `AnalysisWorkerError('analysis timed out')` is raised, which the API returns as the generic 500; there is no thread fallback for a timed-out job. With a pool larger than 1, a timeout also kills that pool's other in-flight jobs, which then fall back in process. Not tested with a real hung worker on Windows.
- Worker start-up failure (plausible risk; not observed). Mitigation implemented 2026-11-26: a cool-down, set by `ANALYSIS_WORKER_COOLDOWN_SECONDS` (default 30, range 0 to 3600). Previously a worker that crashed at start-up (initializer failure) was re-spawned on every request, a spawn storm; no investigation was lost, because each request fell back to a thread. Now, after a pool failure (broken pool, spawn error, failed pre-warm or timeout), requests run in process without touching a pool until the cool-down ends, and then one fresh pool is built. A value of 0 reproduces the old behaviour.
- Minor, from the same review: `shutdown_pool` now loops until no pool remains. A request that obtained the pool just before shutdown would still get a `RuntimeError` from submit (existed before, not changed; unlikely, because uvicorn drains requests first). On Windows the first submit starts a process on the loop thread, a brief stall at start-up that the warm-up hides.
- Tests: 8 tests for the deadline, the cool-down and shutdown (`test_analysis_executor_hardening.py`). Still not written: cancelling `run_deterministic` mid-job, and changing the worker setting after the pool exists. No real Windows crash of a worker was provoked.
- Test impact: tests that monkeypatch the gate or other in-process objects do not reach a child process, so they keep using the default in-process path (setting 0). The architecture test that forbids model calls outside the gate is unaffected.
- Tests required: a differential test that the process path payload equals the thread path payload byte for byte on the same 17 datasets; error propagation (an exception in the worker surfaces as the same fail-closed error); worker-crash fallback; shutdown; the existing multi-source, reliability and adversarial suites with the setting on and off.

## Acceptance criteria for adoption
Taken from section 7 of the profiling record, from at least three repeats per scenario, with the setting enabled and interleaved with the setting off. None of these is yet shown with the setting enabled (**to be confirmed by the benchmark**).
- Responsiveness, 1,000-record investigation: liveness polls received at least 90% of expected, worst liveness delay at most 250 ms, worst auth-only and cases database-check delay at most 300 ms. The same for two parallel investigations of 500 and for ingestion during an investigation.
- Throughput: a single 1,000-record investigation no slower than 1.25x the 3.5 s baseline, two parallel 500-record investigations no slower than 1.5x the single-500 baseline time, total server CPU seconds no more than 1.25x the baseline.
- Correctness: differential test byte-identical, result digests identical across repeats, 0 lost alerts, exactly one record per duplicate, all existing suites green, per-case isolation and error handling unchanged.
- Memory: server peak at most 200 MB (plus any worker) and no growth across repeated runs.
- Evidence: the benchmark and its results are kept with the change, and the unmodified original evidence folders remain.

## Rollback
Set `ANALYSIS_WORKER_PROCESSES=0` and restart. The thread path is unchanged and remains the default, so rollback needs no migration and no data change.

## Evidence
Record: `docs/05_Backend/Investigation_Responsiveness_Profiling_2026-11-25.md`. Folders under `D:\AISOP-Backups\AISOP_LoadTest_20261125\` (names only):
- Baseline runs: `cmp2_A_default`, `cmp2_B_switch0p5ms`, `cmp2_A2_default_repeat`
- After the two optimisations: `new_N1_new_default`, `new_N2_new_default`
- Verdict lookup: `verdict_lookup_breakdown.json`, `verdict_after_new_rows.json`, `verdict_after_any_rows.json`
- Process worker spike: `spike_process_worker.json`
- Kept failed or partial attempts: `profile_run1_instrumented`, `profile_run2_instrumented`, `profile_run3_switch0p5ms`, `cmp_A_default`, `cmp_B_switch0p5ms`, `cmp_A2_default_repeat`
- Benchmark with `ANALYSIS_WORKER_PROCESSES=1` (ON, OFF, ON on the same code, three repeats each): `wk2_P1_workers_on`, `wk2_OFF3_workers_off`, `wk2_P2_workers_on`; failed first attempts kept in `_failed_first_attempt`. Results and their limits are in section 13 of the record. In summary (after a correction of the poll-rate calculation, record section 15): during a 1,000-record investigation the health-check poll rate relative to idle rose from about 30-35% to 86%, the worst health delay fell from 0.7-0.9 s to 0.12-0.25 s (the 95th percentile from 0.7-1.1 s to under 0.09 s), with no throughput penalty and about 75 MB more total memory. One of six repeats was an unexplained slow outlier (database checks 347 and 416 ms against a 300 ms limit). The "at least 90% of polls" criterion is not met for single investigations (83% and 86%) and is met only for two parallel investigations (94%); ingestion-heavy scenarios are not helped because ingestion runs in the server's event loop. The latency criteria are met in most repeats and the poll-rate criterion is not, so the criteria are only partly met; the ADR stays PROPOSED pending the owner's decision. Since then the owner approved enabling `ANALYSIS_WORKER_PROCESSES=1` in the demo backend script (the code default is still 0), and an independent read-only review on 2026-11-26 recorded further findings (record section 19); this ADR is still PROPOSED. The findings about a hung job and a start-up failure storm were then fixed (the two settings named in Consequences), as recorded in section 21 of the record.

Related follow-up changes, separate from the worker-process decision (record section 22): reading the evidence inputs through one column-only query (A2), a chunked ingestion fast path with the old per-alert path kept as fallback, and an opt-in `GC_FREEZE_AT_STARTUP` setting. They address the server's own loop-thread work and ingestion, not where the analysis runs. Chunked ingestion is not part of this ADR and does not depend on it; this ADR remains PROPOSED and decides none of them.

## What this ADR does not decide
Whether to adopt the worker process as the default, whether to move to a background job with polling, or how to reduce the loop-thread database steps. Each needs its own measurement and an owner decision.
