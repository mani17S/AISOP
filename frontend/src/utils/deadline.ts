/**
 * Run a slow task (the optional AI explanation) with a hard deadline and a cancel handle.
 *
 * The result is always one of four outcomes, so the screen can say exactly what happened and the deterministic result,
 * which is shown before this runs, is never affected: done, timeout, cancelled, failed. Nothing is retried here.
 * Aborting stops the browser waiting; the server finishes or times out the run on its own.
 */

export type DeadlineOutcome<T> =
  | { kind: 'done'; value: T }
  | { kind: 'timeout' }
  | { kind: 'cancelled' }
  | { kind: 'failed'; message: string };

export interface DeadlineHandle<T> {
  /** Resolves with the outcome; never rejects. */
  result: Promise<DeadlineOutcome<T>>;
  /** Stop waiting. Ignored once the task has finished. */
  cancel: () => void;
}

export function runWithDeadline<T>(task: (signal: AbortSignal) => Promise<T>, timeoutMs: number): DeadlineHandle<T> {
  const controller = new AbortController();
  let reason: 'timeout' | 'cancelled' | null = null;
  let settled = false;
  const timer = setTimeout(() => {
    if (settled) return;
    reason = 'timeout';
    controller.abort();
  }, timeoutMs);

  const result = new Promise<DeadlineOutcome<T>>((resolve) => {
    const finish = (o: DeadlineOutcome<T>) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(o);
    };
    // An abort wins even if the task never settles on its own.
    controller.signal.addEventListener('abort', () => finish({ kind: reason ?? 'cancelled' }));
    task(controller.signal).then(
      (value) => finish(reason ? { kind: reason } : { kind: 'done', value }),
      (e: unknown) => finish(reason ? { kind: reason } : { kind: 'failed', message: e instanceof Error ? e.message : 'The task could not be completed.' }),
    );
  });

  return {
    result,
    cancel: () => {
      if (settled) return;
      reason = 'cancelled';
      controller.abort();
    },
  };
}
