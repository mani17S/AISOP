/**
 * Conservative sweep of STALE throwaway Chrome profiles left by a crashed or killed cdp_driver run (Phase 2.6).
 *
 * Safety model (every rule is a refusal; when in doubt the directory is kept):
 * - Operates ONLY inside one dedicated root: `<outDir>/cdp-profiles` (exact name), which must be a real directory,
 *   not a symlink or junction, whose parent is the driver's output folder. Nothing outside it is ever touched.
 * - Considers ONLY direct children that are real directories named exactly `chrome-profile-cdp-<pid>-<13-digit ms>`.
 *   Files, other names, `.sweeping` leftovers and anything unexpected are ignored.
 * - A candidate must be OLD: both the timestamp in its name and its directory mtime older than `minAgeMs`
 *   (default 24 h). A name timestamp in the future is refused.
 * - A candidate must be INACTIVE: its owner pid is not alive (a live or unknowable pid, including pid reuse, keeps it),
 *   and it must be claimable: an atomic rename to `<name>.sweeping` must succeed (on Windows this fails while Chrome or
 *   any process holds files open, so a locked profile is never deleted).
 * - Reparse points are never followed: a candidate that is itself a symlink/junction, resolves outside the root, or
 *   contains any symlink/junction anywhere inside is skipped, not deleted.
 * - At most `maxRemovals` directories are removed per call. `dryRun` removes nothing.
 * - Never throws; returns `{ removed, skipped }` with a reason for every skip.
 */
import { lstatSync, readdirSync, realpathSync, renameSync, rmSync } from 'node:fs';
import { basename, dirname, join, resolve, sep } from 'node:path';

export const PROFILE_ROOT_NAME = 'cdp-profiles';
export const PROFILE_NAME = /^chrome-profile-cdp-(\d{1,10})-(\d{13})$/;
export const DEFAULT_MIN_AGE_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_MAX_REMOVALS = 20;
const MAX_TREE_ENTRIES = 20000;

export function pidIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e?.code === 'EPERM'; // exists but not ours: alive. ESRCH: gone.
  }
}

function containsReparsePoint(dir) {
  const stack = [dir];
  let seen = 0;
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try { entries = readdirSync(current, { withFileTypes: true }); } catch { return true; } // unreadable: refuse
    for (const entry of entries) {
      if (++seen > MAX_TREE_ENTRIES) return true; // unexpectedly huge: refuse
      const full = join(current, entry.name);
      let st;
      try { st = lstatSync(full); } catch { return true; }
      if (st.isSymbolicLink()) return true;
      if (st.isDirectory()) stack.push(full);
    }
  }
  return false;
}

/**
 * @param {string} profileRoot absolute path of `<outDir>/cdp-profiles`
 * @param {{ outDir: string, now?: number, minAgeMs?: number, maxRemovals?: number, dryRun?: boolean, isPidAlive?: (pid:number)=>boolean }} opts
 */
export function sweepStaleProfiles(profileRoot, opts) {
  const result = { removed: [], skipped: [] };
  const skip = (name, reason) => result.skipped.push({ name, reason });
  try {
    const now = opts.now ?? Date.now();
    const minAgeMs = opts.minAgeMs ?? DEFAULT_MIN_AGE_MS;
    const maxRemovals = opts.maxRemovals ?? DEFAULT_MAX_REMOVALS;
    const alive = opts.isPidAlive ?? pidIsAlive;
    const root = resolve(profileRoot);
    const out = resolve(opts.outDir);

    if (basename(root) !== PROFILE_ROOT_NAME || dirname(root) !== out) { skip('(root)', 'root is not <outDir>/cdp-profiles'); return result; }
    let rootStat;
    try { rootStat = lstatSync(root); } catch { return result; } // nothing to sweep
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) { skip('(root)', 'root is a link or not a directory'); return result; }
    const realRoot = realpathSync(root);

    for (const entry of readdirSync(root, { withFileTypes: true })) {
      const name = entry.name;
      const match = PROFILE_NAME.exec(name);
      if (!match) { skip(name, 'unexpected name'); continue; }
      const full = join(root, name);
      let st;
      try { st = lstatSync(full); } catch { skip(name, 'vanished'); continue; }
      if (st.isSymbolicLink()) { skip(name, 'is a symlink or junction'); continue; }
      if (!st.isDirectory()) { skip(name, 'not a directory'); continue; }
      let realFull;
      try { realFull = realpathSync(full); } catch { skip(name, 'unresolvable'); continue; }
      if (!realFull.startsWith(realRoot + sep) || dirname(realFull) !== realRoot) { skip(name, 'resolves outside the root'); continue; }

      const pid = Number(match[1]);
      const created = Number(match[2]);
      if (created > now) { skip(name, 'timestamp in the future'); continue; }
      if (now - created < minAgeMs || now - st.mtimeMs < minAgeMs) { skip(name, 'too recent'); continue; }
      if (alive(pid)) { skip(name, 'owner process is alive or unknowable'); continue; }
      if (containsReparsePoint(full)) { skip(name, 'contains a symlink or junction (or is unreadable or oversized)'); continue; }
      if (result.removed.length >= maxRemovals) { skip(name, 'removal cap reached'); continue; }
      if (opts.dryRun) { skip(name, 'dry run (would remove)'); continue; }

      // Atomic claim: fails on Windows while any process holds a file in the directory open.
      const claimed = `${full}.sweeping`;
      try { renameSync(full, claimed); } catch { skip(name, 'locked or in use (claim failed)'); continue; }
      try {
        rmSync(claimed, { recursive: true, force: true });
        result.removed.push(name);
      } catch {
        skip(name, 'claimed but could not be fully removed (left as .sweeping)');
      }
    }
  } catch (e) {
    skip('(sweep)', `aborted safely: ${String(e?.code ?? e).slice(0, 60)}`);
  }
  return result;
}
