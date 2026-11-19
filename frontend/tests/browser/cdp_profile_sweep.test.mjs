/**
 * Negative and positive tests for the stale-profile sweep. Plain node:test, no dependencies, no browser.
 * Temporary files go under SWEEP_TEST_BASE (set it to a folder under D:\AISOP-Backups) or the OS temp folder.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, openSync, closeSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { sweepStaleProfiles, PROFILE_ROOT_NAME, DEFAULT_MIN_AGE_MS } from './cdp_profile_sweep.mjs';

const DAY = DEFAULT_MIN_AGE_MS;
const NOW = Date.parse('2026-11-13T12:00:00Z');
const base = mkdtempSync(join(process.env.SWEEP_TEST_BASE || tmpdir(), 'sweep-test-'));
const DEAD_PID = 2147483000; // practically never a live pid
const dead = () => false;

let counter = 0;
function fresh() {
  const out = join(base, `out${++counter}`);
  const root = join(out, PROFILE_ROOT_NAME);
  mkdirSync(root, { recursive: true });
  return { out, root };
}
function plant(root, pid, ageMs, { mtimeAgeMs = ageMs } = {}) {
  const name = `chrome-profile-cdp-${pid}-${NOW - ageMs}`;
  const dir = join(root, name);
  mkdirSync(join(dir, 'Default'), { recursive: true });
  writeFileSync(join(dir, 'Default', 'Preferences'), '{}');
  const t = new Date(NOW - mtimeAgeMs);
  utimesSync(dir, t, t);
  return { name, dir };
}
const sweep = (root, out, extra = {}) => sweepStaleProfiles(root, { outDir: out, now: NOW, isPidAlive: dead, ...extra });

after(() => { try { rmSync(base, { recursive: true, force: true }); } catch { /* best effort */ } });

describe('stale profile sweep: positive', () => {
  it('removes an old profile whose owner process is gone', () => {
    const { out, root } = fresh();
    const p = plant(root, DEAD_PID, 2 * DAY);
    const r = sweep(root, out);
    assert.deepStrictEqual(r.removed, [p.name]);
    assert.ok(!existsSync(p.dir) && !existsSync(p.dir + '.sweeping'));
  });

  it('dry run removes nothing and says so', () => {
    const { out, root } = fresh();
    const p = plant(root, DEAD_PID, 2 * DAY);
    const r = sweep(root, out, { dryRun: true });
    assert.deepStrictEqual(r.removed, []);
    assert.ok(existsSync(p.dir));
    assert.ok(r.skipped.some((s) => s.reason.startsWith('dry run')));
  });

  it('honours the per-call removal cap', () => {
    const { out, root } = fresh();
    for (let i = 0; i < 5; i++) plant(root, DEAD_PID + i, 2 * DAY + i);
    const r = sweep(root, out, { maxRemovals: 2 });
    assert.strictEqual(r.removed.length, 2);
    assert.strictEqual(r.skipped.filter((s) => s.reason === 'removal cap reached').length, 3);
  });
});

describe('stale profile sweep: negative (nothing may be deleted)', () => {
  it('keeps a recent profile (young by name or by mtime)', () => {
    const { out, root } = fresh();
    const young = plant(root, DEAD_PID, DAY / 2);
    const oldNameYoungMtime = plant(root, DEAD_PID + 1, 3 * DAY, { mtimeAgeMs: DAY / 4 });
    const r = sweep(root, out);
    assert.deepStrictEqual(r.removed, []);
    assert.ok(existsSync(young.dir) && existsSync(oldNameYoungMtime.dir));
  });

  it('keeps an old profile whose owner pid is alive (active profile)', () => {
    const { out, root } = fresh();
    const p = plant(root, process.pid, 5 * DAY);
    const r = sweepStaleProfiles(root, { outDir: out, now: NOW }); // real pid check
    assert.deepStrictEqual(r.removed, []);
    assert.ok(existsSync(p.dir));
    assert.ok(r.skipped.some((s) => s.reason.includes('alive')));
  });

  it('ignores unexpected directories, bad names, files and leftovers', () => {
    const { out, root } = fresh();
    const keep = [
      'other', 'chrome-profile-cdp-x', 'chrome-profile-cdp-1-2', 'chrome-profile-cdp-123-1700000000000.sweeping',
      `chrome-profile-cdp-123-${NOW - 3 * DAY}-extra`, 'CHROME-PROFILE-CDP-123-1700000000000', '..hidden',
    ];
    for (const n of keep) { mkdirSync(join(root, n), { recursive: true }); utimesSync(join(root, n), new Date(NOW - 9 * DAY), new Date(NOW - 9 * DAY)); }
    const fileLike = `chrome-profile-cdp-${DEAD_PID}-${NOW - 3 * DAY}`;
    writeFileSync(join(root, fileLike), 'a file, not a directory');
    const valid = plant(root, DEAD_PID + 7, 3 * DAY); // proves entries are judged one by one, not that the whole sweep aborted
    const r = sweep(root, out);
    assert.deepStrictEqual(r.removed, [valid.name]);
    for (const n of [...keep, fileLike]) assert.ok(existsSync(join(root, n)), n);
  });

  it('refuses a root that is not <outDir>/cdp-profiles (path confusion and traversal), even with stale profiles inside', () => {
    const { out, root } = fresh();
    const mine = plant(root, DEAD_PID, 2 * DAY);
    const decoys = [
      join(out, 'cdp-profiles-evil'),                 // wrong name
      join(base, 'elsewhere', PROFILE_ROOT_NAME),     // right name, wrong parent
      out,                                            // the output folder itself
    ];
    const planted = decoys.map((dir) => { mkdirSync(dir, { recursive: true }); return plant(dir, DEAD_PID + 3, 2 * DAY); });
    for (const bad of decoys) {
      const r = sweepStaleProfiles(bad, { outDir: out, now: NOW, isPidAlive: dead });
      assert.deepStrictEqual(r.removed, [], bad);
      assert.ok(r.skipped.some((s) => s.reason.includes('root is not')), bad);
    }
    // a traversal spelling that lands on a different folder than outDir/cdp-profiles
    const sneaky = join(root, '..', '..', `out${counter}`, PROFILE_ROOT_NAME, '..', 'cdp-profiles-evil');
    assert.deepStrictEqual(sweepStaleProfiles(sneaky, { outDir: out, now: NOW, isPidAlive: dead }).removed, []);
    for (const p of [mine, ...planted]) assert.ok(existsSync(p.dir), p.dir);
  });

  it('never follows a symlink or junction candidate out of the root', () => {
    const { out, root } = fresh();
    const outside = join(base, 'precious-outside');
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(outside, 'keep.txt'), 'must survive');
    const name = `chrome-profile-cdp-${DEAD_PID}-${NOW - 3 * DAY}`;
    symlinkSync(outside, join(root, name), 'junction');
    const r = sweep(root, out);
    assert.deepStrictEqual(r.removed, []);
    assert.ok(existsSync(join(outside, 'keep.txt')));
    assert.ok(r.skipped.some((s) => s.reason.includes('symlink')));
  });

  it('skips (does not delete) a stale profile that contains a link to somewhere else', () => {
    const { out, root } = fresh();
    const outside = join(base, 'precious-inside-link');
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(outside, 'keep.txt'), 'must survive');
    const p = plant(root, DEAD_PID, 3 * DAY);
    symlinkSync(outside, join(p.dir, 'Default', 'escape'), 'junction');
    const r = sweep(root, out);
    assert.deepStrictEqual(r.removed, []);
    assert.ok(existsSync(p.dir) && existsSync(join(outside, 'keep.txt')));
    assert.ok(r.skipped.some((s) => s.reason.includes('contains a symlink')));
  });

  it('refuses when the root itself is a link', () => {
    const { out, root } = fresh();
    const realTarget = join(base, 'real-root');
    mkdirSync(realTarget, { recursive: true });
    const p = join(realTarget, `chrome-profile-cdp-${DEAD_PID}-${NOW - 3 * DAY}`);
    mkdirSync(p);
    rmSync(root, { recursive: true, force: true });
    symlinkSync(realTarget, root, 'junction');
    const r = sweep(root, out);
    assert.deepStrictEqual(r.removed, []);
    assert.ok(existsSync(p));
  });

  it('refuses a name timestamp in the future', () => {
    const { out, root } = fresh();
    const dir = join(root, `chrome-profile-cdp-${DEAD_PID}-${NOW + 5 * DAY}`);
    mkdirSync(dir);
    const r = sweep(root, out);
    assert.deepStrictEqual(r.removed, []);
    assert.ok(existsSync(dir));
  });

  it('does not touch a profile that is locked (a file inside is held open)', { skip: process.platform !== 'win32' && 'Windows-only: rename of a directory with open files is a Windows lock behaviour' }, () => {
    const { out, root } = fresh();
    const p = plant(root, DEAD_PID, 3 * DAY);
    const handle = openSync(join(p.dir, 'Default', 'Preferences'), 'r+');
    try {
      const r = sweep(root, out);
      assert.deepStrictEqual(r.removed, []);
      assert.ok(existsSync(p.dir));
      assert.ok(r.skipped.some((s) => s.reason.includes('locked')));
    } finally { closeSync(handle); }
    const after2 = sweep(root, out);
    assert.deepStrictEqual(after2.removed, [p.name], 'removable once the lock is released');
  });

  it('never throws on a missing, empty or unreadable root', () => {
    const { out, root } = fresh();
    assert.doesNotThrow(() => sweep(root, out));
    rmSync(root, { recursive: true, force: true });
    assert.deepStrictEqual(sweep(root, out).removed, []);
  });
});

describe('stale profile sweep: abrupt termination', () => {
  const child = (root, ageMs) => spawn(process.execPath, ['-e', `
    const fs = require('fs'), path = require('path');
    const now = ${NOW};
    const dir = path.join(${JSON.stringify(root)}, 'chrome-profile-cdp-' + process.pid + '-' + (now - ${ageMs}));
    fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), '{}');
    const t = new Date(now - ${ageMs}); fs.utimesSync(dir, t, t);
    console.log(path.basename(dir));
    setInterval(() => {}, 1000);
  `], { stdio: ['ignore', 'pipe', 'ignore'] });
  const firstLine = (c) => new Promise((res) => c.stdout.once('data', (d) => res(String(d).trim())));
  const exited = (c) => new Promise((res) => c.once('exit', res));

  it('a profile left by a driver that was killed abruptly is swept; one owned by a live driver is not', async () => {
    const { out, root } = fresh();
    const killed = child(root, 3 * DAY);
    const alive = child(root, 3 * DAY);
    const killedName = await firstLine(killed);
    const aliveName = await firstLine(alive);
    killed.kill('SIGKILL'); // abrupt: no cleanup handler can run
    await exited(killed);
    try {
      const r = sweepStaleProfiles(root, { outDir: out, now: NOW }); // real pid liveness
      assert.deepStrictEqual(r.removed, [killedName]);
      assert.ok(existsSync(join(root, aliveName)), 'live owner keeps its profile');
      assert.ok(r.skipped.some((s) => s.name === aliveName && s.reason.includes('alive')));
    } finally {
      alive.kill('SIGKILL');
      await exited(alive);
    }
  });
});
