/**
 * AISOP Phase 2.2 real-input driver for the existing browser harness.
 *
 * Uses ONLY already-installed pieces: Chrome (headless), Node's built-in WebSocket and fetch, and Chrome's own DevTools
 * protocol. Nothing is installed and no framework is used. It sends TRUSTED input events (Input.dispatchMouseEvent,
 * Input.dispatchKeyEvent), so, unlike the synthetic events of harness.tsx, the browser performs genuine pointer hover
 * and genuine Tab / Shift+Tab focus traversal.
 *
 * This is automated headless input. It is NOT the owner's manual keyboard check and NOT a screen reader test.
 *
 * Security model (Phase 2.3 hardening; see CDP_Driver_Security_Review.md):
 * - Loopback only: the debugging endpoint is requested on 127.0.0.1 (--remote-debugging-address=127.0.0.1) and every URL
 *   the driver uses is checked to be 127.0.0.1. It never binds 0.0.0.0 or a LAN address.
 * - Ephemeral port (--remote-debugging-port=0, read from DevToolsActivePort), not a predictable fixed port.
 * - Throwaway profile: a new, empty user-data-dir per run under <outDir>/cdp-profiles, deleted at the end. Profiles abandoned
 *   by a crashed or killed run are swept at the next start (cdp_profile_sweep.mjs: dedicated root only, own name pattern
 *   only, age and liveness checks, never follows links). It never touches the
 *   user's normal Chrome profile, cookies, sessions or extensions; the driver refuses a profile path that looks like one.
 * - Only the synthetic harness page (file://<outDir>/index.html) is opened; no network pages, no real data.
 * - The browser is killed on normal exit, error, SIGINT/SIGTERM and after a watchdog timeout.
 * - Not imported by the application, not bundled by Vite, not part of `npm test`; run by hand.
 *
 * Transports (Phase 2.4):
 * - `pipe` (DEFAULT): Chrome's --remote-debugging-pipe. Commands go to Chrome on fd 3 and responses come back on fd 4 as
 *   NUL-terminated JSON. There is NO TCP debugging listener at all, so nothing on the machine can connect to the browser
 *   except this process. Pages are driven through a flattened Target session (Target.createTarget + attachToTarget).
 * - `tcp` (kept as a fallback, `--transport=tcp`): the Phase 2.3 hardened loopback ephemeral-port listener.
 *
 * Usage: node cdp_driver.mjs <outDir> [width=1440] [height=900] [--transport=pipe|tcp]
 *   <outDir> contains index.html, harness.js, harness.css (built by esbuild from harness.tsx).
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, resolve, sep } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { PROFILE_ROOT_NAME, sweepStaleProfiles } from './cdp_profile_sweep.mjs';

const positional = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const [outDir, widthArg = '1440', heightArg = '900'] = positional;
const TRANSPORT = (process.argv.find((a) => a.startsWith('--transport=')) ?? '--transport=pipe').split('=')[1];
if (!['pipe', 'tcp'].includes(TRANSPORT)) { console.error('--transport must be pipe or tcp'); process.exit(2); }
const WIDTH = Number(widthArg);
const HEIGHT = Number(heightArg);
const CHROME = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const HOST = '127.0.0.1'; // loopback only, never configurable
const WATCHDOG_MS = Number(process.env.CDP_WATCHDOG_MS) || 5 * 60 * 1000; // env override exists only to test the watchdog

if (!outDir) { console.error('usage: node cdp_driver.mjs <outDir> [width] [height]'); process.exit(2); }
const OUT = resolve(outDir);
if (!existsSync(resolve(OUT, 'index.html')) || !existsSync(resolve(OUT, 'harness.js'))) {
  console.error('outDir must contain the built harness (index.html, harness.js)'); process.exit(2);
}
// Refuse anything that looks like a real browser profile directory.
if (/[\\/](User Data|Chrome|Chromium|Edge)[\\/]/i.test(OUT + sep) && /User Data/i.test(OUT)) {
  console.error('refusing: outDir looks like a browser profile location'); process.exit(2);
}
// Throwaway profiles live in ONE dedicated root, <outDir>/cdp-profiles, so the stale-profile sweep can be confined to it.
const PROFILE_ROOT = resolve(OUT, PROFILE_ROOT_NAME);
const PROFILE = resolve(PROFILE_ROOT, `chrome-profile-cdp-${process.pid}-${Date.now()}`);
// Remove profiles abandoned by crashed or killed earlier runs (conservative rules: see cdp_profile_sweep.mjs). Never throws.
const sweep = sweepStaleProfiles(PROFILE_ROOT, { outDir: OUT });
mkdirSync(PROFILE, { recursive: true });
const base = `file:///${OUT.replace(/\\/g, '/')}/index.html`;
let PORT = 0; // discovered after launch

const results = { width: WIDTH, height: HEIGHT, checks: [], hover: [], traversal: [] };
const check = (area, name, pass, detail = '') => results.checks.push({ area, name, pass: !!pass, detail: String(detail).slice(0, 300) });

const commonArgs = [
  '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--hide-scrollbars',
  '--disable-extensions', '--disable-sync', '--disable-background-networking', '--disable-component-update',
];
const chrome = TRANSPORT === 'pipe'
  ? spawn(CHROME, [...commonArgs, '--remote-debugging-pipe', `--user-data-dir=${PROFILE}`, 'about:blank'],
      { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] })
  : spawn(CHROME, [...commonArgs, `--remote-debugging-address=${HOST}`, '--remote-debugging-port=0', `--user-data-dir=${PROFILE}`, 'about:blank'],
      { stdio: 'ignore' });
const pipeIn = TRANSPORT === 'pipe' ? chrome.stdio[3] : null;  // we write commands here (Chrome fd 3)
const pipeOut = TRANSPORT === 'pipe' ? chrome.stdio[4] : null; // we read responses here (Chrome fd 4)
pipeIn?.on('error', () => { /* browser went away; cleanup handles it */ });
pipeOut?.on('error', () => { /* same */ });

let cleaned = false;
function cleanup() {
  if (cleaned) return;
  cleaned = true;
  try { ws?.close(); } catch { /* ignore */ }
  try { pipeIn?.destroy(); } catch { /* closing the pipe also makes Chrome exit */ }
  try { chrome.kill(); } catch { /* ignore */ }
  // Delete only our own throwaway profile (name and location are re-checked before removal).
  if (PROFILE.startsWith(PROFILE_ROOT + sep) && basename(PROFILE).startsWith('chrome-profile-cdp-')) {
    // Chrome needs a moment to release its files after being killed; retry with a short synchronous pause.
    const pause = () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
    for (let i = 0; i < 40; i++) {
      try { rmSync(PROFILE, { recursive: true, force: true }); if (!existsSync(PROFILE)) return; } catch { /* still locked */ }
      pause();
    }
    console.error('warning: could not remove the throwaway profile: ' + PROFILE);
  }
}
process.on('exit', cleanup);
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { cleanup(); process.exit(130); });
const watchdog = setTimeout(() => { console.error('watchdog timeout: killing the browser'); cleanup(); process.exit(3); }, WATCHDOG_MS);
watchdog.unref();

async function waitForChrome() {
  if (TRANSPORT === 'pipe') return; // nothing to wait for: the pipe exists from spawn
  // Chrome writes the chosen ephemeral port to <profile>/DevToolsActivePort.
  const file = resolve(PROFILE, 'DevToolsActivePort');
  for (let i = 0; i < 150; i++) {
    if (existsSync(file)) {
      const port = Number(readFileSync(file, 'utf8').split(/\r?\n/)[0]);
      if (Number.isInteger(port) && port > 0) {
        try { const r = await fetch(`http://${HOST}:${port}/json/version`); if (r.ok) { PORT = port; return; } } catch { /* not up yet */ }
      }
    }
    await sleep(100);
  }
  throw new Error('Chrome did not start');
}

let ws; let nextId = 1; const pending = new Map();
let sessionId; // pipe transport: flattened page session
function handleMessage(msg) {
  if (msg.id && pending.has(msg.id)) { const p = pending.get(msg.id); pending.delete(msg.id); msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result); }
}
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    if (TRANSPORT === 'pipe') {
      // Browser-level methods (Target.*, Browser.*) go without a session; everything else goes to the page session.
      const browserLevel = method.startsWith('Target.') || method.startsWith('Browser.');
      pipeIn.write(JSON.stringify({ id, method, params, ...(!browserLevel && sessionId ? { sessionId } : {}) }) + '\0');
    } else {
      ws.send(JSON.stringify({ id, method, params }));
    }
  });
}
async function evaluate(expression) {
  const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + ' ' + (r.exceptionDetails.exception?.description ?? ''));
  return r.result.value;
}

async function connect() {
  if (TRANSPORT === 'pipe') {
    let buf = '';
    pipeOut.on('data', (d) => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\0')) >= 0) {
        const raw = buf.slice(0, i); buf = buf.slice(i + 1);
        try { handleMessage(JSON.parse(raw)); } catch { /* ignore malformed */ }
      }
    });
    const created = await send('Target.createTarget', { url: 'about:blank' });
    const attached = await send('Target.attachToTarget', { targetId: created.targetId, flatten: true });
    sessionId = attached.sessionId;
    await send('Page.enable');
    await send('Runtime.enable');
    await send('Emulation.setDeviceMetricsOverride', { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false });
    return;
  }
  const target = await (await fetch(`http://${HOST}:${PORT}/json/new?about:blank`, { method: 'PUT' })).json();
  const wsUrl = new URL(target.webSocketDebuggerUrl);
  if (wsUrl.hostname !== HOST) throw new Error(`refusing a non-loopback debugger address: ${wsUrl.hostname}`);
  ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  ws.onmessage = (ev) => handleMessage(JSON.parse(ev.data));
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false });
}

async function openState(state) {
  await send('Page.navigate', { url: 'about:blank' });
  await sleep(100);
  await send('Page.navigate', { url: `${base}#mode=shot&state=${state}` });
  for (let i = 0; i < 150; i++) {
    await sleep(100);
    try { if (await evaluate(`document.body && document.body.getAttribute('data-ready') === '1'`)) { await sleep(150); return; } } catch { /* navigating */ }
  }
  throw new Error(`state ${state} never became ready`);
}

const KEYS = {
  Tab: { key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 },
  Escape: { key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 },
  ArrowRight: { key: 'ArrowRight', code: 'ArrowRight', windowsVirtualKeyCode: 39 },
  ArrowLeft: { key: 'ArrowLeft', code: 'ArrowLeft', windowsVirtualKeyCode: 37 },
  Home: { key: 'Home', code: 'Home', windowsVirtualKeyCode: 36 },
  End: { key: 'End', code: 'End', windowsVirtualKeyCode: 35 },
};
async function press(name, shift = false) {
  const k = KEYS[name];
  const modifiers = shift ? 8 : 0;
  await send('Input.dispatchKeyEvent', { type: 'rawKeyDown', modifiers, ...k });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', modifiers, ...k });
  await sleep(60);
}
async function moveMouse(x, y) {
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y, buttons: 0 });
  await sleep(500); // real clock: CSS transitions (0.15s) finish
}

const describeActive = `(() => { const a = document.activeElement; if (!a) return null; const dlg = document.querySelector('[role="dialog"]:last-of-type'); const all = Array.from(document.querySelectorAll('[role="dialog"]')); const top = all[all.length - 1] || null; return { tag: a.tagName.toLowerCase(), id: a.id || '', label: (a.getAttribute('aria-label') || a.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 40), inDialog: !!(top && top.contains(a)), isBody: a === document.body }; })()`;

// ── Real Tab / Shift+Tab / Escape in all ten dialogs ─────────────────────────
const DIALOGS = [
  ['API key (Navbar)', 'api-key', 'Set API Key'],
  ['Create case (Cases)', 'cases-create', '+ Create New Incident'],
  ['Case detail (Cases)', 'cases-detail', 'View Details'],
  ['Close case, nested (Cases)', 'cases-close-nested', 'Close Incident'],
  ['Ingest alerts (Alerts)', 'alerts-ingest', 'Ingest Alerts'],
  ['Alert detail (Alerts)', 'alerts-detail', 'Inspect'],
  ['Promote alert (Alerts)', 'alerts-promote', 'Promote'],
  ['Inspect evidence (Workspace)', 'workspace-inspect', 'Inspect Evidence'],
  ['Link evidence (Workspace)', 'workspace-link', '+ Link Evidence by UUID'],
  ['Close case (Workspace)', 'workspace-close', 'Close Case'],
];
async function traverseDialogs() {
  for (const [name, state, openerText] of DIALOGS) {
    const area = `real Tab: ${name}`;
    await openState(state);
    const count = await evaluate(`(() => { const all = Array.from(document.querySelectorAll('[role="dialog"]')); const d = all[all.length - 1]; return d ? d.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled])').length : -1; })()`);
    check(area, 'dialog is open with focusable controls', count > 0, `focusables=${count}`);
    if (count <= 0) continue;
    const entry = await evaluate(describeActive);
    check(area, 'focus is inside the dialog on open', entry?.inDialog, JSON.stringify(entry));
    const forward = [];
    for (let i = 0; i < count + 2; i++) { await press('Tab'); forward.push(await evaluate(describeActive)); }
    check(area, `${count + 2} real Tab presses never leave the dialog`, forward.every((f) => f?.inDialog && !f.isBody), forward.map((f) => f?.label).join(' | '));
    const distinct = new Set(forward.map((f) => `${f.tag}:${f.id}:${f.label}`)).size;
    check(area, 'Tab visits every focusable control then wraps', distinct >= Math.min(count, forward.length), `distinct=${distinct} of ${count}`);
    const backward = [];
    for (let i = 0; i < count + 2; i++) { await press('Tab', true); backward.push(await evaluate(describeActive)); }
    check(area, `${count + 2} real Shift+Tab presses never leave the dialog`, backward.every((f) => f?.inDialog && !f.isBody), backward.map((f) => f?.label).join(' | '));
    const before = await evaluate(`document.querySelectorAll('[role="dialog"]').length`);
    await press('Escape');
    const after = await evaluate(`document.querySelectorAll('[role="dialog"]').length`);
    check(area, 'real Escape closes the (top) dialog', after === before - 1, `${before} -> ${after}`);
    const restored = await evaluate(describeActive);
    check(area, 'focus returned to the invoking control', !restored?.isBody && restored?.label.startsWith(openerText), JSON.stringify(restored));
    results.traversal.push({ name, count, forward: forward.map((f) => f?.label), backward: backward.map((f) => f?.label), restored: restored?.label });
  }
}

// ── Real arrow keys on both tab interfaces ───────────────────────────────────
async function traverseTabs() {
  for (const [name, state, tabSel] of [['workspace', 'workspace', '[role="tab"]'], ['report viewer', 'report', '[role="tab"]']]) {
    const area = `real keys: ${name} tabs`;
    await openState(state);
    const sel = `Array.from(document.querySelectorAll('${tabSel}'))`;
    const n = await evaluate(`${sel}.length`);
    check(area, 'tabs present', n >= 4, `count=${n}`);
    await evaluate(`${sel}.find(t => t.getAttribute('aria-selected') === 'true').focus()`);
    const selectedIndex = `${sel}.findIndex(t => t.getAttribute('aria-selected') === 'true')`;
    const activeIndex = `${sel}.indexOf(document.activeElement)`;
    const start = await evaluate(selectedIndex);
    await press('ArrowRight');
    check(area, 'ArrowRight moves selection and focus together', (await evaluate(selectedIndex)) === (start + 1) % n && (await evaluate(activeIndex)) === (start + 1) % n);
    await press('End');
    check(area, 'End selects the last tab', (await evaluate(selectedIndex)) === n - 1 && (await evaluate(activeIndex)) === n - 1);
    await press('ArrowRight');
    check(area, 'ArrowRight wraps to the first tab', (await evaluate(selectedIndex)) === 0);
    await press('ArrowLeft');
    check(area, 'ArrowLeft wraps to the last tab', (await evaluate(selectedIndex)) === n - 1);
    await press('Home');
    check(area, 'Home selects the first tab', (await evaluate(selectedIndex)) === 0 && (await evaluate(activeIndex)) === 0);
    await press('Tab');
    const leftTablist = await evaluate(`!document.activeElement.closest('[role="tablist"]')`);
    check(area, 'real Tab leaves the tab list (only the selected tab is a tab stop)', leftTablist, JSON.stringify(await evaluate(describeActive)));
  }
}

// ── Audit-details disclosure with real Enter / Space activation and real Tab order ──────────────────────────
async function traverseAudit() {
  const area = 'real keys: audit details disclosure';
  await openState('workspace-activity');
  const buttons = `Array.from(document.querySelectorAll('button[aria-expanded][aria-controls^="audit-details-"]'))`;
  const n = await evaluate(`${buttons}.length`);
  check(area, 'a Show details button exists for each row with details', n >= 3, `buttons=${n}`);
  if (n < 1) return;
  await evaluate(`${buttons}[0].focus()`);
  const state = () => evaluate(`(() => { const b = ${buttons}[0]; const r = document.getElementById(b.getAttribute('aria-controls')); return { expanded: b.getAttribute('aria-expanded'), hidden: r ? r.hidden : null, name: b.getAttribute('aria-label') }; })()`);
  const start = await state();
  check(area, 'starts collapsed with the region hidden', start.expanded === 'false' && start.hidden === true, JSON.stringify(start));
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  await sleep(150);
  const afterEnter = await state();
  check(area, 'real Enter expands (aria-expanded true, region visible)', afterEnter.expanded === 'true' && afterEnter.hidden === false, JSON.stringify(afterEnter));
  check(area, 'focus stays on the button after expanding', await evaluate(`document.activeElement === ${buttons}[0]`));
  const geometry = await evaluate(`(() => { const b = ${buttons}[0]; const r = document.getElementById(b.getAttribute('aria-controls')).getBoundingClientRect(); return { right: r.right, vw: window.innerWidth, pageOverflow: document.documentElement.scrollWidth > window.innerWidth, text: document.getElementById(b.getAttribute('aria-controls')).textContent.length }; })()`);
  check(area, 'disclosed text fits the viewport width (wrapped, no page overflow)', geometry.right <= geometry.vw && !geometry.pageOverflow && geometry.text > 20, JSON.stringify(geometry));
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: ' ', code: 'Space', windowsVirtualKeyCode: 32, text: ' ' });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: ' ', code: 'Space', windowsVirtualKeyCode: 32 });
  await sleep(150);
  const afterSpace = await state();
  check(area, 'real Space collapses again', afterSpace.expanded === 'false' && afterSpace.hidden === true, JSON.stringify(afterSpace));
  // Real Tab order: from the button the next Tab reaches the next row's button (the collapsed region is skipped).
  await press('Tab');
  const next = await evaluate(`${buttons}.indexOf(document.activeElement)`);
  check(area, 'real Tab moves to the next row\'s button, skipping the hidden region', next === 1, `index=${next}`);
}
// ── Real pointer hover ───────────────────────────────────────────────────────
async function hoverTarget({ area, name, state, find, measure, expect }) {
  // find / measure are page expressions returning an Element (find) and an Element to measure (measure, default find).
  const rect = await evaluate(`(() => { const el = ${find}; if (!el) return null; el.scrollIntoView({block:'center'}); const r = el.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; })()`);
  if (!rect) { results.hover.push({ area, name, status: 'UNVERIFIED', detail: 'element not found' }); return; }
  const measureExpr = measure || find;
  const read = () => evaluate(`(() => { const el = ${measureExpr}; const c = window.__contrast(el); const cs = getComputedStyle(el); return { ...c, background: cs.backgroundColor, cursor: cs.cursor, outline: cs.outlineStyle, hovered: el.matches(':hover') || !!el.closest(':hover') }; })()`);
  await moveMouse(2, 2);
  const before = await read();
  await moveMouse(rect.x, rect.y);
  const after = await read();
  const pass = after.ratio >= (expect?.min ?? 4.5);
  results.hover.push({ area, name, state, before, after, status: after.hovered ? (pass ? 'PASS' : 'FAIL') : 'UNVERIFIED', min: expect?.min ?? 4.5 });
}

const HOVER = [
  { state: 'workspace', area: 'row hover', name: 'muted observed-time text while its row is hovered', find: `document.querySelector('tbody tr')`, measure: `document.querySelector('tbody tr td')` },
  { state: 'workspace', area: 'severity badge', name: 'severity badge (HIGH)', find: `document.querySelector('tbody .badge')` },
  { state: 'workspace', area: 'button', name: 'Inspect Evidence (secondary) hover', find: `Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim().startsWith('Inspect Evidence'))` },
  { state: 'workspace', area: 'button', name: 'Start AI Investigation (primary) hover', find: `Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim().startsWith('Start AI Investigation'))` },
  { state: 'workspace', area: 'button', name: 'Close Case (danger) hover', find: `Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === 'Close Case')` },
  { state: 'workspace', area: 'tab', name: 'unselected workspace tab hover', find: `document.querySelector('[role="tab"][aria-selected="false"]')` },
  { state: 'workspace', area: 'truncated action', name: 'truncated evidence action cell hover (contrast; tooltip display not observable)', find: `Array.from(document.querySelectorAll('td[title]'))[0]` },
  { state: 'cases', area: 'row hover', name: 'muted created-time text while its row is hovered', find: `document.querySelector('tbody tr')`, measure: `Array.from(document.querySelectorAll('tbody tr td')).find(td => getComputedStyle(td).color === 'rgb(135, 149, 173)')` },
  { state: 'cases', area: 'button on hovered row', name: 'Investigate (primary) on a hovered row', find: `Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === 'Investigate')` },
  { state: 'cases', area: 'navigation', name: 'inactive nav item hover', find: `Array.from(document.querySelectorAll('nav button')).find(b => !b.hasAttribute('aria-current'))` },
  { state: 'alerts', area: 'button', name: 'Promote (primary) in table row hover', find: `Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === 'Promote')` },
  { state: 'evidence-populated', area: 'row hover', name: 'muted provider text in a hovered evidence row', find: `document.querySelector('tbody tr')`, measure: `Array.from(document.querySelectorAll('tbody tr td div')).find(d => getComputedStyle(d).color === 'rgb(135, 149, 173)')` },
  { state: 'report', area: 'tab', name: 'unselected report tab hover', find: `document.querySelector('.report-tab-btn:not(.active)')` },
  { state: 'report', area: 'tab', name: 'muted tab counter inside a hovered report tab', find: `document.querySelector('.report-tab-btn:not(.active)')`, measure: `document.querySelector('.report-tab-btn:not(.active) .tab-counter')` },
];

try {
  await waitForChrome();
  await connect();
  await traverseDialogs();
  await traverseTabs();
  await traverseAudit();
  let current = '';
  for (const h of HOVER) {
    if (h.state !== current) { await openState(h.state === 'evidence-populated' ? 'evidence' : h.state); current = h.state; }
    try { await hoverTarget(h); } catch (e) { results.hover.push({ area: h.area, name: h.name, status: 'UNVERIFIED', detail: String(e).slice(0, 200) }); }
  }
} catch (e) {
  check('driver', 'completed without exception', false, e?.stack ?? e);
} finally {
  cleanup();
  writeFileSync(`${OUT}\\cdp_results_${WIDTH}.json`, JSON.stringify(results, null, 1));
  const failed = results.checks.filter((c) => !c.pass);
  console.log(`width ${WIDTH}: checks ${results.checks.length}, failed ${failed.length} (sweep removed ${sweep.removed.length}, kept ${sweep.skipped.length}; transport ${TRANSPORT}${TRANSPORT === 'pipe' ? ', no TCP listener' : `, port ${PORT} on ${HOST}`}); hover entries ${results.hover.length} (` +
    `PASS ${results.hover.filter((h) => h.status === 'PASS').length}, FAIL ${results.hover.filter((h) => h.status === 'FAIL').length}, UNVERIFIED ${results.hover.filter((h) => h.status === 'UNVERIFIED').length})`);
  for (const c of failed) console.log('  FAIL', c.area, '|', c.name, '|', c.detail);
  for (const h of results.hover.filter((x) => x.status !== 'PASS')) console.log('  HOVER', h.status, h.area, '|', h.name, '|', JSON.stringify(h.after ?? h.detail));
  process.exit(failed.length ? 1 : 0);
}
