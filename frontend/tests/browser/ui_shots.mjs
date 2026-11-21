/**
 * Demo-path screenshots for before/after comparison (loopback only, one headless browser instance, closed at the end).
 *   node ui_shots.mjs <baseUrl> <tokensFile> <outDir> <label> [width=1440] [height=900]
 * Screens: dashboard, alerts, cases, case workspace, multi-source panel, reports. Uses the synthetic analyst key (never printed).
 * Saves <outDir>/<label>_<NN>_<screen>.png and <label>_result.json (what was clicked, console errors, failed requests).
 * Full-page capture, height capped at 2400 px.
 */
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [base, tokensFile, out, label, w = '1440', h = '900'] = process.argv.slice(2);
if (!base?.startsWith('http://127.0.0.1') && !base?.startsWith('https://127.0.0.1') || !tokensFile || !out || !label) { console.error('usage: node ui_shots.mjs http://127.0.0.1:PORT tokensFile outDir label [w] [h]'); process.exit(2); }
const token = readFileSync(tokensFile, 'utf8').split(/\r?\n/).find((l) => l.startsWith('analyst=')).slice(8).trim();
const OUT = resolve(out); mkdirSync(OUT, { recursive: true });
const PROFILE = resolve(OUT, `edge-profile-${Date.now()}`);
const BROWSER = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe'].find((p) => existsSync(p));
const proc = spawn(BROWSER, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${PROFILE}`, `--window-size=${w},${h}`, '--no-first-run', '--disable-extensions', '--disable-background-networking', '--disable-gpu', ...(base.startsWith('https://127.0.0.1') ? ['--ignore-certificate-errors'] : []), 'about:blank'], { stdio: 'ignore' });
let closed = false;
const cleanup = () => { if (closed) return; closed = true; try { proc.kill(); } catch {} setTimeout(() => { try { rmSync(PROFILE, { recursive: true, force: true }); } catch {} }, 1500); };
process.on('exit', cleanup);

let port;
for (let i = 0; i < 50 && !port; i++) { await sleep(200); try { port = readFileSync(resolve(PROFILE, 'DevToolsActivePort'), 'utf8').split('\n')[0]; } catch {} }
const page = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find((t) => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const consoleErrors = []; const failed = [];
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); return; }
  if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error') consoleErrors.push(d.params.args.map((a) => a.value ?? a.description).join(' ').slice(0, 160));
  if (d.method === 'Network.responseReceived' && d.params.response.status >= 400) failed.push(`${d.params.response.status} ${new URL(d.params.response.url).pathname}`);
};
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => (await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true })).result?.result?.value;
await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
await send('Emulation.setDeviceMetricsOverride', { width: Number(w), height: Number(h), deviceScaleFactor: 1, mobile: Number(w) < 768 });
const shots = []; const clicked = {}; const pageChecks = [];
const shot = async (n, name) => {
  await sleep(1500);
  const m = (await send('Page.getLayoutMetrics')).result;
  const height = Math.min(2400, Math.max(Number(h), Math.ceil(m.cssContentSize?.height ?? m.contentSize.height)));
  const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: Number(w), height, scale: 1 } });
  const file = `${label}_${String(n).padStart(2, '0')}_${name}.png`;
  writeFileSync(resolve(OUT, file), Buffer.from(r.result.data, 'base64')); shots.push(file);
  const txt = (await ev('document.body.innerText')) || '';
  pageChecks.push({ file, errorScreen: /Application view error|Authentication required|API key needed|Unexpected|could not be completed/i.test(txt), chars: txt.length, first: txt.split(/\s+/).join(' ').slice(0, 140) });
};
const click = (re, sel = 'button,a,[role=tab],tr,td') => ev(`(() => { const r = new RegExp(${JSON.stringify(re)}, 'i'); const el = [...document.querySelectorAll(${JSON.stringify(sel)})].find((e) => r.test((e.innerText || '').trim())); if (!el) return false; el.click(); return true; })()`);

await send('Page.navigate', { url: `${base}/app` }); await sleep(1200);
await ev(`sessionStorage.setItem('aisop_api_key', ${JSON.stringify(token)}); true`);
await send('Page.navigate', { url: `${base}/app` }); await shot(1, 'dashboard');
clicked.alerts = await click('^\\s*Alerts\\s*$'); await shot(2, 'alerts');
clicked.cases = await click('^\\s*Cases\\s*$'); await shot(3, 'cases');
const CASE_TITLE = process.env.CASE_TITLE || 'R12 retry case';
clicked.case = await ev(`(() => { const row = [...document.querySelectorAll('tr')].find((r) => (r.innerText || '').includes(${JSON.stringify(CASE_TITLE)})); const b = row && [...row.querySelectorAll('button')].find((x) => /View Details/i.test(x.innerText)); if (!b) return false; b.click(); return true; })()`); await shot(4, 'case_dialog');
clicked.workspace = await click('Open Investigation Workspace'); await sleep(1500); await shot(5, 'case_workspace');
clicked.multisource = await click('^\s*Multi-source\s*$'); await sleep(3000);
// Optional: open the evidence-class legend and scroll it into view before the screenshot. Enabled with OPEN_LEGEND=1.
if (process.env.OPEN_LEGEND === '1') { clicked.legend = await ev(`(() => { const d = document.querySelector('details.class-legend'); if (!d) return false; d.open = true; d.scrollIntoView(); return true; })()`); }
await shot(6, 'multisource');
clicked.reports = await click('^\s*Reports\s*$'); await shot(7, 'reports');
// Optional: drive the AI explanation step through the real UI (proxy, API, Ollama). Enabled with AI_STEP=1.
let aiStep = null;
if (process.env.AI_STEP === '1') {
  await click('^\s*Cases\s*$'); await sleep(1200);
  await ev(`(() => { const row = [...document.querySelectorAll('tr')].find((r) => (r.innerText || '').includes(${JSON.stringify(CASE_TITLE)})); const b = row && [...row.querySelectorAll('button')].find((x) => /View Details/i.test(x.innerText)); if (b) b.click(); return !!b; })()`);
  await sleep(1000); await click('Open Investigation Workspace'); await sleep(1500);
  await click('^\s*Multi-source\s*$'); await sleep(3000);
  const started = await click('^\s*Run AI explanation( again)?\s*$');
  const t0 = Date.now(); let outcome = 'none'; let sawRunning = false;
  for (let i = 0; i < 100; i++) {
    await sleep(1000);
    const txt = (await ev('document.body.innerText')) || '';
    if (/AI explanation running/i.test(txt)) sawRunning = true;
    if (/AI explanation finished/i.test(txt)) { outcome = 'finished'; break; }
    if (/AI timed out/i.test(txt)) { outcome = 'timeout'; break; }
    if (/could not be completed/i.test(txt)) { outcome = 'failed'; break; }
  }
  aiStep = { clicked: started, sawRunningState: sawRunning, outcome, seconds: Math.round((Date.now() - t0) / 1000) };
  await shot(8, 'ai_step_result');
}

// Keyboard-only check: Tab through the first controls of the current page and record each focused element's visible outline.
const keyboard = [];
await send('Page.navigate', { url: `${base}/app` }); await sleep(1500);
for (let i = 0; i < 10; i++) {
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
  await sleep(150);
  keyboard.push(await ev(`(() => { const e = document.activeElement; if (!e) return null; const c = getComputedStyle(e); const r = e.getBoundingClientRect(); return { tag: e.tagName.toLowerCase(), text: (e.innerText || e.getAttribute('aria-label') || e.placeholder || '').trim().slice(0, 24), outline: c.outlineStyle + ' ' + c.outlineWidth + ' ' + c.outlineColor, height: Math.round(r.height) }; })()`));
}
writeFileSync(resolve(OUT, `${label}_result.json`), JSON.stringify({ label, width: w, height: h, shots, clicked, consoleErrors, failedRequests: failed, keyboard, pageChecks, aiStep }, null, 2));
console.log(JSON.stringify({ label, shots, clicked, consoleErrors, failedRequests: failed }, null, 1));
ws.close(); cleanup(); setTimeout(() => process.exit(0), 1500);
