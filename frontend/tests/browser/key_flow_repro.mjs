/**
 * Reproduces the "API key needed / Authentication required" report in a real (headless) browser, loopback only.
 *   node key_flow_repro.mjs <baseUrl> <tokensFile> <outDir>
 * Flow: open /app -> Set API key -> paste the synthetic analyst token with a real insertText event -> Save key -> navigate
 * with the in-app tabs only. Records, for every /api request: path, whether X-API-Key was sent (never its value), status.
 * Screenshots and a json result go to <outDir>. The token is never printed or written.
 */
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [base, tokensFile, out] = process.argv.slice(2);
if (!base?.startsWith('http://127.0.0.1') || !tokensFile || !out) { console.error('usage: node key_flow_repro.mjs http://127.0.0.1:PORT tokensFile outDir'); process.exit(2); }
const token = readFileSync(tokensFile, 'utf8').split(/\r?\n/).find((l) => l.startsWith('analyst=')).slice(8);
const OUT = resolve(out); mkdirSync(OUT, { recursive: true });
const PROFILE = resolve(OUT, `edge-profile-${Date.now()}`);
const BROWSER = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe'].find((p) => existsSync(p));
const proc = spawn(BROWSER, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${PROFILE}`, '--window-size=1440,900', '--no-first-run', '--disable-extensions', '--disable-background-networking', 'about:blank'], { stdio: 'ignore' });
const cleanup = () => { try { proc.kill(); } catch {} setTimeout(() => { try { rmSync(PROFILE, { recursive: true, force: true }); } catch {} }, 1500); };
process.on('exit', cleanup);

let port;
for (let i = 0; i < 50 && !port; i++) { await sleep(200); try { port = readFileSync(resolve(PROFILE, 'DevToolsActivePort'), 'utf8').split('\n')[0]; } catch {} }
const page = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find((t) => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const reqs = []; const consoleErrors = [];
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); return; }
  if (d.method === 'Network.requestWillBeSent') {
    const u = new URL(d.params.request.url);
    if (u.pathname.startsWith('/api')) { const h = d.params.request.headers; const k = h['X-API-Key'] ?? h['x-api-key']; reqs.push({ rid: d.params.requestId, method: d.params.request.method, path: u.pathname, keySent: Boolean(k), keyLength: k ? k.length : 0, keyHasWhitespace: k ? /\s/.test(k) : false, status: null }); }
  }
  if (d.method === 'Network.responseReceived') { const r = reqs.find((x) => x.rid === d.params.requestId); if (r) r.status = d.params.response.status; }
  if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error') consoleErrors.push(d.params.args.map((a) => a.value ?? a.description).join(' ').slice(0, 160));
};
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => (await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true })).result?.result?.value;
await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
const shot = async (name) => { await sleep(1200); const r = await send('Page.captureScreenshot', { format: 'png' }); writeFileSync(resolve(OUT, `${name}.png`), Buffer.from(r.result.data, 'base64')); };
const text = async () => ((await ev('document.body.innerText')) || '').replace(/\s+/g, ' ').slice(0, 400);
const click = (re) => ev(`(() => { const r = new RegExp(${JSON.stringify(re)}, 'i'); const el = [...document.querySelectorAll('button,a')].find((e) => r.test((e.innerText || '').trim())); if (!el) return false; el.click(); return true; })()`);

const log = {};
await send('Page.navigate', { url: `${base}/app` }); await sleep(1500);
log.step1_initial = await text(); await shot('k1_initial');
log.clickedSetKey = await click('^\\s*Set API key\\s*$'); await sleep(600);
await ev(`document.querySelector('input[type=password]').focus(); true`);
const MODE = process.env.KEY_MODE || 'single';
await send('Input.insertText', { text: token });                       // a real paste-like text insertion into the focused field
if (MODE === 'double') { await send('Input.insertText', { text: ' ' + token }); }   // a second paste appended to the first
await sleep(300);
log.fieldLength = await ev(`document.querySelector('input[type=password]').value.length`);
log.tokenLength = token.length;
await ev(`document.querySelector('input[type=checkbox]')?.click(); true`);   // Show key
log.hintText = await ev(`document.getElementById('api-key-hint')?.innerText || ''`);
await shot('k2_dialog_filled');
log.clickedSave = await click('^\\s*Save key\\s*$'); await sleep(1500);
log.step3_after_save = await text(); await shot('k3_after_save');
log.keyBadge = await ev(`(document.querySelector('.navbar')?.innerText || '').includes('Key set')`);
log.sessionStorageHasKey = await ev(`sessionStorage.getItem('aisop_api_key') !== null`);
const nav = {};
for (const t of ['Alerts', 'Cases', 'Evidence', 'Reports', 'Dashboard']) { nav[t] = await click(`^\\s*${t}\\s*$`); await sleep(1500); log['after_' + t] = await text(); await shot('k4_' + t.toLowerCase()); }
log.nav = nav;
writeFileSync(resolve(OUT, 'key_flow_repro_result.json'), JSON.stringify({ log, requests: reqs.map(({ rid, ...r }) => r), consoleErrors }, null, 2));
const summary = {};
for (const r of reqs) { const k = `${r.method} ${r.path} key=${r.keySent} status=${r.status}`; summary[k] = (summary[k] || 0) + 1; }
console.log(JSON.stringify({ mode: MODE, hintText: log.hintText, fieldLength: log.fieldLength, tokenLength: log.tokenLength, clickedSave: log.clickedSave, keyBadge: log.keyBadge, sessionStorageHasKey: log.sessionStorageHasKey, afterSave: log.step3_after_save.slice(0, 200), requestSummary: summary, consoleErrors }, null, 1));
ws.close(); cleanup(); setTimeout(() => process.exit(0), 2000);
