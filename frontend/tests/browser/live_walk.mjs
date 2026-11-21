/**
 * Live UI walk against a RUNNING dev stack (loopback only): headless Edge/Chrome over the DevTools protocol.
 *   node live_walk.mjs <baseUrl> <tokensFile> <outDir>
 * Sets the synthetic analyst token in sessionStorage (never printed), visits the main views, screenshots each and records
 * console errors / failed requests. Throwaway profile under <outDir>. Not part of `npm test`.
 */
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [base, tokensFile, out] = process.argv.slice(2);
if (!base?.startsWith('http://127.0.0.1') || !tokensFile || !out) { console.error('usage: node live_walk.mjs http://127.0.0.1:PORT tokensFile outDir'); process.exit(2); }
const token = readFileSync(tokensFile, 'utf8').split(/\r?\n/).find((l) => l.startsWith('analyst=')).slice(8).trim();
const OUT = resolve(out); mkdirSync(OUT, { recursive: true });
const PROFILE = resolve(OUT, `edge-profile-${Date.now()}`);
const BROWSER = [process.env.BROWSER_PATH, 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe', 'C:\Program Files\Google\Chrome\Application\chrome.exe'].find((p) => p && existsSync(p));
const proc = spawn(BROWSER, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${PROFILE}`, '--window-size=1440,900', '--no-first-run', '--disable-extensions', '--disable-background-networking', 'about:blank'], { stdio: 'ignore' });
const cleanup = () => { try { proc.kill(); } catch {} setTimeout(() => { try { rmSync(PROFILE, { recursive: true, force: true }); } catch {} }, 1500); };
process.on('exit', cleanup);

let port;
for (let i = 0; i < 50 && !port; i++) { await sleep(200); try { port = readFileSync(resolve(PROFILE, 'DevToolsActivePort'), 'utf8').split('\n')[0]; } catch {} }
const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const page = targets.find((t) => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const consoleErrors = []; const failed = [];
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); return; }
  if (d.method === 'Runtime.consoleAPICalled' && ['error', 'assert'].includes(d.params.type)) consoleErrors.push(d.params.args.map((a) => a.value ?? a.description).join(' ').slice(0, 200));
  if (d.method === 'Runtime.exceptionThrown') consoleErrors.push('EXC ' + (d.params.exceptionDetails.exception?.description ?? d.params.exceptionDetails.text).slice(0, 200));
  if (d.method === 'Network.responseReceived' && d.params.response.status >= 400) failed.push(`${d.params.response.status} ${new URL(d.params.response.url).pathname}`);
};
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => (await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true })).result?.result?.value;
await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });

const shots = []; const texts = {};
async function shot(name) {
  await sleep(1200);
  const r = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(resolve(OUT, `${name}.png`), Buffer.from(r.result.data, 'base64')); shots.push(name);
  texts[name] = ((await ev('document.body.innerText')) || '').slice(0, 1800);
}
const click = (labelRe) => ev(`(() => { const re = new RegExp(${JSON.stringify(labelRe)}, 'i'); const el = [...document.querySelectorAll('button,a,[role=tab],[role=button],tr')].find((e) => re.test(e.innerText || e.getAttribute('aria-label') || '')); if (!el) return false; el.click(); return true; })()`);

await send('Page.navigate', { url: `${base}/app` }); await sleep(1500);
await ev(`sessionStorage.setItem('aisop_api_key', ${JSON.stringify(token)}); true`);
await send('Page.navigate', { url: `${base}/app` }); await shot('01_dashboard');
const steps = [['Alerts', '02_alerts'], ['Cases', '03_cases'], ['Evidence', '04_evidence'], ['Reports', '05_reports']];
const clicked = {};
for (const [label, name] of steps) { clicked[label] = await click(`^\s*${label}\s*$`); await shot(name); }
// open the first case, then try the multi-source investigation view
await click('^\s*Cases\s*$'); await sleep(800);
clicked.openCase = await click('Live E2E');
await shot('06_case_workspace');
for (const re of ['multi.?source', 'investigation', 'timeline']) { clicked[re] = await click(re); await shot(`07_${re.replace(/\W/g, '')}`); }
writeFileSync(resolve(OUT, 'walk_result.json'), JSON.stringify({ shots, clicked, consoleErrors, failedRequests: failed, texts }, null, 2));
console.log(JSON.stringify({ shots, clicked, consoleErrors, failedRequests: failed }, null, 1));
ws.close(); cleanup(); setTimeout(() => process.exit(0), 2000);
