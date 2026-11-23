// Responsive UI audit: drives real Chrome (headless) over the DevTools protocol, no extra dependencies (Node 22+).
//
//   node scripts/ui_audit.mjs --out D:\AISOP-Backups\AISOP_UI_Audit_<stamp> [--base http://127.0.0.1:3010] [--only 390,1280]
//
// For every viewport and page it records: horizontal overflow, elements that stick out past the right edge, interactive
// elements smaller than 44x44 CSS px (touch) or 24x24 (WCAG 2.2 minimum), text under 12 px, nav items not reachable, and
// saves a screenshot. Keys are read from D:\AISOP-Control\role_demo_keys_local.txt and are never printed or written to the report.
// Local demo stack only (frontend + backend running). It reads the page; it does not submit forms or change data.

import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith('--') ? [...a, [v.slice(2), all[i + 1]]] : a), []));
const BASE = args.base || 'http://127.0.0.1:3010';
const OUT = args.out;
if (!OUT || !/^D:/i.test(OUT)) { console.error('--out must be a folder on drive D:'); process.exit(2); }
mkdirSync(OUT, { recursive: true });

const VIEWPORTS = [
  { name: 'phone-small-320', width: 320, height: 568, mobile: true },
  { name: 'phone-360', width: 360, height: 740, mobile: true },
  { name: 'phone-375', width: 375, height: 667, mobile: true },
  { name: 'phone-390', width: 390, height: 844, mobile: true },
  { name: 'phone-large-430', width: 430, height: 932, mobile: true },
  { name: 'tablet-768', width: 768, height: 1024, mobile: true },
  { name: 'tablet-820', width: 820, height: 1180, mobile: true },
  { name: 'laptop-1024', width: 1024, height: 768, mobile: false },
  { name: 'laptop-1280', width: 1280, height: 800, mobile: false },
  { name: 'desktop-1440', width: 1440, height: 900, mobile: false },
  { name: 'wide-1920', width: 1920, height: 1080, mobile: false },
].filter((v) => !args.only || args.only.split(',').includes(String(v.width)));

const keysText = readFileSync('D:/AISOP-Control/role_demo_keys_local.txt', 'utf8');
const KEYS = Object.fromEntries(keysText.split(/\r?\n/).filter(Boolean).map((l) => l.split('=')).filter((p) => p.length === 2));

const PORT = 9333;
const chrome = spawn('C:/Program Files/Google/Chrome/Application/chrome.exe', [
  '--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${join(OUT, 'chrome_profile')}`,
  '--no-first-run', '--disable-gpu', '--no-default-browser-check', 'about:blank',
], { stdio: 'ignore' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function connect() {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = list.find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch { /* not up yet */ }
    await sleep(250);
  }
  throw new Error('Chrome did not start');
}

const ws = new WebSocket(await connect());
await new Promise((r) => ws.addEventListener('open', r, { once: true }));
let id = 0;
const pending = new Map();
ws.addEventListener('message', (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { const { res, rej } = pending.get(d.id); pending.delete(d.id); d.error ? rej(new Error(d.error.message)) : res(d.result); }
});
const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
const evaluate = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + ' ' + (r.exceptionDetails.exception?.description || ''));
  return r.result.value;
};
await send('Page.enable'); await send('Runtime.enable');

// Runs inside the page. Returns plain numbers and short selectors only.
const MEASURE = `(() => {
  const vw = document.documentElement.clientWidth, vh = window.innerHeight;
  const sel = (el) => { let s = el.tagName.toLowerCase(); if (el.id) s += '#' + el.id; else if (el.className && typeof el.className === 'string') s += '.' + el.className.trim().split(/\\s+/).slice(0, 2).join('.'); if (el.matches('a, button, summary, [role=button], [role=tab]')) { const t = (el.textContent || el.getAttribute('aria-label') || '').trim().replace(/\\s+/g, ' ').slice(0, 22); if (t) s += '[' + t + ']'; } else if (el.tagName === 'SPAN') { const t = (el.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 24); if (t) s += '{' + t + '}'; } return s; };
  const inHiddenClip = (el) => { for (let p = el; p && p !== document.body; p = p.parentElement) { const r = p.getBoundingClientRect(); if (r.width <= 1 && r.height <= 1) return true; } return false; };  // screen-reader-only content
  const clippedByParent = (el) => { for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if ((o === 'hidden' || o === 'clip') && p.getBoundingClientRect().right <= vw + 1) return true; } return false; };  // e.g. an ellipsised chip
  const inScroller = (el) => { for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if ((o === 'auto' || o === 'scroll') && p.scrollWidth > p.clientWidth + 1) return true; } return false; };
  const visible = (el) => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  const out = { vw, scrollWidth: document.documentElement.scrollWidth, bodyScrollWidth: document.body.scrollWidth, pageHeight: document.documentElement.scrollHeight };
  out.horizontalOverflow = out.scrollWidth > vw + 1;
  const wide = []; const small24 = []; const small44 = []; const tiny = [];
  for (const el of document.querySelectorAll('body *')) {
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    if (r.right > vw + 1 && !inScroller(el) && !inHiddenClip(el) && !clippedByParent(el)) wide.push(sel(el) + ' right=' + Math.round(r.right));
    const interactive = el.matches('button, a[href], input:not([type=hidden]), select, textarea, [role=button], [role=tab], summary');
    const inlineInSentence = el.matches('a') && getComputedStyle(el).display === 'inline' && el.closest('p, li, dd');  // WCAG 2.5.8 inline exception
    if (interactive && !inlineInSentence) {
      if (r.width < 24 || r.height < 24) small24.push(sel(el) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height));
      if (r.width < 44 || r.height < 44) small44.push(sel(el) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height));
    }
    const hasText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim().length > 1);
    if (hasText) { const fs = parseFloat(getComputedStyle(el).fontSize); if (fs < 12) tiny.push(sel(el) + ' ' + fs + 'px'); }
  }
  const uniq = (a) => [...new Set(a)];
  out.pokesOutRight = uniq(wide).slice(0, 8); out.pokesOutRightCount = wide.length;
  out.interactiveUnder24 = uniq(small24).slice(0, 8); out.interactiveUnder24Count = small24.length;
  out.interactiveUnder44 = uniq(small44).slice(0, 8); out.interactiveUnder44Count = small44.length;
  out.textUnder12px = uniq(tiny).slice(0, 8); out.textUnder12pxCount = tiny.length;
  const nav = [...document.querySelectorAll('nav.nav-links button, nav.nav-links a')].map((b) => { const r = b.getBoundingClientRect(); return { t: b.textContent.trim(), ok: r.width > 0 && r.left >= -1 && r.right <= vw + 1 }; });
  out.scrollRegions = [...document.querySelectorAll('body *')].filter((e) => { const o = getComputedStyle(e).overflowX; return (o === 'auto' || o === 'scroll') && e.scrollWidth > e.clientWidth + 1 && visible(e); }).map((e) => sel(e) + ' ' + e.clientWidth + '<' + e.scrollWidth);
  out.navItems = nav.length; out.navItemsNotFullyVisible = nav.filter((n) => !n.ok).map((n) => n.t);
  const imgs = [...document.images].filter((i) => visible(i) && i.getBoundingClientRect().right > vw + 1).length;
  out.imagesOverflowing = imgs;
  return out;
})()`;

async function setViewport(v) {
  await send('Emulation.setDeviceMetricsOverride', { width: v.width, height: v.height, deviceScaleFactor: 1, mobile: v.mobile, screenWidth: v.width, screenHeight: v.height });
  await send('Emulation.setTouchEmulationEnabled', v.mobile ? { enabled: true, maxTouchPoints: 5 } : { enabled: false });
}
async function go(path) { await send('Page.navigate', { url: BASE + path }); await sleep(1200); }
async function shot(file, fullPage) {
  let params = { format: 'png' };
  if (fullPage) {
    const m = await send('Page.getLayoutMetrics');
    const h = Math.min(Math.ceil(m.cssContentSize.height), 5000);
    params = { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: m.cssContentSize.width, height: h, scale: 1 } };
  }
  const r = await send('Page.captureScreenshot', params);
  writeFileSync(file, Buffer.from(r.data, 'base64'));
}
async function clickByText(text) {
  return evaluate(`(() => { const b = [...document.querySelectorAll('nav.nav-links button')].find((x) => x.textContent.trim() === ${JSON.stringify(text)}); if (!b) return false; b.click(); return true; })()`);
}

const results = [];
const record = async (viewport, page, extra = {}) => {
  const m = await evaluate(MEASURE);
  const file = `${viewport.name}__${page.replace(/[^a-z0-9]+/gi, '_')}.png`;
  await shot(join(OUT, file), true);
  results.push({ viewport: viewport.name, width: viewport.width, page, ...m, screenshot: file, ...extra });
  console.log(`${viewport.name.padEnd(18)} ${page.padEnd(22)} overflow=${m.horizontalOverflow ? 'YES' : 'no '} out=${String(m.pokesOutRightCount).padStart(3)} <44px=${String(m.interactiveUnder44Count).padStart(3)} <24px=${String(m.interactiveUnder24Count).padStart(3)} text<12=${String(m.textUnder12pxCount).padStart(3)}${m.navItemsNotFullyVisible.length ? ' navCut=' + m.navItemsNotFullyVisible.join('/') : ''}`);
};

try {
  for (const v of VIEWPORTS) {
    await setViewport(v);
    for (const p of ['/', '/privacy', '/terms']) { await go(p); await record(v, p === '/' ? 'landing' : p.slice(1)); }
    for (const [role, key] of [['lead', KEYS.viva_lead], ['admin', KEYS.viva_admin]]) {
      if (!key) continue;
      await go('/app');
      await evaluate(`sessionStorage.setItem('aisop_api_key', ${JSON.stringify(key)}); true`);
      await go('/app');
      const tabs = role === 'lead' ? ['Dashboard', 'Alerts', 'Cases', 'Evidence', 'Reports'] : ['Security'];
      for (const t of tabs) {
        if (!(await clickByText(t))) { results.push({ viewport: v.name, page: `${role}/${t}`, missing: true }); continue; }
        await sleep(1500);
        await record(v, `app-${t.toLowerCase()}`, { role });
        if (t === 'Cases') {
          const opened = await evaluate(`(() => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === 'Investigate'); if (!b) return false; b.click(); return true; })()`);
          if (opened) { await sleep(2500); await record(v, 'app-case-workspace', { role }); }
        }
      }
      await evaluate(`sessionStorage.removeItem('aisop_api_key'); true`);
    }
  }
} finally {
  writeFileSync(join(OUT, 'ui_audit_results.json'), JSON.stringify(results, null, 2));
  ws.close(); chrome.kill();
}

// Summary by viewport
const by = {};
for (const r of results.filter((x) => !x.missing)) {
  const s = (by[r.viewport] ||= { pages: 0, overflowPages: [], under44: 0, under24: 0, tinyText: 0, pokesOut: 0 });
  s.pages++; if (r.horizontalOverflow) s.overflowPages.push(r.page);
  s.under44 += r.interactiveUnder44Count; s.under24 += r.interactiveUnder24Count; s.tinyText += r.textUnder12pxCount; s.pokesOut += r.pokesOutRightCount;
}
console.log('\nSUMMARY');
for (const [k, s] of Object.entries(by)) console.log(`${k.padEnd(18)} pages=${s.pages} overflowPages=[${s.overflowPages.join(',')}] <44px=${s.under44} <24px=${s.under24} text<12px=${s.tinyText} pokesOut=${s.pokesOut}`);
console.log('\nresults:', join(OUT, 'ui_audit_results.json'));
