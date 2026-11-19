/**
 * AISOP Phase 2.1 real-browser harness.
 *
 * Bundled with esbuild and opened in an already-installed headless Chrome (no automation framework). It mounts the real
 * <App/> with a stubbed fetch (synthetic data only, no backend), drives it with real DOM events, and writes JSON results
 * into #results. Run with hash `#mode=test` (default) or `#mode=shot&state=<name>` to leave the UI in a state for a screenshot.
 *
 * Limits: events are synthetic (isTrusted=false), so the browser does not perform default Tab traversal; Tab behaviour
 * is therefore the dialog's own trap logic being exercised in a real engine. Real inert, focus, :focus-visible, CSS,
 * layout, reduced-motion and computed colours ARE real. No screen reader is involved.
 */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import '../../src/styles/index.css';
import { App } from '../../src/App';
import { ReportViewer } from '../../src/components/ReportViewer';
import { createBaseMockBundle } from '../fixtures/report_bundle';
import { populatedActivities, populatedAlertDetailExtras, populatedValidationResult } from '../fixtures/workspace_data';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type Check = { area: string; name: string; pass: boolean; detail?: string };
const checks: Check[] = [];
const record = (area: string, name: string, pass: boolean, detail?: string) => checks.push({ area, name, pass, detail });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const params = new URLSearchParams(location.hash.slice(1));
const mode = params.get('mode') ?? 'test';

// ── Synthetic API ───────────────────────────────────────────────────────────
const NOW = '2026-11-13T10:00:00Z';
const caseRow = (id: string, n: number, status = 'open') => ({
  id, case_number: `CASE-2026-00${n}`, title: `Synthetic case ${n}: suspicious process activity`, description: 'Synthetic briefing text for layout checks.',
  severity: n === 1 ? 'high' : 'medium', status, lead_analyst_id: 'analyst-01', created_at: NOW, updated_at: NOW, closed_at: null,
});
const CASE1 = '11111111-1111-1111-1111-111111111111';
const CASE2 = '22222222-2222-2222-2222-222222222222';
const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, limit: 10, total_pages: 1, has_next: false, has_previous: false });
const evidence = (n: number) => ({
  id: `ev-${n}`, event_id: `ev-${n}`, event_timestamp: NOW, event_type: n === 1 ? 'ProcessCreate' : 'NetworkConnect', source_type: 'edr_malware',
  source_identifier: 'HOST-01', severity: 'high', outcome: 'success', provider: 'Synthetic', action: 'synthetic action with a long command line value to test wrapping behaviour',
  primary_subject: 'SYSTEM', summary: `Synthetic event ${n}`, normalized_payload: { process: { name: 'synthetic.exe' } }, linked_at: NOW, linked_by_analyst_id: 'analyst-01',
});
const alertRow = {
  id: 'al-1', source_alert_id: 'SYN-ALERT-1', source_type: 'edr_malware', provider: 'Synthetic EDR', source_identifier: 'collector-1', title: 'Synthetic detection title',
  description: 'Synthetic description.', category: 'execution', severity: 'high', vendor_severity: null, status: 'new', timestamp: NOW, ingested_at: NOW,
  mitre_attack: [], top_observables: [], has_case: false, case_count: 0,
};
const alertDetail = { ...alertRow, raw_ref: 'sha256:' + 'a'.repeat(64), entities: [], associated_case_ids: [], has_case: false, ...populatedAlertDetailExtras };

let failDetail = false;
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

window.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(String(input), 'http://localhost');
  const path = url.pathname;
  const method = (init?.method ?? 'GET').toUpperCase();
  await sleep(5);
  if (path === '/api/v1/health') return json(200, { status: 'ok', app: 'AISOP', version: '0' });
  if (path === '/api/v1/cases' && method === 'GET') return json(200, page([caseRow(CASE1, 1), caseRow(CASE2, 2)]));
  if (path === '/api/v1/cases' && method === 'POST') return json(201, caseRow('33333333-3333-3333-3333-333333333333', 3));
  if (path === `/api/v1/cases/${CASE1}` && method === 'GET') {
    return failDetail
      ? json(500, { detail: 'psycopg.OperationalError: SELECT * FROM cases WHERE password=hunter2 at /app/backend/db.py 10.0.0.5' }, { 'X-Request-ID': 'req0123456789abcd' })
      : json(200, caseRow(CASE1, 1));
  }
  if (path.endsWith('/evidence') && method === 'GET') return json(200, page([evidence(1), evidence(2)]));
  if (path === '/api/v1/evidence/events') return json(200, page([
    { id: 'e1', event_id: 'e1', event_timestamp: NOW, event_type: 'ProcessCreate', source_type: 'edr_malware', source_identifier: 'HOST-01', severity: 'high', provider: 'Synthetic', action: 'created', outcome: 'success', primary_subject: 'SYSTEM', summary: 'Synthetic process creation event with a long summary to test wrapping in the table cell', entities: [{ id: 'x1', event_id: 'e1', raw_evidence_id: 'r1', entity_type: 'host', entity_value: 'HOST-01-with-a-very-long-entity-value-for-truncation', role: 'subject' }, { id: 'x2', event_id: 'e1', raw_evidence_id: 'r1', entity_type: 'user', entity_value: 'a', role: 'subject' }, { id: 'x3', event_id: 'e1', raw_evidence_id: 'r1', entity_type: 'ip', entity_value: '10.0.0.1', role: 'subject' }, { id: 'x4', event_id: 'e1', raw_evidence_id: 'r1', entity_type: 'file', entity_value: 'b', role: 'subject' }] },
    { id: 'e2', event_id: 'e2', event_timestamp: NOW, event_type: 'NetworkConnect', source_type: 'network_traffic', source_identifier: 'HOST-02', severity: 'low', provider: 'Synthetic', action: 'connect', outcome: 'success', summary: '', entities: [] },
  ]));
  if (path.endsWith('/activity')) return json(200, populatedActivities);
  if (path.endsWith('/investigations/synthesize') && method === 'POST') return json(200, populatedValidationResult);
  if (path.includes('/investigations/multisource')) return json(404, { detail: 'No multi-source investigation has been started for this case.' });
  if (path === '/api/v1/alerts/adapters') return json(200, { adapters: [{ name: 'edr_malware', display_name: 'EDR Malware', description: 'd', source_type: 'edr_malware' }], count: 1, supported_severities: [], supported_categories: [] });
  if (path === '/api/v1/alerts' && method === 'GET') return json(200, page([alertRow]));
  if (path === '/api/v1/alerts/al-1') return json(200, alertDetail);
  return json(404, { detail: 'not found' });
}) as typeof fetch;

// ── DOM helpers ──────────────────────────────────────────────────────────────
const $$ = <E extends Element = HTMLElement>(sel: string, root: ParentNode = document) => Array.from(root.querySelectorAll<E>(sel));
const buttonByText = (text: string, root: ParentNode = document) =>
  $$('button', root).find((b) => (b.textContent ?? '').replace(/\s+/g, ' ').trim().startsWith(text) && !b.closest('[inert]'));
async function click(el: HTMLElement | undefined | null, what: string): Promise<boolean> {
  if (!el) { record('harness', `found control: ${what}`, false); return false; }
  el.focus();
  await act(async () => { el.click(); });
  await sleep(40);
  return true;
}
function key(target: Element, k: string, init: KeyboardEventInit = {}): KeyboardEvent {
  const e = new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...init });
  target.dispatchEvent(e);
  return e;
}
async function pressKey(target: Element, k: string, init: KeyboardEventInit = {}): Promise<KeyboardEvent> {
  let e!: KeyboardEvent;
  await act(async () => { e = key(target, k, init); });
  await sleep(40);
  return e;
}
const dialogs = () => $$('[role="dialog"]');
const topDialog = () => dialogs()[dialogs().length - 1];
const focusables = (dlg: HTMLElement) =>
  $$('a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])', dlg);

/** Open a dialog from `opener` and verify the full contract in the real engine. */
async function verifyDialog(name: string, opener: HTMLElement | undefined | null, expectTrap = true): Promise<void> {
  const area = `dialog: ${name}`;
  if (!opener) { record(area, 'opener found', false); return; }
  const before = dialogs().length;
  await click(opener, name);
  const dlg = topDialog();
  record(area, 'opens as role=dialog', dialogs().length === before + 1 && !!dlg);
  if (!dlg) return;
  record(area, 'aria-modal=true', dlg.getAttribute('aria-modal') === 'true');
  const labelId = dlg.getAttribute('aria-labelledby');
  const label = labelId ? document.getElementById(labelId)?.textContent?.trim() : '';
  record(area, 'accessible name resolves', !!label, label || '(none)');
  record(area, 'focus entered the dialog', dlg.contains(document.activeElement), String((document.activeElement as HTMLElement | null)?.tagName));
  const close = $$('button[aria-label="Close dialog"]', dlg);
  record(area, 'close button has accessible name', close.length >= 1);
  // Real inert: the opener must not be focusable while the dialog is open.
  opener.focus();
  record(area, 'opener is inert (cannot take focus)', document.activeElement !== opener && !!opener.closest('[inert]'));
  topDialog()?.focus();
  const items = focusables(dlg);
  if (expectTrap && items.length > 1) {
    items[items.length - 1]!.focus();
    const forward = await pressKey(document.activeElement!, 'Tab');
    record(area, 'Tab on last control wraps to first', forward.defaultPrevented && document.activeElement === items[0]);
    const backward = await pressKey(document.activeElement!, 'Tab', { shiftKey: true });
    record(area, 'Shift+Tab on first control wraps to last', backward.defaultPrevented && document.activeElement === items[items.length - 1]);
  }
  // Rendered audits of this dialog's own content (the background is inert and skipped by the audit).
  results.audits.push(auditContrast(area));
  results.overflow.push(overflowReport(area));
  // Layout: dialog fits the viewport.
  const r = dlg.getBoundingClientRect();
  record(area, 'fits viewport width and height', r.left >= 0 && r.right <= window.innerWidth + 0.5 && r.top >= 0 && r.bottom <= window.innerHeight + 0.5,
    `rect ${Math.round(r.left)},${Math.round(r.top)} ${Math.round(r.right)}x${Math.round(r.bottom)} vs ${window.innerWidth}x${window.innerHeight}`);
  const esc = await pressKey(document.activeElement ?? document.body, 'Escape');
  record(area, 'Escape closes it', esc.defaultPrevented && dialogs().length === before);
  record(area, 'focus restored to the opener', document.activeElement === opener, String((document.activeElement as HTMLElement | null)?.textContent?.slice(0, 30)));
  record(area, 'background no longer inert', !opener.closest('[inert]'));
}

// ── Contrast audit on the rendered DOM (real computed colours) ───────────────
type RGBA = [number, number, number, number];
const parse = (c: string): RGBA => {
  const m = c.match(/rgba?\(([^)]+)\)/);
  if (!m) return [0, 0, 0, 0];
  const p = m[1]!.split(/[ ,/]+/).filter(Boolean).map(Number);
  return [p[0] ?? 0, p[1] ?? 0, p[2] ?? 0, p[3] ?? 1];
};
const over = (top: RGBA, bottom: RGBA): RGBA => {
  const a = top[3] + bottom[3] * (1 - top[3]);
  if (a === 0) return [0, 0, 0, 0];
  return [0, 1, 2].map((i) => (top[i]! * top[3] + bottom[i]! * bottom[3] * (1 - top[3])) / a).concat(a) as RGBA;
};
const lum = ([r, g, b]: RGBA) => {
  const f = (v: number) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4); };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
};
const ratio = (a: RGBA, b: RGBA) => { const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x) as [number, number]; return (hi + 0.05) / (lo + 0.05); };
function effectiveBackground(el: Element): RGBA {
  const layers: RGBA[] = [];
  for (let n: Element | null = el; n; n = n.parentElement) {
    const bg = parse(getComputedStyle(n).backgroundColor);
    if (bg[3] > 0) layers.push(bg);
    if (bg[3] >= 1) break;
  }
  let acc: RGBA = parse(getComputedStyle(document.body).backgroundColor);
  if (acc[3] === 0) acc = [10, 14, 23, 1];
  for (let i = layers.length - 1; i >= 0; i--) acc = over(layers[i]!, acc);
  return acc;
}
function auditContrast(view: string) {
  const muted: { ratio: number; bg: string; where: string; text: string; size: string }[] = [];
  const groups = new Map<string, { count: number; ratio: number; fg: string; bg: string; sample: string; size: string; example: string }>();
  let total = 0;
  for (const el of $$('body *')) {
    if (el.closest('[inert]') || el.closest('script,style')) continue;
    const own = Array.from(el.childNodes).filter((n) => n.nodeType === 3 && (n.textContent ?? '').trim()).map((n) => n.textContent!.trim()).join(' ');
    if (!own) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    const bg = effectiveBackground(el);
    let fg = parse(cs.color);
    fg = over([fg[0], fg[1], fg[2], fg[3] * parseFloat(cs.opacity || '1')], bg);
    const r = ratio(fg, bg);
    total++;
    if (cs.color === 'rgb(135, 149, 173)') muted.push({ ratio: Math.round(r * 100) / 100, bg: `rgb(${bg.slice(0, 3).map(Math.round).join(',')})`, where: `<${el.tagName.toLowerCase()}> ${(el.className?.toString() ?? '').split(' ')[0]}`.trim(), text: own.slice(0, 32), size: cs.fontSize });
    const px = parseFloat(cs.fontSize);
    const large = px >= 24 || (px >= 18.66 && parseInt(cs.fontWeight, 10) >= 700);
    const need = large ? 3 : 4.5;
    const disabled = (el as HTMLButtonElement).disabled === true;
    if (r + 0.005 < need && !disabled) {
      const k = `${cs.color}|${bg.slice(0, 3).map(Math.round).join(',')}`;
      const g = groups.get(k) ?? { count: 0, ratio: r, fg: cs.color, bg: `rgb(${bg.slice(0, 3).map(Math.round).join(',')})`, sample: '', size: cs.fontSize, example: '' };
      g.count++;
      if (!g.sample) { g.sample = own.slice(0, 40); g.example = `${el.tagName.toLowerCase()}.${(el.className?.toString() ?? '').split(' ')[0] ?? ''}`; }
      groups.set(k, g);
    }
  }
  return { view, textNodesChecked: total, mutedText: muted, failing: Array.from(groups.values()).sort((a, b) => a.ratio - b.ratio) };
}
const overflowReport = (view: string) => {
  const de = document.documentElement;
  const clipped = $$('*').filter((el) => {
    if (el.closest('[inert]')) return false;
    const cs = getComputedStyle(el);
    return cs.overflowX === 'hidden' && cs.textOverflow === 'ellipsis' && el.scrollWidth > el.clientWidth + 1;
  }).map((el) => `${el.tagName.toLowerCase()}.${(el.className?.toString() ?? '').split(' ')[0]}: "${(el.textContent ?? '').trim().slice(0, 40)}"`);
  const wide = $$('*').filter((el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.right > window.innerWidth + 0.4; }).slice(0, 5)
    .map((el) => `${el.tagName.toLowerCase()}.${(el.className?.toString() ?? '').split(' ')[0]} right=${Math.round(el.getBoundingClientRect().right)}`);
  return { view, innerWidth: window.innerWidth, scrollWidth: de.scrollWidth, horizontalPageOverflow: de.scrollWidth > window.innerWidth, ellipsisTruncated: clipped.slice(0, 6), elementsPastViewportRight: wide };
};

// Helpers for the real-input driver (tests/browser/cdp_driver.mjs).
(window as unknown as Record<string, unknown>).__contrast = (el: Element) => {
  const bg = effectiveBackground(el);
  const cs = getComputedStyle(el);
  let fg = parse(cs.color);
  fg = over([fg[0], fg[1], fg[2], fg[3] * parseFloat(cs.opacity || '1')], bg);
  return { fg: cs.color, bg: `rgb(${bg.slice(0, 3).map(Math.round).join(',')})`, ratio: Math.round(ratio(fg, bg) * 100) / 100, size: cs.fontSize };
};

const results = { audits: [] as unknown[], overflow: [] as unknown[], computed: {} as Record<string, unknown> };

async function run() {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => { root.render(<App />); });
  await sleep(80);

  results.computed = {
    innerWidth: window.innerWidth, innerHeight: window.innerHeight, userAgent: navigator.userAgent,
    prefersReducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
    inertSupported: 'inert' in HTMLElement.prototype,
  };

  const goto = async (label: string) => { await click(buttonByText(label, document.querySelector('nav') ?? document), `nav ${label}`); await sleep(120); };
  const snap = (view: string) => { results.audits.push(auditContrast(view)); results.overflow.push(overflowReport(view)); };

  // Dashboard
  await sleep(100); snap('dashboard');
  const bar = document.querySelector('.navbar')!.getBoundingClientRect();
  const clippedKids = $$('.navbar *').filter((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && (r.top < bar.top - 0.5 || r.bottom > bar.bottom + 0.5); }).map((e) => `.${(e.className?.toString() ?? '').split(' ')[0]}`);
  record('layout', 'navbar content fits inside the navbar (no clipping)', clippedKids.length === 0, `navbar height ${Math.round(bar.height)}px; outside: ${clippedKids.slice(0, 4).join(', ') || 'none'}`);

  // Keyboard focus visibility (real CSS)
  const nav = buttonByText('Cases', document.querySelector('nav') ?? document);
  nav?.focus();
  // `transition: all 0.15s` on .nav-item animates the outline in and the headless clock is virtual, so settle it explicitly.
  nav?.getAnimations().forEach((a) => a.finish());
  const ring = nav ? getComputedStyle(nav) : null;
  record('focus visibility', 'nav button shows a 2px solid ring', !!ring && ring.outlineStyle === 'solid' && ring.outlineWidth === '2px', ring ? `${ring.outlineStyle} ${ring.outlineWidth} ${ring.outlineColor}` : 'n/a');
  const reduce = results.computed['prefersReducedMotion'] === true;
  const btnTransition = getComputedStyle(document.querySelector('.btn') ?? document.body).transitionDuration;
  record('reduced motion', reduce ? 'transitions collapsed under prefers-reduced-motion' : 'transitions unchanged without the preference',
    reduce ? parseFloat(btnTransition) < 0.001 : parseFloat(btnTransition) >= 0.1, `transition-duration=${btnTransition}`);

  // 1. API key dialog (Navbar)
  await verifyDialog('API key (Navbar)', buttonByText('Set API Key') ?? buttonByText('Key Configured'));

  // Cases
  await goto('Cases'); snap('cases-list');
  await verifyDialog('Create case (Cases)', buttonByText('+ Create New Incident'));

  // Detail failure feedback, then success path
  failDetail = true;
  await click(buttonByText('View Details'), 'View Details (failing)');
  const alertBox = document.querySelector('[role="alert"]');
  const text = alertBox?.textContent ?? '';
  record('error feedback', 'detail failure shown as role=alert', !!alertBox);
  record('error feedback', 'no sensitive diagnostics in the page', !/psycopg|SELECT|hunter2|\/app\/backend|10\.0\.0\.5/.test(document.body.textContent ?? ''), text.slice(0, 120));
  record('error feedback', 'request reference shown', text.includes('req0123456789abcd'));
  snap('cases-error-banner');
  failDetail = false;

  // Detail dialog with nested close dialog
  const viewDetails = buttonByText('View Details');
  await click(viewDetails, 'View Details');
  const detail = topDialog();
  record('dialog: Case detail (Cases)', 'opens as role=dialog', !!detail);
  if (detail) {
    record('dialog: Case detail (Cases)', 'focus entered the dialog', detail.contains(document.activeElement));
    record('dialog: Case detail (Cases)', 'aria-labelledby resolves', !!document.getElementById(detail.getAttribute('aria-labelledby') ?? '')?.textContent);
    snap('cases-detail-dialog');
    // Nested: Close Incident opens a second dialog
    const closeIncident = buttonByText('Close Incident', detail);
    await verifyDialog('Close case, nested (Cases)', closeIncident);
    record('dialog: Case detail (Cases)', 'outer dialog still open after nested closes', dialogs().length === 1);
    // Escape on the outer dialog; focus returns to the View Details button
    const escOuter = await pressKey(document.activeElement ?? document.body, 'Escape');
    record('dialog: Case detail (Cases)', 'Escape closes it', escOuter.defaultPrevented && dialogs().length === 0);
    record('dialog: Case detail (Cases)', 'focus restored to opener', document.activeElement === viewDetails, String((document.activeElement as HTMLElement | null)?.textContent?.slice(0, 30)));
  }

  // Evidence and Reports pages (error/empty states with the stubbed API)
  await goto('Evidence'); await sleep(150); snap('evidence-page');
  await goto('Investigation Reports'); await sleep(150); snap('reports-page');

  // Alerts
  await goto('Alerts'); await sleep(120); snap('alerts-list');
  await verifyDialog('Ingest alerts (Alerts)', buttonByText('Ingest Alerts'));
  const inspect = buttonByText('Inspect');
  await verifyDialog('Alert detail (Alerts)', inspect);
  await click(buttonByText('Inspect'), 'Inspect');
  snap('alerts-detail-dialog');
  await pressKey(document.activeElement ?? document.body, 'Escape');
  await verifyDialog('Promote alert (Alerts)', buttonByText('Promote'));

  // Workspace
  await goto('Cases');
  await click(buttonByText('Investigate'), 'Investigate'); await sleep(250); snap('workspace-evidence');
  const tabsEl = () => $$('[role="tab"]');
  record('tabs: workspace', 'five tabs with tablist', tabsEl().length === 5 && !!document.querySelector('[role="tablist"]'));
  const selected = () => tabsEl().filter((t) => t.getAttribute('aria-selected') === 'true');
  record('tabs: workspace', 'exactly one selected, roving tabindex', selected().length === 1 && tabsEl().filter((t) => t.tabIndex === 0).length === 1);
  const first = tabsEl()[0]!;
  first.focus();
  await pressKey(first, 'ArrowRight');
  record('tabs: workspace', 'ArrowRight selects and focuses next tab', selected()[0] === tabsEl()[1] && document.activeElement === tabsEl()[1]);
  await pressKey(document.activeElement!, 'End');
  record('tabs: workspace', 'End selects the last tab', selected()[0] === tabsEl()[4] && document.activeElement === tabsEl()[4]);
  await pressKey(document.activeElement!, 'ArrowRight');
  record('tabs: workspace', 'ArrowRight wraps to the first tab', selected()[0] === tabsEl()[0]);
  await pressKey(document.activeElement!, 'ArrowLeft');
  record('tabs: workspace', 'ArrowLeft wraps to the last tab', selected()[0] === tabsEl()[4]);
  await pressKey(document.activeElement!, 'Home');
  record('tabs: workspace', 'Home selects the first tab', selected()[0] === tabsEl()[0]);
  const panel = document.querySelector('[role="tabpanel"]');
  record('tabs: workspace', 'tabpanel labelled by the selected tab', panel?.getAttribute('aria-labelledby') === selected()[0]?.id);
  // Populated findings: run the (stubbed) human-invoked investigation so claims, hypotheses and ATT&CK rows render.
  await click(buttonByText('Start AI Investigation'), 'Start AI Investigation'); await sleep(200);
  const bodyText = document.body.textContent ?? '';
  record('populated: findings', 'hypothesis and ATT&CK rows rendered with labelled confidence', bodyText.includes('T1059.001') && bodyText.includes('Model-reported confidence'));
  snap('workspace-findings-populated');
  for (const t of ['findings', 'context', 'multisource', 'activity']) {
    const el = document.getElementById(`ws-tab-${t}`) as HTMLElement | null;
    if (el) { await click(el, `tab ${t}`); await sleep(100); snap(`workspace-${t}`); }
  }
  await click(document.getElementById('ws-tab-evidence'), 'tab evidence'); await sleep(120);
  // Evidence-action truncation: ellipsis is applied, and the full text is discoverable through the title attribute.
  const actionCells = $$('td').filter((td) => td.getAttribute('title')?.startsWith('synthetic action with a long command line'));
  record('populated: evidence action', 'cells carry the full text in a title', actionCells.length === 2 && actionCells.every((td) => td.getAttribute('title') === 'synthetic action with a long command line value to test wrapping behaviour'));
  record('populated: evidence action', 'text is visibly truncated with an ellipsis', actionCells.every((td) => td.scrollWidth > td.clientWidth && getComputedStyle(td).textOverflow === 'ellipsis'));
  await click(document.getElementById('ws-tab-activity'), 'tab activity'); await sleep(120);
  record('populated: activity', 'activity rows rendered', $$('tbody tr').length >= 3);
  snap('workspace-activity-populated');
  const detailBtn = $$<HTMLButtonElement>('button[aria-expanded][aria-controls^="audit-details-"]')[0];
  if (detailBtn) {
    await click(detailBtn, 'Show details'); await sleep(80);
    const region = document.getElementById(detailBtn.getAttribute('aria-controls') ?? '');
    record('populated: audit details', 'disclosure expands via its button (aria-expanded true, region visible)', detailBtn.getAttribute('aria-expanded') === 'true' && !!region && !region.hidden);
    record('populated: audit details', 'disclosed text is wrapped and fits the viewport', !!region && region.getBoundingClientRect().right <= window.innerWidth && document.documentElement.scrollWidth <= window.innerWidth);
    snap('workspace-activity-expanded');
  } else { record('populated: audit details', 'a Show details button exists', false); }
  const truncated = $$('td, td span').filter((el) => getComputedStyle(el).textOverflow === 'ellipsis' && el.scrollWidth > el.clientWidth);
  record('populated: activity', 'every ellipsis-truncated element has a title or a keyboard disclosure button beside it', truncated.every((el) => !!el.getAttribute('title') || !!el.closest('td')?.querySelector('button[aria-expanded]')), `truncated=${truncated.length}`);
  await click(document.getElementById('ws-tab-evidence'), 'tab evidence'); await sleep(120);
  await verifyDialog('Inspect evidence (Workspace)', buttonByText('Inspect Evidence'));
  await verifyDialog('Link evidence (Workspace)', buttonByText('+ Link Evidence by UUID'));
  await verifyDialog('Close case (Workspace)', buttonByText('Close Case'));

  // Report viewer tabs (real component, synthetic bundle)
  const c2 = document.createElement('div');
  document.body.appendChild(c2);
  const r2 = createRoot(c2);
  await act(async () => { r2.render(<ReportViewer bundle={createBaseMockBundle()} />); });
  await sleep(50);
  const rt = () => $$('[role="tab"]', c2);
  const rsel = () => rt().filter((t) => t.getAttribute('aria-selected') === 'true');
  record('tabs: report viewer', 'four tabs, one selected', rt().length === 4 && rsel().length === 1);
  rt()[0]!.focus();
  await pressKey(rt()[0]!, 'ArrowRight');
  record('tabs: report viewer', 'ArrowRight selects and focuses next tab', rsel()[0] === rt()[1] && document.activeElement === rt()[1]);
  await pressKey(document.activeElement!, 'End');
  record('tabs: report viewer', 'End selects last', rsel()[0] === rt()[3]);
  await pressKey(document.activeElement!, 'ArrowRight');
  record('tabs: report viewer', 'ArrowRight wraps to first', rsel()[0] === rt()[0]);
  await pressKey(document.activeElement!, 'Home');
  record('tabs: report viewer', 'Home selects first', rsel()[0] === rt()[0]);
  snap('report-viewer');
  r2.unmount(); c2.remove();
}

async function shot(state: string) {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => { root.render(<App />); });
  await sleep(150);
  const nav = (t: string) => click(buttonByText(t, document.querySelector('nav') ?? document), t);
  if (state === 'dashboard') { /* default view */ }
  if (state === 'cases') { await nav('Cases'); await sleep(150); }
  if (state === 'cases-detail') { await nav('Cases'); await sleep(150); await click(buttonByText('View Details'), 'details'); }
  if (state === 'alerts') { await nav('Alerts'); await sleep(150); }
  if (state === 'alerts-detail') { await nav('Alerts'); await sleep(150); await click(buttonByText('Inspect'), 'inspect'); await sleep(100); }
  if (state === 'evidence') { await nav('Evidence'); await sleep(200); }
  if (state === 'api-key') { await click(buttonByText('Set API Key') ?? buttonByText('Key Configured'), 'key'); }
  if (state === 'alerts-ingest') { await nav('Alerts'); await sleep(150); await click(buttonByText('Ingest Alerts'), 'ingest'); }
  if (state === 'alerts-promote') { await nav('Alerts'); await sleep(150); await click(buttonByText('Promote'), 'promote'); }
  if (state === 'cases-close-nested') { await nav('Cases'); await sleep(150); await click(buttonByText('View Details'), 'details'); await click(buttonByText('Close Incident'), 'close'); }
  if (state === 'cases-create') { await nav('Cases'); await sleep(150); await click(buttonByText('+ Create New Incident'), 'create'); }
  if (state.startsWith('workspace')) {
    await nav('Cases'); await sleep(150); await click(buttonByText('Investigate'), 'inv'); await sleep(250);
    if (state === 'workspace-inspect') await click(buttonByText('Inspect Evidence'), 'inspect');
    if (state === 'workspace-link') await click(buttonByText('+ Link Evidence by UUID'), 'link');
    if (state === 'workspace-close') await click(buttonByText('Close Case'), 'close');
    if (state === 'workspace-findings') { await click(buttonByText('Start AI Investigation'), 'start'); await sleep(200); }
    if (state === 'workspace-audit-open') { await click(document.getElementById('ws-tab-activity'), 'activity'); await sleep(120); await click(document.querySelector<HTMLButtonElement>('button[aria-expanded][aria-controls^="audit-details-"]'), 'details'); }
    if (state === 'workspace-activity') { await click(document.getElementById('ws-tab-activity'), 'activity'); await sleep(120); }
  }
  if (state === 'report') {
    container.remove();
    const c2 = document.createElement('div'); document.body.appendChild(c2);
    await act(async () => { createRoot(c2).render(<ReportViewer bundle={createBaseMockBundle()} initialTab="technical" />); });
  }
  await sleep(100);
  document.body.setAttribute('data-ready', '1');
}

(async () => {
  try {
    if (mode === 'shot') { await shot(params.get('state') ?? 'dashboard'); return; }
    await run();
  } catch (e) {
    record('harness', 'completed without exception', false, String((e as Error)?.stack ?? e).slice(0, 400));
  }
  const pre = document.createElement('pre');
  pre.id = 'results';
  pre.textContent = JSON.stringify({ checks, ...results });
  document.body.appendChild(pre);
  document.body.setAttribute('data-done', '1');
})();
