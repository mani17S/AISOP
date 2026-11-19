/**
 * AISOP Phase 2.1: DOM-simulated accessibility and error-presentation tests (jsdom).
 *
 * These tests mount the real components, dispatch real keyboard and mouse events, and assert on focus and on the
 * resulting DOM. They are DOM-SIMULATED: no layout, no CSS, no real browser, no screen reader.
 */
import { dom } from './dom_setup';
import React, { act, useState } from 'react';
import { createRoot, Root } from 'react-dom/client';
import { describe, it, afterEach, beforeEach, after } from 'node:test';
import assert from 'node:assert';
import { Dialog } from '../src/components/Dialog';
import { ReportViewer } from '../src/components/ReportViewer';
import { InvestigationWorkspace } from '../src/components/InvestigationWorkspace';
import { Cases } from '../src/pages/Cases';
import { MultiSourcePanel } from '../src/components/MultiSourcePanel';
import { Navbar } from '../src/components/Navbar';
import { AuthProvider } from '../src/contexts/AuthContext';
import { createBaseMockBundle } from './fixtures/report_bundle';
import { AuditDetailsCell, AuditDetailsRow, auditRegionId, formatAuditDetails } from '../src/components/AuditDetails';

// Close the jsdom window at the end so its timers do not keep the test process alive.
after(() => { dom.window.close(); });

let container: HTMLElement;
let root: Root;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  (globalThis as { fetch?: unknown }).fetch = originalFetch;
});

const originalFetch = (globalThis as { fetch?: unknown }).fetch;
const $ = (id: string) => document.getElementById(id) as HTMLElement;
const render = (el: React.ReactElement) => act(() => root.render(el));
const click = (el: HTMLElement) => act(() => { el.click(); });

function press(target: Element, key: string, init: KeyboardEventInit = {}): KeyboardEvent {
  const event = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...init });
  act(() => { target.dispatchEvent(event); });
  return event;
}

// Harness: an opener, background content, a dialog with 4 focusables, and a nested dialog.
const Harness: React.FC<{ dismissible?: boolean }> = ({ dismissible = true }) => {
  const [open, setOpen] = useState(false);
  const [inner, setInner] = useState(false);
  return (
    <>
      <button id="opener" onClick={() => setOpen(true)}>Open</button>
      <main id="bg"><button id="bg-btn">Background action</button></main>
      <aside id="pre-hidden" aria-hidden="true">decorative</aside>
      {open && (
        <Dialog onClose={() => setOpen(false)} labelledBy="t1" describedBy="d1" dismissible={dismissible}>
          <div className="modal-header">
            <h3 id="t1">Outer title</h3>
            <button id="x" aria-label="Close dialog" onClick={() => setOpen(false)}>✕</button>
          </div>
          <div className="modal-body">
            <p id="d1">Outer description</p>
            <input id="f1" />
            <button id="open-inner" onClick={() => setInner(true)}>Inner</button>
          </div>
          <div className="modal-footer"><button id="ok">OK</button></div>
        </Dialog>
      )}
      {inner && (
        <Dialog onClose={() => setInner(false)} labelledBy="t2">
          <h3 id="t2">Inner title</h3>
          <div className="modal-body"><input id="g1" /></div>
        </Dialog>
      )}
    </>
  );
};

const openOuter = () => {
  $('opener').focus();
  click($('opener'));
};

describe('Dialog: focus, keyboard and inertness (DOM-simulated)', () => {
  it('moves focus into the first form control on open', () => {
    render(<Harness />);
    openOuter();
    assert.strictEqual(document.activeElement, $('f1'));
  });

  it('focuses the dialog container when there is no form control', () => {
    render(<Dialog onClose={() => {}} labelledBy="t"><h3 id="t">Only buttons</h3><button id="b1">One</button></Dialog>);
    const dialog = document.querySelector('[role="dialog"]');
    assert.strictEqual(document.activeElement, dialog);
  });

  it('exposes an accessible name and description that resolve to real elements', () => {
    render(<Harness />);
    openOuter();
    const dialog = document.querySelector('[role="dialog"]')!;
    assert.strictEqual(dialog.getAttribute('aria-modal'), 'true');
    assert.strictEqual(document.getElementById(dialog.getAttribute('aria-labelledby')!)!.textContent, 'Outer title');
    assert.strictEqual(document.getElementById(dialog.getAttribute('aria-describedby')!)!.textContent, 'Outer description');
  });

  it('closes on Escape and restores focus to the invoking element', () => {
    render(<Harness />);
    openOuter();
    const event = press(document.activeElement!, 'Escape');
    assert.ok(event.defaultPrevented);
    assert.strictEqual(document.querySelector('[role="dialog"]'), null);
    assert.strictEqual(document.activeElement, $('opener'));
  });

  it('restores focus to the real invoker even when it lost focus before the dialog mounted (button disabled while loading)', () => {
    render(<Harness />);
    $('opener').focus();
    $('opener').blur(); // what the browser does when a focused button becomes disabled while loading
    assert.strictEqual(document.activeElement, document.body);
    click($('opener'));
    press(document.activeElement!, 'Escape');
    assert.strictEqual(document.activeElement, $('opener'));
  });

  it('restores focus to the clicked control even when no focus event was delivered (browser or page without focus)', () => {
    render(<Harness />);
    assert.strictEqual(document.activeElement, document.body);
    click($('opener')); // click only: no focus() call, no focusin
    press(document.activeElement!, 'Escape');
    assert.strictEqual(document.activeElement, $('opener'));
  });

  it('does not close on Escape when not dismissible', () => {
    render(<Harness dismissible={false} />);
    openOuter();
    press(document.activeElement!, 'Escape');
    assert.ok(document.querySelector('[role="dialog"]'), 'dialog must stay open');
  });

  it('closes via the named close button and restores focus', () => {
    render(<Harness />);
    openOuter();
    click($('x'));
    assert.strictEqual(document.querySelector('[role="dialog"]'), null);
    assert.strictEqual(document.activeElement, $('opener'));
  });

  it('closes on backdrop click but not on a click inside the dialog', () => {
    render(<Harness />);
    openOuter();
    click($('f1'));
    assert.ok(document.querySelector('[role="dialog"]'), 'inside click must not close');
    click(document.querySelector('.modal-backdrop') as HTMLElement);
    assert.strictEqual(document.querySelector('[role="dialog"]'), null);
  });

  it('traps Tab: last control wraps to first, Shift+Tab on first wraps to last, interior Tab is left to the browser', () => {
    render(<Harness />);
    openOuter(); // focusables in order: x, f1, open-inner, ok
    $('ok').focus();
    let event = press($('ok'), 'Tab');
    assert.ok(event.defaultPrevented);
    assert.strictEqual(document.activeElement, $('x'));
    event = press($('x'), 'Tab', { shiftKey: true });
    assert.ok(event.defaultPrevented);
    assert.strictEqual(document.activeElement, $('ok'));
    $('f1').focus();
    event = press($('f1'), 'Tab');
    assert.ok(!event.defaultPrevented, 'interior Tab must not be intercepted');
  });

  it('pulls focus back into the dialog when focus is outside it', () => {
    render(<Harness />);
    openOuter();
    $('bg-btn').focus();
    const event = press($('bg-btn'), 'Tab');
    assert.ok(event.defaultPrevented);
    assert.strictEqual(document.activeElement, $('x'));
  });

  it('makes background content inert and hidden while open, and restores prior state on close', () => {
    render(<Harness />);
    openOuter();
    for (const id of ['bg', 'opener']) {
      assert.ok($(id).hasAttribute('inert'), `${id} must be inert`);
      assert.strictEqual($(id).getAttribute('aria-hidden'), 'true');
    }
    assert.ok(!document.querySelector('.modal-backdrop')!.hasAttribute('inert'), 'dialog must stay interactive');
    press(document.activeElement!, 'Escape');
    for (const id of ['bg', 'opener']) {
      assert.ok(!$(id).hasAttribute('inert'));
      assert.strictEqual($(id).getAttribute('aria-hidden'), null);
    }
    assert.strictEqual($('pre-hidden').getAttribute('aria-hidden'), 'true', 'pre-existing aria-hidden is preserved');
  });

  it('handles nested dialogs: inner takes focus, outer becomes inert, Escape closes only the inner and restores focus', () => {
    render(<Harness />);
    openOuter();
    $('open-inner').focus();
    click($('open-inner'));
    assert.strictEqual(document.activeElement, $('g1'));
    const backdrops = document.querySelectorAll('.modal-backdrop');
    assert.strictEqual(backdrops.length, 2);
    assert.ok(backdrops[0]!.hasAttribute('inert'), 'outer dialog must be inert while inner is open');
    assert.ok(!backdrops[1]!.hasAttribute('inert'));

    press(document.activeElement!, 'Escape');
    assert.strictEqual(document.querySelectorAll('[role="dialog"]').length, 1, 'only the inner dialog closes');
    assert.ok(!document.querySelector('.modal-backdrop')!.hasAttribute('inert'), 'outer dialog is interactive again');
    assert.strictEqual(document.activeElement, $('open-inner'), 'focus returns to the control that opened the inner dialog');

    press(document.activeElement!, 'Escape');
    assert.strictEqual(document.querySelector('[role="dialog"]'), null);
    assert.strictEqual(document.activeElement, $('opener'));
  });

  it('Tab in an outer dialog does nothing while the inner dialog is on top', () => {
    render(<Harness />);
    openOuter();
    $('open-inner').focus();
    click($('open-inner'));
    $('g1').focus();
    const event = press($('g1'), 'Tab'); // inner has one focusable: wraps to itself
    assert.ok(event.defaultPrevented);
    assert.strictEqual(document.activeElement, $('g1'));
  });
});

describe('Tabs: keyboard behaviour on the real components (DOM-simulated)', () => {
  const tabs = () => Array.from(document.querySelectorAll('[role="tab"]')) as HTMLElement[];
  const selected = () => tabs().filter((t) => t.getAttribute('aria-selected') === 'true');

  it('ReportViewer: arrows wrap, Home and End jump, selection and roving tabindex follow, panel is relabelled', () => {
    render(<ReportViewer bundle={createBaseMockBundle()} />);
    assert.strictEqual(tabs().length, 4);
    assert.strictEqual(selected().length, 1);
    assert.strictEqual(selected()[0], tabs()[0]);
    tabs()[0]!.focus();

    press(tabs()[0]!, 'ArrowRight');
    assert.strictEqual(selected()[0], tabs()[1]);
    assert.strictEqual(document.activeElement, tabs()[1]);
    assert.deepStrictEqual(tabs().map((t) => t.tabIndex), [-1, 0, -1, -1]);
    assert.strictEqual(document.querySelector('[role="tabpanel"]')!.getAttribute('aria-labelledby'), tabs()[1]!.id);

    press(tabs()[1]!, 'End');
    assert.strictEqual(selected()[0], tabs()[3]);
    press(tabs()[3]!, 'ArrowRight');
    assert.strictEqual(selected()[0], tabs()[0], 'ArrowRight wraps to the first tab');
    press(tabs()[0]!, 'ArrowLeft');
    assert.strictEqual(selected()[0], tabs()[3], 'ArrowLeft wraps to the last tab');
    press(tabs()[3]!, 'Home');
    assert.strictEqual(selected()[0], tabs()[0]);
    assert.strictEqual(document.activeElement, tabs()[0]);
  });

  it('ReportViewer: unrelated keys are ignored', () => {
    render(<ReportViewer bundle={createBaseMockBundle()} />);
    const event = press(tabs()[0]!, 'a');
    assert.ok(!event.defaultPrevented);
    assert.strictEqual(selected()[0], tabs()[0]);
  });

  it('InvestigationWorkspace: five tabs navigate with the keyboard and keep their order', async () => {
    (globalThis as { fetch?: unknown }).fetch = () => Promise.reject(new TypeError('stubbed network'));
    await act(async () => {
      root.render(
        <AuthProvider>
          <InvestigationWorkspace
            caseId="c1"
            initialCaseDetail={{ id: 'c1', case_number: 'CASE-1', title: 'T', description: null, severity: 'low', status: 'open', lead_analyst_id: 'a', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', closed_at: null, closure_reason: null } as never}
            initialEvidence={[]}
            initialActivity={[]}
            onBackToQueue={() => {}}
          />
        </AuthProvider>,
      );
    });
    assert.strictEqual(tabs().length, 5);
    assert.deepStrictEqual(tabs().map((t) => t.id), ['ws-tab-evidence', 'ws-tab-findings', 'ws-tab-context', 'ws-tab-multisource', 'ws-tab-activity']);
    tabs()[0]!.focus();
    press(tabs()[0]!, 'ArrowLeft');
    assert.strictEqual(selected()[0]!.id, 'ws-tab-activity', 'wraps to the last tab');
    assert.strictEqual(document.activeElement!.id, 'ws-tab-activity');
    press(tabs()[4]!, 'Home');
    assert.strictEqual(selected()[0]!.id, 'ws-tab-evidence');
    assert.strictEqual(document.querySelector('[role="tabpanel"]')!.getAttribute('aria-labelledby'), 'ws-tab-evidence');
  });

  it('Navbar stays navigation: aria-current on the active page, no tab roles', () => {
    render(<AuthProvider><Navbar currentTab="cases" onSelectTab={() => {}} /></AuthProvider>);
    const current = document.querySelectorAll('nav [aria-current="page"]');
    assert.strictEqual(current.length, 1);
    assert.strictEqual(current[0]!.textContent, 'Cases');
    assert.strictEqual(document.querySelectorAll('[role="tab"]').length, 0);
  });
});

describe('Safe error presentation in the real UI (DOM-simulated)', () => {
  const SENSITIVE = [
    'psycopg', 'SELECT', 'password', 'secret_value_123', '/app/backend', 'Traceback', '10.0.0.5', 'ollama', 'OperationalError',
  ];

  const stubFetch = (status: number, body: unknown, headers: Record<string, string> = {}) => {
    (globalThis as { fetch?: unknown }).fetch = () =>
      Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } }));
  };

  it('a 500 with a diagnostic body renders only a generic message plus the request reference', async () => {
    stubFetch(
      500,
      { detail: 'psycopg.OperationalError: SELECT * FROM cases WHERE password=secret_value_123 at /app/backend/db.py line 4 host 10.0.0.5 ollama Traceback' },
      { 'X-Request-ID': 'abcdef0123456789' },
    );
    await act(async () => { root.render(<AuthProvider><Cases /></AuthProvider>); });
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    const alertBox = document.querySelector('[role="alert"]');
    assert.ok(alertBox, 'an alert must be shown');
    const text = alertBox!.textContent!;
    assert.ok(text.includes('The server could not complete the request'));
    assert.ok(text.includes('Reference: abcdef0123456789'));
    for (const s of SENSITIVE) assert.ok(!document.body.textContent!.includes(s), `must not show "${s}"`);
  });

  it('a network failure never shows the runtime error text', async () => {
    (globalThis as { fetch?: unknown }).fetch = () => Promise.reject(new TypeError('fetch failed: connect ECONNREFUSED 127.0.0.1:8000'));
    await act(async () => { root.render(<AuthProvider><Cases /></AuthProvider>); });
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    const text = document.querySelector('[role="alert"]')!.textContent!;
    assert.ok(text.includes('Unable to reach the AISOP service'));
    assert.ok(!text.includes('ECONNREFUSED') && !text.includes('127.0.0.1'));
  });
});

describe('Audit details disclosure (DOM-simulated; real keyboard activation is covered by the headless real-input driver and the owner checklist)', () => {
  const audit = (id: string, details: unknown, action = 'investigation_synthesized') =>
    ({ id, case_id: 'c', actor_username: 'a', action, created_at: '2026-10-31T10:05:00Z', details } as never);

  const Table: React.FC<{ rows: ReturnType<typeof audit>[] }> = ({ rows }) => {
    const [open, setOpen] = useState<Set<string>>(new Set());
    const toggle = (id: string) => setOpen((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
    return (
      <table>
        <tbody>
          {rows.map((r: any) => (
            <React.Fragment key={r.id}>
              <tr><td><AuditDetailsCell audit={r} expanded={open.has(r.id)} onToggle={toggle} when="2026-10-31 10:05:00 UTC" /></td></tr>
              <AuditDetailsRow audit={r} expanded={open.has(r.id)} columns={1} when="2026-10-31 10:05:00 UTC" />
            </React.Fragment>
          ))}
        </tbody>
      </table>
    );
  };
  const btn = (n = 0) => Array.from(document.querySelectorAll('button[aria-expanded]'))[n] as HTMLButtonElement;

  it('is a real, named button with aria-expanded and aria-controls that resolve', () => {
    render(<Table rows={[audit('a-1', { decision: 'pass', grounding_score: 0.94 })]} />);
    const b = btn();
    assert.strictEqual(b.tagName, 'BUTTON');
    assert.strictEqual(b.getAttribute('type'), 'button');
    assert.strictEqual(b.getAttribute('aria-expanded'), 'false');
    assert.ok(b.getAttribute('aria-label')!.startsWith('Show details'), 'visible label is contained at the start of the name');
    assert.ok(b.getAttribute('aria-label')!.includes('investigation_synthesized') && b.getAttribute('aria-label')!.includes('2026-10-31'));
    const target = document.getElementById(b.getAttribute('aria-controls')!);
    assert.ok(target, 'aria-controls resolves while collapsed');
    assert.ok(target!.hidden, 'collapsed region is hidden from everyone, including assistive technology');
  });

  it('expands to the full pretty-printed text and collapses again', () => {
    const details = { decision: 'pass', long: 'x'.repeat(400), nested: { a: [1, 2, 3] } };
    render(<Table rows={[audit('a-1', details)]} />);
    click(btn());
    assert.strictEqual(btn().getAttribute('aria-expanded'), 'true');
    assert.ok(btn().getAttribute('aria-label')!.startsWith('Hide details'));
    const region = document.getElementById(btn().getAttribute('aria-controls')!)!;
    assert.ok(!region.hidden);
    assert.strictEqual(region.querySelector('pre')!.textContent, JSON.stringify(details, null, 2), 'full text, nothing truncated');
    assert.ok(region.textContent!.includes('x'.repeat(400)));
    click(btn());
    assert.strictEqual(btn().getAttribute('aria-expanded'), 'false');
    assert.ok(region.hidden);
  });

  it('the disclosed region is a named, focusable, wrapped scroll area', () => {
    render(<Table rows={[audit('a-1', { k: 'v' })]} />);
    click(btn());
    const scroller = document.querySelector('[role="region"]') as HTMLElement;
    assert.ok(scroller.getAttribute('aria-label')!.startsWith('Details for investigation_synthesized'));
    assert.strictEqual(scroller.tabIndex, 0, 'keyboard users can focus it to scroll long content');
    const pre = scroller.querySelector('pre') as HTMLElement;
    assert.strictEqual(pre.style.whiteSpace, 'pre-wrap');
    assert.strictEqual(pre.style.overflowWrap, 'anywhere');
  });

  it('empty details (null, undefined, {}) render no button and no region', () => {
    for (const d of [null, undefined, {}]) {
      render(<Table rows={[audit('e', d)]} />);
      assert.strictEqual(document.querySelectorAll('button[aria-expanded]').length, 0);
      assert.strictEqual(document.querySelectorAll('[role="region"]').length, 0);
      assert.ok(document.body.textContent!.includes('No details recorded'));
    }
  });

  it('multiline and markup-like values are shown as text, never as HTML', () => {
    const details = { note: 'line one\nline two\n<script>alert(1)</script><img src=x onerror=alert(1)>' };
    render(<Table rows={[audit('m', details)]} />);
    click(btn());
    assert.strictEqual(document.querySelectorAll('script, img').length, 0);
    assert.ok(document.querySelector('pre')!.textContent!.includes('<script>alert(1)</script>'));
    assert.ok(document.querySelector('pre')!.textContent!.includes('\\n'), 'newlines inside values stay visible as escapes in JSON');
  });

  it('rows are independent and ids are unique and DOM-safe even for odd audit ids', () => {
    render(<Table rows={[audit('x y"1', { a: 1 }), audit('x_y_1', { b: 2 }, 'created')]} />);
    const ids = Array.from(document.querySelectorAll('button[aria-controls]')).map((b) => b.getAttribute('aria-controls'));
    assert.ok(ids.every((i) => /^audit-details-[A-Za-z0-9_-]+$/.test(i!)));
    click(btn(0));
    assert.strictEqual(btn(0).getAttribute('aria-expanded'), 'true');
    assert.strictEqual(btn(1).getAttribute('aria-expanded'), 'false');
  });

  it('formatAuditDetails never throws (circular input) and reports emptiness', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    assert.strictEqual(formatAuditDetails(circular as never).isEmpty, true);
    assert.strictEqual(formatAuditDetails({ a: 1 } as never).isEmpty, false);
    assert.strictEqual(formatAuditDetails({} as never).isEmpty, true);
    assert.strictEqual(auditRegionId('a b/c'), 'audit-details-a_b_c');
  });
});

describe('Consumers classify errors by stable kind, not by message text (Phase 2.3)', () => {
  const stub = (status: number, body: unknown) => {
    (globalThis as { fetch?: unknown }).fetch = () => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }));
  };
  const mount = async () => {
    await act(async () => { root.render(<AuthProvider><MultiSourcePanel caseId="c1" /></AuthProvider>); });
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  };

  it('a 404 envelope is the normal empty state: no error banner', async () => {
    stub(404, { detail: 'x', error: { code: 'RESOURCE_NOT_FOUND', message: 'anything, even without the words not found' } });
    await mount();
    assert.strictEqual(document.querySelectorAll('[role="alert"]').length, 0);
  });

  it('a 500 whose text happens to contain "not found" is still shown as an error', async () => {
    stub(500, { detail: 'Dependency not found', error: { code: 'INTERNAL_ERROR', message: 'Dependency not found' } });
    await mount();
    assert.ok(document.querySelectorAll('[role="alert"]').length >= 1, 'text matching must not hide a server error');
  });

  it('a 403 is shown as an error', async () => {
    stub(403, { detail: 'nope', error: { code: 'PERMISSION_DENIED', message: 'nope' } });
    await mount();
    assert.ok(document.querySelectorAll('[role="alert"]').length >= 1);
  });
});