/**
 * OWASP A01/A02/A07: API credential handling in the browser client.
 *
 * Threat model: the key lives in memory and, for a refresh-survivable convenience, in sessionStorage (tab scoped, cleared when the tab
 * closes). sessionStorage is readable by any script in the origin, so it is NOT an XSS boundary; the defences are the strict CSP
 * (script-src 'self'), React output escaping and the absence of HTML sinks. These tests pin the rest: the key never reaches
 * localStorage, a URL, an error message or the console; the only credential header is X-API-Key; no role or identity is ever sent
 * (the "view as" role selector is presentation only, the server decides from the key); Clear removes the key everywhere.
 */
import { dom } from './dom_setup';
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { api } from '../src/services/api';

const KEY = 'aisop_live_0123456789abcdef_' + 'ab'.repeat(32);

type Call = { url: string; headers: Record<string, string>; body?: unknown };
const realFetch = globalThis.fetch;
const consoleSpies: Array<[keyof Console, unknown]> = [];
let calls: Call[] = [];
let logged: string[] = [];

function stubFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), headers: { ...(init?.headers as Record<string, string>) }, body: init?.body });
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  }) as typeof fetch;
}

beforeEach(() => {
  calls = [];
  logged = [];
  dom.window.sessionStorage.clear();
  dom.window.localStorage.clear();
  api.clearApiKey();
  for (const m of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    consoleSpies.push([m, console[m]]);
    console[m] = (...args: unknown[]) => { logged.push(args.map(String).join(' ')); };
  }
});

afterEach(() => {
  globalThis.fetch = realFetch;
  for (const [m, fn] of consoleSpies.splice(0)) (console as unknown as Record<string, unknown>)[m as string] = fn;
});

describe('API key storage (A02, A07)', () => {
  it('persists to sessionStorage only when asked, never to localStorage', () => {
    api.setApiKey(KEY, true);
    assert.strictEqual(dom.window.sessionStorage.getItem('aisop_api_key'), KEY);
    assert.strictEqual(dom.window.localStorage.length, 0);
    for (let i = 0; i < dom.window.localStorage.length; i += 1) assert.fail('localStorage must stay empty');
  });

  it('keeps the key in memory only when persistence is not requested', () => {
    api.setApiKey(KEY, false);
    assert.strictEqual(api.getApiKey(), KEY);
    assert.strictEqual(dom.window.sessionStorage.getItem('aisop_api_key'), null);
    assert.strictEqual(dom.window.localStorage.length, 0);
  });

  it('removes the key from memory and storage on clear, and stops sending it', async () => {
    api.setApiKey(KEY, true);
    api.clearApiKey();
    assert.strictEqual(api.getApiKey(), '');
    assert.strictEqual(dom.window.sessionStorage.getItem('aisop_api_key'), null);
    stubFetch(200, { status: 'ok' });
    await api.getHealth();
    assert.ok(!('X-API-Key' in calls[0].headers), 'a cleared key must not be sent');
  });

  it('setting an empty key (the Clear key button) also removes the stored copy', () => {
    api.setApiKey(KEY, true);
    api.setApiKey('', true);
    assert.strictEqual(dom.window.sessionStorage.getItem('aisop_api_key'), null);
  });

  it('strips whitespace so a pasted newline cannot split the header', () => {
    api.setApiKey(` ${KEY}\r\nX-Injected: 1\n`, false);
    assert.ok(!/\s/.test(api.getApiKey()));
  });
});

describe('request shape (A01)', () => {
  it('sends the key only in the X-API-Key header, never in the URL or body', async () => {
    api.setApiKey(KEY, false);
    stubFetch(200, { items: [], total: 0 });
    await api.getEvents({ page: 1, limit: 5, severity: 'high' });
    const call = calls[0];
    assert.strictEqual(call.headers['X-API-Key'], KEY);
    assert.ok(!call.url.includes(KEY), 'key must not appear in the URL');
    assert.ok(!String(call.body ?? '').includes(KEY));
  });

  it('never sends a role, user or identity header: the View-as selector is presentation only', async () => {
    api.setApiKey(KEY, false);
    dom.window.sessionStorage.setItem('aisop_view_as', 'security_admin');
    stubFetch(200, { items: [], total: 0 });
    await api.getEvents();
    const names = Object.keys(calls[0].headers).map((h) => h.toLowerCase());
    assert.deepStrictEqual(names.sort(), ['accept', 'content-type', 'x-api-key']);
    assert.ok(!calls[0].url.includes('security_admin') && !calls[0].url.toLowerCase().includes('role'));
  });
});

describe('secret hygiene in errors and logs (A02, A09)', () => {
  for (const status of [400, 401, 403, 404, 422, 429, 500, 503]) {
    it(`a ${status} response that echoes the key does not surface it`, async () => {
      api.setApiKey(KEY, false);
      stubFetch(status, { detail: `bad credential ${KEY}`, error: { code: 'REQUEST_INVALID', message: `value ${KEY}` } }, { 'X-Request-ID': 'abcdef123456' });
      let message = '';
      try {
        await api.getEvents();
      } catch (e) {
        message = e instanceof Error ? e.message : String(e);
      }
      assert.ok(message.length > 0, 'an error must be thrown');
      assert.ok(!message.includes(KEY), `status ${status}: key leaked into the error message`);
      assert.ok(!message.includes('aisop_live_'), `status ${status}: key prefix leaked`);
      assert.ok(!logged.some((l) => l.includes(KEY)), 'key must never be logged');
    });
  }

  it('a network failure shows no runtime text and no key', async () => {
    api.setApiKey(KEY, false);
    globalThis.fetch = (async () => { throw new TypeError(`Failed to fetch http://127.0.0.1:8000 with ${KEY}`); }) as typeof fetch;
    let message = '';
    try {
      await api.getHealth();
    } catch (e) {
      message = e instanceof Error ? e.message : String(e);
    }
    assert.ok(message && !message.includes(KEY) && !message.includes('127.0.0.1'));
    assert.ok(!logged.some((l) => l.includes(KEY)));
  });
});
