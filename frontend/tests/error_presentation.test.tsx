/**
 * AISOP Phase 2.1: safe error presentation (pure unit tests, no DOM).
 * Sensitive diagnostic strings must never reach user-facing messages; useful safe validation text is preserved.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { apiErrorFromResponse, networkApiError, safeDetailText, safeRequestId } from '../src/services/errors';

const SENSITIVE_SAMPLES = [
  'psycopg.errors.UndefinedTable: relation "cases" does not exist',
  'sqlalchemy.exc.IntegrityError: duplicate key value violates unique constraint',
  'SELECT id FROM cases WHERE owner = 5',
  'INSERT INTO audit_log (id) VALUES (1)',
  'Traceback (most recent call last):',
  'File "/app/backend/app/services/case_service.py", line 99, in close',
  'C:\\Users\\analyst\\secrets\\config.py failed',
  'cannot connect to 127.0.0.1:5433',
  'upstream 10.20.30.40:11434 refused the request',
  'ollama provider raised ReadTimeout',
  'httpx.ConnectError: all connection attempts failed',
  'invalid api key sk-live-abc',
  'Authorization: Bearer abc.def.ghi',
  'ValueError: bad value',
  'x'.repeat(500),
];

describe('safeDetailText', () => {
  it('rejects every sensitive diagnostic sample', () => {
    for (const sample of SENSITIVE_SAMPLES) {
      assert.strictEqual(safeDetailText(sample), null, `must reject: ${sample.slice(0, 40)}`);
    }
  });
  it('keeps short, useful validation and business messages', () => {
    for (const ok of [
      'Title is required',
      'String should have at least 3 characters',
      'Case is already closed.',
      'Evidence event not found in the normalized store.',
      'Closure reason must not be empty',
    ]) {
      assert.strictEqual(safeDetailText(ok), ok);
    }
  });
  it('normalises whitespace and rejects non-strings', () => {
    assert.strictEqual(safeDetailText('  a   b\n c '), 'a b c');
    assert.strictEqual(safeDetailText(undefined), null);
    assert.strictEqual(safeDetailText({ msg: 'x' }), null);
  });
});

describe('apiErrorFromResponse', () => {
  it('uses fixed messages for 401, 403, 404, 429 regardless of body', () => {
    const body = { detail: 'psycopg SELECT password' };
    assert.strictEqual(apiErrorFromResponse(401, body, null).kind, 'auth');
    assert.strictEqual(apiErrorFromResponse(403, body, null).kind, 'forbidden');
    assert.strictEqual(apiErrorFromResponse(404, body, null).kind, 'not_found');
    const rate = apiErrorFromResponse(429, body, null, '30');
    assert.ok(rate.message.includes('30 seconds'));
    for (const status of [401, 403, 404, 429]) {
      const m = apiErrorFromResponse(status, body, null).message;
      assert.ok(!/psycopg|SELECT|password/.test(m), `status ${status} leaked body text`);
    }
  });
  it('hides all 5xx detail and appends a well-formed request reference', () => {
    for (const sample of SENSITIVE_SAMPLES) {
      const err = apiErrorFromResponse(500, { detail: sample }, 'req-12345678');
      assert.strictEqual(err.kind, 'server');
      assert.ok(err.message.startsWith('The server could not complete the request.'));
      assert.ok(err.message.endsWith('(Reference: req-12345678)'));
      assert.ok(!err.message.includes(sample.slice(0, 20)));
    }
  });
  it('ignores a malformed request id', () => {
    assert.strictEqual(safeRequestId('bad id <script>'), undefined);
    assert.ok(!apiErrorFromResponse(500, {}, '<script>alert(1)</script>').message.includes('Reference'));
  });
  it('keeps a safe 4xx detail but falls back to a generic message for unsafe detail', () => {
    assert.ok(apiErrorFromResponse(400, { detail: 'Title is required' }, null).message.startsWith('Title is required'));
    const generic = apiErrorFromResponse(400, { detail: 'psycopg.OperationalError: SELECT 1' }, null).message;
    assert.ok(generic.startsWith('The request could not be processed.'));
  });
  it('for FastAPI validation arrays shows only msg and never input, loc or ctx', () => {
    const body = {
      detail: [
        { loc: ['body', 'title'], msg: 'String should have at least 3 characters', input: 'hunter2-password-secret', ctx: { min_length: 3 } },
        { loc: ['body', 'x'], msg: 'psycopg SELECT leak', input: 'evidence payload 10.1.1.1' },
      ],
    };
    const m = apiErrorFromResponse(422, body, null).message;
    assert.ok(m.includes('String should have at least 3 characters'));
    assert.ok(!/hunter2|evidence payload|10\.1\.1\.1|psycopg|body/.test(m));
  });
  it('network error is fixed text', () => {
    const e = networkApiError();
    assert.strictEqual(e.kind, 'network');
    assert.ok(!/ECONN|fetch failed/.test(e.message));
  });
});

describe('apiErrorFromResponse: stable backend envelope (Phase 2.2)', () => {
  const env = (error: Record<string, unknown>, detail: unknown = 'ignored legacy text') => ({ detail, error });

  it('uses the stable code, the safe message and the envelope request id', () => {
    const err = apiErrorFromResponse(422, env({ code: 'CONTEXT_BUDGET_EXCEEDED', message: 'Mandatory investigation context exceeds maximum evidence budget.', request_id: 'abcdef0123456789' }), 'headerid-12345678');
    assert.strictEqual(err.code, 'CONTEXT_BUDGET_EXCEEDED');
    assert.strictEqual(err.kind, 'validation');
    assert.strictEqual(err.requestId, 'abcdef0123456789', 'envelope id preferred over header');
    assert.ok(err.message.startsWith('Mandatory investigation context exceeds maximum evidence budget.'));
    assert.ok(err.message.endsWith('(Reference: abcdef0123456789)'));
  });
  it('shows field-level details (static messages) and keeps them structured', () => {
    const err = apiErrorFromResponse(422, env({ code: 'VALIDATION_FAILED', message: 'The request failed validation.', details: [
      { field: 'title', code: 'string_too_short', message: 'Value is too short.' },
      { field: 'owner', code: 'uuid_parsing', message: 'Value must be a valid UUID.' },
    ] }), null);
    assert.strictEqual(err.message, 'title: Value is too short. owner: Value must be a valid UUID.');
    assert.strictEqual(err.fieldErrors?.length, 2);
  });
  it('drops unsafe field messages and unsafe envelope messages (defence in depth)', () => {
    const err = apiErrorFromResponse(400, env({ code: 'REQUEST_INVALID', message: 'psycopg SELECT * FROM cases', details: [{ field: 'a', message: 'password=hunter2' }] }), null);
    assert.ok(err.message.startsWith('The request could not be processed.'));
    assert.ok(!/psycopg|SELECT|hunter2/.test(err.message));
  });
  it('5xx: shows a safe envelope message with the reference, otherwise the generic text', () => {
    const ok = apiErrorFromResponse(500, env({ code: 'EVIDENCE_PERSISTENCE_FAILED', message: 'The evidence could not be stored; nothing was imported.', request_id: 'req-12345678' }), null);
    assert.strictEqual(ok.kind, 'server');
    assert.strictEqual(ok.message, 'The evidence could not be stored; nothing was imported. (Reference: req-12345678)');
    const bad = apiErrorFromResponse(500, env({ code: 'INTERNAL_ERROR', message: 'Traceback (most recent call last)' }), 'req-12345678');
    assert.ok(bad.message.startsWith('The server could not complete the request.'));
    assert.ok(!bad.message.includes('Traceback'));
  });
  it('401/403/404/429 keep fixed wording but expose the code', () => {
    assert.strictEqual(apiErrorFromResponse(403, env({ code: 'PERMISSION_DENIED', message: 'x' }), null).code, 'PERMISSION_DENIED');
    assert.ok(apiErrorFromResponse(429, env({ code: 'RATE_LIMITED', message: 'x' }), null, '12').message.includes('12 seconds'));
  });
  it('missing request id: no reference is added and nothing fails', () => {
    const err = apiErrorFromResponse(500, env({ code: 'INTERNAL_ERROR', message: 'The server could not complete the request.' }), null);
    assert.strictEqual(err.message, 'The server could not complete the request.');
    assert.strictEqual(err.requestId, undefined);
  });
  it('malformed envelopes fall back to the legacy path', () => {
    for (const error of ['text', 42, null, [], { code: 'lowercase_code', message: 'x' }, { message: 'no code' }]) {
      const err = apiErrorFromResponse(400, { detail: 'Title is required', error }, null);
      assert.ok(err.message.startsWith('Title is required'), JSON.stringify(error));
      assert.strictEqual(err.code, undefined);
    }
  });
  it('legacy responses (no envelope) behave exactly as before', () => {
    assert.ok(apiErrorFromResponse(400, { detail: 'Title is required' }, null).message.startsWith('Title is required'));
    assert.ok(apiErrorFromResponse(500, { detail: 'anything' }, 'req-12345678').message.startsWith('The server could not complete the request.'));
    assert.ok(apiErrorFromResponse(400, 'not an object', null).message.startsWith('The request could not be processed.'));
    assert.ok(apiErrorFromResponse(400, undefined, null).message.startsWith('The request could not be processed.'));
  });
  it('a hostile envelope request id is ignored', () => {
    const err = apiErrorFromResponse(500, env({ code: 'INTERNAL_ERROR', message: 'The server could not complete the request.', request_id: '<script>x</script>' }), 'header-id-12345678');
    assert.strictEqual(err.requestId, 'header-id-12345678');
  });
});
// ── Plain-language explanations for fixed backend codes (UX review U6, U7) ─────────────────────────────────────
import { explainRecordCode, whatWouldRaiseVerdict } from '../src/utils/explain';

describe('explainRecordCode', () => {
  it('explains known rejection and quarantine codes in a full sentence', () => {
    assert.match(explainRecordCode('TIMESTAMP_MISSING_OR_INVALID'), /no usable event time/);
    assert.match(explainRecordCode('NO_ADAPTER'), /No parser recognises/);
    assert.match(explainRecordCode('FIELD_INVALID:ip'), /"ip".*invalid format/);
    assert.match(explainRecordCode('FIELD_MISSING:source'), /"source".*missing/);
    assert.match(explainRecordCode('ADAPTER_ERROR:KeyError'), /parser failed/);
  });
  it('never invents text for an unknown code and never echoes anything beyond the code', () => {
    assert.strictEqual(explainRecordCode('SOMETHING_NEW'), 'SOMETHING_NEW');
    assert.strictEqual(explainRecordCode('FIELD_INVALID'), 'FIELD_INVALID');
  });
  it('uses no em dashes (interface copy rule)', () => {
    for (const c of ['TIMESTAMP_MISSING_OR_INVALID', 'NO_ADAPTER', 'RECORD_TOO_LARGE', 'FIELD_INVALID:x']) assert.ok(!explainRecordCode(c).includes('—'));
  });
});

describe('whatWouldRaiseVerdict', () => {
  it('maps reason codes to distinct next steps and ignores qualifiers', () => {
    const out = whatWouldRaiseVerdict(['UNCORROBORATED_QUESTION', 'WEAK_LINK_ONLY:host', 'UNCORROBORATED_QUESTION']);
    assert.strictEqual(out.length, 2);
    assert.match(out[0], /independent source/);
  });
  it('returns nothing for codes that are disclosures only or unknown', () => {
    assert.deepStrictEqual(whatWouldRaiseVerdict(['DUPLICATE_EVIDENCE_COLLAPSED', 'IRRELEVANT_EVIDENCE_EXCLUDED', 'NOT_A_CODE']), []);
  });
});

// ── Pasted API key handling (browser check, 2026-11-20) ────────────────────────────────────────────────────────
import { apiKeyShapeHint, normalizeApiKey } from '../src/utils/apiKey';

const GOOD_KEY = 'aisop_live_' + 'a1b2c3d4e5f60718' + '_' + '0123456789abcdef'.repeat(4);

describe('normalizeApiKey', () => {
  it('removes every kind of whitespace, including a newline inside the value', () => {
    assert.strictEqual(normalizeApiKey(`  ${GOOD_KEY}\r\n`), GOOD_KEY);
    assert.strictEqual(normalizeApiKey(`${GOOD_KEY.slice(0, 30)}\n${GOOD_KEY.slice(30)}`), GOOD_KEY);
    assert.strictEqual(normalizeApiKey('a b\tc'), 'abc');
  });
});

describe('apiKeyShapeHint', () => {
  it('has nothing to say about a well-formed key or an empty field', () => {
    assert.strictEqual(GOOD_KEY.length, 92);
    assert.strictEqual(apiKeyShapeHint(GOOD_KEY), null);
    assert.strictEqual(apiKeyShapeHint('  '), null);
  });
  it('detects a key pasted twice, with or without a separator', () => {
    assert.match(apiKeyShapeHint(GOOD_KEY + GOOD_KEY) ?? '', /pasted 2 times/);
    assert.match(apiKeyShapeHint(`${GOOD_KEY} ${GOOD_KEY}`) ?? '', /pasted 2 times/);
  });
  it('detects a key with extra text or a missing part, and tells the length', () => {
    assert.match(apiKeyShapeHint(GOOD_KEY + 'extra') ?? '', /97 characters.*92/);
    assert.match(apiKeyShapeHint(GOOD_KEY.slice(0, 50)) ?? '', /50 characters.*92/);
  });
  it('does not block a different kind of key, and never echoes the key itself', () => {
    const hint = apiKeyShapeHint('legacy-key-123') ?? '';
    assert.match(hint, /can still be saved/);
    assert.ok(!hint.includes('legacy-key-123'));
    assert.ok(!(apiKeyShapeHint(GOOD_KEY + GOOD_KEY) ?? '').includes(GOOD_KEY));
  });
  it('uses no em dashes (interface copy rule)', () => {
    for (const k of [GOOD_KEY + GOOD_KEY, GOOD_KEY + 'x', 'nope']) assert.ok(!(apiKeyShapeHint(k) ?? '').includes('—'));
  });
});

describe('401 message', () => {
  it('tells the person what to do', () => {
    const e = apiErrorFromResponse(401, { detail: 'secret server text' }, null, null);
    assert.match(e.message, /did not accept this API key/);
    assert.match(e.message, /Clear key/);
    assert.ok(!e.message.includes('secret server text'));
  });
});

import { isAuthMessage } from '../src/components/SetupNotice';

describe('auth messages are recognised so a refused request is shown as a setup step, never as "0 results"', () => {
  it('matches the 401 message shown to the person', () => {
    assert.ok(isAuthMessage(apiErrorFromResponse(401, null, null, null).message));
    assert.ok(!isAuthMessage(apiErrorFromResponse(500, null, null, null).message));
  });
});

// ── Optional AI explanation: hard deadline, cancel, and an unchanged deterministic result ──────────────────────
import { runWithDeadline } from '../src/utils/deadline';

const never = (): Promise<string> => new Promise(() => {});                      // a task that never settles and ignores abort
const later = (ms: number, v: string): Promise<string> => new Promise((r) => setTimeout(() => r(v), ms));

describe('runWithDeadline', () => {
  it('returns the value when the task finishes in time', async () => {
    const h = runWithDeadline(async () => 'explained', 500);
    assert.deepStrictEqual(await h.result, { kind: 'done', value: 'explained' });
  });
  it('times out a task that never settles, even if it ignores the abort signal', async () => {
    const t0 = Date.now();
    const out = await runWithDeadline(never, 40).result;
    assert.deepStrictEqual(out, { kind: 'timeout' });
    assert.ok(Date.now() - t0 < 1000);
  });
  it('a late result after the deadline never replaces the timeout outcome', async () => {
    const out = await runWithDeadline(() => later(120, 'too late'), 30).result;
    assert.deepStrictEqual(out, { kind: 'timeout' });
    await later(200, 'wait');                                                  // nothing throws and nothing changes afterwards
  });
  it('cancel stops waiting and reports cancelled; the signal is aborted for the task', async () => {
    let aborted = false;
    const h = runWithDeadline((signal) => new Promise<string>((_r, rej) => signal.addEventListener('abort', () => { aborted = true; rej(new Error('aborted')); })), 5000);
    setTimeout(() => h.cancel(), 20);
    assert.deepStrictEqual(await h.result, { kind: 'cancelled' });
    assert.ok(aborted);
  });
  it('a failing task becomes failed with its safe message and is not retried', async () => {
    let calls = 0;
    const out = await runWithDeadline(async () => { calls += 1; throw new Error('The service is unavailable.'); }, 500).result;
    assert.deepStrictEqual(out, { kind: 'failed', message: 'The service is unavailable.' });
    assert.strictEqual(calls, 1);
  });
  it('cancel after completion is ignored', async () => {
    const h = runWithDeadline(async () => 'ok', 500);
    const out = await h.result;
    h.cancel();
    assert.deepStrictEqual(out, { kind: 'done', value: 'ok' });
  });
});
