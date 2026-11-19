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