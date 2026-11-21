/**
 * Safe API error presentation (Phase 2.1).
 *
 * The backend returns FastAPI `{ "detail": ... }` bodies and an `X-Request-ID` response header. It does not return
 * stable error codes, so classification here is by HTTP status. Rules:
 * - 401, 403, 404, 429 and 5xx always use fixed messages (server text is never shown for them).
 * - Other 4xx responses (validation or business rules) keep the server's detail only when it looks safe:
 *   short, single paragraph, with no SQL, stack trace, file path, host or address, secret keyword, library or
 *   exception class name. Otherwise a generic validation message is shown.
 * - FastAPI validation arrays: only each item's `msg` is used, never `input`, `loc` or `ctx` (they can echo evidence).
 * - The request ID (when the backend supplied one in the right format) is appended as a support reference.
 * - Network and parse failures never show the browser's or runtime's raw message.
 */

export type ApiErrorKind = 'auth' | 'forbidden' | 'not_found' | 'rate_limit' | 'validation' | 'server' | 'network' | 'unknown';

export interface ApiFieldError {
  field: string;
  message: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly kind: ApiErrorKind;
  readonly requestId?: string;
  /** Stable machine-readable code from the backend error envelope (absent for legacy responses). */
  readonly code?: string;
  readonly fieldErrors?: ApiFieldError[];

  constructor(
    kind: ApiErrorKind,
    status: number,
    message: string,
    requestId?: string,
    code?: string,
    fieldErrors?: ApiFieldError[],
  ) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind;
    this.status = status;
    this.requestId = requestId;
    this.code = code;
    this.fieldErrors = fieldErrors;
  }
}

const MAX_SAFE_DETAIL_LENGTH = 240;

const UNSAFE_PATTERNS: RegExp[] = [
  /traceback|stack ?trace/i,
  /\bat\s+\S+\s*\([^)]*:\d+/,
  /\b(select|insert|update|delete)\b[^.]{0,120}\b(from|into|set|where)\b/i,
  /\b(sqlalchemy|psycopg\w*|asyncpg|postgres(ql)?|pgvector|sqlstate|dbapi|alembic)\b/i,
  /[A-Za-z]:\\/,
  /(^|[\s"'(=])\/(usr|home|var|etc|app|opt|srv|tmp|root|mnt|proc|backend)\//,
  /\.(py|pyc|ts|tsx|js|mjs)\b/i,
  /\bFile "/,
  /\b(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal)\b/i,
  /\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b/,
  /\b(ollama|httpx|httpcore|openai|anthropic|uvicorn|starlette|fastapi|pydantic|asyncio|errno|connection refused)\b/i,
  /\b(password|passwd|secret|token|api[-_ ]?key|bearer|authorization|credential)s?\b/i,
  /\b[A-Z]\w*(Error|Exception)\b/,
];

/** Returns a normalised, safe message or null when the text must not be shown. */
export function safeDetailText(text: unknown): string | null {
  if (typeof text !== 'string') return null;
  const collapsed = text.replace(/\s+/g, ' ').trim();
  if (!collapsed || collapsed.length > MAX_SAFE_DETAIL_LENGTH) return null;
  if (UNSAFE_PATTERNS.some((pattern) => pattern.test(collapsed))) return null;
  return collapsed;
}

function safeValidationDetail(detail: unknown): string | null {
  if (typeof detail === 'string') return safeDetailText(detail);
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => (item && typeof item === 'object' ? safeDetailText((item as { msg?: unknown }).msg) : null))
      .filter((m): m is string => m !== null);
    return messages.length > 0 ? messages.slice(0, 3).join('; ') : null;
  }
  return null;
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9-]{8,64}$/;

export function safeRequestId(value: string | null | undefined): string | undefined {
  return value && REQUEST_ID_PATTERN.test(value) ? value : undefined;
}

const withReference = (message: string, requestId?: string): string =>
  requestId ? `${message} (Reference: ${requestId})` : message;

const CODE_PATTERN = /^[A-Z][A-Z0-9_]{2,63}$/;

interface ParsedEnvelope {
  code: string;
  message?: string;
  requestId?: string;
  fieldErrors: ApiFieldError[];
}

/** Parse the backend `{ error: { code, message, request_id, details } }` envelope. Returns null for legacy or malformed bodies. */
function parseEnvelope(body: unknown): ParsedEnvelope | null {
  if (!body || typeof body !== 'object') return null;
  const error = (body as { error?: unknown }).error;
  if (!error || typeof error !== 'object') return null;
  const e = error as { code?: unknown; message?: unknown; request_id?: unknown; details?: unknown };
  if (typeof e.code !== 'string' || !CODE_PATTERN.test(e.code)) return null;
  const fieldErrors: ApiFieldError[] = [];
  if (Array.isArray(e.details)) {
    for (const item of e.details.slice(0, 3)) {
      if (!item || typeof item !== 'object') continue;
      const d = item as { field?: unknown; message?: unknown };
      const message = safeDetailText(d.message);
      const field = typeof d.field === 'string' && /^[A-Za-z0-9_.\-]{1,120}$/.test(d.field) ? d.field : '';
      if (message) fieldErrors.push({ field, message });
    }
  }
  return {
    code: e.code,
    message: safeDetailText(e.message) ?? undefined,
    requestId: typeof e.request_id === 'string' ? safeRequestId(e.request_id) : undefined,
    fieldErrors,
  };
}

const GENERIC_SERVER = 'The server could not complete the request. Try again, or contact an administrator.';
const GENERIC_REQUEST = 'The request could not be processed. Check the entered values and try again.';

/**
 * Build the error for a non-OK response. `body` is the parsed JSON body or undefined.
 * Understands the stable envelope (preferred) and falls back to the legacy `{ detail }` shape.
 */
export function apiErrorFromResponse(
  status: number,
  body: unknown,
  requestIdHeader: string | null,
  retryAfterHeader?: string | null,
): ApiError {
  const envelope = parseEnvelope(body);
  // The id inside the envelope is server generated; the header carries the same value. Prefer the envelope.
  const requestId = envelope?.requestId ?? safeRequestId(requestIdHeader);
  const code = envelope?.code;
  if (status === 429) {
    const wait = retryAfterHeader && /^\d{1,4}$/.test(retryAfterHeader) ? `${retryAfterHeader} seconds` : 'a moment';
    return new ApiError('rate_limit', status, `Too many requests. Please wait ${wait} before retrying.`, requestId, code);
  }
  if (status === 401) {
    return new ApiError('auth', status, 'Authentication required. The server did not accept this API key. Open Set API key, press Clear key, paste the key once and save it.', requestId, code);
  }
  if (status === 403) {
    return new ApiError('forbidden', status, 'Access forbidden. Your role has insufficient privileges.', requestId, code);
  }
  if (status === 404) {
    return new ApiError('not_found', status, 'Requested resource not found or access denied.', requestId, code);
  }
  if (status >= 500) {
    // New contract: the backend message is safe by construction (and still filtered here). Legacy: always generic.
    const base = envelope?.message ?? GENERIC_SERVER;
    return new ApiError('server', status, withReference(base, requestId), requestId, code);
  }
  if (envelope) {
    const fields = envelope.fieldErrors.map((f) => (f.field ? `${f.field}: ${f.message}` : f.message)).join(' ');
    const base = fields || envelope.message || GENERIC_REQUEST;
    return new ApiError('validation', status, withReference(base, requestId), requestId, code, envelope.fieldErrors);
  }
  const detail = body && typeof body === 'object' ? safeValidationDetail((body as { detail?: unknown }).detail) : null;
  return new ApiError('validation', status, withReference(detail ?? GENERIC_REQUEST, requestId), requestId);
}
export function networkApiError(): ApiError {
  return new ApiError('network', 0, 'Unable to reach the AISOP service. Check your connection and that the service is running.');
}

export function unreadableResponseError(requestId?: string): ApiError {
  return new ApiError('unknown', 0, withReference('The server returned an unreadable response.', requestId), requestId);
}
