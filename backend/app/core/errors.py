"""
AISOP stable API error contract (Phase 2.2).

Every error response keeps the legacy top-level ``detail`` field (existing consumers keep working) and adds a stable
``error`` envelope::

    {
      "detail": "<safe message>",                      # legacy, same safe text as error.message (or the legacy list for 422)
      "error": {
        "code": "VALIDATION_FAILED",                   # stable, machine readable, UPPER_SNAKE_CASE
        "message": "<safe, user-facing message>",
        "request_id": "<server-generated id>",         # only when the correlation middleware ran
        "details": [{"field": "title", "code": "string_too_short", "message": "..."}]   # 422 only, never echoes input
      }
    }

Rules enforced here:
- No exception text, traceback, SQL, path, credential, provider detail or submitted value is ever placed in a response
  unless it is a short developer-authored message that passes ``looks_unsafe`` (a backstop, not a proof).
- 5xx responses always carry a fixed message. Diagnostics go to the internal log, redacted by type and length only.
- ``request_id`` comes from the server-side correlation middleware (always server generated), never from a client body.
- Business logic, status codes and authentication policy are unchanged.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.diagnostics import emit_diagnostic

# ── Stable codes ──────────────────────────────────────────────────────────────
REQUEST_INVALID = "REQUEST_INVALID"
VALIDATION_FAILED = "VALIDATION_FAILED"
AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
PERMISSION_DENIED = "PERMISSION_DENIED"
RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
CONFLICT = "CONFLICT"
PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
RATE_LIMITED = "RATE_LIMITED"
SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
INTERNAL_ERROR = "INTERNAL_ERROR"
# Specific codes used at call sites
QUERY_PARAMETER_INVALID = "QUERY_PARAMETER_INVALID"
CONTEXT_INTEGRITY_FAILED = "CONTEXT_INTEGRITY_FAILED"
CONTEXT_BUDGET_EXCEEDED = "CONTEXT_BUDGET_EXCEEDED"
REPORT_PARAMETER_INVALID = "REPORT_PARAMETER_INVALID"
EVIDENCE_PERSISTENCE_FAILED = "EVIDENCE_PERSISTENCE_FAILED"

CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")

_STATUS_CODES: dict[int, str] = {
    400: REQUEST_INVALID,
    401: AUTHENTICATION_REQUIRED,
    403: PERMISSION_DENIED,
    404: RESOURCE_NOT_FOUND,
    405: METHOD_NOT_ALLOWED,
    409: CONFLICT,
    413: PAYLOAD_TOO_LARGE,
    415: UNSUPPORTED_MEDIA_TYPE,
    422: VALIDATION_FAILED,
    429: RATE_LIMITED,
    503: SERVICE_UNAVAILABLE,
}

_GENERIC_MESSAGES: dict[str, str] = {
    REQUEST_INVALID: "The request could not be processed.",
    VALIDATION_FAILED: "The request failed validation.",
    AUTHENTICATION_REQUIRED: "Authentication is required.",
    PERMISSION_DENIED: "You do not have permission to perform this action.",
    RESOURCE_NOT_FOUND: "The requested resource was not found.",
    METHOD_NOT_ALLOWED: "This method is not allowed for the resource.",
    CONFLICT: "The request conflicts with the current state of the resource.",
    PAYLOAD_TOO_LARGE: "The request body is too large.",
    UNSUPPORTED_MEDIA_TYPE: "The request content type is not supported.",
    RATE_LIMITED: "Too many requests. Please slow down.",
    SERVICE_UNAVAILABLE: "The service is temporarily unavailable.",
    INTERNAL_ERROR: "The server could not complete the request.",
}

INTERNAL_MESSAGE = _GENERIC_MESSAGES[INTERNAL_ERROR]


def code_for_status(status_code: int) -> str:
    if status_code in _STATUS_CODES:
        return _STATUS_CODES[status_code]
    if status_code >= 500:
        return INTERNAL_ERROR
    return REQUEST_INVALID


def generic_message(code: str) -> str:
    return _GENERIC_MESSAGES.get(code, _GENERIC_MESSAGES[REQUEST_INVALID])


# ── Safety backstop ───────────────────────────────────────────────────────────
MAX_SAFE_TEXT = 240
_UNSAFE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"traceback|stack ?trace",
        r"\bat\s+\S+\s*\([^)]*:\d+",
        r"\b(select|insert|update|delete)\b[^.]{0,120}\b(from|into|set|where)\b",
        r"\b(sqlalchemy|psycopg\w*|asyncpg|postgres(ql)?|pgvector|sqlstate|dbapi|alembic)\b",
        r"[a-z]:\\",
        r"(^|[\s\"'(=])/(usr|home|var|etc|app|opt|srv|tmp|root|mnt|proc|backend)/",
        r"\.(py|pyc|ts|tsx|js|mjs)\b",
        r"\bFile \"",
        r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal)\b",
        r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b",
        r"\b(ollama|httpx|httpcore|openai|anthropic|uvicorn|starlette|fastapi|pydantic|asyncio|errno|connection refused)\b",
        # Secret-looking assignments and bearer values (plain words such as "credentials" in authored messages are allowed).
        r"\b(password|passwd|secret|token|api[-_ ]?key|authorization)\s*[=:]\s*\S",
        r"\bbearer\s+[A-Za-z0-9._~+/\-]{8,}",
    )
] + [re.compile(r"\b[A-Z]\w*(Error|Exception)\b")]


def looks_unsafe(text: str) -> bool:
    """Conservative backstop for developer-authored messages. Returns True when the text must not be shown."""
    collapsed = " ".join(text.split())
    if not collapsed or len(collapsed) > MAX_SAFE_TEXT:
        return True
    return any(p.search(collapsed) for p in _UNSAFE_PATTERNS)


def safe_exception_text(exc: BaseException, fallback: str) -> str:
    """Developer-authored ValueError-style text if it passes the backstop, otherwise the fixed fallback."""
    text = " ".join(str(exc).split())
    return fallback if looks_unsafe(text) else text


def request_id_from(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    value = getattr(getattr(request, "state", None), "request_id", None)
    return value if isinstance(value, str) and value else None


# ── Typed error for call sites ────────────────────────────────────────────────
class ApiError(HTTPException):
    """HTTPException with a stable code. ``detail`` is the (already safe) message."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.code = code


class CodedHTTPException(HTTPException):
    """Drop-in HTTPException with a stable, shared domain code (keyword-only ``code``).

    Status and ``detail`` behave exactly as for ``HTTPException``; the handler adds ``error.code``.
    Use a shared code for a recurring outcome (for example CASE_TERMINAL_STATE), never one code per call site.
    """

    def __init__(self, status_code: int, detail: Any = None, headers: Optional[dict[str, str]] = None, *, code: str) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code


#: Every code a call site may use. A test fails if a source literal is missing here or malformed.
DOMAIN_CODES: frozenset[str] = frozenset(
    {
        "ACCOUNT_DEACTIVATED",
        "AUTHORIZATION_REVOKED",
        "MACHINE_CREDENTIAL_NOT_PERMITTED",
        "UNSCOPED_ENDPOINT_DISABLED",
        "CASE_TERMINAL_STATE",
        "CASE_CREATION_LIMIT_REACHED",
        "EVIDENCE_ALREADY_LINKED",
        "ASSIGNMENT_ALREADY_EXISTS",
        "SYNTHESIS_INPUT_CHANGED",
        "EVIDENCE_NOT_FOUND",
        "DUPLICATE_EVIDENCE_IDS",
        "ASSIGNMENT_TARGET_INVALID",
        "LEADERSHIP_RULE_VIOLATION",
        "NOT_CASE_LEAD",
        "AUTHORIZATION_SERVICE_UNAVAILABLE",
        "AUTHENTICATION_SERVICE_UNAVAILABLE",
        "AUDIT_LOGGING_FAILED",
        "REPORT_FORMATTING_FAILED",
        "INVALID_CASE_IDENTIFIER",
        "QUERY_PARAMETER_INVALID",
        "CONTEXT_INTEGRITY_FAILED",
        "CONTEXT_BUDGET_EXCEEDED",
        "REPORT_PARAMETER_INVALID",
        "EVIDENCE_PERSISTENCE_FAILED",
    }
)

class StructuredHttpError(HTTPException):
    """HTTPException whose `detail` is a deliberate structured object (for example the readiness report). The route has a
    special contract, so `detail` is preserved as-is for existing consumers and the envelope is added alongside.
    Only use it with an object the route itself has already sanitised."""

    def __init__(self, status_code: int, code: str, message: str, detail: Any) -> None:
        super().__init__(status_code=status_code, detail=detail)
        self.code = code
        self.message = message


# ── Envelope ──────────────────────────────────────────────────────────────────
def build_body(
    code: str,
    message: str,
    request_id: Optional[str],
    *,
    legacy_detail: Any = None,
    details: Optional[list[dict[str, str]]] = None,
    error_extra: Optional[dict[str, Any]] = None,
    top_level_extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if request_id:
        error["request_id"] = request_id
    if details:
        error["details"] = details
    if error_extra:
        error.update(error_extra)
    body: dict[str, Any] = {"detail": message if legacy_detail is None else legacy_detail, "error": error}
    if top_level_extra:
        body.update(top_level_extra)
    return body

def error_response(
    status_code: int,
    code: str,
    message: str,
    request: Optional[Request] = None,
    *,
    request_id: Optional[str] = None,
    headers: Optional[dict[str, str]] = None,
    **kwargs: Any,
) -> JSONResponse:
    rid = request_id if request_id is not None else request_id_from(request)
    out_headers = dict(headers or {})
    if rid:
        out_headers.setdefault("X-Request-ID", rid)
    return JSONResponse(status_code=status_code, content=build_body(code, message, rid, **kwargs), headers=out_headers)


# ── Validation errors (422): static messages, never the submitted value ───────
_VALIDATION_MESSAGES: dict[str, str] = {
    "missing": "Field is required.",
    "string_too_short": "Value is too short.",
    "string_too_long": "Value is too long.",
    "too_short": "Too few items.",
    "too_long": "Too many items.",
    "greater_than": "Value is too small.",
    "greater_than_equal": "Value is too small.",
    "less_than": "Value is too large.",
    "less_than_equal": "Value is too large.",
    "string_type": "Value must be text.",
    "int_type": "Value must be an integer.",
    "int_parsing": "Value must be an integer.",
    "float_type": "Value must be a number.",
    "float_parsing": "Value must be a number.",
    "bool_type": "Value must be true or false.",
    "bool_parsing": "Value must be true or false.",
    "list_type": "Value must be a list.",
    "dict_type": "Value must be an object.",
    "model_type": "Value must be an object.",
    "uuid_parsing": "Value must be a valid UUID.",
    "uuid_type": "Value must be a valid UUID.",
    "datetime_parsing": "Value must be a valid date and time.",
    "datetime_type": "Value must be a valid date and time.",
    "date_parsing": "Value must be a valid date.",
    "json_invalid": "The request body is not valid JSON.",
    "json_type": "The request body is not valid JSON.",
    "extra_forbidden": "Unexpected field.",
    "enum": "Value is not one of the allowed options.",
    "literal_error": "Value is not one of the allowed options.",
    "string_pattern_mismatch": "Value has an invalid format.",
    "value_error": "Value failed validation.",
    "assertion_error": "Value failed validation.",
}
_ALLOWED_LOC_PART = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def _field_from_loc(loc: Any) -> str:
    parts = [str(p) for p in (loc or ()) if str(p) not in ("body", "query", "path", "header", "cookie")]
    safe = [p if (_ALLOWED_LOC_PART.match(p) or p.isdigit()) else "?" for p in parts]
    return ".".join(safe)[:120]


def _value_error_message(err: dict[str, Any]) -> Optional[str]:
    """Developer-authored validator text, only if safe and not reflecting the submitted value."""
    msg = str(err.get("msg", ""))
    if msg.startswith("Value error, "):
        msg = msg[len("Value error, "):]
    submitted = err.get("input")
    if isinstance(submitted, (str, int, float)):
        needle = str(submitted)
        if len(needle) >= 4 and needle in msg:
            return None
    if "!r" in msg or looks_unsafe(msg):
        return None
    return " ".join(msg.split())


def safe_validation_details(errors: list[dict[str, Any]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for err in errors[:20]:
        etype = str(err.get("type", "invalid"))
        etype_safe = etype if re.match(r"^[a-z0-9_.]{1,64}$", etype) else "invalid"
        message = _VALIDATION_MESSAGES.get(etype_safe)
        if etype_safe == "value_error":
            message = _value_error_message(err) or message
        out.append({"field": _field_from_loc(err.get("loc")), "code": etype_safe, "message": message or "Value is invalid."})
    return out


# ── Handlers ──────────────────────────────────────────────────────────────────
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    status_code = exc.status_code
    code = getattr(exc, "code", None)
    if not (isinstance(code, str) and CODE_PATTERN.match(code)):
        code = code_for_status(status_code)
    detail = exc.detail
    rid = request_id_from(request)
    if status_code >= 500 and not isinstance(exc, StructuredHttpError):
        # One restricted diagnostic record (type, code, origin, fingerprint; never the message). The readiness 503 is a
        # deliberate operational response, not an error to diagnose, so it is excluded.
        emit_diagnostic(request, exc, status=status_code, code=code)
    if isinstance(exc, StructuredHttpError):
        return error_response(
            status_code, code, exc.message, request, legacy_detail=jsonable_encoder(detail), headers=getattr(exc, "headers", None)
        )
    if isinstance(detail, str) and not looks_unsafe(detail):
        # Developer-authored text (static messages or ApiError) that passes the backstop is kept, so legacy `detail`
        # text and existing consumers are unchanged.
        message = " ".join(detail.split())
    else:
        # Anything else (unsafe-looking text, non-string detail) is withheld; only its type is logged.
        logger.bind(component="http", request_id=rid).warning(
            "HTTP {} detail withheld by safety backstop: detail_type={}", status_code, type(detail).__name__
        )
        message = generic_message(code)
    return error_response(status_code, code, message, request, headers=getattr(exc, "headers", None))


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    details = safe_validation_details(list(exc.errors()))
    legacy = [{"loc": [d["field"]] if d["field"] else [], "msg": d["message"], "type": d["code"]} for d in details]
    return error_response(
        422, VALIDATION_FAILED, generic_message(VALIDATION_FAILED), request, legacy_detail=legacy, details=details
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Diagnostics stay in the restricted internal record: exception type, code, route template, origin and a message
    # fingerprint, never the message itself (it can hold evidence text or SQL).
    emit_diagnostic(request, exc, status=500, code=INTERNAL_ERROR)
    return error_response(500, INTERNAL_ERROR, INTERNAL_MESSAGE, request)


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)


__all__ = [
    "ApiError",
    "CodedHTTPException",
    "DOMAIN_CODES",
    "StructuredHttpError",
    "CODE_PATTERN",
    "build_body",
    "code_for_status",
    "error_response",
    "generic_message",
    "install_error_handlers",
    "looks_unsafe",
    "request_id_from",
    "safe_exception_text",
    "safe_validation_details",
]
