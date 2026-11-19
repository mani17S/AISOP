"""
Restricted internal diagnostic record for server errors (Phase 2.4).

Public responses never contain exception text (see ``app.core.errors``). Operators still need something to debug a 500,
so every 5xx produces ONE structured diagnostic record on a separate ``component="diagnostic"`` channel.

What is logged (strict allowlist, all bounded):
  request_id (server generated), method, route (the route TEMPLATE, never concrete ids), status, error_code,
  exception_class (module-qualified type name), origin {module, function, line} of the innermost AISOP frame,
  message_sha256_12 and message_length (correlate identical errors without revealing the text).

What is NEVER logged by default: the exception message, the stack trace, local variables, source lines, file paths,
request bodies, headers, query strings, evidence, or secrets.

Optional, off by default (``DIAGNOSTIC_LOG_MESSAGE_SHAPE=true``): ``message_shape``, the exception message reduced to its
"shape": quoted text, numbers, ids, hashes, IPs, emails, URLs and paths are masked, long tokens are dropped, and the result
is truncated. This is NOT a guarantee that no sensitive word survives (free text cannot be proven clean); it exists for
restricted environments and is documented as such. Without it the baseline is exception type only.

Logging must never change the API response: every step is wrapped and failures are swallowed.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from types import TracebackType
from typing import Any, Optional

from fastapi import Request
from loguru import logger

from app.core.config import get_settings
from app.core.logging import redact_text

COMPONENT = "diagnostic"
RECORD_MESSAGE = "server error diagnostic"
MAX_CLASS = 120
MAX_ROUTE = 120
MAX_FUNCTION = 80
MAX_SHAPE = 160

_APP_ROOT = Path(__file__).resolve().parent.parent  # .../backend/app
_SAFE_IDENT = re.compile(r"[^A-Za-z0-9_.<>\[\]-]")
_SAFE_ROUTE = re.compile(r"[^A-Za-z0-9_./{}:-]")


def _ident(value: str, limit: int) -> str:
    return _SAFE_IDENT.sub("?", value)[:limit]


def exception_class(exc: BaseException) -> str:
    cls = type(exc)
    return _ident(f"{cls.__module__}.{cls.__qualname__}", MAX_CLASS)


def origin_of(exc: BaseException) -> Optional[dict[str, Any]]:
    """Innermost frame that belongs to the AISOP package: dotted module, function name, line. No path, no source."""
    tb: Optional[TracebackType] = exc.__traceback__
    found: Optional[tuple[str, str, int]] = None
    while tb is not None:
        try:
            filename = Path(tb.tb_frame.f_code.co_filename).resolve()
            if _APP_ROOT in filename.parents:
                rel = filename.relative_to(_APP_ROOT.parent).with_suffix("")
                found = (".".join(rel.parts), tb.tb_frame.f_code.co_name, tb.tb_lineno)
        except Exception:  # pragma: no cover - defensive
            pass
        tb = tb.tb_next
    if found is None:
        return None
    return {"module": _ident(found[0], MAX_CLASS), "function": _ident(found[1], MAX_FUNCTION), "line": int(found[2])}


def route_template(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return _SAFE_ROUTE.sub("?", path)[:MAX_ROUTE] if isinstance(path, str) else "unmatched"


def message_fingerprint(exc: BaseException) -> tuple[str, int]:
    try:
        text = str(exc)
    except Exception:  # an exception whose __str__ raises
        return "unavailable", 0
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12], min(len(text), 1_000_000)


# ── Message shape (opt-in) ────────────────────────────────────────────────────
_SHAPE_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"https?://\S+", re.I), "<url>"),
    (re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+"), "<email>"),
    (re.compile(r"[A-Za-z]:\\[^\s'\"]*"), "<path>"),
    (re.compile(r"(?<![\w<])/(?:[\w.\-]+/)+[\w.\-]*"), "<path>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b"), "<ip>"),
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<hex>"),
    (re.compile(r"\b[A-Za-z0-9+/_=-]{24,}\b"), "<token>"),
    (re.compile(r"(['\"`])(?:(?!\1).){0,400}\1"), "'?'"),
    (re.compile(r"\d+(\.\d+)?"), "<n>"),
]


def shape_message(text: str) -> str:
    """Mask everything variable in an exception message. Defence in depth only; see the module docstring."""
    out = redact_text(text)
    for pattern, repl in _SHAPE_RULES:
        out = pattern.sub(repl, out)
    out = " ".join(w for w in out.split() if len(w) <= 40)
    return out[:MAX_SHAPE]


def _shape_enabled() -> bool:
    try:
        return bool(get_settings().DIAGNOSTIC_LOG_MESSAGE_SHAPE)
    except Exception:
        return False


def build_record(request: Request, exc: BaseException, *, status: int, code: str) -> dict[str, Any]:
    digest, length = message_fingerprint(exc)
    record: dict[str, Any] = {
        "component": COMPONENT,
        "request_id": getattr(getattr(request, "state", None), "request_id", None),
        "method": _ident(request.method, 10),
        "route": route_template(request),
        "status": int(status),
        "error_code": _ident(code, 64),
        "exception_class": exception_class(exc),
        "origin": origin_of(exc),
        "message_sha256_12": digest,
        "message_length": length,
    }
    if _shape_enabled():
        try:
            record["message_shape"] = shape_message(str(exc))
        except Exception:
            record["message_shape"] = "unavailable"
    return record


def emit_diagnostic(request: Request, exc: BaseException, *, status: int, code: str) -> None:
    """Write at most one diagnostic record per request. Never raises."""
    try:
        state = request.state
        if getattr(state, "diagnostic_logged", False):
            return
        state.diagnostic_logged = True
        record = build_record(request, exc, status=status, code=code)
        logger.bind(**record).error(RECORD_MESSAGE)
    except Exception:  # logging must never change the API response
        return


__all__ = ["COMPONENT", "RECORD_MESSAGE", "build_record", "emit_diagnostic", "shape_message"]
