"""
AISOP Structured Logging & Observability.

Configures Loguru for structured JSON / formatted text output, standard library
interception, correlation tracking, and automatic sensitive data redaction.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any

from app.core.config import Settings, get_settings
from loguru import logger

# Sensitive keys to redact in structured dictionaries and log context
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "auth",
        "authorization",
        "cookie",
        "set-cookie",
        "private_key",
        "client_secret",
        "virustotal_api_key",
        "abuseipdb_api_key",
        "alienvault_otx_api_key",
    }
)

# Regex patterns for redacting sensitive values embedded in log message strings
REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)\b(bearer\s+)[a-zA-Z0-9_\-\.]{8,}", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(basic\s+)[a-zA-Z0-9+/=]{8,}", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(api[_-]?key|password|secret|token)\s*([:=])\s*['\"]?([^\s,'\"&]+)['\"]?",
            re.IGNORECASE,
        ),
        r"\1\2[REDACTED]",
    ),
]


def redact_text(text: str) -> str:
    """Sanitize sensitive tokens or passwords inside arbitrary text messages."""
    for pattern, replacement in REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_sensitive_data(obj: Any, max_depth: int = 5) -> Any:
    """
    Recursively sanitize dictionaries and lists to redact known sensitive keys
    and token patterns, with a recursion depth limit to prevent circular references.
    """
    if max_depth <= 0:
        return "[MAX_DEPTH]"

    if isinstance(obj, dict):
        sanitized: dict[str, Any] = {}
        for k, v in obj.items():
            key_lower = str(k).lower().strip()
            if any(sensitive in key_lower for sensitive in SENSITIVE_KEYS):
                sanitized[str(k)] = "[REDACTED]"
            else:
                sanitized[str(k)] = redact_sensitive_data(v, max_depth=max_depth - 1)
        return sanitized

    if isinstance(obj, list):
        return [redact_sensitive_data(item, max_depth=max_depth - 1) for item in obj]

    if isinstance(obj, tuple):
        return tuple(
            redact_sensitive_data(item, max_depth=max_depth - 1) for item in obj
        )

    if isinstance(obj, str):
        return redact_text(obj)

    return obj


def json_sink_serializer(message: Any) -> None:
    """
    Custom Loguru sink serializer that formats records into clean, machine-readable JSON.
    """
    record = message.record
    extra = redact_sensitive_data(record.get("extra", {}))
    sanitized_message = redact_text(record["message"])

    log_entry: dict[str, Any] = {
        "timestamp": record["time"].astimezone(timezone.utc).isoformat(),
        "level": record["level"].name,
        "logger": record["name"],
        "message": sanitized_message,
        "context": extra,
    }

    if record.get("exception"):
        exc = record["exception"]
        log_entry["exception"] = {
            "type": exc.type.__name__ if exc.type else None,
            "value": redact_text(str(exc.value)) if exc.value else None,
            "traceback": bool(exc.traceback),
        }
    else:
        log_entry["exception"] = None

    sys.stderr.write(json.dumps(log_entry, default=str) + "\n")
    sys.stderr.flush()


class InterceptHandler(logging.Handler):
    """
    Standard library logging handler that intercepts messages from third-party
    libraries (e.g. Uvicorn, FastAPI, SQLAlchemy) and forwards them to Loguru.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup_logging(settings: Settings | None = None) -> None:
    """
    Configure Loguru based on application settings.
    Removes default handlers and installs structured console and file sinks.
    """
    if settings is None:
        settings = get_settings()

    # Clear existing loguru handlers
    logger.remove()

    log_level = settings.LOG_LEVEL.upper()

    if settings.LOG_FORMAT == "json":
        # Machine-readable JSON sink
        logger.add(
            json_sink_serializer,
            level=log_level,
        )
    else:
        # Development human-readable text format
        text_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level> "
            "{extra}"
        )
        logger.add(
            sys.stderr,
            format=text_format,
            level=log_level,
            colorize=True,
        )

    # Intercept standard library loggers
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
    for lib in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi", "sqlalchemy"):
        lib_logger = logging.getLogger(lib)
        lib_logger.handlers = [InterceptHandler()]
        lib_logger.propagate = False
