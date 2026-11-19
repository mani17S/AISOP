"""
Unit tests for AISOP Structured Logging & Observability (Milestone P1-H6).

Tests:
- Log level configuration and filtering
- Sensitive data redaction (dictionary keys, bearer tokens, passwords)
- _safe_sample sanitization
- Structured JSON serializer formatting
- Ingestion batch start, duplicate, and completion logging
- Investigation query logging and validation warnings
- Correlation ID propagation and middleware logging
- Non-serializable object and circular reference safety
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from app.core.config import Settings
from app.core.logging import (
    json_sink_serializer,
    redact_sensitive_data,
    redact_text,
    setup_logging,
)
from app.middleware.correlation import RequestCorrelationMiddleware
from app.schemas.ingest import IngestRequest
from app.services.ingestion_service import IngestionService, _safe_sample
from app.services.query_service import InvestigationQueryService
from fastapi import FastAPI, Request
from loguru import logger


@pytest.fixture
def capture_logs():
    """Fixture that captures Loguru log records into a list for assertions."""
    captured: list[dict] = []

    def sink(message):
        rec = message.record
        captured.append(
            {
                "level": rec["level"].name,
                "message": rec["message"],
                "extra": rec["extra"],
                "text": str(message),
            }
        )

    handler_id = logger.add(sink, level="DEBUG")
    yield captured
    try:
        logger.remove(handler_id)
    except ValueError:
        pass


def test_redact_sensitive_keys():
    """Verify dictionary keys matching sensitive patterns are redacted recursively."""
    payload = {
        "username": "admin",
        "password": "SuperSecretPassword123!",
        "api_key": "vt_1234567890abcdef",
        "Authorization": "Bearer some_token_here",
        "nested": {
            "token": "secret_jwt_token",
            "safe_counter": 42,
            "private_key": "-----BEGIN PRIVATE KEY-----",
        },
        "items": [{"passwd": "pass1"}, {"cookie": "session=abc"}, {"safe": "ok"}],
    }

    sanitized = redact_sensitive_data(payload)

    assert sanitized["username"] == "admin"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["nested"]["token"] == "[REDACTED]"
    assert sanitized["nested"]["safe_counter"] == 42
    assert sanitized["nested"]["private_key"] == "[REDACTED]"
    assert sanitized["items"][0]["passwd"] == "[REDACTED]"
    assert sanitized["items"][1]["cookie"] == "[REDACTED]"
    assert sanitized["items"][2]["safe"] == "ok"


def test_redact_text_embedded_tokens():
    """Verify regex redacts bearer tokens, basic auth, and key-value secrets in strings."""
    text1 = "Connecting with Authorization: Bearer abcdef1234567890 to endpoint"
    assert (
        redact_text(text1)
        == "Connecting with Authorization: Bearer [REDACTED] to endpoint"
    )

    text2 = "Failed auth: password=MySecretPassword123&user=admin"
    assert redact_text(text2) == "Failed auth: password=[REDACTED]&user=admin"

    text3 = "Received request with api_key: 'topsecretkey12345'"
    assert "topsecretkey12345" not in redact_text(text3)
    assert "[REDACTED]" in redact_text(text3)


def test_safe_sample_redacts_sensitive_payloads():
    """Verify _safe_sample redacts sensitive fields before string truncation."""
    sample_payload = {
        "EventID": 1,
        "User": "analyst",
        "password": "PlainTextPasswordHere",
        "CommandLine": "net user admin MySecretP@ss!",
    }
    sample = _safe_sample(sample_payload)

    assert "PlainTextPasswordHere" not in sample
    assert "[REDACTED]" in sample
    assert len(sample) <= 100


def test_circular_reference_redaction_safety():
    """Verify circular references or deeply nested structures do not trigger recursion errors."""
    d: dict = {"key": "value"}
    d["self"] = d  # Circular reference

    # Must complete safely without RecursionError
    result = redact_sensitive_data(d, max_depth=3)
    assert isinstance(result, dict)
    assert result["key"] == "value"
    assert result["self"]["self"]["self"] == "[MAX_DEPTH]"


def test_setup_logging_configuration():
    """Verify setup_logging configures Loguru according to Settings without error."""
    settings_json = Settings(LOG_LEVEL="DEBUG", LOG_FORMAT="json")
    setup_logging(settings_json)

    settings_text = Settings(LOG_LEVEL="INFO", LOG_FORMAT="text")
    setup_logging(settings_text)


def test_log_level_filtering():
    """Verify that messages below configured level are suppressed."""
    captured_warnings = []
    hid = logger.add(lambda m: captured_warnings.append(m.record), level="WARNING")
    try:
        logger.debug("Debug message - should be ignored")
        logger.info("Info message - should be ignored")
        logger.warning("Warning message - should be captured")
        logger.error("Error message - should be captured")

        assert len(captured_warnings) == 2
        assert captured_warnings[0]["level"].name == "WARNING"
        assert captured_warnings[1]["level"].name == "ERROR"
    finally:
        logger.remove(hid)


@pytest.mark.anyio
async def test_ingestion_logging_flow(db_session, capture_logs):
    """Verify IngestionService emits batch start, duplicate, and completion logs."""
    service = IngestionService()
    event = {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\calc.exe",
        "CommandLine": "calc.exe",
        "UtcTime": "2026-09-10 12:00:00.000",
        "User": "CORP\\bob",
    }
    request = IngestRequest(
        source_type="sysmon",
        source_identifier="LOG-HOST-01",
        events=[event],
    )

    # 1. Ingest event
    res1 = await service.ingest_batch(db_session, request)
    assert res1.total_normalized == 1

    # Check captured logs
    messages = [c["message"] for c in capture_logs]
    assert "Received ingestion batch" in messages
    assert "Ingestion batch completed" in messages

    # Check structured extra fields
    start_log = next(
        c for c in capture_logs if c["message"] == "Received ingestion batch"
    )
    assert start_log["extra"]["source_type"] == "sysmon"
    assert start_log["extra"]["total_events"] == 1
    assert "batch_id" in start_log["extra"]

    # 2. Ingest duplicate event
    capture_logs.clear()
    res2 = await service.ingest_batch(db_session, request)
    assert res2.total_skipped_duplicates == 1

    completion_log = next(
        c for c in capture_logs if c["message"] == "Ingestion batch completed"
    )
    assert completion_log["extra"]["total_skipped_duplicates"] == 1
    assert completion_log["extra"]["total_normalized"] == 0


@pytest.mark.anyio
async def test_query_service_logging_flow(db_session, capture_logs):
    """Verify InvestigationQueryService emits debug logs on query and warning logs on validation failure."""
    service = InvestigationQueryService()

    # 1. Successful query
    await service.query_events(db_session, page=1, limit=10)
    messages = [c["message"] for c in capture_logs]
    assert "Executing events query" in messages

    # 2. Invalid validation (page < 1)
    capture_logs.clear()
    with pytest.raises(ValueError):
        await service.query_events(db_session, page=0)

    warn_logs = [c for c in capture_logs if c["level"] == "WARNING"]
    assert any("invalid page" in c["message"] for c in warn_logs)


@pytest.mark.anyio
async def test_request_correlation_middleware_header_and_logging(capture_logs):
    """Verify RequestCorrelationMiddleware propagates X-Request-ID and logs completion."""
    test_app = FastAPI()
    test_app.add_middleware(RequestCorrelationMiddleware)

    @test_app.get("/test-endpoint")
    async def sample_route(request: Request):
        return {"request_id": request.state.request_id}

    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Without client request ID -> generates new one
        res1 = await client.get("/test-endpoint")
        assert res1.status_code == 200
        req_id1 = res1.headers.get("X-Request-ID")
        assert req_id1 is not None
        assert res1.json()["request_id"] == req_id1

        # 2. With a client request ID -> NOT trusted: the server still issues its own (Phase 2.2 error contract)
        client_id = "custom-trace-uuid-12345"
        res2 = await client.get("/test-endpoint", headers={"X-Request-ID": client_id})
        assert res2.status_code == 200
        assert res2.headers.get("X-Request-ID") != client_id
        assert res2.headers.get("X-Request-ID") == res2.json()["request_id"]

    # Verify HTTP request log was recorded
    http_logs = [c for c in capture_logs if c["message"] == "HTTP request completed"]
    assert len(http_logs) >= 2
    assert http_logs[0]["extra"]["status_code"] == 200
    assert http_logs[0]["extra"]["path"] == "/test-endpoint"
