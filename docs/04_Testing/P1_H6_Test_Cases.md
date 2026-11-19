# P1-H6 Test Cases: Structured Logging & Observability

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H6-TC |
| **Milestone** | P1-H6: Structured Logging & Observability |
| **Checkpoint Commit** | `bbc34dd` (`bbc34ddd0d515084dc122f92d312995884a8fc8a`) |
| **Governing SRS** | Non-Functional Requirements: Observability, Auditability & Data Protection |
| **Component Scope** | Logging Module (`app/core/logging.py`), Correlation Middleware (`app/middleware/correlation.py`) |
| **Last Updated** | 2026-09-23 |

---

## 1. Purpose & Scope

This document specifies the test cases for **Milestone P1-H6**. P1-H6 established enterprise observability and auditability across AISOP.

Key capabilities verified:
1. Structured JSON and formatted text logging using Loguru.
2. Standard library `logging` redirection and interception.
3. Request correlation tracing via `X-Request-ID` headers attached to every incoming HTTP request and logged context.
4. Automatic sanitization and masking of sensitive credentials (`password`, `token`, `api_key`, `secret`, `bearer`).
5. Recursion depth protection preventing infinite loops on circular references.

---

## 2. Test Case Catalogue

### TC-P1H6-001 — Sensitive Dictionary Key Redaction
* **Test ID:** `TC-P1H6-001`
* **Module:** `backend/app/core/logging.py`
* **Source Test:** `test_logging.py::test_redact_sensitive_keys`
* **Objective:** Verify `redact_sensitive_data` masks values for sensitive dictionary keys (password, api_key, token, secret).
* **Preconditions:** Dictionary containing sensitive keys and nested dictionaries.
* **Input:** `{"user": "analyst", "password": "supersecret", "meta": {"virustotal_api_key": "12345"}}`.
* **Expected Result:** `sanitized["password"] == "[REDACTED]"`, `sanitized["meta"]["virustotal_api_key"] == "[REDACTED]"`.
* **Status:** PASS (Reconstructed from commit `bbc34dd`).

---

### TC-P1H6-002 — Embedded Token String Redaction via Regex
* **Test ID:** `TC-P1H6-002`
* **Module:** `backend/app/core/logging.py`
* **Source Test:** `test_logging.py::test_redact_text_embedded_tokens`
* **Objective:** Verify regex patterns mask Bearer tokens, Basic auth tokens, and inline credentials in unstructured text.
* **Preconditions:** Text string containing `"Bearer eyJhbGciOi..."` and `"api_key: secret123"`.
* **Input:** `redact_text(sample_text)`.
* **Expected Result:** Tokens replaced with `"[REDACTED]"`.
* **Status:** PASS (Reconstructed from commit `bbc34dd`).

---

### TC-P1H6-003 — Safe Sample Redaction in Ingestion
* **Test ID:** `TC-P1H6-003`
* **Module:** `backend/app/core/logging.py`
* **Source Test:** `test_logging.py::test_safe_sample_redacts_sensitive_payloads`
* **Objective:** Verify payload samples generated for error logs sanitize credentials before formatting.
* **Preconditions:** Payload dictionary with password field.
* **Input:** `_safe_sample({"EventID": 1, "Password": "plaintextpassword"})`.
* **Expected Result:** Output string contains `"[REDACTED]"` and never exposes the plaintext password.
* **Status:** PASS (Reconstructed from commit `bbc34dd`).

---

### TC-P1H6-004 — Circular Reference Redaction Safety
* **Test ID:** `TC-P1H6-004`
* **Module:** `backend/app/core/logging.py`
* **Source Test:** `test_logging.py::test_circular_reference_redaction_safety`
* **Objective:** Verify `redact_sensitive_data` stops recursion safely when encountering self-referential objects.
* **Preconditions:** Dictionary with circular link `d["self"] = d`.
* **Input:** `redact_sensitive_data(d, max_depth=5)`.
* **Expected Result:** Terminates without `RecursionError`; returns `"[MAX_DEPTH]"` at boundary.
* **Status:** PASS (Reconstructed from commit `bbc34dd`).

---

### TC-P1H6-005 — Loguru Logging Configuration Setup
* **Test ID:** `TC-P1H6-005`
* **Module:** `backend/app/core/logging.py`
* **Source Test:** `test_logging.py::test_setup_logging_configuration`
* **Objective:** Verify `setup_logging()` configures standard library handlers and Loguru sinks.
* **Preconditions:** `Settings` instance with `LOG_FORMAT="json"`, `LOG_LEVEL="INFO"`.
* **Input:** `setup_logging(settings)`.
* **Expected Result:** Standard library root logger redirected to InterceptHandler; sinks configured.
* **Status:** PASS (Reconstructed from commit `bbc34dd`).

---

### TC-P1H6-006 — Log Level Filtering
* **Test ID:** `TC-P1H6-006`
* **Module:** `backend/app/core/logging.py`
* **Source Test:** `test_logging.py::test_log_level_filtering`
* **Objective:** Verify messages below the configured log level (e.g. DEBUG when level is INFO) are discarded.
* **Preconditions:** Logger configured at INFO level.
* **Input:** Emit `logger.debug("test debug")` and `logger.info("test info")`.
* **Expected Result:** Log output contains INFO message and omits DEBUG message.
* **Status:** PASS (Reconstructed from commit `bbc34dd`).

---

### TC-P1H6-007 — Contextual Ingestion Logging Flow
* **Test ID:** `TC-P1H6-007`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_logging.py::test_ingestion_logging_flow`
* **Objective:** Verify ingestion operations emit structured log events containing batch size and deduplication counts.
* **Preconditions:** Log capture sink attached.
* **Input:** `service.ingest_batch(db_session, request)`.
* **Expected Result:** Log sink captures messages recording batch start and completion metrics.
* **Status:** PASS (Reconstructed from commit `bbc34dd`).

---

### TC-P1H6-008 — Contextual Query Service Logging Flow
* **Test ID:** `TC-P1H6-008`
* **Module:** `backend/app/services/query_service.py`
* **Source Test:** `test_logging.py::test_query_service_logging_flow`
* **Objective:** Verify investigative queries log filter parameters and result row counts.
* **Preconditions:** Log capture sink attached.
* **Input:** `query_service.get_events(db_session, TimelineFilterParams())`.
* **Expected Result:** Log records reflect query execution and duration.
* **Status:** PASS (Reconstructed from commit `bbc34dd`).

---

### TC-P1H6-009 — Request Correlation Middleware Header & Context Binding
* **Test ID:** `TC-P1H6-009`
* **Module:** `backend/app/middleware/correlation.py`
* **Source Test:** `test_logging.py::test_request_correlation_middleware_header_and_logging`
* **Objective:** Verify incoming `X-Request-ID` is preserved in context and reflected in the HTTP response headers.
* **Preconditions:** HTTP request dispatched with header `X-Request-ID: test-req-uuid-123`.
* **Input:** Request through FastAPI ASGI stack with `RequestCorrelationMiddleware`.
* **Expected Result:** Response headers contain `X-Request-ID == "test-req-uuid-123"`; emitted logs bind `request_id`.
* **Status:** PASS (Reconstructed from commit `bbc34dd`).
