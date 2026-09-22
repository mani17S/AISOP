# P2-H1 Test Cases: LLM Provider Protocol & Local Ollama Adapter

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P2H1-TC |
| **Milestone** | P2-H1: LLM Provider Protocol & Local Ollama Adapter |
| **Governing ADR** | [ADR-001: AI/LLM Layer Abstraction Strategy](docs/03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md) |
| **Component** | AI Inference Subsystem (`backend/app/modules/ai/`) |
| **Test Suite File** | `backend/tests/unit/test_llm_provider.py`, `backend/tests/unit/test_config.py` |
| **Version** | 1.0 (Academic TA Evaluation Baseline) |
| **Last Updated** | 2026-09-22 |

---

## 1. Purpose

This document provides formal test case specifications for milestone **P2-H1** of the AI-Assisted Security Operations Platform (AISOP). It defines the verification parameters, preconditions, inputs, expected behaviors, and actual test observations for the LLM Provider Protocol and Local Ollama Adapter.

The primary objective is to verify that AISOP provides a resilient, vendor-independent AI provider interface in accordance with **ADR-001**, enforcing strict boundary decoupling without relying on heavyweight frameworks such as LangChain, LangGraph, or LlamaIndex.

---

## 2. Scope

### In-Scope Verification
* Conformance of `OllamaProvider` to the `@runtime_checkable` `LLMProvider` Protocol.
* Validation and immutability of Pydantic v2 domain schemas (`MessageRole`, `LLMMessage`, `LLMRequest`, `LLMResponse`, `TokenUsage`, `ProviderHealthResponse`).
* Direct asynchronous HTTP payload serialization and deserialization for Ollama endpoints (`/api/chat` and `/api/tags`).
* Request-level overrides for target model, temperature, max generation tokens, and JSON mode enforcement.
* Token accounting and execution latency metric extraction from nanosecond duration fields.
* Exception hierarchy translation and fail-fast behavior for non-retryable conditions (HTTP 404, HTTP 400, inference timeout, malformed payloads).
* Tenacity-backed exponential backoff retry loop for transient connection and server errors (HTTP 502, 503, 504).
* Graceful, non-raising health check probing across operational, degraded, and unavailable states.
* Provider factory (`get_llm_provider`) configuration resolution and input validation.
* Default configuration parameters in application settings.

### Explicitly Out-of-Scope (Deferred Capabilities)
* Cloud provider adapters (OpenAI, Anthropic, Google Gemini) — deferred to Phase 3.
* Streaming response generation (Server-Sent Events) — explicitly deferred to Phase 4 (Frontend Investigation Dashboard).
* Retrieval-Augmented Generation (RAG) and pgvector embeddings — deferred to P2-H2 and P2-H3.
* Context building, prompt templates, and hypothesis generation — deferred to P2-H5 and P2-H6.
* Database models, Alembic migrations, and schema modifications — strictly prohibited in P2-H1.

---

## 3. Test Environment

All P2-H1 unit test cases are executed deterministically within an isolated local test harness:

* **Host Operating System:** Windows 11 Enterprise (win32)
* **Python Runtime:** Python 3.12.0 (`.venv`)
* **Test Framework:** pytest 9.1.1 with anyio 4.15.1 plugin
* **HTTP Mocking Engine:** `httpx.MockTransport` (direct in-memory request interceptor)
* **Target HTTP Client:** `httpx.AsyncClient` 0.28.1
* **Retry Engine:** `tenacity` 9.1.4
* **Schema Engine:** `pydantic` 2.13.5
* **Network Isolation:** 100% in-memory; zero live sockets, zero GPU dependencies, zero live Ollama daemon dependencies.

---

## 4. Testing Approach

Testing is conducted at the unit test level using deterministic mock transports (`httpx.MockTransport`). Instead of relying on a running Ollama server—which introduces non-determinism, model warm-up delays, and hardware dependencies—every outgoing HTTP request is intercepted in memory by a custom handler function.

This approach guarantees:
1. **Full Fault Injection:** The harness simulates arbitrary HTTP status codes (400, 404, 500, 503), read timeouts, connection refusals, and malformed non-JSON payloads.
2. **Deterministic State Verification:** Captured HTTP requests are inspected to verify serialization fidelity (e.g., verifying `format="json"`, `stream=False`, temperature values, and message dictionaries).
3. **Execution Efficiency:** The entire 19-test suite executes in under 6 seconds, ensuring rapid feedback for continuous integration.

---

## 5. Test Case Catalogue

### TC-P2H1-001 — Protocol Conformance Verification

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-001 |
| **Module** | `backend/app/modules/ai/llm/protocol.py`, `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that `OllamaProvider` satisfies the runtime-checkable `LLMProvider` Protocol. |
| **Preconditions** | `OllamaProvider` instantiated with default parameters. |
| **Test Method** | Inspect runtime type conformance using `isinstance()` and verify required property access. |
| **Input / Stimulus** | `provider = OllamaProvider()` |
| **Expected Result** | `isinstance(provider, LLMProvider)` is `True`; `provider.model_name` returns `"llama3.1:8b"`. |
| **Actual Result** | Protocol conformance verified; active model property returned configured default. |
| **Status** | **PASS** |

---

### TC-P2H1-002 — Successful Chat Generation & Payload Serialization

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-002 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify standard non-streaming chat completion, request payload serialization, and response parsing. |
| **Preconditions** | In-memory `httpx.MockTransport` intercepting POST to `/api/chat` and returning 200 OK with valid JSON. |
| **Test Method** | Asynchronous invocation of `provider.generate(request)`; capture and inspect serialized JSON request. |
| **Input / Stimulus** | `LLMRequest` containing two `LLMMessage` objects (System and User roles). |
| **Expected Result** | `LLMResponse` returned with `role=MessageRole.ASSISTANT`, `model="llama3.1:8b"`, content containing expected text, `finish_reason="stop"`. Outgoing payload has `stream=False`, `temperature=0.2`, and matching message structures. |
| **Actual Result** | Response fields mapped accurately; outgoing payload matched specification. |
| **Status** | **PASS** |

---

### TC-P2H1-003 — JSON Mode Enforcement

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-003 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that `json_mode=True` injects `"format": "json"` into the Ollama payload. |
| **Preconditions** | In-memory `httpx.MockTransport` intercepting POST to `/api/chat`. |
| **Test Method** | Execute `provider.generate(request)` with `json_mode=True`; decode and inspect captured payload. |
| **Input / Stimulus** | `LLMRequest(messages=sample_messages, json_mode=True)` |
| **Expected Result** | Serialized payload contains top-level key `"format": "json"`. |
| **Actual Result** | Key `"format": "json"` present in outgoing request. |
| **Status** | **PASS** |

---

### TC-P2H1-004 — Request-Level Parameter Overrides

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-004 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that request-level model, temperature, and max_tokens parameters override provider defaults. |
| **Preconditions** | `OllamaProvider` initialized with `model="llama3.1:8b"`, `temperature=0.1`. |
| **Test Method** | Invoke `provider.generate(request)` with custom parameters; inspect intercepted payload. |
| **Input / Stimulus** | `LLMRequest(messages=..., model="custom-sec:8b", temperature=0.5, max_tokens=500)` |
| **Expected Result** | Payload contains `"model": "custom-sec:8b"`, `"options": {"temperature": 0.5, "num_predict": 500}`. |
| **Actual Result** | All parameter overrides correctly propagated to Ollama API request payload. |
| **Status** | **PASS** |

---

### TC-P2H1-005 — Token Usage & Latency Accounting

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-005 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify prompt token, completion token, total token calculation, and nanosecond-to-millisecond conversion. |
| **Preconditions** | Mock response containing `prompt_eval_count=35`, `eval_count=150`, `total_duration=4200000000`. |
| **Test Method** | Execute `generate()` and assert properties on `response.usage`. |
| **Input / Stimulus** | Standard `LLMRequest`. |
| **Expected Result** | `usage.prompt_tokens == 35`, `usage.completion_tokens == 150`, `usage.total_tokens == 185`, `usage.duration_ms == 4200.0`. |
| **Actual Result** | Token counts and execution latency converted and aggregated accurately. |
| **Status** | **PASS** |

---

### TC-P2H1-006 — Health Probe: Operational State (Healthy)

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-006 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify health probe reports `status="healthy"` when the target model tag is installed in Ollama. |
| **Preconditions** | Mock GET `/api/tags` returns HTTP 200 with installed model list including `"llama3.1:8b"`. |
| **Test Method** | Invoke `await provider.health()` and assert fields on `ProviderHealthResponse`. |
| **Input / Stimulus** | Health check execution on `OllamaProvider(model="llama3.1:8b")`. |
| **Expected Result** | `health.status == "healthy"`, `health.model == "llama3.1:8b"`, `health.provider == "ollama"`, `health.error is None`, `health.latency_ms >= 0.0`. |
| **Actual Result** | Health status evaluated to healthy with zero error strings. |
| **Status** | **PASS** |

---

### TC-P2H1-007 — Health Probe: Missing Model (Degraded)

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-007 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify health probe reports `status="degraded"` when Ollama is running but target model is not pulled. |
| **Preconditions** | Mock GET `/api/tags` returns HTTP 200 with models list containing only `"mistral:7b"`. |
| **Test Method** | Invoke `await provider.health()` on provider configured for `"llama3.1:8b"`. |
| **Input / Stimulus** | Health check execution where configured model is absent. |
| **Expected Result** | `health.status == "degraded"`, `health.error` contains `"not pulled"`, latency recorded. |
| **Actual Result** | Provider marked degraded with actionable diagnostic error string. |
| **Status** | **PASS** |

---

### TC-P2H1-008 — Health Probe: Daemon Offline (Unavailable)

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-008 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify health probe catches connection refusal gracefully without raising an unhandled exception. |
| **Preconditions** | Mock GET `/api/tags` raises `httpx.ConnectError("Connection refused")`. |
| **Test Method** | Invoke `await provider.health()` and assert safe handling. |
| **Input / Stimulus** | Connection refused failure during health probe. |
| **Expected Result** | `health.status == "unavailable"`, `health.error` contains `"Connection refused"`. No exception raised. |
| **Actual Result** | Provider safely returned `unavailable` status response. |
| **Status** | **PASS** |

---

### TC-P2H1-009 — Inference Timeout Handling

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-009 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that an inference request exceeding the timeout threshold raises `LLMTimeoutError`. |
| **Preconditions** | Mock POST `/api/chat` raises `httpx.ReadTimeout("Inference exceeded threshold")`. `timeout_seconds=10`. |
| **Test Method** | Assert `pytest.raises(LLMTimeoutError)` during `provider.generate()`. |
| **Input / Stimulus** | `provider.generate(request)` with read timeout simulated. |
| **Expected Result** | `LLMTimeoutError` raised; error message contains `"timed out after 10s"`. |
| **Actual Result** | Typed exception raised with contextual timeout details. |
| **Status** | **PASS** |

---

### TC-P2H1-010 — Connection Refused Error Handling

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-010 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify connection refusal during generation attempts retries and raises `LLMConnectionError`. |
| **Preconditions** | Mock POST `/api/chat` consistently raises `httpx.ConnectError("Connection refused")`. `max_retries=2`. |
| **Test Method** | Execute `provider.generate(request)` and assert raised exception. |
| **Input / Stimulus** | Unreachable Ollama daemon. |
| **Expected Result** | `LLMConnectionError` raised after retry exhaustion; message indicates connection failure. |
| **Actual Result** | Typed `LLMConnectionError` raised after retries. |
| **Status** | **PASS** |

---

### TC-P2H1-011 — Fail-Fast on Model Not Found (HTTP 404)

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-011 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify HTTP 404 from Ollama immediately raises `LLMModelNotFoundError` without retrying. |
| **Preconditions** | Mock POST `/api/chat` returns HTTP 404 with error body. `max_retries=3`. |
| **Test Method** | Track call attempts via non-local counter and assert `LLMModelNotFoundError`. |
| **Input / Stimulus** | Inference request referencing uninstalled model tag `"unknown:tag"`. |
| **Expected Result** | Handler called exactly once (`call_count == 1`); raises `LLMModelNotFoundError`. |
| **Actual Result** | Non-retryable error failed fast on first attempt with typed model-not-found error. |
| **Status** | **PASS** |

---

### TC-P2H1-012 — Fail-Fast on Client Syntax Error (HTTP 400)

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-012 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify HTTP 400 from Ollama immediately raises `LLMResponseError` without retrying. |
| **Preconditions** | Mock POST `/api/chat` returns HTTP 400 with text `"malformed request syntax"`. |
| **Test Method** | Track call attempts via counter and assert `LLMResponseError` with preserved status code. |
| **Input / Stimulus** | Malformed client request payload. |
| **Expected Result** | `call_count == 1`; raises `LLMResponseError`; `status_code == 400`. |
| **Actual Result** | Failed fast without retry; status code 400 preserved on domain exception. |
| **Status** | **PASS** |

---

### TC-P2H1-013 — Transient Error Recovery (HTTP 503 Retry)

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-013 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that a transient HTTP 503 service unavailable error retries and succeeds on the second attempt. |
| **Preconditions** | Mock POST returns HTTP 503 on attempt 1, and HTTP 200 with valid JSON on attempt 2. |
| **Test Method** | Execute `provider.generate(request)` with `max_retries=3`; verify call counter. |
| **Input / Stimulus** | Transient server overload followed by service recovery. |
| **Expected Result** | `call_count == 2`; response generated successfully without raising an exception. |
| **Actual Result** | Tenacity retry loop caught 503, executed exponential backoff, and completed on attempt 2. |
| **Status** | **PASS** |

---

### TC-P2H1-014 — Malformed Non-JSON Response Handling

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-014 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that non-JSON response bodies (e.g. HTML proxy errors with 200 OK) raise `LLMResponseError`. |
| **Preconditions** | Mock POST `/api/chat` returns HTTP 200 with HTML text `"<html>502 Bad Gateway Proxy</html>"`. |
| **Test Method** | Assert `pytest.raises(LLMResponseError)` during response decoding. |
| **Input / Stimulus** | Invalid JSON response payload from intermediary proxy. |
| **Expected Result** | `LLMResponseError` raised; message indicates unexpected error or JSON decoding failure. |
| **Actual Result** | JSON decode exception intercepted and translated to typed `LLMResponseError`. |
| **Status** | **PASS** |

---

### TC-P2H1-015 — Missing Message Content Validation

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-015 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that a response dictionary missing `'message.content'` raises `LLMResponseError`. |
| **Preconditions** | Mock POST `/api/chat` returns HTTP 200 with incomplete JSON `{"done": True, "total_duration": 1000}`. |
| **Test Method** | Assert `pytest.raises(LLMResponseError)` during dictionary key validation. |
| **Input / Stimulus** | Structurally incomplete response payload. |
| **Expected Result** | `LLMResponseError` raised with message containing `"missing 'message.content'"`. |
| **Actual Result** | Structural validation caught missing content key and raised typed domain error. |
| **Status** | **PASS** |

---

### TC-P2H1-016 — Persistent 5xx Retry Exhaustion

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-016 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that persistent HTTP 503 errors exhaust all retries and raise `LLMResponseError` preserving HTTP status. |
| **Preconditions** | Mock POST `/api/chat` returns HTTP 503 on every attempt. `max_retries=3`. |
| **Test Method** | Execute `provider.generate(request)`; verify call attempts and exception attributes. |
| **Input / Stimulus** | Unrecoverable HTTP 503 server outage. |
| **Expected Result** | `call_count == 3`; `LLMResponseError` raised; `exc.status_code == 503`; message contains `"Ollama server error (503)"`. |
| **Actual Result** | Retried exactly 3 times before failing with preserved status code 503. |
| **Status** | **PASS** |

---

### TC-P2H1-017 — Health Probe Timeout

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-017 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that health probe returns `status="unavailable"` when the GET request times out. |
| **Preconditions** | Mock GET `/api/tags` raises `httpx.ReadTimeout("Health probe timeout")`. |
| **Test Method** | Invoke `await provider.health()` and assert safe handling. |
| **Input / Stimulus** | Latency spike exceeding probe threshold. |
| **Expected Result** | `health.status == "unavailable"`; `health.error` contains `"timed out"`. No exception raised. |
| **Actual Result** | Probe timed out safely and returned unavailable state. |
| **Status** | **PASS** |

---

### TC-P2H1-018 — Health Probe Server Error (HTTP 500)

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-018 |
| **Module** | `backend/app/modules/ai/providers/ollama/provider.py` |
| **Objective** | Verify that health probe returns `status="degraded"` when Ollama returns an internal server error. |
| **Preconditions** | Mock GET `/api/tags` returns HTTP 500 with text `"Internal engine failure"`. |
| **Test Method** | Invoke `await provider.health()` and inspect returned status. |
| **Input / Stimulus** | Internal server failure on model tags endpoint. |
| **Expected Result** | `health.status == "degraded"`; `health.error` contains `"HTTP 500"`. |
| **Actual Result** | Degraded health reported with status code in error message. |
| **Status** | **PASS** |

---

### TC-P2H1-019 — Provider Factory Resolution & Validation

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-019 |
| **Module** | `backend/app/modules/ai/llm/manager.py` |
| **Objective** | Verify that `get_llm_provider()` instantiates `OllamaProvider` when configured, and rejects unsupported names. |
| **Preconditions** | Custom `Settings` instances with valid (`"ollama"`) and invalid (`"unsupported_cloud"`) configurations. |
| **Test Method** | Invoke `get_llm_provider(settings)` and verify returned object type or raised exception. |
| **Input / Stimulus** | Valid settings vs invalid provider name string. |
| **Expected Result** | Resolves `OllamaProvider` for `"ollama"`; raises `LLMError("Unsupported LLM provider...")` for invalid provider. |
| **Actual Result** | Factory successfully resolved provider and rejected invalid input. |
| **Status** | **PASS** |

---

### TC-P2H1-020 — Application Settings Ollama Configuration Defaults

| Field | Details |
|---|---|
| **Test ID** | TC-P2H1-020 |
| **Module** | `backend/app/core/config.py`, `backend/tests/unit/test_config.py` |
| **Objective** | Verify that `Settings` defaults for Ollama and LLM provider conform to baseline requirements. |
| **Preconditions** | Instantiation of `Settings(_env_file=None)` without environment overrides. |
| **Test Method** | Attribute value assertions against defined defaults. |
| **Input / Stimulus** | Fresh `Settings` instance. |
| **Expected Result** | `OLLAMA_BASE_URL == "http://localhost:11434"`, `OLLAMA_MODEL == "llama3.1:8b"`, `OLLAMA_TIMEOUT_SECONDS == 120`, `OLLAMA_TEMPERATURE == 0.2`, `OLLAMA_MAX_RETRIES == 3`, `OLLAMA_KEEP_ALIVE == "5m"`, `LLM_PROVIDER == "ollama"`. |
| **Actual Result** | All default attributes matched specification exactly. |
| **Status** | **PASS** |

---

## 6. Traceability to P2-H1 Requirements

| Functional / Architectural Requirement | Related Test Cases | Verification Method | Status |
|---|---|---|:---:|
| **Provider Protocol Abstraction (ADR-001)** | TC-P2H1-001 | Runtime `typing.Protocol` check | **PASS** |
| **Payload Serialization & Chat Generation** | TC-P2H1-002, TC-P2H1-004 | Intercepted JSON body inspection | **PASS** |
| **Structured Output (JSON Mode)** | TC-P2H1-003 | Top-level `"format": "json"` validation | **PASS** |
| **Token Usage & Execution Observability** | TC-P2H1-005 | Duration & token metric conversion | **PASS** |
| **Health Probe Lifecycle (Healthy/Degraded/Unavailable)** | TC-P2H1-006, TC-P2H1-007, TC-P2H1-008, TC-P2H1-017, TC-P2H1-018 | Mock GET `/api/tags` inspection | **PASS** |
| **Timeout & Non-Retryable Error Fast-Fail** | TC-P2H1-009, TC-P2H1-011, TC-P2H1-012 | Single-attempt exception assertion | **PASS** |
| **Network Resilience & Retry Loop** | TC-P2H1-010, TC-P2H1-013, TC-P2H1-016 | Tenacity loop tracking with backoff | **PASS** |
| **Malformed Response Fault Injection** | TC-P2H1-014, TC-P2H1-015 | Non-JSON & missing key injection | **PASS** |
| **Provider Factory & Configuration** | TC-P2H1-019, TC-P2H1-020 | Dynamic instantiation & config tests | **PASS** |

---

## 7. Test Coverage Summary & Coverage Gaps

### Coverage Summary
* **Total P2-H1 Specific Test Cases:** 20 (19 in `test_llm_provider.py`, 1 in `test_config.py`).
* **Test Pass Rate:** 100% (20/20 passed).
* **Fault Injection Coverage:** 100% of defined exception types in `app.modules.ai.llm.exceptions` are verified with direct triggering test cases.

### Documented Coverage Gaps
The following capabilities were intentionally not tested in P2-H1 because their underlying implementations are deferred to later project phases:
1. **Server-Sent Events (SSE) Streaming:** Ollama streaming (`stream: True`) was not tested because streaming is explicitly deferred to Phase 4 (Frontend Investigation Dashboard). All Phase 2 backend services consume complete responses (`stream: False`).
2. **Context Window Exceedance:** Token context truncation or model context window overflow handling is deferred to P2-H5 (Context Management & Prompt Engineering).
3. **Multi-Turn Stateful Session Management:** Chat history persistence across investigation steps is managed at the investigation service layer, not inside the stateless provider adapter.
