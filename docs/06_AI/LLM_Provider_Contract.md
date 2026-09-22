# AISOP LLM Provider Contract & Protocol Specification (P2-H1)

| Field | Value |
|---|---|
| **Document ID** | AI-SPEC-001 |
| **Milestone** | P2-H1 (LLM Provider Protocol & Local Ollama Adapter) |
| **Status** | ACTIVE |
| **Governing ADR** | [ADR-001: AI/LLM Layer Abstraction Strategy](file:///docs/03_System_Design/ADR/ADR-001_LLM_Layer_Abstraction.md) |
| **Last Updated** | 2026-09-22 |

---

## 1. Overview & Purpose

AISOP's AI layer drives automated threat investigation, evidence correlation, MITRE ATT&CK technique mapping, and SOC report generation. In accordance with **ADR-001 (Direct Lightweight LLM Abstraction)**, AISOP rejects vendor and framework lock-in (prohibiting LangChain, LangGraph, and LlamaIndex).

This document specifies the team-owned **Provider Protocol Contract** and the reference **Local Ollama Adapter** implementation delivered in Milestone **P2-H1**.

---

## 2. Architectural Invariants

1. **Vendor Independence:** Core application services interact solely with the runtime `LLMProvider` Protocol. They never import Ollama, OpenAI, or other vendor modules directly.
2. **Deterministic Schemas:** All inputs (`LLMRequest`) and outputs (`LLMResponse`) are validated using immutable Pydantic v2 schemas (`frozen=True`).
3. **Local-First Reference Implementation:** Ollama is the default inference engine, requiring zero cloud connectivity and zero API keys for baseline operations.
4. **Resilient HTTP Communication:** Communication is performed directly over asynchronous HTTP (`httpx.AsyncClient`) with exponential backoff retries (`tenacity`) for transient failures.
5. **Deterministic In-Memory Testing:** All provider adapters must be fully testable without a live GPU daemon using `httpx.MockTransport`.
6. **Streaming Policy:** Streaming responses are **explicitly deferred** to Phase 4 (Investigation Dashboard). All Phase 2 backend pipelines require complete structured JSON or text outputs before database insertion or multi-step analysis.

---

## 3. Core Interface & Data Contracts

### 3.1 Provider Protocol (`app.modules.ai.llm.protocol.LLMProvider`)

```python
from typing import Protocol, runtime_checkable
from app.schemas.ai import LLMRequest, LLMResponse, ProviderHealthResponse

@runtime_checkable
class LLMProvider(Protocol):
    """Contract for all AISOP LLM inference adapters."""

    @property
    def model_name(self) -> str:
        """Active model identifier configured for this provider instance (e.g. 'llama3.1:8b')."""
        ...

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Execute a complete, non-streaming chat generation request.

        Args:
            request: Standardized request containing conversation history, optional
                     model override, temperature, max tokens, and JSON mode flag.

        Returns:
            LLMResponse containing assistant content, model identifier, and token metrics.

        Raises:
            LLMConnectionError: If the provider daemon is unreachable.
            LLMTimeoutError: If inference execution exceeds configured timeout.
            LLMModelNotFoundError: If requested model is not pulled or available.
            LLMResponseError: If provider returns HTTP 5xx/4xx or malformed payload.
        """
        ...

    async def health(self) -> ProviderHealthResponse:
        """
        Perform a non-intrusive probe of provider reachability and model availability.

        Returns:
            ProviderHealthResponse containing status, target model, latency, and error details.
        """
        ...
```

### 3.2 Schemas & Data Contracts (`app.schemas.ai`)

* **`MessageRole(StrEnum)`:** Supported participant roles: `SYSTEM = "system"`, `USER = "user"`, `ASSISTANT = "assistant"`.
* **`LLMMessage`:**
  * `role: MessageRole`
  * `content: str` (min_length=1)
* **`LLMRequest`:**
  * `messages: list[LLMMessage]` (min_length=1, chronological order)
  * `model: str | None = None` (request-level model override)
  * `temperature: float | None = None` (0.0 to 2.0; defaults to provider setting)
  * `max_tokens: int | None = None` (maximum tokens to generate)
  * `json_mode: bool = False` (enforces valid JSON output when True)
* **`TokenUsage`:**
  * `prompt_tokens: int = 0` (input context token count)
  * `completion_tokens: int = 0` (generated output token count)
  * `total_tokens: int = 0` (prompt + completion)
  * `duration_ms: float = 0.0` (inference execution latency in milliseconds)
* **`LLMResponse`:**
  * `content: str` (generated assistant text or JSON string)
  * `role: MessageRole = MessageRole.ASSISTANT`
  * `model: str` (identifier of the model that generated the response)
  * `usage: TokenUsage` (token and latency metrics)
  * `finish_reason: str = "stop"` (termination reason: 'stop' or 'incomplete')
  * `raw_response: dict[str, Any] | None = None` (sanitized raw dictionary for debugging)
* **`ProviderHealthResponse`:**
  * `status: Literal["healthy", "degraded", "unavailable"]`
  * `model: str` (configured model tag)
  * `provider: str` (provider name, e.g. "ollama")
  * `latency_ms: float` (round-trip probe latency)
  * `error: str | None` (diagnostic error message if status != healthy)

---

## 4. Ollama Reference Adapter Specification

The reference adapter is located at `app.modules.ai.providers.ollama.provider.OllamaProvider`.

### 4.1 Endpoint Mapping

* **Inference Endpoint:** `POST {base_url}/api/chat`
* **Health & Model Probe:** `GET {base_url}/api/tags`

### 4.2 Request Translation

| AISOP `LLMRequest` Property | Ollama `/api/chat` Payload Field | Notes |
|---|---|---|
| `messages` | `"messages"` | Converted to list of `{"role": msg.role.value, "content": msg.content}` |
| `model` or configured default | `"model"` | Target model tag (e.g. `"llama3.1:8b"`) |
| `temperature` or default (0.2) | `"options": {"temperature": ...}` | Sampling temperature |
| `max_tokens` (if provided) | `"options": {"num_predict": ...}` | Maximum generation tokens |
| `json_mode: True` | `"format": "json"` | Instructs Ollama to constrain decoding to valid JSON |
| Hardcoded | `"stream": False` | Disables chunked SSE streaming |
| Configured `keep_alive` | `"keep_alive": "5m"` | Keeps model resident in memory |

### 4.3 Response Translation & Accounting

| Ollama Response Property | AISOP `LLMResponse` Mapping | Notes |
|---|---|---|
| `message.content` | `content` | Extracted string output |
| `model` | `model` | Exact model used by provider |
| `prompt_eval_count` | `usage.prompt_tokens` | Prompt tokens evaluated |
| `eval_count` | `usage.completion_tokens` | Tokens generated |
| `total_duration` | `usage.duration_ms` | Converted from nanoseconds (`duration_ns / 1_000_000.0`) |
| `done == True` | `finish_reason = "stop"` | Set to "incomplete" if done is False |
| Entire payload | `raw_response` | Recursively sanitized via `redact_sensitive_data()` |

---

## 5. Domain Exception Hierarchy & Error Handling Policy

All AI-related exceptions inherit from `app.modules.ai.llm.exceptions.LLMError`.

```
LLMError (base)
├── LLMConnectionError       # Daemon unreachable, connection refused, or network broken
├── LLMTimeoutError          # Inference or health probe exceeded timeout threshold
├── LLMModelNotFoundError   # Requested model tag absent from provider (HTTP 404)
└── LLMResponseError         # HTTP error (4xx, 5xx) or unparseable/malformed response
```

### 5.1 Failure Matrix & Resilience Strategy

| Failure Scenario | HTTP / Underlying Cause | Retry Policy | Translated Domain Error |
|---|---|---|---|
| **Connection Refused** | `httpx.ConnectError` (Ollama down) | Retry with exponential backoff (1s to 8s, up to 3 attempts). | `LLMConnectionError` |
| **Server Overload** | HTTP 502, 503, 504 | Retry with exponential backoff (up to 3 attempts). | `LLMResponseError` (preserving HTTP status) |
| **Model Absent** | HTTP 404 (model not pulled) | **Fail fast.** Zero retries. | `LLMModelNotFoundError` |
| **Client Error** | HTTP 400 (bad parameters) | **Fail fast.** Zero retries. | `LLMResponseError(status_code=400)` |
| **Inference Timeout** | `httpx.ReadTimeout` (>120s) | **Fail fast.** Zero retries (prevents compounding latency). | `LLMTimeoutError` |
| **Malformed JSON** | Non-JSON text or missing `message.content` | **Fail fast.** Zero retries. | `LLMResponseError` |
| **Health: Model Missing** | GET `/api/tags` 200 OK, tag not found | Probes return structured response without raising. | `ProviderHealthResponse(status="degraded")` |
| **Health: Daemon Down** | GET `/api/tags` connection error | Probes return structured response without raising. | `ProviderHealthResponse(status="unavailable")` |

---

## 6. Configuration Reference

Ollama settings are defined in `app.core.config.Settings` and loaded via `.env` or system environment variables:

| Environment Variable | Default Value | Type | Description |
|---|---|---|---|
| `LLM_PROVIDER` | `"ollama"` | `str` | Active provider resolved by `get_llm_provider()` |
| `OLLAMA_BASE_URL` | `"http://localhost:11434"` | `str` | Host and port for the Ollama REST API |
| `OLLAMA_MODEL` | `"llama3.1:8b"` | `str` | Default model tag for inference |
| `OLLAMA_TIMEOUT_SECONDS` | `120` | `int` (gt 0) | Request execution timeout in seconds |
| `OLLAMA_TEMPERATURE` | `0.2` | `float` (0.0–2.0) | Default sampling temperature (deterministic SOC reasoning) |
| `OLLAMA_MAX_RETRIES` | `3` | `int` (1–10) | Maximum retry attempts for transient server errors |
| `OLLAMA_KEEP_ALIVE` | `"5m"` | `str` | Model retention duration in Ollama memory |

---

## 7. Factory Usage

To acquire the configured provider in application services:

```python
from app.modules.ai.llm import get_llm_provider, LLMProvider
from app.schemas.ai import LLMMessage, LLMRequest, MessageRole

provider: LLMProvider = get_llm_provider()

request = LLMRequest(
    messages=[
        LLMMessage(role=MessageRole.SYSTEM, content="You are a security analyst."),
        LLMMessage(role=MessageRole.USER, content="Summarize the suspicious process activity."),
    ],
    temperature=0.1,
    json_mode=False,
)

response = await provider.generate(request)
print(response.content)
print(f"Tokens: {response.usage.total_tokens}, Latency: {response.usage.duration_ms}ms")
```
