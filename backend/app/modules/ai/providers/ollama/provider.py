"""
AISOP Ollama LLM Provider Implementation.

In accordance with ADR-001 (Direct Lightweight LLM Abstraction):
Implements the LLMProvider protocol by making asynchronous HTTP calls directly to Ollama's
REST API (/api/chat and /api/tags) via httpx.
Includes transient error resilience via tenacity, JSON mode enforcement, token accounting,
and health check probing.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from app.core.logging import redact_sensitive_data
from app.modules.ai.llm.exceptions import (
    LLMConnectionError,
    LLMError,
    LLMModelNotFoundError,
    LLMResponseError,
    LLMTimeoutError,
)
from app.modules.ai.llm.protocol import LLMProvider
from app.schemas.ai import (
    LLMRequest,
    LLMResponse,
    MessageRole,
    ProviderHealthResponse,
    TokenUsage,
)
from loguru import logger
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)


def _is_transient_network_error(exc: BaseException) -> bool:
    """Identify transient network and server errors eligible for retry."""
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)):
        return True
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (
        502,
        503,
        504,
    ):
        return True
    return False


class OllamaProvider:
    """
    Direct asynchronous HTTP provider for local Ollama instances.

    Communicates with Ollama's /api/chat endpoint to execute inference,
    handle structured JSON output modes, track token metrics, and report health.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.1:8b",
        timeout_seconds: int = 120,
        temperature: float = 0.2,
        max_retries: int = 3,
        keep_alive: str = "5m",
        client: httpx.AsyncClient | None = None,
        num_ctx: int | None = None,
    ) -> None:
        self._num_ctx = num_ctx
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._temperature = temperature
        self._max_retries = max_retries
        self._keep_alive = keep_alive
        self._client = client
        self._owns_client = client is None

    @property
    def model_name(self) -> str:
        """The active model identifier configured for this provider."""
        return self._model

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout_seconds, connect=10.0)
            )
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        """Close the underlying HTTP client if owned by this instance."""
        if (
            self._owns_client
            and self._client is not None
            and not self._client.is_closed
        ):
            await self._client.aclose()

    async def __aenter__(self) -> OllamaProvider:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    def _build_payload(self, request: LLMRequest) -> dict[str, Any]:
        target_model = request.model or self._model
        target_temp = (
            request.temperature
            if request.temperature is not None
            else self._temperature
        )

        payload: dict[str, Any] = {
            "model": target_model,
            "messages": [
                {"role": msg.role.value, "content": msg.content}
                for msg in request.messages
            ],
            "stream": False,
            "keep_alive": self._keep_alive,
            "options": {
                "temperature": target_temp,
            },
        }

        if getattr(request, "response_schema", None):
            payload["format"] = request.response_schema
        elif request.json_mode:
            payload["format"] = "json"

        if getattr(request, "think", None) is not None:
            payload["think"] = request.think
        elif request.json_mode:
            payload["think"] = False

        if request.max_tokens is not None:
            payload["options"]["num_predict"] = request.max_tokens

        if self._num_ctx is not None:
            payload["options"]["num_ctx"] = self._num_ctx

        return payload

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Execute non-streaming inference via Ollama /api/chat.

        Args:
            request: Standardized request containing messages, optional overrides, and flags.

        Returns:
            LLMResponse containing assistant content and token usage metrics.
        """
        target_model = request.model or self._model
        url = f"{self._base_url}/api/chat"
        payload = self._build_payload(request)
        client = self._get_client()

        logger.debug(
            "Dispatching LLM inference request to Ollama",
            model=target_model,
            endpoint=url,
            message_count=len(request.messages),
            json_mode=request.json_mode,
        )

        response_data: dict[str, Any] = {}

        try:
            retryer = AsyncRetrying(
                retry=retry_if_exception(_is_transient_network_error),
                stop=stop_after_attempt(max(1, self._max_retries)),
                wait=wait_exponential(multiplier=1.0, min=1.0, max=8.0),
                reraise=True,
            )

            async for attempt in retryer:
                with attempt:
                    try:
                        response = await client.post(
                            url,
                            json=payload,
                            timeout=httpx.Timeout(self._timeout_seconds, connect=10.0),
                        )
                        response.raise_for_status()
                        response_data = response.json()
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            raise LLMModelNotFoundError(
                                f"Model '{target_model}' not found in Ollama at {self._base_url}",
                                details={
                                    "status_code": 404,
                                    "response": exc.response.text,
                                },
                            ) from exc
                        if 400 <= exc.response.status_code < 500:
                            raise LLMResponseError(
                                f"Ollama client error ({exc.response.status_code}): {exc.response.text}",
                                status_code=exc.response.status_code,
                                response_body=exc.response.text,
                            ) from exc
                        # 5xx status codes trigger retry via _is_transient_network_error
                        raise

        except RetryError as exc:
            # All retry attempts exhausted
            last_exc = exc.last_attempt.exception()
            if isinstance(last_exc, (httpx.ConnectError, httpx.ConnectTimeout)):
                raise LLMConnectionError(
                    f"Failed to connect to Ollama at {self._base_url} after {self._max_retries} attempts: {last_exc}",
                    details={"base_url": self._base_url},
                ) from last_exc
            if isinstance(last_exc, httpx.HTTPStatusError):
                raise LLMResponseError(
                    f"Ollama server error ({last_exc.response.status_code}) persisted after {self._max_retries} retries",
                    status_code=last_exc.response.status_code,
                    response_body=last_exc.response.text,
                ) from last_exc
            raise LLMError(
                f"Ollama inference failed after retries: {last_exc}"
            ) from last_exc

        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(
                f"Ollama inference timed out after {self._timeout_seconds}s at {self._base_url}",
                details={
                    "timeout_seconds": self._timeout_seconds,
                    "model": target_model,
                },
            ) from exc

        except httpx.ConnectError as exc:
            raise LLMConnectionError(
                f"Failed to connect to Ollama daemon at {self._base_url}. Is Ollama running?",
                details={"base_url": self._base_url},
            ) from exc

        except (LLMError, LLMModelNotFoundError, LLMResponseError):
            raise

        except httpx.HTTPStatusError as exc:
            raise LLMResponseError(
                f"Ollama server error ({exc.response.status_code}): {exc.response.text}",
                status_code=exc.response.status_code,
                response_body=exc.response.text,
            ) from exc

        except Exception as exc:
            raise LLMResponseError(
                f"Unexpected error during Ollama inference: {exc}",
                details={"error_type": type(exc).__name__},
            ) from exc

        if not isinstance(response_data, dict):
            raise LLMResponseError(
                f"Expected dictionary response from Ollama, got {type(response_data).__name__}",
                details={"response_data": str(response_data)[:200]},
            )

        # Parse message content
        message_data = response_data.get("message")
        if not isinstance(message_data, dict) or "content" not in message_data:
            raise LLMResponseError(
                "Malformed response from Ollama: missing 'message.content'",
                details={"response_keys": list(response_data.keys())},
            )
        content = message_data.get("content", "")

        # Extract token usage and latency metrics
        prompt_tokens = int(response_data.get("prompt_eval_count", 0) or 0)
        completion_tokens = int(response_data.get("eval_count", 0) or 0)
        total_tokens = prompt_tokens + completion_tokens
        duration_ns = float(response_data.get("total_duration", 0) or 0)
        duration_ms = round(duration_ns / 1_000_000.0, 2)

        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            duration_ms=duration_ms,
        )

        done_reason = response_data.get("done_reason")
        if done_reason:
            finish_reason = done_reason
        elif response_data.get("done", True):
            finish_reason = "stop"
        else:
            finish_reason = "incomplete"

        if self._num_ctx is not None and total_tokens >= int(self._num_ctx * 0.9):
            logger.warning(
                "Ollama response used most of the configured context window; the prompt may have been truncated",
                model=target_model,
                num_ctx=self._num_ctx,
                total_tokens=total_tokens,
            )

        # Latency breakdown (milliseconds) for operators: where the time went, as reported by Ollama itself.
        load_ms = round(float(response_data.get("load_duration", 0) or 0) / 1_000_000.0, 2)
        prompt_eval_ms = round(float(response_data.get("prompt_eval_duration", 0) or 0) / 1_000_000.0, 2)
        eval_ms = round(float(response_data.get("eval_duration", 0) or 0) / 1_000_000.0, 2)

        logger.info(
            "Ollama inference completed successfully",
            load_ms=load_ms,
            prompt_eval_ms=prompt_eval_ms,
            eval_ms=eval_ms,
            model=target_model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            finish_reason=finish_reason,
            total_tokens=total_tokens,
            duration_ms=duration_ms,
        )

        return LLMResponse(
            content=content,
            role=MessageRole.ASSISTANT,
            model=target_model,
            usage=usage,
            finish_reason=finish_reason,
            raw_response=(
                redact_sensitive_data(response_data)
                if isinstance(response_data, dict)
                else None
            ),
        )

    async def health(self) -> ProviderHealthResponse:
        """
        Probe Ollama liveness and verify model availability via GET /api/tags.

        Returns:
            ProviderHealthResponse with status ('healthy', 'degraded', 'unavailable').
        """
        url = f"{self._base_url}/api/tags"
        client = self._get_client()
        probe_timeout = min(self._timeout_seconds, 5.0)
        start_time = time.perf_counter()

        try:
            response = await client.get(
                url, timeout=httpx.Timeout(probe_timeout, connect=2.0)
            )
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

            if response.status_code != 200:
                return ProviderHealthResponse(
                    status="degraded",
                    model=self._model,
                    provider="ollama",
                    latency_ms=latency_ms,
                    error=f"Ollama returned HTTP {response.status_code}: {response.text[:100]}",
                )

            data = response.json()
            models_list = data.get("models", [])
            installed_models = [
                m.get("name", "") for m in models_list if isinstance(m, dict)
            ]

            # Check if model tag is matched (exact match or prefix match e.g. llama3.1:8b in llama3.1:8b-instruct)
            model_present = any(
                self._model == name
                or name.startswith(f"{self._model}:")
                or self._model.startswith(f"{name}:")
                for name in installed_models
            )

            if not model_present:
                return ProviderHealthResponse(
                    status="degraded",
                    model=self._model,
                    provider="ollama",
                    latency_ms=latency_ms,
                    error=f"Ollama reachable but model '{self._model}' is not pulled. Available: {installed_models}",
                )

            return ProviderHealthResponse(
                status="healthy",
                model=self._model,
                provider="ollama",
                latency_ms=latency_ms,
                error=None,
            )

        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return ProviderHealthResponse(
                status="unavailable",
                model=self._model,
                provider="ollama",
                latency_ms=latency_ms,
                error=f"Connection refused at {self._base_url}: {exc}",
            )

        except httpx.TimeoutException:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return ProviderHealthResponse(
                status="unavailable",
                model=self._model,
                provider="ollama",
                latency_ms=latency_ms,
                error=f"Health check probe timed out after {probe_timeout}s",
            )

        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return ProviderHealthResponse(
                status="unavailable",
                model=self._model,
                provider="ollama",
                latency_ms=latency_ms,
                error=f"Unexpected health check error: {exc}",
            )
