"""
AISOP Cloudflare Workers AI provider: an OPT-IN, external language model for the public demo (ADR-016).

Local-first remains the default (Ollama). This provider is built only when the operator sets LLM_PROVIDER, the explicit
LLM_ALLOW_EXTERNAL_PROVIDER switch and credentials, and it is meant for synthetic demo data: the prompt, including evidence text, is sent
to Cloudflare. It uses the OpenAI-compatible chat route with a JSON schema, so the output is constrained exactly as it is locally, and
every claim still goes through the same deterministic validator.

Secrets: the token is held in a SecretStr and appears only in the Authorization header. It is never put in a request body, a log line,
an error, a health response or a stored raw response.

Budget: Workers AI's free allowance is 10,000 neurons a day. Each response reports the neurons it cost; this provider keeps a running
count per UTC day and refuses further calls (without sending them) once the configured limit is reached, so a public demo cannot
exhaust the allowance. The refusal is a typed connection error, so the pipeline falls back to the deterministic result.
"""

from __future__ import annotations

import time
from datetime import date, datetime, timezone
from typing import Any, Callable

import httpx
from loguru import logger
from pydantic import SecretStr

from app.modules.ai.llm.exceptions import (
    LLMConfigurationError,
    LLMConnectionError,
    LLMModelNotFoundError,
    LLMResponseError,
    LLMTimeoutError,
)
from app.modules.ai.providers.ollama.provider import _inference_gate
from app.schemas.ai import LLMRequest, LLMResponse, MessageRole, ProviderHealthResponse, TokenUsage

PROVIDER_NAME = "cloudflare_workers_ai"
API_ROOT = "https://api.cloudflare.com/client/v4/accounts"

# The allowance belongs to the account, and the application builds a provider per request, so what has been spent today is shared
# process state, not instance state. (A per-instance counter would restart on every request and protect nothing.)
_BUDGET: dict[str, Any] = {"day": None, "spent": 0.0}


def reset_budget_for_tests() -> None:
    _BUDGET["day"], _BUDGET["spent"] = None, 0.0


class CloudflareWorkersAIProvider:
    def __init__(
        self,
        account_id: str,
        api_token: str | SecretStr,
        model: str = "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        timeout_seconds: int = 120,
        daily_neuron_limit: int = 9000,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._account_id = account_id
        self._token = api_token if isinstance(api_token, SecretStr) else SecretStr(api_token)
        self._model = model
        self._timeout = timeout_seconds
        self._limit = daily_neuron_limit
        self._client = client
        self._owns_client = client is None
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:  # never show the token
        return f"CloudflareWorkersAIProvider(model={self._model!r})"

    @property
    def model_name(self) -> str:
        return self._model

    # ── budget ────────────────────────────────────────────────────────────────────────────────────────────────

    def _roll_day(self) -> None:
        today: date = self._clock().date()
        if _BUDGET["day"] != today:
            _BUDGET["day"], _BUDGET["spent"] = today, 0.0

    def _check_budget(self) -> None:
        self._roll_day()
        if _BUDGET["spent"] >= self._limit:
            raise LLMConnectionError(
                "The hosted AI daily allowance for this deployment is used up; AI assistance resumes tomorrow (UTC). "
                "The deterministic result is unaffected.",
                details={"neurons_spent": round(_BUDGET["spent"]), "daily_limit": self._limit},
            )

    # ── transport ─────────────────────────────────────────────────────────────────────────────────────────────

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(self._timeout, connect=10.0))
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token.get_secret_value()}", "Content-Type": "application/json"}

    @staticmethod
    def _raise_for_status(status: int) -> None:
        if status in (401, 403):
            raise LLMConfigurationError("The hosted AI service rejected the configured credentials.", details={"status_code": status})
        if status == 429:
            raise LLMConnectionError("The hosted AI service is rate limiting requests; try again shortly.", details={"status_code": status})
        if status in (404, 410):
            raise LLMModelNotFoundError("The configured hosted AI model is not available.", details={"status_code": status})
        if status >= 500:
            raise LLMResponseError("The hosted AI service returned a server error.", details={"status_code": status})
        raise LLMResponseError("The hosted AI service refused the request.", details={"status_code": status})

    def _body(self, request: LLMRequest) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": request.model or self._model,
            "messages": [{"role": getattr(m.role, "value", str(m.role)), "content": m.content} for m in request.messages],
            "max_tokens": request.max_tokens or 1024,
            "temperature": request.temperature if request.temperature is not None else 0.0,
        }
        if request.response_schema:
            body["response_format"] = {"type": "json_schema", "json_schema": {"name": "aisop_output", "schema": request.response_schema}}
        elif request.json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    # ── LLMProvider contract ──────────────────────────────────────────────────────────────────────────────────

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self._check_budget()
        target_model = request.model or self._model
        started = time.monotonic()
        async with _inference_gate():  # one shared cap on concurrent model calls, as for the local provider
            try:
                response = await self._get_client().post(
                    f"{API_ROOT}/{self._account_id}/ai/v1/chat/completions",
                    headers=self._headers(),
                    json=self._body(request),
                    timeout=httpx.Timeout(self._timeout, connect=10.0),
                )
            except httpx.TimeoutException:
                raise LLMTimeoutError("The hosted AI service did not answer in time.") from None
            except httpx.HTTPError as exc:
                raise LLMConnectionError("The hosted AI service could not be reached.", details={"error_type": type(exc).__name__}) from None
        if response.status_code != 200:
            self._raise_for_status(response.status_code)
        try:
            data = response.json()
            choice = data["choices"][0]
            content = (choice.get("message") or {}).get("content")
        except (ValueError, KeyError, IndexError, TypeError):
            raise LLMResponseError("The hosted AI service returned an answer in an unexpected shape.") from None
        if not isinstance(content, str):
            raise LLMResponseError("The hosted AI service returned no text.")
        usage = data.get("usage") or {}
        self._roll_day()
        _BUDGET["spent"] += float(usage.get("neurons") or 0.0)
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        duration_ms = round((time.monotonic() - started) * 1000.0, 2)
        logger.info(
            "Hosted AI inference completed",
            model=target_model, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            neurons=round(float(usage.get("neurons") or 0.0), 1), neurons_today=round(_BUDGET["spent"]), duration_ms=duration_ms,
        )
        return LLMResponse(
            content=content,
            role=MessageRole.ASSISTANT,
            model=target_model,
            usage=TokenUsage(
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                total_tokens=int(usage.get("total_tokens") or (prompt_tokens + completion_tokens)), duration_ms=duration_ms,
            ),
            finish_reason=str(choice.get("finish_reason") or "stop"),
            raw_response=None,  # never store the service's raw answer
        )

    async def health(self) -> ProviderHealthResponse:
        """Free probe (model search, no inference): reachability and credentials, without spending neurons."""
        started = time.monotonic()
        try:
            response = await self._get_client().get(
                f"{API_ROOT}/{self._account_id}/ai/models/search", params={"per_page": 1}, headers=self._headers(), timeout=httpx.Timeout(10.0, connect=5.0)
            )
        except httpx.HTTPError:
            return ProviderHealthResponse(
                status="unavailable", model=self._model, provider=PROVIDER_NAME, latency_ms=0.0, error="The hosted AI service could not be reached."
            )
        latency = round((time.monotonic() - started) * 1000.0, 2)
        if response.status_code == 200:
            return ProviderHealthResponse(status="healthy", model=self._model, provider=PROVIDER_NAME, latency_ms=latency)
        return ProviderHealthResponse(
            status="degraded", model=self._model, provider=PROVIDER_NAME, latency_ms=latency, error=f"The hosted AI service answered {response.status_code}."
        )
