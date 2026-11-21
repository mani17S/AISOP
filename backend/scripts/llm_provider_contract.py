"""
Provider contract checker (a developer tool, deliberately OUTSIDE the product tree).

Checks the SHAPE of an LLM provider before you select it with ``LLM_PROVIDER=<name>``:

    from llm_provider_contract import check_provider_contract      # with backend/scripts on sys.path
    problems = await check_provider_contract(provider)

Returns plain-language problems; an empty list means the provider has the shape AISOP relies on (the protocol, a model name, a health probe that
reports instead of raising). It never calls ``generate``: the architecture guard allows only the gated generator to call a model, so the
generation path is verified the supported way, by running an AI-on investigation with the provider selected and checking that each incident
ends in ``validated`` or a ``fallback:`` status. It checks shape, not model quality.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.modules.ai.llm.protocol import LLMProvider  # noqa: E402
from app.schemas.ai import ProviderHealthResponse  # noqa: E402


async def check_provider_contract(provider: object) -> list[str]:
    problems: list[str] = []
    if not isinstance(provider, LLMProvider):
        return ["The object does not implement the LLMProvider protocol (model_name, generate, health)."]
    name = provider.model_name
    if not isinstance(name, str) or not name.strip():
        problems.append("model_name must be a non-empty string.")
    try:
        health = await provider.health()
    except Exception:  # noqa: BLE001
        problems.append("health() must report a status, not raise.")
    else:
        if not isinstance(health, ProviderHealthResponse):
            problems.append("health() must return a ProviderHealthResponse.")
    return problems
