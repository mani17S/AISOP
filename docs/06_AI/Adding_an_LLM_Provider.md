# Adding an LLM provider

AISOP's AI layer is optional and modular. The built-in provider is local Ollama (free, runs on this machine). Anyone with an authorized model can add theirs without editing AISOP's core logic. Written 2026-11-21.

## What is and is not true today
- Implemented and tested: a provider registry (`register_llm_provider`), the `LLMProvider` protocol, a contract checker (a developer script outside the product tree, `backend/scripts/llm_provider_contract.py`), and the local Ollama provider (built in, the default).
- Not implemented: any second provider. The folders `providers/openai`, `providers/anthropic` and `providers/gemini` are empty placeholders and do nothing.
- The AI layer never decides facts. Whatever a provider returns goes through the same evidence-sufficiency gate and claim verification as Ollama output, and stays labelled as AI output, never as observed evidence.

## Rules every provider inherits (they are enforced by the core, not by the provider)
1. Off unless selected: registering a provider never activates it. The operator selects it with `LLM_PROVIDER=<name>`. The provider is never inferred from API keys, and there is no fallback from one provider to another.
2. `LLM_ENABLED=false` builds no provider at all; every deterministic path keeps working.
3. Local-first: a provider that talks to another host must call `assert_endpoint_allowed` and so needs the operator's explicit `LLM_ALLOW_NON_LOCAL_ENDPOINT=true`. Prompts contain case evidence, so sending them to another host is an explicit decision.
4. Zero billing by default: nothing paid is configured, and no key is required for the built-in provider. A provider that costs money is the operator's own choice and responsibility.
5. A factory that raises never leaks its error text (it might hold a key); the configuration error is a fixed message.
6. A provider must raise only the typed errors in `app/modules/ai/llm/exceptions.py`, so the investigation paths can fall back to the deterministic result.

## How to add one (three steps)
1. Write a class with `model_name`, `async generate(request) -> LLMResponse` and `async health() -> ProviderHealthResponse` (see `app/modules/ai/llm/protocol.py`). Put it in `backend/app/modules/ai/providers/<name>/`.
2. Register it once at start-up: in `providers/<name>/__init__.py` call `register_llm_provider("<name>", lambda settings: YourProvider(...))`, and add `from . import <name>` to `providers/__init__.py`. Use `assert_endpoint_allowed` for any non-local URL.
3. Verify it before use:
   - Shape: `problems = await check_provider_contract(YourProvider(...))` from `backend/scripts/llm_provider_contract.py`; an empty list means it has the protocol, a model name and a health probe that reports instead of raising. The checker never calls `generate`, because an architecture test allows only the gated generator to call a model.
   - Generation: set `LLM_PROVIDER=<name>`, run an AI-on investigation, and check that every incident ends `validated` or `fallback:...`. Then run the suites.

## Evidence
`backend/tests/unit/test_llm_provider_registry.py` (8 tests): a plug-in provider is added with no change to core code, is used only when selected, unregistered names fail closed without echoing the value, disabled AI builds nothing, a failing factory does not leak its text, a non-provider object is refused, names are validated and duplicates need an explicit replace, and the contract checker names the problems of a bad provider.
Not evidenced: that any hosted model behaves well behind this layer, or what it would cost.
