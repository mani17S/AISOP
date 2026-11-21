"""
Modular LLM layer: a provider is added by registering a factory, with no change to core code; the local-first and fail-closed rules still hold.
"""
from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.modules.ai.llm import manager
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from llm_provider_contract import check_provider_contract  # noqa: E402  (developer tool, kept outside the product tree)
from app.modules.ai.llm.exceptions import LLMConfigurationError, LLMError
from app.modules.ai.llm.inert import InertLLMProvider
from app.modules.ai.llm.manager import get_llm_provider, register_llm_provider, registered_llm_providers
from app.schemas.ai import LLMRequest, LLMResponse, ProviderHealthResponse


class FakeProvider:
    """A third-party provider written only against the public protocol."""

    def __init__(self, model: str = "fake-1") -> None:
        self._model = model

    @property
    def model_name(self) -> str:
        return self._model

    async def generate(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(content="ok", model=self._model)

    async def health(self) -> ProviderHealthResponse:
        return ProviderHealthResponse(status="healthy", model=self._model, provider="fakeprov")


@pytest.fixture
def clean_registry():
    saved = dict(manager._FACTORIES)
    yield
    manager._FACTORIES.clear()
    manager._FACTORIES.update(saved)


def cfg(**kw):
    return get_settings().model_copy(update={"LLM_ENABLED": True, **kw})


def test_ollama_is_built_in_and_the_default_is_unchanged(clean_registry):
    assert "ollama" in registered_llm_providers()
    p = get_llm_provider(cfg(LLM_PROVIDER="ollama"))
    assert type(p).__name__ == "OllamaProvider"


def test_a_new_provider_plugs_in_without_touching_core_and_is_used_only_when_selected(clean_registry):
    register_llm_provider("fakeprov", lambda s: FakeProvider())
    assert "fakeprov" in registered_llm_providers()
    assert type(get_llm_provider(cfg(LLM_PROVIDER="ollama"))).__name__ == "OllamaProvider"        # registering never activates it
    assert isinstance(get_llm_provider(cfg(LLM_PROVIDER="FakeProv ")), FakeProvider)              # selected by name only (case and spaces tolerated)


def test_unregistered_names_fail_closed_and_list_what_exists(clean_registry):
    with pytest.raises(LLMError) as e:
        get_llm_provider(cfg(LLM_PROVIDER="gpt-something"))
    assert "ollama" in str(e.value) and "gpt-something" not in str(e.value)                       # no echo of the requested value


def test_disabled_ai_never_builds_any_provider(clean_registry):
    def boom(_s):
        raise AssertionError("factory must not run when AI is disabled")
    register_llm_provider("fakeprov", boom)
    assert isinstance(get_llm_provider(cfg(LLM_ENABLED=False, LLM_PROVIDER="fakeprov")), InertLLMProvider)


def test_a_failing_factory_never_leaks_its_error_text(clean_registry):
    register_llm_provider("leaky", lambda s: (_ for _ in ()).throw(RuntimeError("secret-key-abc123")))
    with pytest.raises(LLMConfigurationError) as e:
        get_llm_provider(cfg(LLM_PROVIDER="leaky"))
    assert "secret-key-abc123" not in str(e.value)


def test_an_object_that_breaks_the_contract_is_refused(clean_registry):
    register_llm_provider("notaprovider", lambda s: object())
    with pytest.raises(LLMConfigurationError):
        get_llm_provider(cfg(LLM_PROVIDER="notaprovider"))


def test_names_are_validated_and_duplicates_need_an_explicit_replace(clean_registry):
    for bad in ("", "A", "has space", "x" * 33, "9start", "a/b"):
        with pytest.raises(LLMConfigurationError):
            register_llm_provider(bad, lambda s: FakeProvider())
    register_llm_provider("fakeprov", lambda s: FakeProvider())
    with pytest.raises(LLMConfigurationError):
        register_llm_provider("fakeprov", lambda s: FakeProvider())
    register_llm_provider("fakeprov", lambda s: FakeProvider("fake-2"), replace=True)
    assert get_llm_provider(cfg(LLM_PROVIDER="fakeprov")).model_name == "fake-2"


@pytest.mark.anyio
async def test_the_contract_checker_accepts_a_good_provider_and_names_the_problems_of_a_bad_one():
    assert await check_provider_contract(FakeProvider()) == []

    class NoHealth(FakeProvider):
        async def health(self):
            raise RuntimeError("down")

    class NoName(FakeProvider):
        @property
        def model_name(self):
            return " "

    assert any("health()" in p for p in await check_provider_contract(NoHealth()))
    assert any("model_name" in p for p in await check_provider_contract(NoName()))
    assert await check_provider_contract(object())                                                  # not a provider at all


@pytest.fixture
def anyio_backend():
    return "asyncio"
