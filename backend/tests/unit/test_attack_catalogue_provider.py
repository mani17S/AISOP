"""
Offline tests for the optional ATT&CK catalogue provider and its production composition point.

Covers: load at most once per provider, thread-safe lazy loading, explicit not-configured / unavailable states, no retry
loop after a failure, in-memory replacement for tests, no network, and no state leaking between tests. Nothing reads
``.env`` (the production factory's settings getter is replaced), starts the app, touches a database or calls a model.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

import app.services.attack_reference_service as svc
from app.modules.ai.guardrails.validator import InvestigationOutputValidator
from app.modules.attack_reference import CatalogueLoadResult, ErrorCode, try_load_catalogue
from app.modules.attack_reference.loader import PinnedRelease
from app.modules.attack_reference.provider import AttackCatalogueProvider, ProviderState
from tests.unit.test_attack_guardrail_lifecycle import hyp, make_event
from tests.unit.test_attack_reference_loader import base_document, mem, pin_for, write_doc
from tests.unit.test_output_guardrails_p2 import make_test_context, make_test_output


class CountingLoader:
    def __init__(self, result: CatalogueLoadResult, delay: float = 0.0) -> None:
        self.calls = 0
        self.args: list[tuple] = []
        self._result, self._delay = result, delay

    def __call__(self, path, expected):
        self.calls += 1
        self.args.append((path, expected))
        if self._delay:
            time.sleep(self._delay)
        return self._result


@pytest.fixture
def ok_result():
    return CatalogueLoadResult(catalogue=mem(base_document()))


@pytest.fixture
def clean_factory():
    svc.get_attack_reference_provider.cache_clear()
    yield
    svc.get_attack_reference_provider.cache_clear()


# ── provider lifecycle ──────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("path", [None, "", "   "])
def test_not_configured_is_explicit_and_never_loads(path):
    loader = CountingLoader(CatalogueLoadResult(catalogue=None, error_code=ErrorCode.PATH_MISSING))
    p = AttackCatalogueProvider(path, loader=loader)
    assert p.state == ProviderState.NOT_CONFIGURED and p.resolve() is None
    assert loader.calls == 0 and p.load_count == 0


def test_construction_is_lazy_and_loading_happens_once_per_provider(ok_result):
    loader = CountingLoader(ok_result)
    p = AttackCatalogueProvider("D:/somewhere/file.json", loader=loader)
    assert p.state == ProviderState.NOT_LOADED and loader.calls == 0           # nothing loaded at construction
    first = p.resolve()
    for _ in range(200):                                                       # many alerts / hypotheses / requests
        assert p.resolve() is first
    assert loader.calls == 1 and p.load_count == 1 and p.state == ProviderState.AVAILABLE


def test_concurrent_first_use_triggers_a_single_load(ok_result):
    loader = CountingLoader(ok_result, delay=0.05)
    p = AttackCatalogueProvider("D:/somewhere/file.json", loader=loader)
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: p.resolve(), range(32)))
    assert loader.calls == 1 and p.load_count == 1
    assert all(r is results[0] for r in results)


def test_a_failed_load_is_explicit_cached_and_not_retried_in_a_loop():
    failure = CatalogueLoadResult(catalogue=None, error_code=ErrorCode.HASH_MISMATCH, message="x")
    loader = CountingLoader(failure)
    p = AttackCatalogueProvider("D:/somewhere/file.json", loader=loader)
    for _ in range(50):
        r = p.resolve()
        assert r is not None and r.available is False and r.error_code == ErrorCode.HASH_MISMATCH
    assert loader.calls == 1 and p.state == ProviderState.UNAVAILABLE            # never presented as available


def test_the_provider_passes_the_configured_path_and_pinned_release_to_the_loader(ok_result):
    loader = CountingLoader(ok_result)
    pin = PinnedRelease("20.1", "0" * 64, "enterprise-attack", "Enterprise ATT&CK")
    AttackCatalogueProvider(" D:/x/y.json ", pin, loader=loader).resolve()
    assert loader.args == [("D:/x/y.json", pin)]


def test_real_loader_states_missing_hash_mismatch_version_mismatch_and_success(tmp_path):
    missing = AttackCatalogueProvider(tmp_path / "absent.json", pin_for(b"x"))
    assert missing.resolve().error_code == ErrorCode.PATH_MISSING and missing.state == ProviderState.UNAVAILABLE

    path, pin = write_doc(tmp_path, base_document())
    bad_hash = AttackCatalogueProvider(path, PinnedRelease(pin.release_version, "F" * 64, pin.domain, pin.collection_name))
    assert bad_hash.resolve().error_code == ErrorCode.HASH_MISMATCH

    bad_version = AttackCatalogueProvider(path, PinnedRelease("19.0", pin.sha256, pin.domain, pin.collection_name))
    assert bad_version.resolve().error_code == ErrorCode.VERSION_MISMATCH

    good = AttackCatalogueProvider(path, pin)
    r = good.resolve()
    assert r.available and good.state == ProviderState.AVAILABLE and good.load_count == 1


def test_a_loaded_catalogue_is_reused_without_reading_the_file_again(tmp_path):
    path, pin = write_doc(tmp_path, base_document())
    p = AttackCatalogueProvider(path, pin)
    first = p.resolve()
    path.unlink()                                                              # the file is gone: nothing may re-parse it
    assert p.resolve() is first and p.load_count == 1


def test_an_in_memory_catalogue_can_replace_the_provider_and_never_loads(ok_result):
    def boom(*_a, **_k):
        raise AssertionError("the loader must not be called")

    p = AttackCatalogueProvider.from_catalogue(ok_result.catalogue)
    p._loader = boom                                                           # noqa: SLF001 - proving it is never used
    assert p.state == ProviderState.AVAILABLE and p.resolve().catalogue is ok_result.catalogue and p.load_count == 0


def test_no_network_dns_or_socket_activity(tmp_path, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("network activity attempted")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refuse)
    path, pin = write_doc(tmp_path, base_document())
    assert AttackCatalogueProvider(path, pin).resolve().available


def test_many_validations_share_one_load_and_never_parse_per_alert(ok_result):
    loader = CountingLoader(ok_result)
    p = AttackCatalogueProvider("D:/x/f.json", loader=loader)
    for i in range(60):                                                        # sixty "alerts", each building a validator
        e = make_event()
        ctx = make_test_context(events=[e])
        out = make_test_output(ctx, mitre_hypotheses=[hyp("T1070.001", [e]), hyp("T9999", [e]), hyp("T1059.001", [e])])
        InvestigationOutputValidator(attack_reference=p.resolve()).validate(out, ctx)
    assert loader.calls == 1


# ── production composition (settings replaced: nothing reads .env) ──────────────────────────────────────────────
def _settings(monkeypatch, path):
    monkeypatch.setattr(svc, "get_settings", lambda: SimpleNamespace(ATTACK_REFERENCE_PATH=path))


def test_unset_path_means_not_configured_and_validation_continues(monkeypatch, clean_factory):
    _settings(monkeypatch, None)
    assert svc.resolve_attack_reference() is None
    assert svc.get_attack_reference_provider().state == ProviderState.NOT_CONFIGURED
    e = make_event()
    ctx = make_test_context(events=[e])
    res = InvestigationOutputValidator(attack_reference=svc.resolve_attack_reference()).validate(
        make_test_output(ctx, mitre_hypotheses=[hyp("T1078", [e], conf=0.6)]), ctx)
    h = res.output.mitre_attack_hypotheses[0]
    assert h.taxonomy.state.value == "NOT_CONFIGURED" and h.confidence == 0.6 and res.is_valid


def test_configured_but_mismatching_file_is_explicitly_unavailable_not_valid(monkeypatch, tmp_path, clean_factory):
    path, _ = write_doc(tmp_path, base_document())                              # valid JSON, but not the pinned release bytes
    _settings(monkeypatch, str(path))
    r = svc.resolve_attack_reference()
    assert isinstance(r, CatalogueLoadResult) and r.available is False and r.error_code == ErrorCode.SIZE_MISMATCH   # the pinned size is checked before the digest
    assert svc.get_attack_reference_provider().load_count == 1
    for _ in range(5):
        svc.resolve_attack_reference()
    assert svc.get_attack_reference_provider().load_count == 1                  # no retry loop


def test_the_factory_is_cached_per_process_and_resettable_without_leakage(monkeypatch, clean_factory):
    _settings(monkeypatch, None)
    a = svc.get_attack_reference_provider()
    assert a is svc.get_attack_reference_provider()
    svc.get_attack_reference_provider.cache_clear()
    _settings(monkeypatch, "D:/other/path.json")
    b = svc.get_attack_reference_provider()
    assert b is not a and a.state == ProviderState.NOT_CONFIGURED and b.state == ProviderState.NOT_LOADED


def test_importing_the_composition_module_loads_nothing(clean_factory):
    assert svc.get_attack_reference_provider.cache_info().currsize == 0        # no startup-time construction


def test_settings_field_defaults_to_not_configured():
    from app.core.config import Settings

    assert Settings.model_fields["ATTACK_REFERENCE_PATH"].default is None


def test_default_try_load_catalogue_is_the_only_loader_used_by_the_provider():
    import inspect

    sig = inspect.signature(AttackCatalogueProvider.__init__)
    assert sig.parameters["loader"].default is try_load_catalogue
