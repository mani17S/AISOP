"""Phase 4A work item B: enrichment provenance. Offline, synthetic fixtures only."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.modules.evidence_domains.ti import Enrichment, IndicatorMatch, StaticIndicatorSet, enrich

RETRIEVED = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
OBSERVED = datetime(2026, 11, 10, 8, 30, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    real_connect = socket.socket.connect

    def _blocked(*a, **k):
        raise AssertionError("network or DNS access attempted in an offline test")

    def _loopback_only(self, address, *a, **k):
        # asyncio's Windows event loop connects an internal loopback socket pair; anything else is a real network attempt.
        host = address[0] if isinstance(address, tuple) else address
        if host in ("127.0.0.1", "::1"):
            return real_connect(self, address, *a, **k)
        raise AssertionError("network access attempted in an offline test")

    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _loopback_only)


def _full_match() -> IndicatorMatch:
    return IndicatorMatch(
        source="Synthetic Feed", description="listed as a scanner", kind="indicator", reference="syn-001",
        source_id="synthetic_feed", record_id="rec-42", retrieved_at=RETRIEVED, source_observed_at=OBSERVED,
        dataset_version="2026-11-14T00:00Z", lineage=("upstream-a",), freshness="fresh",
    )


def _enrichment(match: IndicatorMatch) -> Enrichment:
    return Enrichment(entity=("ip", "91.240.118.172"), matches=(match,), observed_in=("obs-1",))


def test_new_enrichment_serializes_and_deserializes_with_provenance():
    view = _enrichment(_full_match()).view()
    prov = view["matches"][0]["provenance"]
    assert prov["source_id"] == "synthetic_feed" and prov["record_id"] == "rec-42" and prov["dataset_version"] == "2026-11-14T00:00Z"
    assert prov["retrieved_at"] == RETRIEVED.isoformat() and prov["source_observed_at"] == OBSERVED.isoformat() and prov["lineage"] == ["upstream-a"]
    restored = Enrichment.from_view(json.loads(json.dumps(view)))  # survives a JSON round trip (as stored in an audit row)
    assert restored.matches[0] == _full_match() and restored.entity == ("ip", "91.240.118.172")


def test_historical_view_without_provenance_deserializes_and_stays_without_provenance():
    historical = {"entity": "ip:91.240.118.172", "trust_class": "ti_context", "observed_in": ["obs-1"],
                  "matches": [{"source": "old-feed", "kind": "indicator", "description": "old", "reference": None}], "statement": "x"}
    restored = Enrichment.from_view(historical)
    m = restored.matches[0]
    assert m.source == "old-feed" and m.source_id is None and m.retrieved_at is None and m.source_observed_at is None and m.freshness is None and m.lineage == ()
    assert "provenance" not in restored.view()["matches"][0]  # nothing is invented for an old record


def test_match_without_provenance_produces_the_same_view_as_before():
    view = _enrichment(IndicatorMatch(source="s", description="d")).view()
    assert view["matches"][0] == {"source": "s", "kind": "indicator", "description": "d", "reference": None}


def test_missing_provider_timestamps_stay_missing_and_are_not_filled_from_retrieval_time():
    m = IndicatorMatch(source="s", description="d", retrieved_at=RETRIEVED)
    assert m.source_observed_at is None and m.source_updated_at is None
    prov = m.provenance_view()
    assert prov == {"retrieved_at": RETRIEVED.isoformat()}
    back = IndicatorMatch.from_view(_enrichment(m).view()["matches"][0])
    assert back.source_observed_at is None and back.source_updated_at is None


def test_retrieval_time_is_distinct_from_provider_observed_and_updated_times():
    updated = OBSERVED + timedelta(days=1)
    m = IndicatorMatch(source="s", description="d", retrieved_at=RETRIEVED, source_observed_at=OBSERVED, source_updated_at=updated)
    assert len({m.retrieved_at, m.source_observed_at, m.source_updated_at}) == 3
    back = IndicatorMatch.from_view(_enrichment(m).view()["matches"][0])
    assert (back.retrieved_at, back.source_observed_at, back.source_updated_at) == (RETRIEVED, OBSERVED, updated)


def test_naive_timestamps_are_rejected_and_timezones_are_normalised_to_utc():
    with pytest.raises(ValueError):
        IndicatorMatch(source="s", description="d", retrieved_at=datetime(2026, 11, 14, 12, 0))
    plus2 = datetime(2026, 11, 14, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    assert IndicatorMatch(source="s", description="d", retrieved_at=plus2).retrieved_at == RETRIEVED


def test_source_identity_is_preserved_and_display_name_stays_separate():
    m = _full_match()
    assert m.source == "Synthetic Feed" and m.source_id == "synthetic_feed"


def test_lineage_is_declared_not_an_independence_claim():
    a = IndicatorMatch(source="a", description="d", source_id="a", lineage=("shared-upstream",))
    b = IndicatorMatch(source="b", description="d", source_id="b", lineage=("shared-upstream",))
    assert a.lineage == b.lineage and a.source_id != b.source_id
    view = _enrichment(a).view()["matches"][0]["provenance"]
    assert set(view) == {"source_id", "lineage"}  # nothing like "independent" or a combined score is emitted
    assert not any("independent" in str(v).lower() or "corroborat" in str(v).lower() for v in view.values())


def test_invalid_provenance_values_are_rejected():
    with pytest.raises(ValueError):
        IndicatorMatch(source="s", description="d", freshness="fresh-ish")
    with pytest.raises(ValueError):
        IndicatorMatch(source="s", description="d", source_id="   ")
    with pytest.raises(ValueError):
        IndicatorMatch(source="s", description="d", lineage=("ok", ""))
    with pytest.raises(ValueError):
        IndicatorMatch(source="s", description="d", lineage=tuple(str(i) for i in range(50)))


def test_provenance_does_not_copy_the_queried_value_and_no_logging_is_involved(caplog):
    value = "91.240.118.172"
    with caplog.at_level("DEBUG"):
        view = _enrichment(_full_match()).view()
    assert value not in json.dumps(view["matches"])  # the indicator is only on the Enrichment entity, never duplicated into provenance
    assert value not in caplog.text


def test_provenance_does_not_mutate_the_observation_or_change_what_is_enriched():
    obs = SimpleNamespace(counts_for_corroboration=True, entities=[("ip", "91.240.118.172")], key="k1")
    before = (tuple(obs.entities), obs.key, obs.counts_for_corroboration)
    plain, rich = StaticIndicatorSet(), StaticIndicatorSet()
    plain.add("ip", "91.240.118.172", IndicatorMatch(source="s", description="d"))
    rich.add("ip", "91.240.118.172", _full_match())
    a, b = enrich([obs], plain), enrich([obs], rich)
    assert (tuple(obs.entities), obs.key, obs.counts_for_corroboration) == before
    assert [(e.entity, e.observed_in, e.trust_class, e.statement) for e in a] == [(e.entity, e.observed_in, e.trust_class, e.statement) for e in b]
    assert b[0].trust_class == "ti_context"  # still reference context, never evidence
