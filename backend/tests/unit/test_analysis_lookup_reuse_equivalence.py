"""
Differential test for the whole-run lookup reuse in ``workflow.analyze`` (docs/05_Backend/Investigation_Responsiveness_Profiling_2026-11-25.md, section 3).

``analyze`` now builds ``{event_key: event}`` and the contradiction mapping ONCE from the final correlation result and passes them to
``build_incident_context`` / ``build_timeline``; each of those still builds its own tables when they are not passed. The REFERENCE path here is
the legacy construction (the two build functions are wrapped so the new parameters are dropped); the OPTIMISED path is ``analyze`` as shipped.
Both run on the same inputs and every analyst-visible and hash-bearing output must be byte-identical.

The complexity guard at the end is deliberately loose: it only distinguishes about linear from about quadratic growth.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.modules.correlation import demo_data as dd
from app.modules.correlation import workflow
from app.modules.correlation.normalize import raw_digest
from app.modules.correlation.timeline import build_timeline, conflicts_of
from app.modules.correlation.workflow import MAX_CONTEXT_EVENTS, analyze
from app.modules.evidence_domains import scenarios as S

_BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _separate(n: int) -> list[dict[str, Any]]:
    """n records that share no entity and are more than a day apart: n one-event incidents."""
    return [
        dd._siem(
            _iso(_BASE + timedelta(days=2 * i)), f"Isolated alert {i}", host=f"HOST-{i:04d}", user=f"user{i}",
            src_ip=f"{11 + i // 250}.{(i * 37) % 250 + 1}.{(i * 11) % 250 + 1}.{i % 250 + 1}", rule_id=f"R-{i}",
        )
        for i in range(n)
    ]


def _big_incident() -> list[dict[str, Any]]:
    """The intrusion chain (10 records) plus 250 alerts on the same host, user and source address: one incident of 260 events."""
    base = dd.intrusion_chain()
    t0 = datetime(2026, 11, 10, 9, 5, 0, tzinfo=timezone.utc)
    extra = [
        dd._siem(_iso(t0 + timedelta(seconds=5 * i)), f"Follow-on alert {i}", rule_id=f"R-F{i}", severity="medium")
        for i in range(250)
    ]
    return base + extra


def _tied() -> list[dict[str, Any]]:
    """Many alerts at one instant on one host, plus others at the same instant on another host."""
    t = "2026-11-12T10:00:00Z"
    a = [dd._siem(t, f"Tied alert {i}", rule_id=f"R-T{i}", host="TIE-01", user="tieuser", src_ip="45.33.32.156") for i in range(12)]
    b = [dd._siem(t, f"Tied other {i}", rule_id=f"R-U{i}", host="TIE-02", user="otheruser", src_ip="45.33.32.157") for i in range(3)]
    return a + b


def _mixed() -> list[Any]:
    return dd.unrelated_noise() + _separate(15) + _tied() + [{"foo": "bar"}, "not json"]


def _keyed() -> dict[str, Any]:
    recs = dd.duplicates_and_near_duplicates()
    dup = uuid.UUID("00000000-0000-4000-8000-0000000000aa")
    other = uuid.UUID("00000000-0000-4000-8000-0000000000bb")
    keys: list[Any] = [dup, None, dup, other, None, None, uuid.UUID("00000000-0000-4000-8000-0000000000cc")]
    digests: list[Any] = ["not-a-digest", None, "A" * 64, "z" * 64, None, "b" * 64]
    return {"records": recs, "event_keys": keys, "digests": digests}


def _dataset(name: str) -> dict[str, Any]:
    if name == "separate_60":
        return {"records": _separate(60)}
    if name == "big_incident_260":
        return {"records": _big_incident(), "assets": dd.ASSETS}
    if name == "mixed":
        return {"records": _mixed(), "assets": dd.ASSETS}
    if name == "keyed_duplicates_bad_digest":
        return _keyed()
    if name == "tied_timestamps":
        return {"records": _tied()}
    if name == "no_incidents":
        return {"records": dd.insufficient_unparseable()}
    if name.startswith("demo:"):
        s = dd.SCENARIOS[name.split(":", 1)[1]]
        return {"records": s["build"](), "assets": s.get("assets")}
    if name.startswith("envelope:"):
        return {"records": getattr(S, name.split(":", 1)[1])()}
    raise KeyError(name)


_NAMES = (
    ["separate_60", "big_incident_260", "mixed", "keyed_duplicates_bad_digest", "tied_timestamps", "no_incidents"]
    + [f"demo:{k}" for k in sorted(dd.SCENARIOS)]
    + [f"envelope:{f}" for f in ("scenario_a_identity_cloud", "scenario_b_network_endpoint", "scenario_c_email_forensic", "negative_analyst_only", "negative_contradiction")]
)


def _plain(obj: Any) -> str:
    """Deterministic text of dataclasses, models, sets and dicts with non-string keys."""
    def norm(o: Any) -> Any:
        if dataclasses.is_dataclass(o) and not isinstance(o, type):
            return norm({f.name: getattr(o, f.name) for f in dataclasses.fields(o)})
        if hasattr(o, "model_dump"):
            return norm(o.model_dump(mode="json"))
        if isinstance(o, dict):
            return {str(k): norm(v) for k, v in o.items()}
        if isinstance(o, (set, frozenset)):
            return sorted((json.dumps(norm(x), sort_keys=True) for x in o))
        if isinstance(o, (list, tuple)):
            return [norm(x) for x in o]
        if o is None or isinstance(o, (str, int, float, bool)):
            return o
        return str(o)

    return json.dumps(norm(obj), sort_keys=True)


def _snapshot(result: Any) -> dict[str, str]:
    snap: dict[str, str] = {"summary": _plain(result.summary())}
    for n, a in enumerate(result.incidents):
        snap[f"inc{n}.context"] = a.context.model_dump_json()
        snap[f"inc{n}.context_sha256"] = a.context.reproducibility.context_sha256
        snap[f"inc{n}.timeline"] = _plain([t.model_dump_json() for t in a.timeline])
        snap[f"inc{n}.assessment"] = a.assessment.model_dump_json()
        snap[f"inc{n}.assessment_sha256"] = a.assessment.assessment_sha256
        snap[f"inc{n}.reason_codes"] = _plain(a.assessment.reason_codes)
        snap[f"inc{n}.trace"] = _plain(a.trace)
        snap[f"inc{n}.attack"] = _plain([[m.model_dump_json() for m in a.mitre], a.asserted_only])
        snap[f"inc{n}.markdown"] = a.markdown
        snap[f"inc{n}.graph"] = _plain(a.graph)
    snap["batch_assessment"] = result.batch_assessment.model_dump_json() if result.batch_assessment is not None else ""
    snap["batch_trace"] = _plain(result.batch_trace)
    snap["batch_markdown"] = result.batch_markdown
    snap["ledger"] = _plain(result.ledger)
    snap["ledger_head"] = result.ledger_head
    snap["ledger_ok"] = str(result.ledger_ok)
    return snap


def _run_reference(monkeypatch: pytest.MonkeyPatch, ds: dict[str, Any]) -> Any:
    """The legacy path: the new optional parameters are dropped, so each build function constructs its own tables."""
    ctx, tl = workflow.build_incident_context, workflow.build_timeline

    def ref_ctx(result, incident, rejected_count=0, extra_flags=None, by_key=None):
        return ctx(result, incident, rejected_count, extra_flags)

    def ref_tl(result, incident, by_key=None, conflicts=None):
        return tl(result, incident)

    with monkeypatch.context() as m:
        m.setattr(workflow, "build_incident_context", ref_ctx)
        m.setattr(workflow, "build_timeline", ref_tl)
        return analyze(**ds)


def _run_optimised(monkeypatch: pytest.MonkeyPatch, ds: dict[str, Any]) -> tuple[Any, list[bool]]:
    """The shipped path, with a spy proving the shared tables really reach every per-incident call."""
    ctx, tl = workflow.build_incident_context, workflow.build_timeline
    passed: list[bool] = []

    def spy_ctx(result, incident, rejected_count=0, extra_flags=None, by_key=None):
        passed.append(by_key is not None)
        return ctx(result, incident, rejected_count, extra_flags, by_key=by_key)

    def spy_tl(result, incident, by_key=None, conflicts=None):
        passed.append(by_key is not None and conflicts is not None)
        return tl(result, incident, by_key=by_key, conflicts=conflicts)

    with monkeypatch.context() as m:
        m.setattr(workflow, "build_incident_context", spy_ctx)
        m.setattr(workflow, "build_timeline", spy_tl)
        return analyze(**ds), passed


@pytest.mark.parametrize("name", _NAMES)
def test_reference_and_optimised_paths_are_byte_identical(name, monkeypatch):
    ref = _snapshot(_run_reference(monkeypatch, _dataset(name)))
    result, passed = _run_optimised(monkeypatch, _dataset(name))
    opt = _snapshot(result)
    assert passed == [True] * (2 * len(result.incidents))  # the optimised path really used the shared tables
    assert opt.keys() == ref.keys()
    for key in ref:
        assert opt[key] == ref[key], f"{name}: {key} differs between the reference and the optimised path"


def test_the_datasets_exercise_what_they_claim(monkeypatch):
    sep = analyze(**_dataset("separate_60"))
    assert len(sep.incidents) >= 50 and all(len(a.incident.event_keys) == 1 for a in sep.incidents)

    big = analyze(**_dataset("big_incident_260"))
    biggest = max(big.incidents, key=lambda a: len(a.incident.event_keys))
    assert len(biggest.incident.event_keys) > MAX_CONTEXT_EVENTS
    assert len(biggest.context.events) == MAX_CONTEXT_EVENTS
    assert "CONTEXT_TRUNCATED_TO_BUDGET" in biggest.context.uncertainty_flags

    con = analyze(**_dataset("demo:03_contradictory_evidence"))
    assert any(row.contradicts for a in con.incidents for row in a.timeline)  # the conflicts mapping is non-empty and used

    tied = analyze(**_dataset("tied_timestamps"))
    assert len({e.timestamp for e in tied.normalization.events}) < len(tied.normalization.events)

    none = analyze(**_dataset("no_incidents"))
    assert not none.incidents and none.batch_assessment is not None

    keyed = analyze(**_dataset("keyed_duplicates_bad_digest"))
    keys = [e.event_key for e in keyed.normalization.events]
    assert len(set(keys)) < len(keys)


@pytest.mark.parametrize("name", [n for n in _NAMES if n not in ("keyed_duplicates_bad_digest", "no_incidents")])
def test_provenance_is_preserved_for_every_timeline_row_and_context_item(name):
    ds = _dataset(name)
    result = analyze(**ds)
    events = result.normalization.events
    keys = [e.event_key for e in events]
    assert len(set(keys)) == len(keys), "provenance check needs unique keys"
    by_key = {e.event_key: e for e in events}
    records = ds["records"]
    for e in events:
        assert e.raw_sha256 == raw_digest(records[e.record_index])  # normalisation kept the raw digest of the raw record
    for a in result.incidents:
        for row in a.timeline:
            assert row.raw_sha256_prefix == by_key[row.event_key].raw_sha256[:12]
        for item in a.context.events:
            assert item.raw_evidence_sha256 == by_key[item.event_uuid].raw_sha256


@pytest.mark.parametrize("name", ["big_incident_260", "demo:03_contradictory_evidence", "mixed", "tied_timestamps", "keyed_duplicates_bad_digest"])
def test_build_timeline_with_shared_tables_equals_the_legacy_construction(name):
    corr = analyze(**_dataset(name)).correlation
    by_key = {e.event_key: e for e in corr.events}
    conflicts = conflicts_of(corr)
    assert corr.incidents
    for inc in corr.incidents:
        assert build_timeline(corr, inc) == build_timeline(corr, inc, by_key=by_key, conflicts=conflicts)


def _uuid_hash_calls(monkeypatch: pytest.MonkeyPatch, n_incidents: int) -> int:
    records = _separate(n_incidents)
    calls = [0]
    original = uuid.UUID.__hash__

    def counting(self):
        calls[0] += 1
        return original(self)

    with monkeypatch.context() as m:
        m.setattr(uuid.UUID, "__hash__", counting)
        result = analyze(records)
    assert len(result.incidents) == n_incidents
    return calls[0]


def test_uuid_hashing_grows_closer_to_linear_than_quadratic_with_incident_count(monkeypatch):
    """Deliberately loose: doubling the incidents must cost well under 3x the UUID hashes (the per-incident table rebuilds made it about 4x)."""
    small = _uuid_hash_calls(monkeypatch, 100)
    large = _uuid_hash_calls(monkeypatch, 200)
    assert small > 0
    assert large < 3 * small, f"UUID hash calls {small} -> {large}: the work looks quadratic in the number of incidents"
