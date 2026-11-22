"""MITRE D3FEND optional reference: hash pin, tamper refusal, lookup, no-op when unconfigured, report section."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.modules.defense_reference import (
    Category,
    DefenseReferenceProvider,
    ErrorCode,
    PinnedD3fend,
    load_defense_catalogue,
    render_section,
    try_load_defense_catalogue,
)
from app.modules.defense_reference.section import SECTION_TITLE

ENT = "http://d3fend.mitre.org/ontologies/d3fend.owl#ATTACKEnterpriseTechnique"
ICS = "http://d3fend.mitre.org/ontologies/d3fend.owl#ATTACKICSTechnique"
ONTOLOGY = (
    "ID,D3FEND Tactic,D3FEND Technique,D3FEND Technique Level 0,D3FEND Technique Level 1,Definition\n"
    "D3-AL,Evict,,Account Locking,,Locks an account.\n"
    "D3-FA,Detect,,File Analysis,,Analyzes a file.\n"
    "D3-CF,Isolate,Content Filtering,,,\n"
)


def _mapping(rows: list[tuple[str, str, str, str]]) -> str:
    head = "off_tech_id,def_tech_label,def_tactic_label,framework_root_iri,off_artifact_label\n"
    return head + "".join(f"{a},{b},{c},{d},x\n" for a, b, c, d in rows)


MAPPING = _mapping([
    ("T1078", "Account Locking", "Evict", ENT),
    ("T1078", "Account Locking", "Evict", ENT),      # repeated row (one per shared artifact) collapses
    ("T1078", "File Analysis", "Detect", ENT),
    ("T1059", "Content Filtering", "Isolate", ENT),
    ("T0801", "File Analysis", "Detect", ICS),        # not Enterprise: skipped
])


def _pin(onto: str = ONTOLOGY, mapping: str = MAPPING) -> PinnedD3fend:
    return PinnedD3fend(
        version="test", mappings_file="m.csv", mappings_sha256=hashlib.sha256(mapping.encode()).hexdigest(),
        mappings_size=len(mapping.encode()), ontology_file="o.csv", ontology_sha256=hashlib.sha256(onto.encode()).hexdigest(),
        ontology_size=len(onto.encode()),
    )


@pytest.fixture
def folder(tmp_path: Path) -> Path:
    (tmp_path / "o.csv").write_text(ONTOLOGY, encoding="utf-8", newline="")
    (tmp_path / "m.csv").write_text(MAPPING, encoding="utf-8", newline="")
    return tmp_path


def test_loads_and_looks_up_exact_ids(folder: Path) -> None:
    cat = load_defense_catalogue(folder, _pin())
    assert cat.d3fend_version == "test" and cat.skipped_non_enterprise_rows == 1
    found = cat.lookup(["t1078", "T1078", "T9999"])
    assert list(found) == ["T1078"]                                    # duplicate collapsed, unknown absent
    assert [(t.d3fend_id, t.category) for t in found["T1078"]] == [("D3-FA", Category.DETECT), ("D3-AL", Category.EVICT)]
    assert cat.lookup(["T1059.001"]) == {}                              # no parent fallback: the mapping does not define it
    assert cat.lookup(["T0801"]) == {}                                  # ICS rows are not used


def test_unknown_technique_returns_nothing(folder: Path) -> None:
    assert load_defense_catalogue(folder, _pin()).lookup(["T1110"]) == {}


def test_wrong_pinned_hash_is_refused(folder: Path) -> None:
    pin = _pin()
    bad = PinnedD3fend(**{**pin.__dict__, "mappings_sha256": "0" * 64})
    res = try_load_defense_catalogue(folder, bad)
    assert not res.available and res.error_code == ErrorCode.HASH_MISMATCH


def test_tampered_file_is_refused_even_at_same_size(folder: Path) -> None:
    (folder / "m.csv").write_text(MAPPING.replace("T1059", "T1060"), encoding="utf-8", newline="")
    res = try_load_defense_catalogue(folder, _pin())
    assert res.error_code == ErrorCode.HASH_MISMATCH and res.catalogue is None


def test_size_mismatch_and_missing_file_refused(folder: Path) -> None:
    (folder / "o.csv").write_text(ONTOLOGY + "\n", encoding="utf-8", newline="")
    assert try_load_defense_catalogue(folder, _pin()).error_code == ErrorCode.SIZE_MISMATCH
    (folder / "o.csv").unlink()
    assert try_load_defense_catalogue(folder, _pin()).error_code == ErrorCode.PATH_MISSING
    assert try_load_defense_catalogue(folder / "nope", _pin()).error_code == ErrorCode.PATH_MISSING


def _load_text(tmp_path: Path, onto: str, mapping: str):  # type: ignore[no-untyped-def]
    (tmp_path / "o.csv").write_text(onto, encoding="utf-8", newline="")
    (tmp_path / "m.csv").write_text(mapping, encoding="utf-8", newline="")
    return try_load_defense_catalogue(tmp_path, _pin(onto, mapping))


def test_duplicate_ontology_id_rejected(tmp_path: Path) -> None:
    res = _load_text(tmp_path, ONTOLOGY + "D3-AL,Detect,,Other,,\n", MAPPING)
    assert res.error_code == ErrorCode.DUPLICATE_ID


def test_mapping_to_unlisted_technique_or_wrong_tactic_rejected(tmp_path: Path) -> None:
    assert _load_text(tmp_path, ONTOLOGY, _mapping([("T1078", "Nope", "Evict", ENT)])).error_code == ErrorCode.INCONSISTENT
    assert _load_text(tmp_path, ONTOLOGY, _mapping([("T1078", "Account Locking", "Detect", ENT)])).error_code == ErrorCode.INCONSISTENT


def test_malformed_attack_id_and_oversized_definition_rejected(tmp_path: Path) -> None:
    assert _load_text(tmp_path, ONTOLOGY, _mapping([("X1", "Account Locking", "Evict", ENT)])).error_code == ErrorCode.INVALID_FIELD
    long_def = ONTOLOGY.replace("Locks an account.", "x" * 600)
    assert _load_text(tmp_path, long_def, MAPPING).error_code == ErrorCode.INVALID_FIELD


def test_unconfigured_path_is_a_noop() -> None:
    assert DefenseReferenceProvider(None).resolve() is None
    assert DefenseReferenceProvider("  ").resolve() is None
    assert render_section(["T1078"], provider=DefenseReferenceProvider(None)) == []


def test_section_present_and_labeled(folder: Path) -> None:
    prov = DefenseReferenceProvider(str(folder), loader=lambda p: try_load_defense_catalogue(p, _pin()))
    text = "\n".join(render_section(["T1078", "T1110"], {"T1078": "Valid Accounts"}, provider=prov))
    assert SECTION_TITLE in text
    assert "NOT observed evidence" in text and "NOT a statement that a control is missing" in text
    assert "No language model wrote this section" in text
    assert "T1078 Valid Accounts" in text and "Evict: Account Locking (D3-AL)" in text
    assert "T1110**: no D3FEND technique is mapped" in text


def test_section_absent_when_no_technique_mapped(folder: Path) -> None:
    prov = DefenseReferenceProvider(str(folder), loader=lambda p: try_load_defense_catalogue(p, _pin()))
    assert render_section([], provider=prov) == []


def test_section_reports_unavailable_when_tampered(folder: Path) -> None:
    (folder / "m.csv").write_text("tampered", encoding="utf-8")
    prov = DefenseReferenceProvider(str(folder), loader=lambda p: try_load_defense_catalogue(p, _pin()))
    text = "\n".join(render_section(["T1078"], provider=prov))
    assert "unavailable" in text and "size_mismatch" in text and "Account Locking" not in text


def test_provider_loads_once(folder: Path) -> None:
    calls: list[str] = []

    def loader(p: str):  # type: ignore[no-untyped-def]
        calls.append(p)
        return try_load_defense_catalogue(p, _pin())

    prov = DefenseReferenceProvider(str(folder), loader=loader)
    prov.resolve(), prov.resolve()
    assert len(calls) == 1


def test_incident_report_includes_section_only_when_configured(folder: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.modules.correlation import workflow
    from app.modules.correlation.demo_data import intrusion_chain
    from app.modules.defense_reference import section

    monkeypatch.setattr(section, "default_provider", lambda: DefenseReferenceProvider(None))
    plain = workflow.analyze(intrusion_chain()).incidents[0]
    assert plain.mitre and SECTION_TITLE not in plain.markdown          # unconfigured: report unchanged

    prov = DefenseReferenceProvider(str(folder), loader=lambda p: try_load_defense_catalogue(p, _pin()))
    monkeypatch.setattr(section, "default_provider", lambda: prov)
    with_ref = workflow.analyze(intrusion_chain()).incidents[0].markdown
    assert f"## 4a. {SECTION_TITLE}" in with_ref and "NOT observed evidence" in with_ref
    assert with_ref.index("## 4. ATT&CK mapping") < with_ref.index(SECTION_TITLE) < with_ref.index("## 5. Data-quality notes")
