"""
Offline unit tests for the report-only ATT&CK drift classification (synthetic catalogue only).

The classification is taxonomy validity and label drift. It never changes a mapping, substitutes a successor,
decides severity, or says a technique occurred.
"""

from __future__ import annotations

import pytest

from app.modules.attack_reference import (
    DriftClass,
    MappingOccurrence,
    OccurrenceKind,
    ReferenceStatus,
    classify_all,
    classify_occurrence,
    render_drift_markdown,
    summarize,
)
from tests.unit.test_attack_reference_loader import base_document, mem


def occ(tid: str, label=None, tactics=(), file="backend/app/a.py", line=1, symbol="sym", kind=OccurrenceKind.RULE_TABLE):
    return MappingOccurrence(source_file=file, line=line, symbol=symbol, kind=kind, technique_id=tid,
                             label=label, tactic_labels=tuple(tactics))


@pytest.fixture(scope="module")
def cat():
    return mem(base_document())


@pytest.mark.parametrize("o,expected", [
    (occ("T1059", "Command and Scripting Interpreter", ("execution",)), DriftClass.CURRENT_VALID),
    (occ("T1059.001", "Command and Scripting Interpreter: PowerShell"), DriftClass.CURRENT_VALID),   # 'Parent: Sub' convention
    (occ("T1059.001", "PowerShell"), DriftClass.CURRENT_VALID),
    (occ("T1059"), DriftClass.CURRENT_VALID),                                                        # no coded label: nothing to drift
    (occ("T1685.005", "Clear Event Logs"), DriftClass.STALE_NAME),
    (occ("T1059", None, ("defense-evasion",)), DriftClass.STALE_TACTIC_LABEL),                       # legacy slug is not a current tactic
    (occ("T1685.005", None, ("TA0112", "Defense Evasion")), DriftClass.STALE_TACTIC_LABEL),          # valid id, legacy name
    (occ("T1070.001", "Clear Windows Event Logs", ("TA0005",)), DriftClass.REVOKED_WITH_SUCCESSOR),
    (occ("T1562"), DriftClass.REVOKED_WITH_SUCCESSOR),
    (occ("T1111"), DriftClass.UNRESOLVED),                                                           # revoked, no explicit successor
    (occ("T1043"), DriftClass.DEPRECATED),
    (occ("T9999"), DriftClass.UNKNOWN_ID),
    (occ("T1404"), DriftClass.WRONG_DOMAIN),
    (occ("T12"), DriftClass.INVALID_ID_SYNTAX),
    (occ("t1059"), DriftClass.INVALID_ID_SYNTAX),
    (occ(" T1059"), DriftClass.INVALID_ID_SYNTAX),
])
def test_classification(cat, o, expected):
    assert classify_occurrence(cat, o).classification == expected


def test_both_drifts_report_name_as_primary_and_flag_the_tactic_label_independently(cat):
    row = classify_occurrence(cat, occ("T1685.005", "Clear Event Logs", ("Defense Evasion",)))
    assert row.classification == DriftClass.STALE_NAME and row.name_drift and row.tactic_label_drift


def test_revoked_row_keeps_flags_and_successors_without_substituting_anything(cat):
    row = classify_occurrence(cat, occ("T1070.001", "Clear Windows Event Logs", ("TA0005", "Defense Evasion")))
    assert row.successors == ("T1685.005",) and row.tactic_label_drift and not row.name_drift
    assert row.occurrence.technique_id == "T1070.001"                       # the coded id is reported, never replaced
    assert row.canonical_name == "Clear Windows Event Logs" and row.lifecycle == "revoked"


def test_shared_and_multiple_successors_are_all_preserved(cat):
    assert classify_occurrence(cat, occ("T1562")).successors == ("T1685",)
    assert classify_occurrence(cat, occ("T1562.001")).successors == ("T1685",)
    assert classify_occurrence(cat, occ("T1562.003")).successors == ("T1685.005", "T1690")


def test_resolved_tactic_not_associated_is_a_note_not_drift(cat):
    row = classify_occurrence(cat, occ("T1059", None, ("stealth",)))
    assert row.classification == DriftClass.CURRENT_VALID and not row.tactic_label_drift
    assert any("not associated" in n for n in row.notes)


def test_unknown_and_invalid_rows_carry_no_catalogue_claims(cat):
    for tid, status in (("T9999", ReferenceStatus.UNKNOWN), ("T12", ReferenceStatus.INVALID_SYNTAX), ("T1404", ReferenceStatus.WRONG_DOMAIN)):
        row = classify_occurrence(cat, occ(tid, "Some Name", ("execution",)))
        assert row.status == status and row.canonical_name is None and not row.name_drift and not row.tactic_label_drift


def test_classification_is_not_a_severity_and_uses_only_taxonomy_classes():
    assert {c.value for c in DriftClass} == {
        "CURRENT_VALID", "STALE_NAME", "STALE_TACTIC_LABEL", "REVOKED_WITH_SUCCESSOR", "DEPRECATED",
        "UNKNOWN_ID", "INVALID_ID_SYNTAX", "WRONG_DOMAIN", "UNRESOLVED"}


def _sample_rows(cat):
    return classify_all(cat, [
        occ("T1070.001", "Clear Windows Event Logs", ("TA0005", "Defense Evasion"), "backend/app/b.py", 5, "adapter"),
        occ("T1059.001", "Command and Scripting Interpreter: PowerShell", ("execution",), "backend/app/a.py", 9, "MAP-1"),
        occ("T1685.005", "Clear | Event Logs", (), "backend/app/a.py", 2, "MAP-2"),
        occ("T9999", None, (), "backend/app/c.py", 1, "x"),
    ])


def test_rows_are_sorted_deterministically_and_totals_add_up(cat):
    rows = _sample_rows(cat)
    assert [(r.occurrence.source_file, r.occurrence.line) for r in rows] == sorted((r.occurrence.source_file, r.occurrence.line) for r in rows)
    s = summarize(rows)
    assert s["occurrences"] == 4 and s["distinct_ids"] == 4 and sum(s[c.value] for c in DriftClass) == 4
    assert s["REVOKED_WITH_SUCCESSOR"] == 1 and s["UNKNOWN_ID"] == 1 and s["STALE_NAME"] == 1 and s["tactic_label_drift_flags"] == 1


def test_rendering_is_deterministic_and_timestamp_is_isolated(cat):
    rows = _sample_rows(cat)
    a = render_drift_markdown(rows, cat.meta, generated_at="2026-01-01T00:00:00Z")
    b = render_drift_markdown(rows, cat.meta, generated_at="2030-12-31T23:59:59Z")
    marker = "## Run metadata (excluded from deterministic comparison)"
    assert a != b and a.split(marker)[0] == b.split(marker)[0]
    assert render_drift_markdown(rows, cat.meta) == render_drift_markdown(rows, cat.meta)
    assert render_drift_markdown(rows, cat.meta).count(marker) == 0


def test_rendering_escapes_table_cells_and_states_report_only_and_no_full_stix_claim(cat):
    md = render_drift_markdown(_sample_rows(cat), cat.meta)
    assert "Clear \\| Event Logs" in md
    assert "Report-only" in md and "not a complete STIX 2.1 schema validation" in md
    assert "SECRET-DESCRIPTION-SENTINEL" not in md                           # descriptions never reach the report
    assert cat.meta.sha256 in md and "REVOKED_WITH_SUCCESSOR" in md and "T1685.005" in md


def test_render_accepts_extra_sections_after_the_tables(cat):
    md = render_drift_markdown(_sample_rows(cat), cat.meta, sections_after=["## Extra\nbody"])
    assert md.rstrip().endswith("body") and md.index("## Occurrences") < md.index("## Extra")
