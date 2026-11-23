"""The owner labelling helper must never leak the gate's answer or generator metadata, and must turn a filled CSV into the JSON the scorer reads."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("label_cases", _ROOT / "backend" / "evaluation_tools" / "label_cases.py")
lc = importlib.util.module_from_spec(_SPEC)
sys.modules["label_cases"] = lc
_SPEC.loader.exec_module(lc)  # type: ignore[union-attr]

_CASES = lc.load_cases("dev", lc.DEFAULT_BASE_DIR)


def test_the_display_never_shows_generator_metadata_or_a_verdict():
    for case in _CASES:
        text = lc.render_case(case)
        for hidden in (case["transform"], case["family"], case["base_scenario_id"], "SUFFICIENT", "LIMITED", "INSUFFICIENT"):
            assert hidden not in text, f"{hidden!r} leaked into the display of {case['case_id']}"


def test_the_display_names_the_case_the_events_and_the_shared_entities():
    text = lc.render_case(_CASES[0])
    assert _CASES[0]["case_id"] in text and "events (" in text and "entities and the events that share them" in text


def test_a_filled_csv_becomes_the_json_the_scorer_reads(tmp_path):
    ids = [c["case_id"] for c in _CASES[:3]]
    csv_path = tmp_path / "labels.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "description", "label", "notes"])
        w.writerow([ids[0], "d", "Sufficient", "two sources"])
        w.writerow([ids[1], "d", "limited", ""])
        w.writerow([ids[2], "d", "", ""])  # left blank on purpose
    doc = lc.empty_document("Tester", None)
    labelled, problems = lc.import_csv(csv_path, set(ids), doc)
    assert (labelled, problems) == (2, [])
    assert doc["labels"][ids[0]] == {"label": "SUFFICIENT", "justification": "two sources"}
    assert ids[2] not in doc["labels"]
    out = tmp_path / "labels.json"
    lc.save_document(out, doc)
    assert json.loads(out.read_text(encoding="utf-8"))["labeller"] == "Tester"


def test_a_bad_label_or_unknown_case_is_reported_not_written(tmp_path):
    csv_path = tmp_path / "labels.csv"
    csv_path.write_text("case_id,description,label,notes\nSUFC-nope,d,sufficient,\n" + f"{_CASES[0]['case_id']},d,maybe,\n", encoding="utf-8")
    doc = lc.empty_document("Tester", None)
    labelled, problems = lc.import_csv(csv_path, {_CASES[0]["case_id"]}, doc)
    assert labelled == 0 and len(problems) == 2 and doc["labels"] == {}


def test_only_the_three_allowed_labels_parse():
    assert lc.parse_label(" limited ") == "LIMITED"
    with pytest.raises(ValueError):
        lc.parse_label("probably")
