"""Scoring script for the baselines: Wilson interval, held-out guard, labelled metrics, no invented labels."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "evaluation_tools" / "score_sufficiency_baselines.py"
_spec = importlib.util.spec_from_file_location("score_sufficiency_baselines", _SCRIPT)
sc = importlib.util.module_from_spec(_spec)
sys.modules["score_sufficiency_baselines"] = sc
_spec.loader.exec_module(sc)


def test_wilson_interval_known_values():
    lo, hi = sc.wilson_interval(5, 10)
    assert (lo, hi) == pytest.approx((0.2366, 0.7634), abs=1e-3)
    assert sc.wilson_interval(0, 10)[0] == 0.0
    assert sc.wilson_interval(10, 10)[1] == 1.0
    assert sc.wilson_interval(0, 0) is None


def test_held_out_is_not_run_without_flag(monkeypatch, capsys):
    loaded = []
    monkeypatch.setattr(sc, "load_cases", lambda split, base=None: loaded.append(split) or [])
    monkeypatch.setattr(sc, "verify_manifest", lambda base=None: None)
    monkeypatch.setattr(sc, "_load_labels", lambda *a, **k: None)
    monkeypatch.setattr(sc.csv, "DictWriter", lambda fh, fieldnames: type("W", (), {"writeheader": lambda s: None, "writerows": lambda s, r: None})())
    monkeypatch.setattr(sc.Path, "mkdir", lambda *a, **k: None)
    monkeypatch.setattr(sc.Path, "open", lambda self, *a, **k: __import__("io").StringIO())
    assert sc.main(["--out", "D:\\pytest_unused_dir"]) == 0
    assert loaded == ["dev"]                              # development only unless --held-out is given
    assert "ONE final run" not in capsys.readouterr().out


def test_held_out_flag_prints_warning(monkeypatch, capsys):
    monkeypatch.setattr(sc, "load_cases", lambda split, base=None: [])
    monkeypatch.setattr(sc, "verify_manifest", lambda base=None: None)
    rc = sc.main(["--held-out"])          # no --out: refuses, but the warning is printed first
    out = capsys.readouterr().out
    assert rc == 2 and "held-out" in out and "ONE final run" in out


def test_out_must_be_on_d_drive(capsys):
    assert sc.main(["--out", "C:\\somewhere"]) == 2
    assert "drive D:" in capsys.readouterr().out


def test_labelled_metrics_false_sufficient_and_abstention():
    rows = [
        {"case_id": "a", "B0": "SUFFICIENT", "B1": "SUFFICIENT", "AISOP": "LIMITED"},
        {"case_id": "b", "B0": "SUFFICIENT", "B1": "INSUFFICIENT", "AISOP": "INSUFFICIENT"},
        {"case_id": "c", "B0": "SUFFICIENT", "B1": "SUFFICIENT", "AISOP": "SUFFICIENT"},
        {"case_id": "d", "B0": "INSUFFICIENT", "B1": "INSUFFICIENT", "AISOP": "LIMITED"},
    ]
    labels = {"a": {"label": "LIMITED"}, "b": {"label": "INSUFFICIENT"}, "c": {"label": "SUFFICIENT"}}  # d unlabelled
    m = sc.labelled_metrics(rows, labels)
    assert m["labelled_cases"] == 3 and m["labelled_not_sufficient"] == 2
    assert m["B0"]["false_sufficient"] == 2 and m["B0"]["false_sufficient_rate"] == 1.0
    assert m["B1"]["false_sufficient"] == 1 and m["AISOP"]["false_sufficient"] == 0
    assert m["AISOP"]["false_sufficient_ci95"][0] == 0.0
    assert m["B1"]["abstained"] == 1 and m["AISOP"]["abstention_rate"] == pytest.approx(0.3333, abs=1e-4)


def test_agreement_counts_are_label_independent():
    rows = [{"case_id": "a", "B0": "SUFFICIENT", "B1": "INSUFFICIENT", "AISOP": "LIMITED"}]
    c = sc.agreement_counts(rows)
    assert c["B0_sufficient_AISOP_not"] == 1 and c["B1_sufficient_AISOP_not"] == 0


def test_labels_template_is_empty_and_any_labels_file_is_human_attributed():
    base = sc.DEFAULT_BASE_DIR
    labels_path = base / "labels.json"
    if labels_path.exists():                            # owner labels may exist; the scripts still never create them
        import json
        doc = json.loads(labels_path.read_text(encoding="utf-8"))
        dev_ids = {p.stem for p in (base / "dev" / "cases").glob("*.json")}
        assert str(doc.get("labeller", "")).strip(), "labels must name the human who wrote them"
        assert set(doc["labels"]) <= dev_ids and all(v["label"] in ("SUFFICIENT", "LIMITED", "INSUFFICIENT") for v in doc["labels"].values())
    import csv
    with (base / "labels_template.csv").open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 67 and all(r["label"] == "" and r["notes"] == "" for r in rows)
