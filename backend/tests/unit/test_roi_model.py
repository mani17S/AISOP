"""The break-even calculator is plain arithmetic on the company's own inputs; pin the arithmetic so a board paper built on it is correct."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("roi_model", _ROOT / "scripts" / "roi_model.py")
roi = importlib.util.module_from_spec(_SPEC)
sys.modules["roi_model"] = roi
_SPEC.loader.exec_module(roi)  # type: ignore[union-attr]


def test_weekly_cost_and_saving_are_the_obvious_arithmetic():
    assert roi.weekly_cost(40, 45, 60) == 1800.0
    s = roi.saving(40, 45, 60, 10)
    assert s == {"weekly_cost": 1800.0, "weekly_saving": 180.0, "annual_saving": 9360.0}


def test_break_even_is_cost_over_weekly_saving_and_never_when_nothing_is_saved():
    assert roi.break_even_weeks(12000, 180.0) == 12000 / 180.0
    assert roi.break_even_weeks(12000, 0) is None


def test_the_required_time_saved_is_the_share_that_repays_the_pilot_in_the_period():
    pct = roi.required_time_saved_pct(12000, 52, 40, 45, 60)
    assert round(pct, 2) == round(100 * 12000 / (1800 * 52), 2)
    assert roi.required_time_saved_pct(12000, 0, 40, 45, 60) is None and roi.required_time_saved_pct(12000, 52, 0, 45, 60) is None


def test_the_command_line_prints_the_sensitivity_without_inventing_an_estimate(capsys):
    assert roi.main(["--investigations-per-week", "40", "--minutes-each", "45", "--cost-per-hour", "60", "--pilot-cost", "12000", "--time-saved", "10", "20"]) == 0
    out = capsys.readouterr().out
    assert "Measure that number; do not assume it." in out and "10%" in out and "20%" in out
