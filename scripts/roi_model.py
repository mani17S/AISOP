#!/usr/bin/env python3
"""
Break-even calculator for an AISOP pilot. The inputs are THE COMPANY'S, not the project's: AISOP has no measured analyst time saved, so this does not
predict a saving; it shows how large a saving would have to be for the pilot to pay for itself, so the pilot can measure that one number.

    .venv\\Scripts\\python.exe scripts\\roi_model.py --investigations-per-week 40 --minutes-each 45 --cost-per-hour 60 --pilot-cost 12000

Every figure is arithmetic on the inputs; nothing is looked up or assumed. The ``--time-saved`` list is a sensitivity range (percent of investigation time
saved), not an estimate.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

WEEKS_PER_YEAR = 52


def weekly_cost(investigations_per_week: float, minutes_each: float, cost_per_hour: float) -> float:
    return investigations_per_week * minutes_each / 60.0 * cost_per_hour


def saving(investigations_per_week: float, minutes_each: float, cost_per_hour: float, time_saved_pct: float) -> dict[str, float]:
    base = weekly_cost(investigations_per_week, minutes_each, cost_per_hour)
    weekly = base * time_saved_pct / 100.0
    return {"weekly_cost": base, "weekly_saving": weekly, "annual_saving": weekly * WEEKS_PER_YEAR}


def break_even_weeks(pilot_cost: float, weekly_saving: float) -> Optional[float]:
    return None if weekly_saving <= 0 else pilot_cost / weekly_saving


def required_time_saved_pct(pilot_cost: float, weeks: float, investigations_per_week: float, minutes_each: float, cost_per_hour: float) -> Optional[float]:
    """The share of investigation time that must be saved for the saving over ``weeks`` to equal the pilot cost."""
    base = weekly_cost(investigations_per_week, minutes_each, cost_per_hour)
    return None if base <= 0 or weeks <= 0 else 100.0 * pilot_cost / (base * weeks)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--investigations-per-week", type=float, required=True)
    ap.add_argument("--minutes-each", type=float, required=True, help="analyst minutes per investigation today")
    ap.add_argument("--cost-per-hour", type=float, required=True, help="fully loaded analyst cost per hour (any currency)")
    ap.add_argument("--pilot-cost", type=float, required=True, help="total cost of the pilot (staff time, hardware, review) in the same currency")
    ap.add_argument("--time-saved", type=float, nargs="+", default=[5, 10, 20, 30], help="sensitivity: percent of investigation time saved")
    args = ap.parse_args(argv)

    base = weekly_cost(args.investigations_per_week, args.minutes_each, args.cost_per_hour)
    print(f"Today: {args.investigations_per_week:g} investigations a week x {args.minutes_each:g} min x {args.cost_per_hour:g} per hour = {base:,.0f} a week ({base * WEEKS_PER_YEAR:,.0f} a year)")
    print(f"Pilot cost: {args.pilot_cost:,.0f}\n")
    print(f"{'time saved':>11} {'weekly saving':>14} {'annual saving':>14} {'break-even (weeks)':>19}")
    for pct in args.time_saved:
        s = saving(args.investigations_per_week, args.minutes_each, args.cost_per_hour, pct)
        be = break_even_weeks(args.pilot_cost, s["weekly_saving"])
        print(f"{pct:10g}% {s['weekly_saving']:14,.0f} {s['annual_saving']:14,.0f} {('never' if be is None else f'{be:,.1f}'):>19}")
    need = required_time_saved_pct(args.pilot_cost, WEEKS_PER_YEAR, args.investigations_per_week, args.minutes_each, args.cost_per_hour)
    print(f"\nTo recover the pilot cost within one year the pilot must show about {need:.1f}% of investigation time saved. Measure that number; do not assume it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
