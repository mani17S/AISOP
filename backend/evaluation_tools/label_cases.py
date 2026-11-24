#!/usr/bin/env python3
"""
Owner labelling helper for the sufficiency cases. It NEVER writes a label itself and never shows the gate's answer or the generator's
metadata (transform, family, base scenario); it only displays case content and records what the human types.

Three ways to produce the labels file the scorer reads (``datasets/sufficiency_eval/labels.json``):

  1. Interactive, one case at a time (resumable; run it in a normal terminal window, not through an assistant):
         .venv\\Scripts\\python.exe backend\\evaluation_tools\\label_cases.py --labeller "Your Name"
     Keys: s = SUFFICIENT, l = LIMITED, i = INSUFFICIENT, k = skip, q = save and quit. A one-line reason is optional.
  2. Convert a spreadsheet: fill the ``label`` column of ``labels_template.csv`` with sufficient / limited / insufficient, then
         ... label_cases.py --from-csv datasets\\sufficiency_eval\\labels_template.csv --labeller "Your Name"
  3. Second reviewer on every 4th case (agreement is reported by hand from the two files; the scorer uses the first reviewer's):
         ... label_cases.py --labeller "Second Name" --every 4 --out datasets\\sufficiency_eval\\labels_second.json

Labelling rules are in ``datasets/sufficiency_eval/labelling_guide.md`` plus the four rules of ``docs/10_Research/Evaluation/Labelling_Guide_Addendum.md`` (shown at the start of each interactive session; the labels file records which guide was used). Label before you run the scorer; do not look at its output first.
Only the development split is offered. The held-out split is labelled separately and evaluated once, after the rules are frozen.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.modules.evaluation.sufficiency_evaluator import DEFAULT_BASE_DIR, LABELS, load_cases  # noqa: E402

KEYS = {"s": "SUFFICIENT", "l": "LIMITED", "i": "INSUFFICIENT"}
GUIDE_VERSION = "labelling_guide.md + Labelling_Guide_Addendum.md (2026-11-24)"
ADDENDUM = """Rules added by the addendum (docs/10_Research/Evaluation/Labelling_Guide_Addendum.md), on top of datasets/sufficiency_eval/labelling_guide.md:
  1. Repeated observation: a later record of the SAME observation (same host or sensor, event id, event type, action) is a repetition, not corroboration,
     even if its digest differs. Corroboration needs a different observation.
  2. Vantage: records seen by the same source type at the same host are ONE witness. Corroboration needs two vantage points somewhere in the chain of
     specific links around the key event. If a record's source is not stated, do not assume it is the same.
  3. Placeholder artefacts: an empty, all-zero or repeated-character hash, localhost, a loopback, private or link-local address, or a single-label name is
     NOT a specific artefact.
  4. Near-duplicate: same identity and same entities within 2 seconds of each other is one record."""
SHOWN_ATTRIBUTES = ("Image", "CommandLine", "ParentImage", "TargetFilename", "TargetImage", "SourceImage", "DestinationIp",
                    "DestinationPort", "QueryName", "QueryResults", "Hashes", "User", "TargetObject")


def render_case(case: dict[str, Any]) -> str:
    """Neutral text for one case: content only (no transform, family, scenario id, split, or gate output)."""
    q = case.get("question", {})
    lines = [
        f"CASE {case['case_id']}",
        f"question: root event {q.get('root_event_key') or 'none'}; target hosts {', '.join(q.get('target_hosts', [])) or 'none'}; "
        f"window {case['window']['start_offset_s']}s to {case['window']['end_offset_s']}s",
        f"omitted events (budget truncation): {int(case.get('omitted_events', 0))}",
        "events (a record is a different raw record only if its digest differs):",
    ]
    for ev in case.get("events", []):
        attrs = {k: v for k, v in ev.get("attributes", {}).items() if k in SHOWN_ATTRIBUTES}
        lines.append(
            f"  {ev['key']:>8}  t={ev['timestamp_offset_s']:>6}s  {ev['event_type']:<20} {ev['action']}/{ev['outcome']}  "
            f"source={ev['source_identifier']}  digest={ev['raw_evidence_sha256'][:8]}"
        )
        lines.append(f"            {ev['summary']}")
        for k, v in attrs.items():
            lines.append(f"            {k}: {str(v)[:110]}")
    lines.append("entities and the events that share them:")
    for ent in case.get("entities", []):
        lines.append(f"  {ent['entity_type']:<10} {str(ent['entity_value'])[:70]:<70} -> {', '.join(ent['event_keys'])}")
    return "\n".join(lines)


def empty_document(labeller: str, second_reviewer: Optional[str]) -> dict[str, Any]:
    return {"labeller": labeller, "second_reviewer": second_reviewer, "date": date.today().isoformat(), "guide": GUIDE_VERSION, "labels": {}}


def load_document(path: Path, labeller: str, second_reviewer: Optional[str]) -> dict[str, Any]:
    if path.is_file():
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc.setdefault("labels", {})
        return doc
    return empty_document(labeller, second_reviewer)


def save_document(path: Path, doc: dict[str, Any]) -> None:
    doc["date"] = date.today().isoformat()
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def parse_label(text: str) -> str:
    value = text.strip().upper()
    if value not in LABELS:
        raise ValueError(f"invalid label {text!r}; use sufficient, limited or insufficient")
    return value


def import_csv(csv_path: Path, case_ids: set[str], doc: dict[str, Any]) -> tuple[int, list[str]]:
    """Copy the filled ``label`` (and ``notes``) cells into the document. Returns (labelled, problems). Blank rows are left unlabelled."""
    labelled, problems = 0, []
    with csv_path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cid, cell = row.get("case_id", "").strip(), (row.get("label") or "").strip()
            if not cell:
                continue
            if cid not in case_ids:
                problems.append(f"{cid}: not a development case")
                continue
            try:
                doc["labels"][cid] = {"label": parse_label(cell), "justification": (row.get("notes") or "").strip()}
                labelled += 1
            except ValueError as exc:
                problems.append(f"{cid}: {exc}")
    return labelled, problems


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--labeller", required=True, help="your name, recorded in the file")
    ap.add_argument("--second-reviewer", default=None)
    ap.add_argument("--out", type=Path, default=DEFAULT_BASE_DIR / "labels.json")
    ap.add_argument("--from-csv", type=Path, default=None, help="import the label column of a filled labels_template.csv")
    ap.add_argument("--every", type=int, default=1, help="offer only every Nth case (use 4 for a second reviewer)")
    ap.add_argument("--base-dir", type=Path, default=DEFAULT_BASE_DIR, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    cases = load_cases("dev", args.base_dir)
    doc = load_document(args.out, args.labeller, args.second_reviewer)

    if args.from_csv:
        labelled, problems = import_csv(args.from_csv, {c["case_id"] for c in cases}, doc)
        save_document(args.out, doc)
        print(f"imported {labelled} labels from {args.from_csv}; {len(doc['labels'])} labelled in {args.out}")
        for p in problems:
            print("  problem:", p)
        return 1 if problems else 0

    offered = [c for i, c in enumerate(cases) if i % max(args.every, 1) == 0]
    todo = [c for c in offered if c["case_id"] not in doc["labels"]]
    print(ADDENDUM + chr(10))
    doc.setdefault("guide", GUIDE_VERSION)
    print(f"{len(offered)} cases offered, {len(offered) - len(todo)} already labelled, {len(todo)} to go. Saving to {args.out}.")
    for n, case in enumerate(todo, 1):
        print("\n" + "=" * 100 + f"\n[{n}/{len(todo)}]\n" + render_case(case))
        while True:
            answer = input("\nlabel? (s)ufficient (l)imited (i)nsufficient (k)skip (q)uit > ").strip().lower()
            if answer in KEYS:
                reason = input("one-line reason (optional) > ").strip()
                doc["labels"][case["case_id"]] = {"label": KEYS[answer], "justification": reason}
                save_document(args.out, doc)
                break
            if answer == "k":
                break
            if answer == "q":
                save_document(args.out, doc)
                print(f"saved {len(doc['labels'])} labels to {args.out}")
                return 0
            print("please type s, l, i, k or q")
    save_document(args.out, doc)
    print(f"done: {len(doc['labels'])} labels in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
