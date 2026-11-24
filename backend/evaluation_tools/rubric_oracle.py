#!/usr/bin/env python3
"""
Reference implementation of the labelling guide (datasets/sufficiency_eval/labelling_guide.md), compared with the sufficiency gate on the 67 development
cases. No labels, no model, no network, no database; the held-out split is never used.

The oracle is written ONLY from the guide's text and works on the raw case JSON. It imports nothing from the gate. It reads the guide literally, so
where the gate adds a rule the guide does not state, the two will disagree and that disagreement is the finding (a gate stricter than its written
rubric, or a rubric that is silent). It cannot judge contradictions (they need meaning, not structure), so cases the generator built as
``contradictory`` are reported separately and left out of the agreement figures.

Guide, as implemented:
  SUFFICIENT   the relevant evidence is tied to a well-formed raw digest and another relevant record, with a DIFFERENT digest and not a duplicate or
               near-duplicate, is linked to the key event by a specific shared artefact (file hash, domain, file path, registry key, URL, e-mail address
               or public IP address); a shared host, user, process name or internal address is not corroboration.
  LIMITED      a bounded investigation is possible but not a definitive one: the key event is uncorroborated, its digest is missing or malformed, the
               evidence was truncated, the key event is absent from the evidence, or an obviously required detail of the key event is missing
               (a network connection without an address, a process start without a process).
  INSUFFICIENT there is no evidence, none relevant to the question, or none usable.

    .venv\\Scripts\\python.exe backend\\evaluation_tools\\rubric_oracle.py
"""

from __future__ import annotations

import ipaddress
import re
import sys
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency  # noqa: E402  (only to obtain the gate's verdict for the comparison)
from app.modules.evaluation.sufficiency_evaluator import DEFAULT_BASE_DIR, build_context_from_case, load_cases, verify_manifest  # noqa: E402

SPECIFIC = {"file_hash", "domain", "file", "registry", "url", "email", "ip"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LABELS = ("SUFFICIENT", "LIMITED", "INSUFFICIENT")


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False


def _norm(value: str) -> str:
    return value.strip().lower().rstrip(".")


def rubric_label(case: dict[str, Any]) -> str:
    events = {e["key"]: e for e in case.get("events", [])}
    if not events:
        return "INSUFFICIENT"
    window = case["window"]
    end = window["end_offset_s"]
    start = window["start_offset_s"]
    root = case.get("question", {}).get("root_event_key")
    hosts = set(case.get("question", {}).get("target_hosts", []))
    entities_of: dict[str, set[tuple[str, str]]] = {k: set() for k in events}
    for ent in case.get("entities", []):
        for key in ent["event_keys"]:
            if key in entities_of:
                entities_of[key].add((ent["entity_type"].lower(), _norm(ent["entity_value"])))

    def usable(e: dict[str, Any]) -> bool:
        return bool(HEX64.match(str(e.get("raw_evidence_sha256", "")).lower())) and set(str(e["raw_evidence_sha256"]).lower()) != {"0"}

    def in_window(e: dict[str, Any]) -> bool:
        return start <= e["timestamp_offset_s"] <= end

    root_ev = events.get(root) if root else None
    relevant = []
    for key, e in events.items():
        if not in_window(e):
            continue
        if key == root or (not hosts or e["source_identifier"] in hosts) or (root_ev is not None and entities_of[key] & entities_of[root]):
            relevant.append(key)
    if not relevant:
        return "INSUFFICIENT"
    if root_ev is None:
        return "LIMITED"  # the key event is not in the evidence
    limited = False
    if not usable(root_ev):
        limited = True
    if int(case.get("omitted_events", 0)) > 0:
        limited = True
    types = {t for t, _ in entities_of[root]}
    if (root_ev["event_type"] == "network_connection" and "ip" not in types) or (root_ev["event_type"] == "process_creation" and "process" not in types):
        limited = True

    corroborated = False
    for key in relevant:
        if key == root:
            continue
        e = events[key]
        if not usable(e) or e["raw_evidence_sha256"].lower() == root_ev["raw_evidence_sha256"].lower():
            continue
        same_observation = (e["source_identifier"], e["event_id"], e["event_type"], e["action"]) == (
            root_ev["source_identifier"], root_ev["event_id"], root_ev["event_type"], root_ev["action"])
        near = same_observation and abs(e["timestamp_offset_s"] - root_ev["timestamp_offset_s"]) <= 2.0 and e["attributes"] == root_ev["attributes"]
        if near:
            continue
        for kind, value in entities_of[key] & entities_of[root]:
            if kind in SPECIFIC and value and (kind != "ip" or _public_ip(value)):
                corroborated = True
    if corroborated and not limited:
        return "SUFFICIENT"
    return "LIMITED"


def kappa(pairs: list[tuple[str, str]]) -> float:
    n = len(pairs)
    po = sum(a == b for a, b in pairs) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[l] * cb[l] for l in LABELS) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def main() -> int:
    verify_manifest(DEFAULT_BASE_DIR)
    cases = load_cases("dev", DEFAULT_BASE_DIR)
    rows = []
    for c in cases:
        gate = evaluate_sufficiency(build_context_from_case(c)).verdict.value.upper()
        rows.append({"id": c["case_id"], "transform": c["transform"], "oracle": rubric_label(c), "gate": gate})
    judged = [r for r in rows if r["transform"] != "contradictory"]
    pairs = [(r["oracle"], r["gate"]) for r in judged]
    print(f"development cases: {len(cases)} (manifest verified); judged {len(judged)} (the {len(rows) - len(judged)} built as contradictory are excluded: the oracle cannot read meaning)\n")
    print("confusion matrix, rows = rubric oracle, columns = gate")
    print(f"{'':14}" + "".join(f"{l:>14}" for l in LABELS))
    for a in LABELS:
        print(f"{a:14}" + "".join(f"{sum(1 for o, g in pairs if o == a and g == b):14d}" for b in LABELS))
    agree = sum(o == g for o, g in pairs)
    print(f"\nagreement {agree} of {len(pairs)} ({agree / len(pairs):.3f}), Cohen's kappa {kappa(pairs):.3f}")
    dis = [r for r in judged if r["oracle"] != r["gate"]]
    print(f"\ndisagreements ({len(dis)}), by how the case was generated:")
    for (t, o, g), n in sorted(Counter((r["transform"], r["oracle"], r["gate"]) for r in dis).items()):
        print(f"  {t:28} oracle {o:12} gate {g:12} x{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
