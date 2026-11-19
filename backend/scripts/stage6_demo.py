"""
Stage 6 demonstration: runs the three source-agnostic scenarios (and the negative ones) through the real workflow.

    .venv\\Scripts\\python.exe backend\\scripts\\stage6_demo.py [A|B|C|neg]  [--report]

Offline, synthetic data only, no database, no network, no LLM.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.modules.correlation.workflow import analyze  # noqa: E402
from app.modules.evidence_domains import scenarios as S  # noqa: E402


def show(name: str, records: list, report: bool) -> None:
    r = analyze(records)
    print(f"\n=== {name}: {len(records)} record(s), {len(r.observations)} observation(s), rejected {[x.reason for x in r.normalization.rejected]}")
    if r.batch_assessment is not None:
        print(f"  no incident formed; verdict={r.batch_assessment.verdict.value} {r.batch_assessment.reason_codes}")
    for a in r.incidents:
        print(f"  incident {str(a.incident.incident_id)[:8]}: {len(a.events)} event(s), verdict={a.assessment.verdict.value} {a.assessment.reason_codes}, "
              f"corroborating={a.assessment.corroborating_events}")
        print(f"    techniques: {[(m.technique_id, m.independent_evidence_count) for m in a.mitre] or 'none derived'}")
        if a.graph:
            print(f"    graph: {len(a.graph.nodes)} nodes, {len(a.graph.edges)} typed edges, {len(a.graph.correlations)} correlations, "
                  f"uncertainties {[u['kind'] for u in a.graph.uncertainties]}")
        print(f"    analyst statements (context only): {len(a.analyst_notes)}")
        if report:
            print(a.markdown)
    print(f"  ledger verified: {r.ledger_ok}")


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    report = "--report" in sys.argv
    which = args[0] if args else "all"
    if which in ("A", "all"):
        show("Scenario A identity + cloud", S.scenario_a_identity_cloud(), report)
    if which in ("B", "all"):
        show("Scenario B network + endpoint", S.scenario_b_network_endpoint(), report)
    if which in ("C", "all"):
        show("Scenario C e-mail + forensic", S.scenario_c_email_forensic(), report)
    if which in ("neg", "all"):
        for n in ("negative_duplicates", "negative_analyst_only", "negative_unrelated", "negative_bad_times", "negative_unknown_type", "negative_contradiction"):
            show(n, getattr(S, n)(), report)
        show("malformed_records", S.malformed_records(), report)


if __name__ == "__main__":
    main()
