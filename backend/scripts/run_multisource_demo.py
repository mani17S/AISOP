"""
AISOP multi-source investigation demo (Stage 3C-R, ADR-009).

Runs the synthetic scenarios through the real workflow (normalize -> correlate -> timeline ->
sufficiency gate -> ATT&CK mapping -> report, hash-chained ledger) and writes the analyst-facing
reports, raw inputs and ledgers to an output directory. No database, no network.

  .venv\\Scripts\\python.exe backend\\scripts\\run_multisource_demo.py --out D:\\AISOP-Backups\\AISOP_Stage3CR_Demo_Output

``--llm scripted`` additionally exercises the gated LLM path with a deterministic, call-counting
scripted provider (no model, no network). A real local model is NOT started by this script.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.modules.correlation.demo_data import SCENARIOS  # noqa: E402
from app.modules.correlation.workflow import run_workflow  # noqa: E402
from app.schemas.ai import LLMResponse, TokenUsage  # noqa: E402


class ScriptedProvider:
    """Deterministic stand-in for a model: one observed-fact claim copied from the first cited event."""

    model_name = "llama3.1:8b"

    def __init__(self) -> None:
        self.calls = 0

    async def generate(self, request):  # noqa: ANN001
        self.calls += 1
        prompt = request.messages[1].content
        inv = re.search(r'<investigation_context id="([a-f0-9\-]+)"', prompt).group(1)  # type: ignore[union-attr]
        ev = re.search(r'<event uuid="([a-f0-9\-]+)".*?<summary>(.*?)</summary>', prompt, re.S)
        payload = {
            "investigation_id": inv, "generated_at": datetime.now(timezone.utc).isoformat(), "model_identifier": "scripted-demo",
            "investigation_summary": "Scripted demonstration summary; it is not produced by a language model.",
            "claims": [{"claim_id": str(uuid.uuid4()), "claim_text": ev.group(2), "category": "observed_fact",  # type: ignore[union-attr]
                        "supporting_evidence_ids": [ev.group(1)], "references_exist": True,  # type: ignore[union-attr]
                        "grounding_status": "validated_reference", "confidence": 0.9}],
            "mitre_attack_hypotheses": [], "alternative_explanations": ["Authorized administrative activity"],
            "recommended_analyst_actions": ["Review the cited events"], "uncertainty_and_data_gaps": [],
            "overall_grounding_score": 1.0,
        }
        return LLMResponse(content=json.dumps(payload), model=self.model_name, usage=TokenUsage())


async def main_async(out: Path, only: list[str], llm: str) -> int:
    out.mkdir(parents=True, exist_ok=True)
    index = ["# AISOP multi-source demo output", "", "Synthetic data only. Each folder holds the input records, the analyst report(s) and the verified ledger.", ""]
    provider = ScriptedProvider() if llm == "scripted" else None
    for name, sc in SCENARIOS.items():
        if only and name not in only:
            continue
        records = sc["build"]()
        result = await run_workflow(records, sc["assets"], provider)
        folder = out / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "input_records.json").write_text(json.dumps(records, indent=2, default=str), encoding="utf-8")
        (folder / "summary.json").write_text(json.dumps(result.summary(), indent=2), encoding="utf-8")
        (folder / "ledger.json").write_text(json.dumps(result.ledger, indent=2), encoding="utf-8")
        for i, a in enumerate(result.incidents, start=1):
            (folder / f"incident_{i}.md").write_text(a.markdown, encoding="utf-8")
        if result.batch_markdown:
            (folder / "abstention.md").write_text(result.batch_markdown, encoding="utf-8")
        s = result.summary()
        verdicts = ", ".join(f"{x['verdict']}({x['events']} ev, {len(x['techniques'])} tech)" for x in s["incidents"]) or (
            f"batch {result.batch_assessment.verdict.value}" if result.batch_assessment else "none")
        print(f"{name}: records={s['records_normalized']} rejected={s['records_rejected']} clusters={s['evidence_clusters']} "
              f"incidents={len(s['incidents'])} [{verdicts}] ledger_verified={s['ledger_verified']}")
        index.append(f"- **{sc['title']}** ({name}): {verdicts}; ledger verified: {s['ledger_verified']}")
    (out / "index.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    if provider is not None:
        print(f"scripted provider calls: {provider.calls}")
    print(f"output written to {out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="output directory (use a D: path)")
    ap.add_argument("--scenario", action="append", default=[], help="scenario name (repeatable); default all")
    ap.add_argument("--llm", choices=["none", "scripted"], default="none")
    args = ap.parse_args()
    return asyncio.run(main_async(Path(args.out), args.scenario, args.llm))


if __name__ == "__main__":
    sys.exit(main())
