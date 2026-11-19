"""
AISOP Stage 4 integrated demo (ADR-010): the REAL application, end to end, in one process.

Runs the actual FastAPI app (authentication, RBAC, case scoping, ingestion, persistence, audit) against an
in-memory SQLite database (nothing on disk, no PostgreSQL, no network, no model) and walks the analyst
workflow with a synthetic multi-source incident:

  ingest raw alerts (POST /alerts/ingest)  ->  create case, link evidence
  -> start investigation (POST /cases/{id}/investigations/multisource)
  -> read status / timeline / correlation / attack / sufficiency / report sections
  -> repeat request (idempotent), add evidence (stale), optional scripted-LLM run (gated, claim-verified)

All HTTP calls are made through httpx's ASGI transport against the real routers. Outputs (JSON per step and the
analyst report) are written to --out (use a D: path). SQLite behaviour does not validate PostgreSQL behaviour.

  .venv\\Scripts\\python.exe backend\\scripts\\run_integrated_demo.py --out D:\\AISOP-Backups\\AISOP_Stage4_Integration_2026-11-12\\demo_output
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import httpx  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import joinedload, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.api.v1.endpoints.cases import get_case_llm_provider  # noqa: E402
from app.core.config import Settings, get_settings  # noqa: E402
from app.core.rbac import hash_canonical_token  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import get_db_session, get_db_session_factory  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models.analyst import Analyst, AnalystApiClient  # noqa: E402
from app.models.case import CaseAssignmentModel, CaseEvidenceModel, CaseModel  # noqa: E402
from app.models.evidence import NormalizedEventModel  # noqa: E402
from app.modules.correlation.demo_data import SCENARIOS, intrusion_chain  # noqa: E402
from app.modules.evidence.hasher import compute_sha256  # noqa: E402
from app.schemas.ai import LLMResponse, TokenUsage  # noqa: E402
from tests.conftest import AsyncSessionAdapter  # noqa: E402

MACHINE = {"Authorization": "Bearer legacy-machine-key-999"}


class ScriptedProvider:
    """Deterministic stand-in for a model (the real local model is NOT used or required)."""

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


def build_app(session: AsyncSessionAdapter, provider: ScriptedProvider):
    app = create_app()
    settings = Settings(_env_file=None, API_AUTH_ENABLED=True, API_AUTH_ALLOW_LEGACY_KEYS=True,
                        API_AUTH_KEYS=["legacy-machine:legacy-machine-key-999"])

    async def db():
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    factory = sessionmaker(bind=session._sync.bind)
    app.dependency_overrides[get_db_session] = db
    app.dependency_overrides[get_db_session_factory] = lambda: (lambda: AsyncSessionAdapter(factory()))
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_case_llm_provider] = lambda: provider
    return app


async def seed_case(session: AsyncSessionAdapter) -> tuple[str, CaseModel]:
    analyst = Analyst(id=uuid.uuid4(), username="demo_lead", email="demo_lead@example.com", global_role="analyst_tier_2", is_active=True)
    session.add(analyst)
    await session.flush()
    prefix = hashlib.md5(b"demo").hexdigest()[:16]
    token = f"aisop_live_{prefix}_{'b' * 64}"
    session.add(AnalystApiClient(id=uuid.uuid4(), analyst_id=analyst.id, client_name="demo", token_prefix=prefix,
                                 hashed_secret=hash_canonical_token(token), is_active=True))
    now = datetime.now(timezone.utc)
    case = CaseModel(id=uuid.uuid4(), case_number="CASE-DEMO-0001", title="Synthetic multi-source incident", description="Stage 4 demo",
                     status="open", severity="high", created_at=now, updated_at=now)
    session.add(case)
    await session.flush()
    session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=analyst.id, case_role="lead", assigned_at=now))
    await session.commit()
    return token, case


async def link_new_events(session: AsyncSessionAdapter, case: CaseModel, analyst_id: Any) -> int:
    have = set((await session.execute(select(CaseEvidenceModel.evidence_id))).scalars().all())
    n = 0
    for ev in (await session.execute(select(NormalizedEventModel))).scalars().all():
        if ev.id not in have:
            session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=ev.id, linked_by_analyst_id=analyst_id))
            n += 1
    await session.commit()
    return n


async def main_async(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = AsyncSessionAdapter(sessionmaker(bind=engine.connect())())
    provider = ScriptedProvider()
    app = build_app(session, provider)
    token, case = await seed_case(session)
    analyst_id = (await session.execute(select(Analyst.id))).scalars().first()
    bearer = {"Authorization": f"Bearer {token}"}
    base = f"/api/v1/cases/{case.id}/investigations/multisource"
    log: list[str] = []

    def save(name: str, obj: Any) -> None:
        (out / f"{name}.json").write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://demo") as c:
        records = intrusion_chain()
        first_part, second_part = records[:6], records[6:]
        r = await c.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "demo-forwarder", "alerts": first_part}, headers=MACHINE)
        save("01_ingest_first_batch", r.json())
        log.append(f"1. ingest batch 1: HTTP {r.status_code}, normalized {r.json()['total_normalized']} of {r.json()['total_received']}")
        linked = await link_new_events(session, case, analyst_id)
        log.append(f"2. linked {linked} evidence rows to {case.case_number}")

        r = await c.post(base, json={}, headers=bearer)
        save("02_start_deterministic_partial_evidence", r.json())
        inc = r.json()["incidents"][0]
        log.append(f"3. start (partial evidence): HTTP {r.status_code}; verdict {inc['sufficiency']['verdict']} {inc['sufficiency']['reason_codes']}")

        r = await c.post(base, json={}, headers=bearer)
        log.append(f"4. repeat request: HTTP {r.status_code}; reused={r.json().get('reused')} (no new audit record)")

        r = await c.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "demo-forwarder", "alerts": second_part}, headers=MACHINE)
        log.append(f"5. ingest batch 2 (DNS, Sysmon, firewall): HTTP {r.status_code}, normalized {r.json()['total_normalized']}")
        await link_new_events(session, case, analyst_id)
        r = await c.get(base + "/status", headers=bearer)
        log.append(f"6. status after new evidence: stale_evidence={r.json()['stale_evidence']}")

        r = await c.post(base, json={}, headers=bearer)
        body = r.json()
        save("03_start_deterministic_full_evidence", body)
        inc = body["incidents"][0]
        log.append(f"7. start (full evidence): HTTP {r.status_code}; verdict {inc['sufficiency']['verdict']}; "
                   f"{inc['event_count']} events from {len(body['sources'])} sources; {len(inc['mitre'])} techniques; ledger verified={body['ledger']['verified']}")
        for section in ("status", "timeline", "correlation", "attack", "sufficiency", "report"):
            rs = await c.get(f"{base}/{section}", headers=bearer)
            save(f"04_section_{section}", rs.json())
            log.append(f"   GET {section}: HTTP {rs.status_code}")
        (out / "05_analyst_report.md").write_text(inc["report_markdown"], encoding="utf-8")

        r = await c.post(base, json={"use_llm": True, "force": True}, headers=bearer)
        body = r.json()
        save("06_start_with_scripted_llm", body)
        inc = body["incidents"][0]
        log.append(f"8. start with scripted LLM: HTTP {r.status_code}; provider calls {provider.calls}; llm_status {inc['llm_status']}; "
                   f"claims {[(cl['category'], cl['grounding']) for cl in inc['llm']['claims']]}")
        (out / "07_analyst_report_with_llm.md").write_text(inc["report_markdown"], encoding="utf-8")

        activity = (await c.get(f"/api/v1/cases/{case.id}/activity", headers=bearer)).json()
        log.append("9. audit trail actions: " + ", ".join(a["action"] for a in activity))
        save("08_case_activity", activity)

        # negative / edge scenarios through the application
        for name in ("05_insufficient_unparseable", "03_contradictory_evidence", "06_uncorroborated_single_alert"):
            case2 = CaseModel(id=uuid.uuid4(), case_number=f"CASE-DEMO-{name[:2]}", title=name, description="edge", status="open", severity="medium",
                              created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc))
            session.add(case2)
            await session.flush()
            session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case2.id, analyst_id=analyst_id, case_role="lead", assigned_at=datetime.now(timezone.utc)))
            await session.commit()
            scenario_records = [x for x in SCENARIOS[name]["build"]() if isinstance(x, dict)]
            await c.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "demo-forwarder", "alerts": scenario_records}, headers=MACHINE)
            wanted = {compute_sha256(x) for x in scenario_records}  # exact duplicates of earlier evidence are re-used, not re-stored
            for ev in (await session.execute(select(NormalizedEventModel).options(joinedload(NormalizedEventModel.raw_evidence)))).unique().scalars().all():
                if ev.raw_evidence is not None and ev.raw_evidence.sha256_hash in wanted:
                    session.add(CaseEvidenceModel(id=uuid.uuid4(), case_id=case2.id, evidence_id=ev.id, linked_by_analyst_id=analyst_id))
            await session.commit()
            rr = await c.post(f"/api/v1/cases/{case2.id}/investigations/multisource", json={}, headers=bearer)
            b = rr.json()
            verdict = (b["batch_sufficiency"] or b["incidents"][0]["sufficiency"])["verdict"] if (b["batch_sufficiency"] or b["incidents"]) else "n/a"
            log.append(f"10. edge scenario {name}: HTTP {rr.status_code}; verdict {verdict}; contradictions {b['counts']['contradictions']}")
            save(f"09_edge_{name}", b)

    (out / "run_log.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    print("\n".join(log))
    print(f"\noutput written to {out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="output directory (use a D: path)")
    return asyncio.run(main_async(Path(ap.parse_args().out)))


if __name__ == "__main__":
    sys.exit(main())
