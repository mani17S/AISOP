r"""
Measurement only: how expensive is the evidence-changed check, and where does the time go? Read-only against a SCRATCH database (name must start with aisop_load).

    .venv\Scripts\python.exe backend\scripts\profile_fingerprint_load.py --dbpw <app role password file> --db aisop_loadtest --out <json> [--repeats 7]

The investigation service reloads every linked evidence row through the ORM (rows plus the joined raw record and its JSON payload) only to compute a fingerprint of
(event id, raw SHA-256) pairs, once after the analysis and once for every section the UI reads. This compares, for the case with the most linked evidence:
  A  the current way: `_load_rows` (ORM entities with joined raw evidence) then `fingerprint`
  B  the same SELECT through Core without building ORM objects (database, transfer and JSON decoding of the payload, but no entity construction)
  C  a column-only SELECT of (event id, raw SHA-256) feeding the SAME `fingerprint` function through light stand-in objects
and checks that A and C give the identical fingerprint (the correctness condition for any change). It writes nothing to the database.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
os.chdir(ROOT)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
PROTECTED = {"aisop_demo", "aisop_dev", "aisop", "aisop_test", "postgres"}


def med(v):
    s = sorted(v)
    return round(s[len(s) // 2] * 1000, 1)


async def main_async(a) -> dict:
    from sqlalchemy import func, select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.orm import joinedload
    from app.models.case import CaseEvidenceModel
    from app.models.evidence import NormalizedEventModel, RawEvidence
    from app.services.multisource_investigation_service import MultiSourceInvestigationService

    pw = Path(a.dbpw).read_text(encoding="utf-8").strip()
    eng = create_async_engine(f"postgresql+psycopg://aisop_app:{pw}@127.0.0.1:5433/{a.db}")
    Session = async_sessionmaker(eng, expire_on_commit=False)
    svc = MultiSourceInvestigationService()
    res: dict = {"db": a.db, "repeats": a.repeats}
    async with Session() as s:
        top = (await s.execute(select(CaseEvidenceModel.case_id, func.count().label("n")).group_by(CaseEvidenceModel.case_id).order_by(func.count().desc()).limit(1))).first()
        case_id, n = top
        res["case_linked_evidence"] = n
        base = (select(NormalizedEventModel).join(CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id)
                .options(joinedload(NormalizedEventModel.raw_evidence)).where(CaseEvidenceModel.case_id == case_id)
                .order_by(NormalizedEventModel.event_timestamp.asc(), NormalizedEventModel.id.asc()))
        # A: current way
        ta, fa = [], None
        for _ in range(a.repeats):
            t = time.perf_counter()
            rows = await svc._load_rows(s, case_id)
            t_load = time.perf_counter() - t
            fa = svc.fingerprint(rows, False)
            ta.append((t_load, time.perf_counter() - t))
        res["A_orm_load_ms_median"] = med([x[0] for x in ta]); res["A_orm_load_plus_fingerprint_ms_median"] = med([x[1] for x in ta])
        # B: same columns through Core, no entity construction (includes raw_payload JSON decoding)
        cols = select(NormalizedEventModel.id, RawEvidence.sha256_hash, RawEvidence.raw_payload).select_from(NormalizedEventModel) \
            .join(RawEvidence, NormalizedEventModel.raw_evidence_id == RawEvidence.id) \
            .join(CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case_id)
        tb = []
        for _ in range(a.repeats):
            t = time.perf_counter()
            (await s.execute(cols)).all()
            tb.append(time.perf_counter() - t)
        res["B_core_select_with_payload_ms_median"] = med(tb)
        # C: column-only (no payload) feeding the same fingerprint function
        light = select(NormalizedEventModel.id, RawEvidence.sha256_hash).select_from(NormalizedEventModel) \
            .join(RawEvidence, NormalizedEventModel.raw_evidence_id == RawEvidence.id) \
            .join(CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case_id)
        tc, fc = [], None
        for _ in range(a.repeats):
            t = time.perf_counter()
            pairs = (await s.execute(light)).all()
            stand_ins = [types.SimpleNamespace(id=i, raw_evidence=types.SimpleNamespace(sha256_hash=h)) for i, h in pairs]
            fc = svc.fingerprint(stand_ins, False)
            tc.append(time.perf_counter() - t)
        res["C_light_select_plus_fingerprint_ms_median"] = med(tc)
        res["fingerprints_identical"] = fa == fc
        res["rows_with_payload_bytes"] = None
        r = (await s.execute(select(func.sum(func.length(RawEvidence.raw_payload.cast(__import__("sqlalchemy").Text)))).select_from(NormalizedEventModel)
                             .join(RawEvidence, NormalizedEventModel.raw_evidence_id == RawEvidence.id)
                             .join(CaseEvidenceModel, NormalizedEventModel.id == CaseEvidenceModel.evidence_id).where(CaseEvidenceModel.case_id == case_id))).scalar()
        res["raw_payload_text_bytes_for_case"] = int(r or 0)
    await eng.dispose()
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dbpw", required=True); ap.add_argument("--db", required=True); ap.add_argument("--out", required=True); ap.add_argument("--repeats", type=int, default=7)
    a = ap.parse_args()
    if a.db in PROTECTED or not a.db.startswith("aisop_load"):
        print("Refusing: database name must start with aisop_load and not be protected.", file=sys.stderr); return 2
    if not a.out.upper().startswith("D:"):
        print("--out must be on drive D:", file=sys.stderr); return 2
    res = asyncio.run(main_async(a))
    Path(a.out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
