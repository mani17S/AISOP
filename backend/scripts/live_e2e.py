r"""
Live end-to-end check against a RUNNING backend (PostgreSQL-backed): ingest -> case -> multi-source investigation -> report.

    .venv\Scripts\python.exe backend\scripts\live_e2e.py --base http://127.0.0.1:8010 --tokens D:\path\tokens.txt --out D:\path\result.json

The tokens file has two lines, ``analyst=<token>`` and ``sensor=<token>`` (synthetic demo identities). Tokens are never printed.
All data is synthetic (app.modules.correlation.demo_data, app.modules.evidence_domains.scenarios, generated filler).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.modules.correlation import demo_data as dd  # noqa: E402
from app.modules.evidence_domains import scenarios as sc  # noqa: E402


def load_tokens(path: str) -> dict[str, str]:
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def filler(n: int) -> list[dict]:
    t0 = datetime(2026, 11, 7, 6, 0, 0, tzinfo=timezone.utc)
    return [{
        "source_type": "generic_siem", "rule_id": f"R-FILL-{i}", "rule_name": f"Synthetic low-severity rule {i % 7}", "severity": "low",
        "timestamp": (t0 + timedelta(seconds=30 * i)).isoformat().replace("+00:00", "Z"), "host": f"filler-host-{i % 12}", "user": f"user{i % 9}",
    } for i in range(n)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    tok = load_tokens(a.tokens)
    sensor = {"Authorization": f"Bearer {tok['sensor']}"}
    analyst = {"Authorization": f"Bearer {tok['analyst']}"}
    res: dict = {"started": datetime.now(timezone.utc).isoformat(), "steps": {}}
    ok = True

    def step(name: str, cond: bool, **info) -> None:
        nonlocal ok
        ok = ok and cond
        res["steps"][name] = {"pass": cond, **info}
        print(("PASS " if cond else "FAIL ") + name, {k: v for k, v in info.items() if not isinstance(v, (list, dict))})

    with httpx.Client(base_url=a.base, timeout=120) as c:
        step("health", c.get("/api/v1/health").status_code == 200)
        step("auth_required", c.get("/api/v1/cases").status_code in (401, 403))

        chain = dd.intrusion_chain()
        bad = [{"source_type": "generic_siem", "rule_id": "R-NO-TIME", "rule_name": "alert without an event time"}, {}]
        r = c.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "live-e2e", "alerts": chain + dd.duplicates_and_near_duplicates()[:2] + bad}, headers=sensor)
        b = r.json()
        step("ingest_mixed_batch", r.status_code == 200 and b["total_normalized"] >= len(chain) - 1 and len(b["errors"]) >= 2,
             received=b.get("total_received"), normalized=b.get("total_normalized"), duplicates=b.get("total_skipped_duplicates"), errors=len(b.get("errors", [])))
        chain_ids = b["alert_ids"]

        t = time.perf_counter()
        r = c.post("/api/v1/alerts/ingest", json={"source_type": "generic_siem", "source_identifier": "live-e2e-filler", "alerts": filler(200)}, headers=sensor)
        f = r.json()
        step("ingest_200_alert_batch", r.status_code == 200 and f["total_normalized"] == 200 and not f["errors"], seconds=round(time.perf_counter() - t, 2))
        r2 = c.post("/api/v1/alerts/ingest", json={"source_type": "generic_siem", "source_identifier": "live-e2e-filler", "alerts": filler(200)}, headers=sensor)
        step("ingest_repeat_is_idempotent", r2.status_code == 200 and r2.json()["total_normalized"] == 0 and r2.json()["total_skipped_duplicates"] == 200)

        r = c.post("/api/v1/cases", json={"title": "Live E2E: multi-source intrusion (synthetic)", "description": "Synthetic data only."}, headers=analyst)
        case = r.json()
        step("create_case", r.status_code in (200, 201), case_id=case.get("id", "")[:8])
        cid = case["id"]
        linked = 0
        for eid in chain_ids:
            lr = c.post(f"/api/v1/cases/{cid}/evidence", json={"evidence_id": eid}, headers=analyst)
            linked += lr.status_code == 201
        step("link_evidence", linked == len(chain_ids), linked=linked)
        step("sensor_cannot_open_the_case", c.get(f"/api/v1/cases/{cid}", headers=sensor).status_code in (401, 403, 404))

        dom = sc.scenario_b_network_endpoint()
        r = c.post(f"/api/v1/cases/{cid}/evidence/domain", json={"records": dom}, headers=analyst)
        step("import_domain_evidence", r.status_code in (200, 201), status=r.status_code, body=r.text[:160] if r.status_code >= 300 else "")

        t = time.perf_counter()
        r = c.post(f"/api/v1/cases/{cid}/investigations/multisource", json={"use_llm": False}, headers=analyst)
        inv = r.json() if r.status_code < 300 else {}
        step("investigate_deterministic", r.status_code in (200, 201), seconds=round(time.perf_counter() - t, 2), status=r.status_code,
             incidents=len(inv.get("incidents", [])), verdict=(inv.get("batch_sufficiency") or {}).get("verdict"), rejected=len(inv.get("rejected", [])))
        res["investigation_keys"] = sorted(inv.keys())
        res["investigation_summary"] = {k: inv.get(k) for k in ("counts", "batch_sufficiency", "llm_status", "status") if k in inv}
        for sec in ("timeline", "correlation", "attack", "sufficiency", "report", "graph", "evidence"):
            sr = c.get(f"/api/v1/cases/{cid}/investigations/multisource/{sec}", headers=analyst)
            step(f"section_{sec}", sr.status_code == 200)
        att = c.get(f"/api/v1/cases/{cid}/investigations/multisource/attack", headers=analyst).json()
        res["attack"] = att
        r3 = c.post(f"/api/v1/cases/{cid}/investigations/multisource", json={"use_llm": False}, headers=analyst)
        step("investigation_is_idempotent", r3.status_code in (200, 201))
        act = c.get(f"/api/v1/cases/{cid}/activity", headers=analyst)
        rows = act.json() if act.status_code == 200 else []
        rows = rows if isinstance(rows, list) else rows.get("items", [])
        step("audit_trail_has_rows", act.status_code == 200 and len(rows) >= 1, rows=len(rows))
        res["case_id"] = cid
    res["all_pass"] = ok
    Path(a.out).write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    print("ALL PASS" if ok else "SOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
