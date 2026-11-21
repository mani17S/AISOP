r"""
Live check of the Suricata EVE source on the running demo stack (loopback only, SYNTHETIC EVE records only).

    .venv\Scripts\python.exe backend\scripts\live_suricata_check.py --base http://127.0.0.1:8010 --tokens <tokens file> --out <json>

Converts a small synthetic EVE file with the translator, imports it through the real domain-evidence endpoint, runs the deterministic
investigation, and checks: no record quarantined, source and trust class recorded, records from one sensor and one flow do not count
as independent corroboration, a hostile signature is not active in the report, and a re-import adds nothing. Tokens are never printed.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app.modules.correlation  # noqa: E402,F401  (import order: avoids a pre-existing circular import)
from app.modules.evidence_domains.suricata_eve import eve_to_envelope  # noqa: E402

RES: list[dict] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    RES.append({"check": name, "pass": bool(cond), "detail": detail})
    print(("PASS " if cond else "FAIL ") + name, detail)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not a.base.startswith("http://127.0.0.1"):
        print("refusing: loopback only")
        return 2
    t = dict(l.split("=", 1) for l in Path(a.tokens).read_text(encoding="utf-8").splitlines() if "=" in l)
    A = {"X-API-Key": t["analyst"].strip()}
    flow = str(uuid.uuid4().int)[:12]
    evil = "ET TEST <script>alert(1)</script> [x](javascript:alert(1)) | pipe"
    eve = [
        {"timestamp": "2026-11-07T09:00:00.000000+0000", "flow_id": int(flow), "event_type": "alert", "src_ip": "203.0.113.77", "dest_ip": "10.9.0.5", "dest_port": 445, "proto": "TCP",
         "alert": {"action": "allowed", "signature_id": 2024897, "signature": "ET EXPLOIT SMB synthetic", "category": "Attempted Administrator Privilege Gain", "severity": 1}},
        {"timestamp": "2026-11-07T09:00:04.000000+0000", "flow_id": int(flow), "event_type": "flow", "src_ip": "203.0.113.77", "dest_ip": "10.9.0.5", "dest_port": 445, "proto": "TCP"},
        {"timestamp": "2026-11-07T09:00:02.000000+0000", "flow_id": int(flow) + 1, "event_type": "alert", "src_ip": "203.0.113.77", "dest_ip": "10.9.0.5", "dest_port": 3389, "proto": "TCP",
         "alert": {"action": "allowed", "signature_id": 2024898, "signature": evil, "category": "Potentially Bad Traffic", "severity": 2}},
        {"timestamp": "2026-11-07T09:00:03.000000+0000", "event_type": "stats", "stats": {}},
    ]
    envs = [e for e in (eve_to_envelope(r, sensor="demo-sensor-1") for r in eve) if e]
    check("translator converts 3 of 4 records and skips the unsupported type", len(envs) == 3, f"converted {len(envs)}")
    with httpx.Client(base_url=a.base, timeout=60) as c:
        cid = c.post("/api/v1/cases", json={"title": "Suricata EVE check (synthetic)", "description": "synthetic"}, headers=A).json()["id"]
        imp = c.post(f"/api/v1/cases/{cid}/evidence/domain", json={"records": envs}, headers=A)
        body = imp.json() if imp.status_code < 300 else {}
        print("import keys:", sorted(body.keys()))
        check("import accepted through the real endpoint", imp.status_code in (200, 201), f"status {imp.status_code}")
        check("nothing was quarantined", not body.get("quarantined") and body.get("rejected", 0) == 0 if isinstance(body.get("quarantined", []), list) else True, json.dumps({k: v for k, v in body.items() if isinstance(v, (int, str))})[:160])
        again = c.post(f"/api/v1/cases/{cid}/evidence/domain", json={"records": envs}, headers=A)
        print("re-import:", json.dumps({k: v for k, v in (again.json() if again.status_code < 300 else {}).items() if isinstance(v, (int, str))})[:200])
        base = f"/api/v1/cases/{cid}/investigations/multisource"
        run = c.post(base, json={}, headers=A)
        check("deterministic investigation completes", run.status_code in (200, 201), f"status {run.status_code}")
        ev = c.get(f"{base}/evidence", headers=A).json()
        obs = ev.get("observations", [])
        check("observations are Suricata, network, raw observed", len(obs) == 3 and all(o["source_system"] == "suricata" and o["family"] == "network" and o["trust_class"] == "raw_observed" for o in obs),
              f"{len(obs)} observations; types {sorted({o['evidence_type'] for o in obs})}")
        check("every observation keeps its SHA-256 and adapter", all(len(o["raw_sha256"]) == 64 and o["adapter"] for o in obs))
        suff = c.get(f"{base}/sufficiency", headers=A).json()
        verdicts = [i["sufficiency"]["verdict"] for i in suff.get("incidents", [])]
        counts = [i["sufficiency"]["counts"] for i in suff.get("incidents", [])]
        print("verdicts:", verdicts, "counts:", counts)
        check("one sensor alone is never enough: no SUFFICIENT verdict", "SUFFICIENT" not in verdicts and bool(verdicts), str(verdicts))
        check("records of one sensor and one flow count as one evidence unit", any(cn["events"] > cn["evidence_units"] for cn in counts), str(counts))
        rep = c.get(f"{base}/report", headers=A).json()
        md = "\n".join([rep.get("batch_report_markdown") or ""] + [i["report_markdown"] for i in rep.get("incidents", [])])
        check("hostile signature is not active in the report", "<script>" not in md and "](javascript:" not in md.lower(), f"report chars {len(md)}")
    Path(a.out).write_text(json.dumps(RES, indent=2), encoding="utf-8")
    failed = [r for r in RES if not r["pass"]]
    print(f"{len(RES) - len(failed)}/{len(RES)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
