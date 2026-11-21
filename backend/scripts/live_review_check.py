r"""
Live check of the lead review record against a RUNNING backend on PostgreSQL (loopback only, synthetic data only).

    .venv\Scripts\python.exe backend\scripts\live_review_check.py --base http://127.0.0.1:8010 --tokens <tokens file> --out <json>

Uses a fresh case with a small synthetic investigation so existing demo cases are not touched. Tokens are never printed.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

import httpx


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
    S = {"X-API-Key": t["sensor"].strip()}
    res: list[dict] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        res.append({"check": name, "pass": bool(cond), "detail": detail})
        print(("PASS " if cond else "FAIL ") + name, detail)

    nonce = uuid.uuid4().hex[:8]
    with httpx.Client(base_url=a.base, timeout=60) as c:
        alerts = [{"source_type": "generic_siem", "rule_id": f"R-REV-{nonce}-{i}", "rule_name": "review check", "severity": "high", "timestamp": f"2026-11-07T09:0{i}:00Z",
                   "host": "rev-host", "user": "rev-user", "src_ip": "203.0.113.7"} for i in range(3)]
        b = c.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "live-review", "alerts": alerts}, headers=S).json()
        cid = c.post("/api/v1/cases", json={"title": "Review check (synthetic)", "description": "synthetic"}, headers=A).json()["id"]
        for eid in b["alert_ids"]:
            c.post(f"/api/v1/cases/{cid}/evidence", json={"evidence_id": eid}, headers=A)
        base = f"/api/v1/cases/{cid}/investigations/multisource"
        check("investigation stored", c.post(base, json={}, headers=A).status_code in (200, 201))
        st = c.get(f"{base}/status", headers=A).json()
        fp = st["evidence_fingerprint"]
        check("not reviewed before the lead decides", st["review"]["state"] == "not_reviewed", str(st["review"]["state"]))
        check("export is refused before approval (409)", c.get(f"{base}/export", headers=A).status_code == 409)
        check("a wrong fingerprint is refused (409)", c.post(f"{base}/review", json={"decision": "approved", "evidence_fingerprint": "0" * 64}, headers=A).status_code == 409)
        check("the sensor identity cannot review", c.post(f"{base}/review", json={"decision": "approved", "evidence_fingerprint": fp}, headers=S).status_code in (401, 403, 404))
        r = c.post(f"{base}/review", json={"decision": "approved", "evidence_fingerprint": fp, "note": "Live check on PostgreSQL."}, headers=A)
        check("lead approves", r.status_code == 200 and r.json()["state"] == "approved", f"status {r.status_code}")
        after = c.get(f"{base}/status", headers=A).json()
        check("status shows approved with the reviewer", after["review"]["state"] == "approved" and bool(after["review"]["reviewed_by"]))
        rep = c.get(f"{base}/report", headers=A).json()
        check("report section shows the review too", rep["review"]["state"] == "approved")
        ex = c.get(f"{base}/export", headers=A)
        check("export is released after approval, with the approval stated", ex.status_code == 200 and "Approved by" in ex.json().get("markdown", ""), f"status {ex.status_code}")
        check("the sensor identity cannot export", c.get(f"{base}/export", headers=S).status_code in (401, 403, 404))
        act = c.get(f"/api/v1/cases/{cid}/activity", headers=A).json()
        rows = act if isinstance(act, list) else act.get("items", [])
        check("review and export are in the append-only audit trail", any("case_multisource_review" in json.dumps(x) for x in rows) and any("case_multisource_export" in json.dumps(x) for x in rows))
        # change the evidence: the review must go stale and a new review of the old run must be refused
        extra = {"source_type": "generic_siem", "rule_id": f"R-REV-{nonce}-extra", "rule_name": "extra", "severity": "low", "timestamp": "2026-11-07T09:30:00Z", "host": "rev-host", "user": "rev-user"}
        eb = c.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "live-review", "alerts": [extra]}, headers=S).json()
        for eid in eb["alert_ids"]:
            c.post(f"/api/v1/cases/{cid}/evidence", json={"evidence_id": eid}, headers=A)
        stale = c.get(f"{base}/status", headers=A).json()
        check("review goes stale when evidence changes", stale["stale_evidence"] is True and stale["review"]["state"] == "stale", str(stale["review"]["state"]))
        check("export is refused again after the evidence changes (409)", c.get(f"{base}/export", headers=A).status_code == 409)
        check("a review of the old run is refused after the change (409)", c.post(f"{base}/review", json={"decision": "approved", "evidence_fingerprint": fp}, headers=A).status_code == 409)
    Path(a.out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    failed = [r for r in res if not r["pass"]]
    print(f"{len(res) - len(failed)}/{len(res)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
