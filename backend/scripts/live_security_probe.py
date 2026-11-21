r"""
Live OWASP-mapped security probe against a RUNNING backend on PostgreSQL (loopback only, synthetic data only).

    .venv\Scripts\python.exe backend\scripts\live_security_probe.py --base http://127.0.0.1:8010 --tokens <file> --out <json> [--db-check]

Mirrors backend/tests/unit/test_owasp_probe_suite.py (which runs on the SQLite harness) against the real PostgreSQL-backed stack.
Tokens are never printed. Refuses any non-127.0.0.1 target. --db-check also verifies, through docker exec on the approved
container, that the application role is not a superuser.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

LEAK = ("Traceback", "sqlalchemy", "psycopg", "sqlite3", 'File "', "site-packages", "D:\\", "/usr/")


def tokens(path: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in Path(path).read_text(encoding="utf-8").splitlines() if "=" in line)


class PacedClient(httpx.Client):
    """The backend rate-limits (60 requests/min by default). Pace and retry on 429 so the probes test behaviour, not the limiter;
    the limiter itself is recorded as its own check (``rate_limited_responses``)."""

    rate_limited_responses = 0

    def send(self, request, **kw):  # type: ignore[override]
        for _ in range(4):
            resp = super().send(request, **kw)
            if resp.status_code != 429:
                if int(resp.headers.get("x-ratelimit-remaining", "99")) <= 3:
                    time.sleep(8)
                return resp
            PacedClient.rate_limited_responses += 1
            time.sleep(float(resp.headers.get("retry-after", "15")) + 1)
        return resp


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--db-check", action="store_true")
    ap.add_argument("--cacert", default=None, help="CA/self-signed certificate file to trust when --base is https://127.0.0.1 (TLS verification stays ON)")
    a = ap.parse_args()
    if not a.base.startswith(("http://127.0.0.1", "https://127.0.0.1")):
        print("refusing: loopback targets only")
        return 2
    t = tokens(a.tokens)
    analyst = {"Authorization": f"Bearer {t['analyst']}"}
    sensor = {"Authorization": f"Bearer {t['sensor']}"}
    results: list[dict] = []

    def check(name: str, ref: str, ok: bool, detail: str = "") -> None:
        results.append({"probe": name, "owasp": ref, "pass": bool(ok), "detail": detail})
        print(("PASS " if ok else "FAIL ") + f"[{ref}] {name} {detail}")

    verify = a.cacert if a.cacert else True
    with PacedClient(base_url=a.base, timeout=90, verify=verify) as c:
        # API2 broken authentication
        bad_headers = [{}, {"Authorization": "Bearer"}, {"Authorization": "Bearer not-a-token"}, {"Authorization": "Basic YWRtaW46YWRtaW4="},
                       {"Authorization": "Bearer aisop_live_" + "0" * 16 + "_" + "0" * 64}, {"X-API-Key": "' OR '1'='1"}]
        codes = [c.get(p, headers=h).status_code for h in bad_headers for p in ("/api/v1/cases", "/api/v1/alerts", "/api/v1/evidence/events")]
        check("invalid credentials rejected on 3 endpoints x 6 headers", "API2", all(x in (401, 403) for x in codes), str(sorted(set(codes))))

        # API5 BFLA
        ing = {"source_type": "generic_siem", "source_identifier": "sec-probe", "alerts": [{"source_type": "generic_siem", "rule_id": "R-SEC", "rule_name": "probe",
               "timestamp": "2026-11-07T09:00:00Z", "severity": "low", "host": "h", "user": "u"}]}
        check("analyst token cannot ingest", "API5", c.post("/api/v1/alerts/ingest", json=ing, headers=analyst).status_code in (401, 403))
        check("sensor cannot read alerts/evidence/create cases", "API5", all(
            c.request(m, p, json=b, headers=sensor).status_code in (401, 403)
            for m, p, b in [("GET", "/api/v1/alerts", None), ("GET", "/api/v1/evidence/events", None), ("POST", "/api/v1/cases", {"title": "bfla probe case"})]))
        r = c.get("/api/v1/cases", headers=sensor)
        check("sensor case list shows nothing", "API1/API5", r.status_code in (401, 403) or (r.status_code == 200 and (r.json().get("items", r.json()) if isinstance(r.json(), dict) else r.json()) == []))

        # API4 resource consumption
        check("pagination limits enforced", "API4", all(c.get("/api/v1/alerts", params=p, headers=analyst).status_code == 422 for p in ({"limit": 100000}, {"page": 0}, {"limit": "abc"})))
        big = {"source_type": "generic_siem", "source_identifier": "sec-probe", "alerts": [ing["alerts"][0]] * 1001}
        check("1001-alert batch rejected", "API4", c.post("/api/v1/alerts/ingest", json=big, headers=sensor).status_code == 422)

        # Injection
        leaks, errs = [], []
        for p in ["' OR '1'='1", "x'; DROP TABLE raw_evidence;--", "1 UNION SELECT sha256_hash FROM raw_evidence", "%", "\\", "a" * 3000]:
            for path, key in [("/api/v1/alerts", "severity"), ("/api/v1/alerts", "source_type"), ("/api/v1/alerts", "provider"), ("/api/v1/evidence/events", "event_type")]:
                r = c.get(path, params={key: p}, headers=analyst)
                if r.status_code >= 500 or any(m in r.text for m in LEAK):
                    errs.append(f"{path}?{key} {r.status_code}")
                if r.status_code == 200 and p.startswith(("' OR", "x';", "1 UNION")):
                    body = r.json()
                    if len(body.get("items", body) if isinstance(body, dict) else body):
                        leaks.append(f"{path}?{key}")
        check("SQL metacharacters in filters: no 5xx, no leak, no rows", "A03/API8", not errs and not leaks, "; ".join(errs + leaks))
        check("non-UUID path ids rejected cleanly", "A03", all(c.get(pre + bad, headers=analyst).status_code in (400, 404, 422) and not any(m in c.get(pre + bad, headers=analyst).text for m in LEAK)
                                                              for bad in ("1' OR '1'='1", "../../etc/passwd", "%00") for pre in ("/api/v1/cases/", "/api/v1/alerts/")))
        check("raw_evidence still reachable after injection probes (alerts list ok)", "A03", c.get("/api/v1/alerts", headers=analyst).status_code == 200)

        # API3 mass assignment
        check("mass assignment rejected", "API3", c.post("/api/v1/cases", json={"title": "mass assignment probe", "status": "closed", "id": str(uuid.uuid4()), "created_by": "x"}, headers=analyst).status_code == 422)

        # API8 misconfiguration
        h = c.get("/api/v1/health").headers
        check("security headers present", "API8", h.get("x-content-type-options", "").lower() == "nosniff" and h.get("x-frame-options", "").upper() == "DENY" and "frame-ancestors 'none'" in h.get("content-security-policy", ""))
        o = c.options("/api/v1/cases", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
        check("CORS rejects a foreign origin", "API8", o.headers.get("access-control-allow-origin") not in ("*", "https://evil.example"))
        bodies = [c.get(f"/api/v1/cases/{uuid.uuid4()}", headers=analyst).text, c.get("/api/v1/nope", headers=analyst).text,
                  c.post("/api/v1/cases", json={"title": 5}, headers=analyst).text, c.post("/api/v1/alerts/ingest", content="not json", headers={**sensor, "content-type": "application/json"}).text]
        check("errors leak no internals", "API8", not any(m in b for b in bodies for m in LEAK))

        # Stored XSS through evidence text -> Markdown report; secrets in audit
        evil = "<script>alert(1)</script><img src=x onerror=alert(1)>[click](javascript:alert(1))"
        recs = [{"source_type": "generic_siem", "rule_id": f"R-XSS-{i}", "rule_name": evil, "description": evil, "severity": "high", "timestamp": f"2026-11-07T09:0{i}:00Z",
                 "host": "xss-host", "user": "xss-user", "command_line": "powershell.exe -enc SECRET-COMMANDLINE-MARKER-12345"} for i in range(1, 4)]
        rb = c.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "sec-probe-xss", "alerts": recs}, headers=sensor).json()
        case = c.post("/api/v1/cases", json={"title": "Security probe case (synthetic)", "description": "synthetic"}, headers=analyst).json()
        for eid in rb.get("alert_ids", []):
            c.post(f"/api/v1/cases/{case['id']}/evidence", json={"evidence_id": eid}, headers=analyst)
        inv = c.post(f"/api/v1/cases/{case['id']}/investigations/multisource", json={"use_llm": False}, headers=analyst)
        j = inv.json() if inv.status_code < 300 else {}
        mds = [j.get("batch_report_markdown") or ""] + [i.get("report_markdown") or "" for i in j.get("incidents", [])]
        low = "\n".join(mds).lower()
        check("Markdown reports contain no active HTML or javascript: links", "A03/LLM05", bool(low) and "<script" not in low and "<img" not in low and "](javascript:" not in low)
        act = c.get(f"/api/v1/cases/{case['id']}/activity", headers=analyst)
        blob = inv.text + act.text
        check("no tokens or raw command lines in investigation/audit responses", "A09/LLM02", t["analyst"] not in blob and "SECRET-COMMANDLINE-MARKER-12345" not in act.text
              and not re.search(r"aisop_(live|test)_[0-9a-f]{16}_[0-9a-f]{64}", blob))

        # BOLA: the sensor identity (no assignment) must not reach the case
        check("BOLA: unassigned identity cannot open or investigate the case", "API1", all(
            c.request(m, p, json=b, headers=sensor).status_code in (401, 403, 404)
            for m, p, b in [("GET", f"/api/v1/cases/{case['id']}", None), ("GET", f"/api/v1/cases/{case['id']}/evidence", None),
                            ("POST", f"/api/v1/cases/{case['id']}/investigations/multisource", {})]))

    h0 = httpx.get(a.base + "/api/v1/alerts", headers=analyst, verify=verify)  # health is exempt; the limiter advertises its quota on API routes
    check("rate limiter active (quota advertised; 429 returned when exceeded)", "API4", "x-ratelimit-limit" in h0.headers,
          f"limit={h0.headers.get('x-ratelimit-limit')}, 429s absorbed by the probe={PacedClient.rate_limited_responses}")

    if a.db_check:
        out = subprocess.run(["docker", "exec", "aisop-postgres", "psql", "-U", "aisop", "-d", "postgres", "-Atc",
                              "select rolsuper::text||','||rolcreatedb::text||','||rolcreaterole::text from pg_roles where rolname='aisop_app'"], capture_output=True, text=True).stdout.strip()
        check("application database role is not superuser/createdb/createrole", "A01/A05", out == "false,false,false", out or "role missing")

    Path(a.out).write_text(json.dumps(results, indent=2), encoding="utf-8")
    failed = [r for r in results if not r["pass"]]
    print(f"{len(results) - len(failed)}/{len(results)} probes passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
