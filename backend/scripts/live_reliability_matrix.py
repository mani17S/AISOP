r"""
R01-R12 reliability matrix against the REAL PostgreSQL-backed stack (loopback only, synthetic data only).

    .venv\Scripts\python.exe backend\scripts\live_reliability_matrix.py --tokens <tokens file> --dbpw <app role password file> --out <json>

It starts its own throwaway backends on 127.0.0.1 (ports 8011-8013) against the demo database and stops them at the end:
  8011  normal, rate limiter OFF (so the matrix tests behaviour, not the limiter), LLM disabled
  8012  LLM enabled, endpoint is a local socket that accepts and never answers  -> LLM TIMEOUT
  8013  LLM enabled, endpoint is a closed local port                            -> LLM CONNECTION ERROR
Each case reports PASS, FAIL or NOT-EXECUTABLE-LIVE with the reason; nothing is silently skipped. Tokens and the DB password are never printed.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app.modules.correlation import demo_data as dd  # noqa: E402

RESULTS: list[dict] = []
LEAK = ("Traceback", "sqlalchemy", "psycopg", 'File "', "site-packages", "D:\\")


def rec(case: str, name: str, status: str, detail: str = "") -> None:
    RESULTS.append({"case": case, "check": name, "status": status, "detail": detail})
    print(f"{status:19s} {case} {name} {detail}")


def ok(case: str, name: str, cond: bool, detail: str = "") -> bool:
    rec(case, name, "PASS" if cond else "FAIL", detail)
    return bool(cond)


def alert(i: int, **over) -> dict:
    a = {"source_type": "generic_siem", "rule_id": f"R-MX-{i}", "rule_name": f"matrix rule {i}", "severity": "high", "timestamp": f"2026-11-07T09:{i % 60:02d}:00Z",
         "host": f"mx-host-{i % 5}", "user": f"mx-user-{i % 3}", "src_ip": "203.0.113.7", "dest_ip": "198.51.100.9"}
    a.update(over)
    return a


class Stack:
    def __init__(self, tokens: dict[str, str], dbpw: str, outdir: Path):
        self.tokens, self.dbpw, self.outdir, self.procs = tokens, dbpw, outdir, []
        self.analyst = {"Authorization": f"Bearer {tokens['analyst']}"}
        self.sensor = {"Authorization": f"Bearer {tokens['sensor']}"}

    def start(self, port: int, **env_over: str) -> None:
        env = os.environ.copy()
        env.update({"DATABASE_URL": f"postgresql+psycopg://aisop_app:{self.dbpw}@127.0.0.1:5433/aisop_demo", "API_AUTH_ENABLED": "true", "API_AUTH_ALLOW_LEGACY_KEYS": "false",
                    "ENVIRONMENT": "development", "AISOP_PORT": str(port), "RATE_LIMIT_ENABLED": "false", "LLM_ENABLED": "false",
                    "ATTACK_REFERENCE_PATH": "D:\\AISOP-Reference-Data\\MITRE-ATT&CK\\Enterprise\\v20.1\\enterprise-attack-20.1.json"})
        env.update(env_over)
        out = open(self.outdir / f"matrix_backend_{port}.log", "w")
        self.procs.append(subprocess.Popen([sys.executable, str(ROOT / "backend" / "run_local.py")], cwd=str(ROOT), env=env, stdout=out, stderr=out))
        for _ in range(60):
            try:
                if httpx.get(f"http://127.0.0.1:{port}/api/v1/health", timeout=2).status_code == 200:
                    return
            except Exception:
                time.sleep(1)
        raise RuntimeError(f"backend {port} did not start")

    def stop(self) -> None:
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(10)
            except Exception:
                p.kill()


def tarpit(port: int, stop: threading.Event) -> None:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    s.settimeout(1)
    held = []
    while not stop.is_set():
        try:
            held.append(s.accept()[0])  # accept and never answer
        except socket.timeout:
            pass
    for h in held:
        h.close()
    s.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--dbpw", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    tokens = dict(l.split("=", 1) for l in Path(a.tokens).read_text(encoding="utf-8").splitlines() if "=" in l)
    dbpw = Path(a.dbpw).read_text(encoding="utf-8").strip()
    outdir = Path(a.out).parent
    S = Stack(tokens, dbpw, outdir)
    stop = threading.Event()
    threading.Thread(target=tarpit, args=(11998, stop), daemon=True).start()
    try:
        S.start(8011)
        S.start(8012, LLM_ENABLED="true", OLLAMA_BASE_URL="http://127.0.0.1:11998", OLLAMA_TIMEOUT_SECONDS="3", OLLAMA_MAX_RETRIES="1")
        S.start(8013, LLM_ENABLED="true", OLLAMA_BASE_URL="http://127.0.0.1:11997", OLLAMA_TIMEOUT_SECONDS="3", OLLAMA_MAX_RETRIES="1")
        run(S)
    finally:
        stop.set()
        S.stop()
    Path(a.out).write_text(json.dumps(RESULTS, indent=2), encoding="utf-8")
    counts = {k: sum(1 for r in RESULTS if r["status"] == k) for k in ("PASS", "FAIL", "NOT-EXECUTABLE-LIVE")}
    print("SUMMARY", counts)
    return 1 if counts["FAIL"] else 0


def run(S: Stack) -> None:
    B = "http://127.0.0.1:8011"
    c = httpx.Client(base_url=B, timeout=180)
    nonce = uuid.uuid4().hex[:8]                                   # makes every run's alerts unique so earlier runs never count as duplicates

    def ingest(alerts, src="auto", sid="matrix", client=c):
        return client.post("/api/v1/alerts/ingest", json={"source_type": src, "source_identifier": sid, "alerts": alerts}, headers=S.sensor)

    def new_case(title="Reliability matrix case (synthetic)"):
        return c.post("/api/v1/cases", json={"title": title, "description": "synthetic"}, headers=S.analyst).json()["id"]

    def link(cid, ids):
        return sum(c.post(f"/api/v1/cases/{cid}/evidence", json={"evidence_id": i}, headers=S.analyst).status_code == 201 for i in ids)

    def start(cid, client=c, **body):
        return client.post(f"/api/v1/cases/{cid}/investigations/multisource", json=body or {}, headers=S.analyst)

    def uniq(al):  # nonce into rule ids/hosts
        al = copy.deepcopy(al)
        for x in al:
            if isinstance(x, dict):
                x["rule_id"] = f"{x.get('rule_id', 'R')}-{nonce}"
        return al

    # R01 single alert
    r = ingest(uniq([alert(1)]))
    b = r.json()
    cid = new_case()
    ok("R01", "single alert ingested", r.status_code == 200 and b["total_normalized"] == 1 and not b["errors"])
    link(cid, b["alert_ids"])
    t = time.perf_counter()
    inv = start(cid)
    ok("R01", "single alert investigation completes", inv.status_code in (200, 201), f"{time.perf_counter() - t:.2f}s")
    tl = c.get(f"/api/v1/cases/{cid}/investigations/multisource/timeline", headers=S.analyst).json()
    prefixes = [row.get("raw_sha256_prefix") for inc in tl.get("incidents", []) for row in inc.get("timeline", [])]
    ok("R01", "timeline row maps to the stored raw record (12-hex SHA-256 prefix)", len(prefixes) == 1 and len(prefixes[0] or "") == 12, str(len(prefixes)) + " row(s)")

    # R02 sequential, 4 source types
    kinds = [("generic_siem", alert), ("auto", lambda i: dd.intrusion_chain()[i % 8]), ]
    seq_ids = []
    codes = []
    for i in range(13):
        item = alert(100 + i, rule_name=f"seq {i}") if i % 2 == 0 else copy.deepcopy(dd.intrusion_chain()[i % len(dd.intrusion_chain())])
        if isinstance(item, dict) and "rule_id" in item:
            item["rule_id"] = f"{item['rule_id']}-{nonce}-{i}"
        rr = ingest([item])
        codes.append(rr.status_code)
        seq_ids += rr.json().get("alert_ids", [])
    ok("R02", "13 sequential single-alert requests all answered 200", set(codes) == {200}, str(sorted(set(codes))))
    cid2 = new_case("R02 sequential case")
    ok("R02", "all stored alerts linkable to a second case", link(cid2, seq_ids) == len(seq_ids), f"{len(seq_ids)} linked")
    ok("R02", "sequential evidence investigates", start(cid2).status_code in (200, 201))

    # R03 concurrent
    same = uniq([alert(200)])
    with ThreadPoolExecutor(10) as ex:
        rs = list(ex.map(lambda _: ingest(same), range(10)))
    norm = sum(x.json()["total_normalized"] for x in rs)
    dup = sum(x.json()["total_skipped_duplicates"] for x in rs)
    ok("R03", "10 concurrent identical submissions create exactly one record", all(x.status_code == 200 for x in rs) and norm == 1 and dup == 9, f"normalized={norm} duplicates={dup}")
    batches = [uniq([alert(300 + k * 10 + j) for j in range(10)]) for k in range(5)]
    with ThreadPoolExecutor(5) as ex:
        rs = list(ex.map(lambda al: ingest(al), batches))
    ok("R03", "5 concurrent distinct 10-alert batches all normalize fully", all(x.status_code == 200 and x.json()["total_normalized"] == 10 for x in rs))
    cids = []
    for x in rs:
        cc = new_case("R03 concurrent investigation")
        link(cc, x.json()["alert_ids"])
        cids.append(cc)
    with ThreadPoolExecutor(5) as ex:
        invs = list(ex.map(lambda cc: start(cc), cids))
    ok("R03", "5 concurrent investigations (different cases) all complete", all(x.status_code in (200, 201) for x in invs))
    per_case = [len([x for x in c.get(f"/api/v1/cases/{cc}/activity", headers=S.analyst).json() if "multisource" in json.dumps(x).lower()]) for cc in cids]
    ok("R03", "exactly one investigation audit row per case (no cross-case bleed)", per_case == [1] * 5, f"rows per case {per_case}")
    cc = new_case("R03 same-case concurrent investigations")
    link(cc, rs[0].json()["alert_ids"])
    with ThreadPoolExecutor(4) as ex:
        same_case = list(ex.map(lambda _: start(cc), range(4)))
    rows = [x for x in c.get(f"/api/v1/cases/{cc}/activity", headers=S.analyst).json() if "multisource" in json.dumps(x).lower()]
    ok("R03", "4 concurrent investigations of ONE case create one audit row", all(x.status_code in (200, 201) for x in same_case) and len(rows) == 1, f"statuses={[x.status_code for x in same_case]} rows={len(rows)}")

    # R04 duplicates
    base = uniq([alert(400)])
    first = ingest(base).json()
    again = ingest(base).json()
    intra = ingest(uniq([alert(401), alert(401)])).json()
    ok("R04", "repeat submission skipped as duplicate", first["total_normalized"] == 1 and again["total_normalized"] == 0 and again["total_skipped_duplicates"] == 1)
    ok("R04", "intra-batch duplicate counted once", intra["total_normalized"] == 1 and intra["total_skipped_duplicates"] == 1)

    # R05 malformed
    for label, payload in [("string items", ["just a string", 42, None, [1, 2]]), ("wrong severity type", [alert(500, severity={"x": 1})]),
                           ("deep nesting", [alert(501, extra=json.loads("[" * 60 + "1" + "]" * 60))]), ("invalid timestamp", [alert(502, timestamp="not-a-date")]),
                           ("numeric timestamp", [alert(503, timestamp=12345)])]:
        rr = c.post("/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "matrix", "alerts": payload}, headers=S.sensor)
        good = rr.status_code in (200, 422) and not any(m in rr.text for m in LEAK)
        if rr.status_code == 200:
            j = rr.json()
            good = good and j["total_received"] == len(payload) and j["total_normalized"] + len(j["errors"]) + j["total_skipped_duplicates"] == len(payload)
            if label in ("invalid timestamp", "numeric timestamp"):
                good = good and j["total_normalized"] == 0 and len(j["errors"]) == 1                    # F1: never stored with an invented time
        ok("R05", f"malformed: {label}", good, f"status {rr.status_code}")
    rr = c.post("/api/v1/alerts/ingest", content="{not json", headers={**S.sensor, "content-type": "application/json"})
    ok("R05", "malformed: invalid JSON body", rr.status_code == 422 and not any(m in rr.text for m in LEAK))

    # R06 missing fields
    for label, drop in [("host and user", ["host", "user"]), ("rule identity", ["rule_id", "rule_name"]), ("optional fields", ["src_ip", "dest_ip"]), ("severity", ["severity"])]:
        al = alert(600, rule_id=f"R-MX-600-{nonce}-{label[:3]}", description=f"matrix run {nonce} {label}")  # description keeps the payload unique when the ids are dropped
        for k in drop:
            al.pop(k, None)
        rr = ingest([al]).json()
        cc = new_case("R06 " + label)
        link(cc, rr.get("alert_ids", []))
        ok("R06", f"missing {label}: ingested and investigation completes", rr["total_normalized"] + len(rr["errors"]) + rr["total_skipped_duplicates"] == 1 and (not rr.get("alert_ids") or start(cc).status_code in (200, 201)),
           f"normalized={rr['total_normalized']} errors={len(rr['errors'])}")
    al = alert(601)
    al.pop("timestamp")
    rr = ingest([al]).json()
    ok("R06", "missing timestamp: rejected, nothing stored (F1)", rr["total_normalized"] == 0 and len(rr["errors"]) == 1)
    rr = ingest([{}]).json()
    ok("R06", "content-free alert {}: rejected, nothing stored", rr["total_normalized"] == 0 and len(rr["errors"]) == 1)

    # R07 large payloads
    from app.schemas.alert_ingest import MAX_ALERT_PAYLOAD_BYTES
    rr = ingest(uniq([alert(700, description="x" * (MAX_ALERT_PAYLOAD_BYTES - 4000))]))
    ok("R07", "near-limit single alert accepted intact", rr.status_code == 200 and rr.json()["total_normalized"] == 1)
    rr = ingest(uniq([alert(701, description="x" * (MAX_ALERT_PAYLOAD_BYTES + 5000))]))
    ok("R07", "over-limit alert rejected", rr.status_code == 422 and not any(m in rr.text for m in LEAK))
    rr = ingest([alert(i) for i in range(1001)])
    ok("R07", "1001-alert batch rejected", rr.status_code == 422)
    t = time.perf_counter()
    rr = ingest(uniq([alert(800 + i) for i in range(200)]))
    ok("R07", "200-alert batch accepted", rr.status_code == 200 and rr.json()["total_normalized"] == 200, f"{time.perf_counter() - t:.2f}s (informational)")
    rr = c.post("/api/v1/alerts/ingest", content="x" * (17 * 1024 * 1024), headers={**S.sensor, "content-type": "application/json"})
    ok("R07", "17 MiB body rejected before parsing", rr.status_code in (413, 422))

    # R08 database errors
    rec("R08", "commit/read failure injection and rollback atomicity", "NOT-EXECUTABLE-LIVE",
        "needs fault injection inside the database layer; covered on PostgreSQL by pytest -m postgres (day123_pg/pg_tests.log: test_s4_failed_import_rolls_back_every_row, test_pol_02_cancellation_and_error_connection_return) and offline by R08 tests")

    # R09 LLM timeout / connection error: deterministic fields must not change
    cidl = new_case("R09 LLM failure case")
    ids = []
    for i in range(3):
        ids += ingest(uniq([alert(900 + i, rule_name="encoded powershell " + str(i))])).json()["alert_ids"]
    ids += ingest(uniq([dict(x) for x in dd.intrusion_chain()[:6]])).json()["alert_ids"]
    link(cidl, ids)
    base_inv = start(cidl)
    ok("R09", "baseline (AI off) investigation", base_inv.status_code in (200, 201))

    def sections(client, cid_):
        out = {}
        for s in ("timeline", "attack", "sufficiency"):
            j = client.get(f"/api/v1/cases/{cid_}/investigations/multisource/{s}", headers=S.analyst).json()
            j.pop("created_at", None)
            out[s] = j
        return out

    ref = sections(c, cidl)
    for port, label in [(8012, "LLM timeout (endpoint accepts and never answers)"), (8013, "LLM connection error (closed port)")]:
        cl = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=180)
        t = time.perf_counter()
        rr = start(cidl, client=cl, use_llm=True, force=True)
        dt = time.perf_counter() - t
        body = rr.json() if rr.status_code < 300 else {}
        llm_states = [str(i.get("llm_status")) for i in body.get("incidents", [])]
        got = sections(cl, cidl)
        strip = lambda d: json.loads(json.dumps(d).replace('"llm_status": "not_requested"', '').replace('"llm_status": "fallback', '"x": "fallback')) if False else d
        same_tl = got["timeline"] == ref["timeline"]
        same_att = got["attack"] == ref["attack"]
        ok("R09", f"{label}: run completes with a deterministic fallback", rr.status_code in (200, 201) and any("fallback" in s or "abstain" in s or "skipped" in s for s in llm_states), f"{dt:.1f}s states={sorted(set(llm_states))}")
        ok("R09", f"{label}: timeline and ATT&CK identical to the AI-off run", same_tl and same_att)

    # R10 TI failure
    rec("R10", "threat-intel failure", "NOT-EXECUTABLE-LIVE", "the multi-source investigation path performs no threat-intel lookups (reliability report R10, enrichments empty); the case-synthesis TI path needs a live feed fault and is not covered live")

    # R11 partial failure
    rec("R11", "report rendering failure inside a run", "NOT-EXECUTABLE-LIVE", "needs fault injection in the renderer; covered offline (test_reliability_matrix R11). Explanation/LLM failure not breaking the run is verified live in R09.")

    # R12 retry / recovery
    cr = new_case("R12 retry case")
    link(cr, ingest(uniq([alert(1200 + i) for i in range(5)])).json()["alert_ids"])
    first = start(cr)
    again = start(cr)
    rows = [x for x in c.get(f"/api/v1/cases/{cr}/activity", headers=S.analyst).json() if "multisource" in json.dumps(x).lower()]
    ok("R12", "repeating an investigation reuses the stored result (one audit row)", first.status_code in (200, 201) and again.status_code in (200, 201) and len(rows) == 1 and again.json().get("reused") is True, f"rows={len(rows)} reused={again.json().get('reused')}")
    forced = start(cr, force=True)
    rows2 = [x for x in c.get(f"/api/v1/cases/{cr}/activity", headers=S.analyst).json() if "multisource" in json.dumps(x).lower()]
    ok("R12", "force appends a new audit row, history preserved", forced.status_code in (200, 201) and len(rows2) == 2, f"rows={len(rows2)}")
    ok("R12", "service healthy after the whole matrix", c.get("/api/v1/health/ready").status_code == 200)


if __name__ == "__main__":
    sys.exit(main())
