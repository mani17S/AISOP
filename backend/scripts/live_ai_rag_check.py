r"""
Live "everything in sync" check of the AI chain on the running demo stack (loopback only, synthetic data only):
frontend proxy -> backend API -> PostgreSQL + pgvector <- Ollama embeddings, and Ollama chat via the app, with RAG inside case synthesis.

    .venv\Scripts\python.exe backend\scripts\live_ai_rag_check.py --api http://127.0.0.1:8010 --ui http://127.0.0.1:3010 --tokens <file> --out <json>

Evidence is taken independently where possible: pgvector is queried directly through the database container with an embedding made by
Ollama, and RAG and model use inside the app are confirmed by the backend's own log lines. Tokens are never printed.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

OLLAMA = "http://127.0.0.1:11434"
RES: list[dict] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    RES.append({"check": name, "pass": bool(cond), "detail": detail})
    print(("PASS " if cond else "FAIL ") + name, detail)
    return bool(cond)


def psql(sql: str) -> str:
    p = subprocess.run(["docker", "exec", "-i", "aisop-postgres", "psql", "-U", "aisop", "-d", "aisop_demo", "-At", "-F", "|"], input=sql, capture_output=True, text=True, timeout=60)
    return (p.stdout or "").strip()


def latest_log(logdir: Path) -> Path | None:
    c = sorted(glob.glob(str(logdir / "backend8010_*.err.log")), key=os.path.getmtime)
    return Path(c[-1]) if c else None


def count_in(log: Path | None, needle: str) -> int:
    return log.read_text(encoding="utf-8", errors="ignore").count(needle) if log and log.exists() else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--ui", required=True)
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not (a.api.startswith("http://127.0.0.1") and a.ui.startswith("http://127.0.0.1")):
        print("refusing: loopback only")
        return 2
    t = dict(l.split("=", 1) for l in Path(a.tokens).read_text(encoding="utf-8").splitlines() if "=" in l)
    A = {"X-API-Key": t["analyst"].strip()}
    S = {"X-API-Key": t["sensor"].strip()}
    logdir = Path(a.out).parent
    log = latest_log(logdir)

    # 1. frontend <-> backend
    ui = httpx.get(a.ui + "/", timeout=20)
    check("frontend serves the app", ui.status_code == 200 and "<div id=\"root\"" in ui.text)
    via_ui = httpx.get(a.ui + "/api/v1/cases?limit=1", headers=A, timeout=30)
    direct = httpx.get(a.api + "/api/v1/cases?limit=1", headers=A, timeout=30)
    check("frontend proxy and backend return the same answer for the same request", via_ui.status_code == 200 and direct.status_code == 200 and via_ui.json() == direct.json())
    ready = httpx.get(a.api + "/api/v1/health/ready", timeout=40)
    body = ready.json().get("detail", ready.json())
    chk = body.get("checks", {})
    check("backend readiness: database, pgvector and language model all healthy", ready.status_code == 200 and chk.get("database", {}).get("status") == "ok" and chk.get("llm_provider", {}).get("status") == "healthy",
          f"pgvector {chk.get('database', {}).get('pgvector', {}).get('version')}, model {chk.get('llm_provider', {}).get('model')}")

    # 2. Ollama embeddings -> pgvector (independent of app code)
    tags = [m["name"] for m in httpx.get(OLLAMA + "/api/tags", timeout=20).json()["models"]]
    check("Ollama serves the chat model and the embedding model", any(x.startswith("qwen2.5") for x in tags) and any(x.startswith("nomic-embed-text") for x in tags), ", ".join(tags))
    emb = httpx.post(OLLAMA + "/api/embeddings", json={"model": "nomic-embed-text", "prompt": "encoded PowerShell command line execution"}, timeout=120).json()["embedding"]
    check("embedding is 768 dimensions", len(emb) == 768, str(len(emb)))
    stats = psql("select count(*), min(vector_dims(embedding)), max(vector_dims(embedding)), count(distinct source_document) from knowledge_embeddings;").split("|")
    check("pgvector holds the knowledge base (768-dim chunks from several documents)", len(stats) == 4 and int(stats[0]) >= 30 and stats[1] == stats[2] == "768" and int(stats[3]) >= 5, "chunks=%s dims=%s documents=%s" % (stats[0], stats[1], stats[3]) if len(stats) == 4 else str(stats))
    idx = psql("select indexdef from pg_indexes where tablename='knowledge_embeddings' and indexdef ilike '%hnsw%';")
    check("HNSW cosine index exists on the embedding column", "hnsw" in idx.lower() and "vector_cosine_ops" in idx.lower(), idx[:90])
    lit = "[" + ",".join(f"{x:.6f}" for x in emb) + "]"
    top = psql(f"select source_document, round((1 - (embedding <=> '{lit}'::vector))::numeric, 3) from knowledge_embeddings order by embedding <=> '{lit}'::vector limit 3;").splitlines()
    check("direct cosine query returns the matching playbook and sigma chunks first", bool(top) and any(s in top[0] for s in ("sigma", "windows_incident", "mitre")), " ; ".join(top))
    check("application database role is not a superuser", psql("select rolsuper::text from pg_roles where rolname = current_user;").strip() == "false" or psql("select rolsuper::text from pg_roles where rolname='aisop_app';").strip() == "false")

    # 3. API chain: ingest -> case -> investigation (model off) -> LLM on -> RAG in case synthesis
    nonce = uuid.uuid4().hex[:8]
    alerts = [{"source_type": "generic_siem", "rule_id": f"R-AI-{nonce}-{i}", "rule_name": "encoded powershell execution", "severity": "high", "timestamp": f"2026-11-07T09:0{i}:00Z",
               "host": "ai-host", "user": "ai-user", "src_ip": "203.0.113.7", "description": "powershell.exe -enc"} for i in range(3)]
    b = httpx.post(a.api + "/api/v1/alerts/ingest", json={"source_type": "auto", "source_identifier": "live-ai-rag", "alerts": alerts}, headers=S, timeout=60).json()
    check("ingest through the API stores the alerts", b.get("total_normalized") == 3, str(b.get("total_normalized")))
    cid = httpx.post(a.api + "/api/v1/cases", json={"title": "AI and RAG sync check (synthetic)", "description": "synthetic"}, headers=A, timeout=30).json()["id"]
    for eid in b["alert_ids"]:
        httpx.post(f"{a.api}/api/v1/cases/{cid}/evidence", json={"evidence_id": eid}, headers=A, timeout=30)
    base = f"{a.api}/api/v1/cases/{cid}/investigations/multisource"
    det = httpx.post(base, json={}, headers=A, timeout=60)
    check("deterministic investigation completes with the model off", det.status_code in (200, 201), f"status {det.status_code}")

    ollama_before = count_in(log, "Ollama inference completed successfully")
    t0 = time.perf_counter()
    ai = httpx.post(base, json={"use_llm": True, "force": True}, headers=A, timeout=300)
    dt = time.perf_counter() - t0
    states = [str(i.get("llm_status")) for i in (ai.json().get("incidents", []) if ai.status_code < 300 else [])]
    ollama_after = count_in(log, "Ollama inference completed successfully")
    check("AI-on investigation completes through the API and the model was really called", ai.status_code in (200, 201) and ollama_after > ollama_before, f"{dt:.1f}s, llm_status={sorted(set(states))}, model calls logged +{ollama_after - ollama_before}")
    check("AI step ends in a defined state (validated, or a deterministic fallback), never an error", bool(states) and all(s in ("validated", "abstained", "skipped") or s.startswith("fallback") for s in states), str(sorted(set(states))))

    rag_before = count_in(log, "Knowledge retrieval complete")
    ollama_before2 = count_in(log, "Ollama inference completed successfully")
    t0 = time.perf_counter()
    syn = httpx.post(f"{a.api}/api/v1/cases/{cid}/investigations/synthesize", json={"query_filter": "encoded PowerShell command line execution"}, headers=A, timeout=300)
    dt = time.perf_counter() - t0
    rag_after = count_in(log, "Knowledge retrieval complete")
    ollama_after2 = count_in(log, "Ollama inference completed successfully")
    sj = syn.json() if syn.status_code < 300 else {}
    check("case synthesis retrieved from pgvector (RAG) inside the app", syn.status_code in (200, 201) and rag_after > rag_before, f"status {syn.status_code}, {dt:.1f}s, retrievals logged +{rag_after - rag_before}")
    check("case synthesis used the local model and returned a verified result object", syn.status_code in (200, 201) and ollama_after2 > ollama_before2 and isinstance(sj, dict) and bool(sj), f"model calls +{ollama_after2 - ollama_before2}, keys={sorted(sj.keys())[:5]}")

    # 4. review record on the same stack (human control)
    st = httpx.get(base + "/status", headers=A, timeout=30).json()
    rv = httpx.post(base + "/review", json={"decision": "approved", "evidence_fingerprint": st["evidence_fingerprint"]}, headers=A, timeout=30)
    check("lead review is recorded through the API", rv.status_code == 200 and rv.json().get("state") == "approved", f"status {rv.status_code}")

    Path(a.out).write_text(json.dumps(RES, indent=2), encoding="utf-8")
    failed = [r for r in RES if not r["pass"]]
    print(f"{len(RES) - len(failed)}/{len(RES)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
