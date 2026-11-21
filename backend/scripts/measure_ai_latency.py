r"""
Measure AI-on investigation latency on the demo stack (loopback only, synthetic data only). Prints and saves a json record.

    .venv\Scripts\python.exe backend\scripts\measure_ai_latency.py --base http://127.0.0.1:8010 --tokens <tokens file> --case <case id> --out <json> [--runs 2]

What it records, so no speed statement has to be guessed:
  * machine: GPU name and memory (nvidia-smi), Ollama version, model id, model size, quantization, advertised context length
  * Ollama's own view after load: size, size_vram (GPU share), expires_at (keep_alive), context length in use
  * COLD LOAD: the model is unloaded, then loaded with an empty prompt; Ollama reports load_duration
  * COLD investigation: unload, then one AI-on investigation (wall time includes the model load)
  * WARM investigations: the same request repeated with the model resident (wall time = generation + deterministic work)
  * per run: wall time, llm_status per incident, and prompt/completion tokens and Ollama's duration taken from the backend log line
The deterministic-only time (use_llm false) is measured the same way for comparison.
The tokens file is read for the analyst key only; it is never printed.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import time
from pathlib import Path

import httpx

OLLAMA = "http://127.0.0.1:11434"


def free_ram_gb() -> float | None:
    """Free physical memory in GB (Windows). Recorded beside every timing so memory pressure is visible, not guessed."""
    try:
        import ctypes

        class MEM(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                        ("tpf", ctypes.c_ulonglong), ("apf", ctypes.c_ulonglong), ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong), ("ext", ctypes.c_ulonglong)]
        m = MEM()
        m.length = ctypes.sizeof(MEM)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return round(m.avail / 1024 ** 3, 2)
    except Exception:
        return None


def unload(model: str) -> None:
    httpx.post(f"{OLLAMA}/api/generate", json={"model": model, "keep_alive": 0}, timeout=60)
    for _ in range(20):
        if not httpx.get(f"{OLLAMA}/api/ps").json().get("models"):
            return
        time.sleep(0.5)


def ps() -> dict:
    m = httpx.get(f"{OLLAMA}/api/ps").json().get("models") or []
    return m[0] if m else {}


def latest_backend_log(logdir: Path) -> Path | None:
    cands = sorted(glob.glob(str(logdir / "backend8010_*.err.log")), key=os.path.getmtime)
    return Path(cands[-1]) if cands else None


def usage_since(log: Path | None, offset: int) -> list[dict]:
    if not log or not log.exists():
        return []
    text = log.read_text(encoding="utf-8", errors="ignore")[offset:]
    text = re.sub(r"[[0-9;]*m", "", text)
    pat = re.compile(r"Ollama inference completed successfully.*?prompt_tokens['\"]?[=:]s*(d+).*?completion_tokens['\"]?[=:]s*(d+).*?finish_reason['\"]?[=:]s*['\"]?(w+).*?duration_ms['\"]?[=:]s*([d.]+)", re.S)
    return [{"prompt_tokens": int(m.group(1)), "completion_tokens": int(m.group(2)), "finish_reason": m.group(3), "ollama_duration_ms": float(m.group(4))} for m in pat.finditer(text)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--case", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", type=int, default=2)
    a = ap.parse_args()
    if not a.base.startswith("http://127.0.0.1"):
        print("refusing: loopback only")
        return 2
    key = next(l.split("=", 1)[1].strip() for l in Path(a.tokens).read_text(encoding="utf-8").splitlines() if l.startswith("analyst="))
    H = {"X-API-Key": key}
    logdir = Path(a.out).parent
    out: dict = {"measured_at": time.strftime("%Y-%m-%d %H:%M:%S"), "target": a.base, "case_id": a.case}

    gpu = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"], capture_output=True, text=True).stdout.strip()
    ver = httpx.get(f"{OLLAMA}/api/version").json().get("version")
    ready = httpx.get(f"{a.base}/api/v1/health/ready", timeout=30).json()
    model = (ready.get("checks", {}).get("llm_provider") or {}).get("model", "qwen2.5:1.5b")
    tags = {m["name"]: m for m in httpx.get(f"{OLLAMA}/api/tags").json()["models"]}
    out["machine"] = {"gpu": gpu or "none reported", "ollama_version": ver, "model": model, "model_size_bytes": tags.get(model, {}).get("size"),
                      "quantization": tags.get(model, {}).get("details", {}).get("quantization_level"), "parameter_size": tags.get(model, {}).get("details", {}).get("parameter_size"),
                      "advertised_context_length": tags.get(model, {}).get("details", {}).get("context_length"), "cpu_count": os.cpu_count()}
    out["free_ram_gb_at_start"] = free_ram_gb()
    out["keep_alive_env"] = os.environ.get("OLLAMA_KEEP_ALIVE", "(not set in this shell; backend setting OLLAMA_KEEP_ALIVE default applies, sent with every request)")

    # 1. pure cold load
    unload(model)
    t = time.perf_counter()
    r = httpx.post(f"{OLLAMA}/api/generate", json={"model": model, "prompt": "", "keep_alive": "5m"}, timeout=300).json()
    out["cold_load"] = {"wall_ms": round((time.perf_counter() - t) * 1000), "ollama_load_duration_ms": round(r.get("load_duration", 0) / 1e6)}
    p = ps()
    out["ollama_after_load"] = {"size_bytes": p.get("size"), "size_vram_bytes": p.get("size_vram"), "gpu_share_percent": round(100 * p.get("size_vram", 0) / p["size"]) if p.get("size") else None,
                                 "context_length": p.get("context_length"), "expires_at": p.get("expires_at")}

    base = f"{a.base}/api/v1/cases/{a.case}/investigations/multisource"
    log = latest_backend_log(logdir)

    def run(label: str, body: dict) -> dict:
        off = len(log.read_text(encoding="utf-8", errors="ignore")) if log and log.exists() else 0
        ram_before = free_ram_gb()
        t0 = time.perf_counter()
        r = httpx.post(base, json=body, headers=H, timeout=600)
        wall = time.perf_counter() - t0
        j = r.json() if r.status_code < 300 else {}
        states = [str(i.get("llm_status")) for i in j.get("incidents", [])]
        rec = {"label": label, "http_status": r.status_code, "wall_seconds": round(wall, 2), "llm_status_per_incident": states, "incidents": len(states), "free_ram_gb_before": ram_before, "free_ram_gb_after": free_ram_gb(),
               "llm_calls_logged": usage_since(log, off)}
        print(json.dumps(rec))
        return rec

    runs = []
    runs.append(run("deterministic only (use_llm false, force)", {"use_llm": False, "force": True}))
    unload(model)
    runs.append(run("AI on, COLD model (load included)", {"use_llm": True, "force": True}))
    for i in range(a.runs):
        runs.append(run(f"AI on, WARM model, run {i + 1}", {"use_llm": True, "force": True}))
    out["runs"] = runs
    p = ps()
    out["ollama_after_runs"] = {"expires_at": p.get("expires_at"), "context_length": p.get("context_length"), "size_vram_bytes": p.get("size_vram")}
    Path(a.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("saved", a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
