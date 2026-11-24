#!/usr/bin/env python3
"""
Software bill of materials and known-vulnerability check for AISOP (Python environment and the frontend lock file).

  1. Inventory: every installed Python distribution (importlib.metadata) and every package in frontend/package-lock.json, with version, declared licence
     and whether it is a development-only dependency.
  2. SBOM: written as CycloneDX 1.5 JSON (components with package URLs and declared licences).
  3. Vulnerabilities: each package and version is looked up in the public OSV database (https://api.osv.dev). Only the package name, ecosystem and version
     leave the machine; no source, no data, no credentials. If the service cannot be reached the script says so and reports NO vulnerability result
     (it never reports "clean" without having asked).

What this is NOT: a guarantee. OSV lists known, published advisories for the exact versions; it says nothing about unknown flaws, about whether a
vulnerable function is reachable from AISOP, or about transitive packages missing from the lock file. Licences are the declared metadata, not legal advice.

    .venv\\Scripts\\python.exe scripts\\supply_chain_check.py --out docs\\07_Security\\sbom
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
import uuid
from collections import Counter
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
OSV = "https://api.osv.dev/v1"
#: Installed Python packages that are tooling or test support, not part of what AISOP runs in production.
DEV_PYTHON = {"pip", "setuptools", "wheel", "black", "pytest", "pytest-asyncio", "pytest-cov", "coverage", "mypy", "mypy-extensions", "ruff", "pathspec",
              "platformdirs", "pluggy", "iniconfig", "pytokens"}


def python_components() -> list[dict[str, Any]]:
    out = []
    for dist in metadata.distributions():
        meta = dist.metadata
        name = meta["Name"] or ""
        if not name:
            continue
        lic = (meta.get("License-Expression") or meta.get("License") or "").strip().splitlines()[0][:80] if (meta.get("License-Expression") or meta.get("License")) else ""
        if not lic or len(lic) > 60:
            classifiers = [c.split("::")[-1].strip() for c in (meta.get_all("Classifier") or []) if c.startswith("License ::")]
            lic = ", ".join(classifiers) or "UNKNOWN"
        out.append({"ecosystem": "PyPI", "name": name, "version": meta["Version"], "license": lic, "dev": name.lower().replace("_", "-") in DEV_PYTHON})
    return sorted(out, key=lambda c: c["name"].lower())


def npm_components() -> list[dict[str, Any]]:
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text(encoding="utf-8"))
    out = []
    for path, info in lock.get("packages", {}).items():
        if not path.startswith("node_modules/") or not info.get("version"):
            continue
        name = path.split("node_modules/")[-1]
        out.append({"ecosystem": "npm", "name": name, "version": info["version"], "license": str(info.get("license") or "UNKNOWN"), "dev": bool(info.get("dev"))})
    return sorted(out, key=lambda c: c["name"].lower())


def purl(c: dict[str, Any]) -> str:
    eco = "pypi" if c["ecosystem"] == "PyPI" else "npm"
    name = re.sub(r"[_.]+", "-", c["name"]).lower() if eco == "pypi" else c["name"].replace("@", "%40")
    return f"pkg:{eco}/{name}@{c['version']}"


def cyclonedx(components: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "tools": [{"name": "aisop supply_chain_check.py"}],
                     "component": {"type": "application", "name": "AISOP", "version": "0.1.0"}},
        "components": [{"type": "library", "name": c["name"], "version": c["version"], "purl": purl(c),
                        "scope": "optional" if c["dev"] else "required", "licenses": [{"license": {"name": c["license"]}}]} for c in components],
    }


def osv_query(components: list[dict[str, Any]]) -> Optional[dict[str, list[str]]]:
    """purl -> list of advisory ids, or None if the service could not be reached."""
    found: dict[str, list[str]] = {}
    batch = 500
    for i in range(0, len(components), batch):
        chunk = components[i:i + batch]
        body = json.dumps({"queries": [{"package": {"name": c["name"], "ecosystem": c["ecosystem"]}, "version": c["version"]} for c in chunk]}).encode()
        req = urllib.request.Request(f"{OSV}/querybatch", data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                results = json.load(resp)["results"]
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
            return None
        for c, res in zip(chunk, results):
            ids = [v["id"] for v in res.get("vulns", [])]
            if ids:
                found[purl(c)] = ids
    return found


def advisory(vuln_id: str) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(f"{OSV}/vulns/{vuln_id}", timeout=30) as resp:
            v = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError):
        return {"id": vuln_id, "summary": "(details could not be fetched)"}
    severity = (v.get("database_specific") or {}).get("severity") or ""
    return {"id": vuln_id, "summary": (v.get("summary") or "")[:160], "severity": severity, "aliases": v.get("aliases", [])[:3]}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--out", type=Path, required=True, help="folder for the SBOM and the report")
    ap.add_argument("--offline", action="store_true", help="inventory and SBOM only; no vulnerability lookup")
    args = ap.parse_args(argv)

    components = python_components() + npm_components()
    prod = [c for c in components if not c["dev"]]
    licences = Counter(c["license"] for c in components)
    print(f"components: {len(components)} ({len(prod)} runtime, {len(components) - len(prod)} development-only); "
          f"Python {sum(c['ecosystem'] == 'PyPI' for c in components)}, npm {sum(c['ecosystem'] == 'npm' for c in components)}")
    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    (args.out / f"aisop-sbom-{stamp}.cdx.json").write_text(json.dumps(cyclonedx(components), indent=1), encoding="utf-8")

    report: dict[str, Any] = {"date": stamp, "components": len(components), "runtime": len(prod), "licences": dict(licences.most_common(30))}
    flagged = [c for c in components if re.search(r"GPL|AGPL|SSPL|CC-BY-NC|UNKNOWN", c["license"], re.I) and not re.search(r"LGPL|MPL", c["license"], re.I)]
    report["licence_review"] = [{"name": c["name"], "version": c["version"], "license": c["license"], "runtime": not c["dev"]} for c in flagged]
    if args.offline:
        report["vulnerabilities"] = "not checked (--offline)"
    else:
        found = osv_query(components)
        if found is None:
            report["vulnerabilities"] = "NOT CHECKED: the vulnerability service could not be reached"
            print("vulnerability check: NOT CHECKED (service unreachable)")
        else:
            by_purl = {purl(c): c for c in components}
            detail = {}
            for ids in found.values():
                for vid in ids:
                    detail.setdefault(vid, advisory(vid))
            report["vulnerabilities"] = [
                {"package": by_purl[p]["name"], "version": by_purl[p]["version"], "ecosystem": by_purl[p]["ecosystem"], "runtime": not by_purl[p]["dev"],
                 "advisories": [detail[v] for v in ids]} for p, ids in sorted(found.items())
            ]
            rt = [v for v in report["vulnerabilities"] if v["runtime"]]
            print(f"known advisories: {len(report['vulnerabilities'])} package(s) affected, {len(rt)} of them runtime")
            for v in report["vulnerabilities"]:
                print(f"  {'RUNTIME' if v['runtime'] else 'dev    '} {v['ecosystem']:4} {v['package']} {v['version']}: " + "; ".join(f"{a['id']} {a.get('severity', '')}".strip() for a in v["advisories"]))
    print(f"licences needing a look (copyleft or unknown, excluding LGPL and MPL): {len(flagged)}")
    for f in report["licence_review"][:12]:
        print(f"  {f['name']} {f['version']}: {f['license']} ({'runtime' if f['runtime'] else 'dev'})")
    (args.out / f"supply-chain-report-{stamp}.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
