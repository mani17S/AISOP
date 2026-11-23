#!/usr/bin/env python3
"""
Send a small, clearly labelled burst of attack-like requests at an AISOP server, so the Security page has something to show
during a demonstration:

    .venv\\Scripts\\python.exe backend\\scripts\\demo_probe_traffic.py --base http://127.0.0.1:8010

Only use it against a server you own. It sends requests that the server refuses (paths that do not exist, a rejected API key,
a wrong HTTP method) and carries no payload, no real credential and no exploit. Every request identifies itself in the
User-Agent as a demonstration, so what the Security page shows is never mistaken for a real attack.
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request

AGENT = "aisop-demo-probe/1.0 (demonstration traffic, not a real attack)"
FAKE_KEY = "aisop_live_" + "0" * 16 + "_" + "ab" * 32  # well formed but unknown: never valid anywhere

PROBES = (
    [("GET", p, None) for p in ("/.env", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin", "/actuator/health", "/server-status")]
    + [("GET", "/api/v1/cases", FAKE_KEY)] * 8  # rejected keys, then a lockout
    + [("GET", "/api/v1/cases", None)] * 3  # no credential at all
    + [("DELETE", "/api/v1/cases", None), ("PUT", "/api/v1/alerts/ingest", None)]  # methods the API does not implement
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="server you own, for example http://127.0.0.1:8010")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    print(f"Sending {len(PROBES)} labelled demonstration requests to {base}")
    codes: dict[int, int] = {}
    for method, path, key in PROBES:
        headers = {"User-Agent": AGENT}
        if key:
            headers["X-API-Key"] = key
        request = urllib.request.Request(base + path, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                code = response.status
        except urllib.error.HTTPError as exc:
            code = exc.code
        except OSError as exc:
            print(f"Could not reach the server: {type(exc).__name__}", file=sys.stderr)
            return 1
        codes[code] = codes.get(code, 0) + 1
    print("Responses:", ", ".join(f"{c} x{n}" for c, n in sorted(codes.items())))
    print("The Security page updates within about 10 seconds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
