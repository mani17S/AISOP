#!/usr/bin/env python3
"""
Create a Cloudflare API token that can ONLY run Workers AI (inference), for the hosted AISOP service.

Run it yourself (it makes a new credential, so it is deliberately not something an assistant runs for you):

    .venv\\Scripts\\python.exe backend\\scripts\\create_workers_ai_token.py

It uses the deployment token in D:\\AISOP-Control\\cloudflare_api_token.txt only to create the new one, writes the new token to
D:\\AISOP-Control\\cloudflare_workers_ai_token.txt (outside the repository) and never prints it. The new token expires on the date
given (default 2027-01-10), is limited to the Workers AI Read and Write permissions on this account, and is then checked: it must be
able to run an embedding and must be REFUSED for Pages and for token management. Paste its value into Render as
CLOUDFLARE_AI_API_TOKEN. Never put the deployment token on the server.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ACCOUNT = "5762c110d0baecbf06186b76d6485892"
CONTROL = Path(r"D:\AISOP-Control")
API = "https://api.cloudflare.com/client/v4"
# Workers AI Read and Workers AI Write permission groups, as listed by the account's /tokens/permission_groups.
PERMISSION_GROUPS = ("a92d2450e05d4e7bb7d0a64968f83d11", "bacc64e0f6c34fc0883a1223f938a104")


def call(method: str, url: str, token: str, body: dict | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(
        url, json.dumps(body).encode() if body is not None else None,
        {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.load(exc)
        except ValueError:
            return exc.code, {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--expires", default="2027-01-10", help="expiry date YYYY-MM-DD (end of that day, UTC)")
    args = ap.parse_args()
    deployment = (CONTROL / "cloudflare_api_token.txt").read_text().strip()
    body = {
        "name": "aisop-hosted-workers-ai (inference only)",
        "expires_on": f"{args.expires}T23:59:59Z",
        "policies": [{
            "effect": "allow",
            "resources": {f"com.cloudflare.api.account.{ACCOUNT}": "*"},
            "permission_groups": [{"id": g} for g in PERMISSION_GROUPS],
        }],
    }
    status, data = call("POST", f"{API}/accounts/{ACCOUNT}/tokens", deployment, body)
    result = data.get("result") or {}
    if status != 200 or not result.get("value"):
        print(f"Could not create the token (HTTP {status}): {[e.get('message') for e in data.get('errors', [])][:2]}", file=sys.stderr)
        return 1
    new_token = result["value"]
    (CONTROL / "cloudflare_workers_ai_token.txt").write_text(new_token + "\n")
    print(f"Created token id {result.get('id')}, expires {result.get('expires_on')}. Saved to {CONTROL / 'cloudflare_workers_ai_token.txt'}.")

    ok, _ = call("POST", f"{API}/accounts/{ACCOUNT}/ai/run/@cf/baai/bge-base-en-v1.5", new_token, {"text": ["hello"]})
    pages, _ = call("GET", f"{API}/accounts/{ACCOUNT}/pages/projects", new_token)
    tokens, _ = call("GET", f"{API}/accounts/{ACCOUNT}/tokens", new_token)
    print(f"Check: can run an embedding: {'YES' if ok == 200 else 'NO (HTTP %s)' % ok}")
    print(f"Check: refused for Pages: {'YES' if pages in (401, 403) else 'NO (HTTP %s), the token is broader than intended' % pages}")
    print(f"Check: refused for token management: {'YES' if tokens in (401, 403) else 'NO (HTTP %s), the token is broader than intended' % tokens}")
    return 0 if ok == 200 and pages in (401, 403) and tokens in (401, 403) else 2


if __name__ == "__main__":
    raise SystemExit(main())
