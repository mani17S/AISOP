r"""
Convert a Suricata EVE JSON Lines file into aisop.evidence/1 envelopes (the body for POST /api/v1/cases/{id}/evidence/domain).

    .venv\Scripts\python.exe backend\scripts\eve_to_envelopes.py --eve <eve.json> --sensor <sensor name> --out <envelopes.json>

Reads the file only; writes only the output file; makes no network call. Prints counts: read, converted, skipped (unsupported event types), rejected.
The sensor name is required: flow_id is only unique per sensor, and records of one sensor and one flow count as one piece of evidence.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app.modules.correlation  # noqa: E402,F401  (import order: avoids a pre-existing circular import)
from app.modules.evidence_domains.adapters import EvidenceFormatError  # noqa: E402
from app.modules.evidence_domains.suricata_eve import eve_file_to_envelopes  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eve", required=True)
    ap.add_argument("--sensor", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-records", type=int, default=500)
    a = ap.parse_args()
    try:
        envelopes, counts = eve_file_to_envelopes(a.eve, sensor=a.sensor, max_records=a.max_records)
    except EvidenceFormatError as exc:
        print(f"refused: {exc}")
        return 2
    Path(a.out).write_text(json.dumps({"records": envelopes}, indent=1), encoding="utf-8")
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
