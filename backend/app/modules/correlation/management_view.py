"""
Management view of one multi-source investigation: what a security leader needs to read in one screen, derived only from facts the pipeline already
holds. Pure and deterministic: no model, no network, no database, no new evidence.

It answers five questions: how much reading did this save (records, evidence units, incidents), what is the verdict mix, which kinds of telemetry
are present in THIS evidence and which are absent (the logging blind spots of what was supplied), what to collect next to raise confidence, and how
trustworthy the data is (rejections, assumed times, ledger).

What it is not: a measure of detection coverage, risk or attack likelihood. It describes the evidence that was supplied, not the company's whole
logging estate, and it never recommends a response action.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

_DOMAIN_BY_SOURCE = {
    "sysmon": "endpoint", "edr_malware": "endpoint", "windows_security": "identity", "linux_auth": "identity",
    "firewall_ids": "network", "cloud_audit": "cloud", "email_phishing": "email",
}
_DOMAIN_BY_EVIDENCE_PREFIX = {"identity": "identity", "cloud": "cloud", "network": "network", "email": "email", "forensic": "endpoint", "endpoint": "endpoint"}
ALL_DOMAINS = ("endpoint", "network", "identity", "cloud", "email")
COLLECT = {
    "endpoint": "process, file and registry telemetry from an EDR or Sysmon",
    "network": "DNS, proxy and firewall flow logs",
    "identity": "sign-in and authentication logs",
    "cloud": "cloud audit logs (for example CloudTrail or Entra ID)",
    "email": "mail gateway or phishing-report logs",
}
#: What to do about each reason that holds an incident at LIMITED. Disclosure-only codes (duplicates collapsed, irrelevant evidence excluded) are left out.
NEXT_STEP = {
    "UNCORROBORATED_QUESTION": "Add a record from a different source that shares a specific artefact (file hash, domain, public IP address or file path) with the key event.",
    "SAME_VANTAGE_ONLY": "All the corroboration came from one source at one host. Add evidence from a second source type or a second host.",
    "REPEATED_OBSERVATION_ONLY": "The same observation was repeated. Add a different kind of observation, not more copies.",
    "WEAK_LINK_ONLY": "Records are related only by host, user or an internal address. Add evidence that shares a specific artefact.",
    "CONTRADICTORY_EVIDENCE": "Sources disagree. Find a record that shows which statement is correct before relying on either.",
    "EVIDENCE_TRUNCATED": "Some evidence was left out by the size limit. Narrow the time window or the hosts and run it again.",
    "MISSING_REQUIRED_FIELD": "The key event lacks a required detail. Supply it in the source record and ingest it again.",
    "PROVENANCE_UNVERIFIED_ALL": "No record has a well-formed raw-evidence digest. Re-export the records so each keeps its original bytes.",
    "ROOT_PROVENANCE_MISSING": "The key event has no well-formed raw-evidence digest. Re-export that record.",
    "ROOT_ABSENT": "The event the investigation is anchored on is not in the evidence. Add it or choose another anchor.",
    "TEMPORAL_ANOMALY": "Some records are dated outside the window or in the future. Check the source clocks.",
    "NO_RELEVANT_EVIDENCE": "None of the evidence is relevant to the question. Supply evidence for the right host and time window.",
    "NO_EVIDENCE": "No usable evidence was supplied.",
}
CAVEAT = ("This describes the evidence that was supplied to this investigation, not the company's whole logging, and it is not a measure of detection "
          "coverage or risk. A verdict says whether the evidence is adequate for an investigation; the analyst decides what it means.")


def _domain(event: Any) -> str | None:
    prefix = (getattr(event, "evidence_type", None) or "").split(".")[0]
    if prefix in _DOMAIN_BY_EVIDENCE_PREFIX:
        return _DOMAIN_BY_EVIDENCE_PREFIX[prefix]
    return _DOMAIN_BY_SOURCE.get(getattr(event, "source_type", ""))


def management_view(result: Any) -> dict[str, Any]:
    events = list(result.normalization.events)
    records, units, incidents = len(events), len(result.correlation.clusters), len(result.incidents)
    verdicts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    for analysis in result.incidents:
        verdicts[analysis.assessment.verdict.value] += 1
        for code in set(analysis.assessment.reason_codes):
            reasons[str(code)] += 1
    present = sorted({d for d in (_domain(e) for e in events) if d})
    absent = [d for d in ALL_DOMAINS if d not in present]
    next_steps = [
        {"reason_code": code, "incidents": n, "action": NEXT_STEP[code]}
        for code, n in sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0])) if code in NEXT_STEP
    ][:5]
    return {
        "workload": {
            "records": records, "evidence_units": units, "incidents": incidents,
            "fewer_items_pct": round(100.0 * (1 - incidents / records), 1) if records and incidents else None,
        },
        "verdicts": {k: verdicts.get(k, 0) for k in ("sufficient", "limited", "insufficient")},
        "telemetry": {"present": present, "absent": absent, "collect": {d: COLLECT[d] for d in absent}},
        "next_steps": next_steps,
        "data_quality": {
            "records_rejected": len(result.normalization.rejected),
            "rejected_reasons": dict(Counter(r.reason for r in result.normalization.rejected)),
            "records_with_assumed_time": sum(1 for e in events if getattr(e, "time_assumed_utc", False)),
        },
        "integrity": {"ledger_verified": bool(result.ledger_ok)},
        "caveat": CAVEAT,
    }
