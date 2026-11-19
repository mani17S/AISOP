"""
AISOP investigation ledger (Stage 3C-R vertical slice, ADR-009).

An append-only, hash-chained record of what the workflow did and decided, step by step. Each
entry commits to the previous entry's hash, so any later edit, deletion or reordering is
detectable by ``verify``. Entries hold fixed-shape facts (counts, verdicts, reason codes, hashes),
never raw evidence text or credentials.

AiSOC concept adapted: the investigation ledger (append-only record of agent steps). AiSOC
enforces append-only in the database; AISOP additionally chains the hashes so tampering is
detectable without trusting the store (the roadmap's hash-chained audit item).

Status: IMPLEMENTED as an in-memory/exportable chain with verification. PARTIAL: it is not yet
persisted in the case audit table; ``workflow_audit_details`` produces a fixed-shape dictionary
that fits the existing ``case_audit_events.details`` JSON for that future integration.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

GENESIS_HASH = "0" * 64


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    step: str
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str


def _hash(prev_hash: str, seq: int, step: str, details: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + _canon({"seq": seq, "step": step, "details": details})).encode("utf-8")).hexdigest()


class Ledger:
    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    @property
    def head(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    def append(self, step: str, details: dict[str, Any]) -> LedgerEntry:
        seq = len(self._entries)
        clean = json.loads(_canon(details))  # JSON-safe copy; also freezes the committed content
        entry = LedgerEntry(seq=seq, step=step, details=clean, prev_hash=self.head, entry_hash=_hash(self.head, seq, step, clean))
        self._entries.append(entry)
        return entry

    def export(self) -> list[dict[str, Any]]:
        return [
            {"seq": e.seq, "step": e.step, "details": e.details, "prev_hash": e.prev_hash, "entry_hash": e.entry_hash}
            for e in self._entries
        ]


def verify_chain(exported: list[dict[str, Any]], expected_head: str | None = None) -> tuple[bool, int | None]:
    """
    Recompute the chain; returns (ok, index of the first bad entry or None).

    Guarantees: an edit of any entry, a deletion or insertion before the last entry, or a reordering is
    detected (the first affected index is returned). NOT guaranteed: a chain cut off at the tail, or a chain
    rewritten consistently end to end, still verifies unless the caller also holds the head hash from a trusted
    place and passes it as ``expected_head`` (a mismatch returns ``(False, len(exported))``). The ledger is
    tamper-evident relative to a trusted head; it is not immutable storage.
    """
    prev = GENESIS_HASH
    if not isinstance(exported, list):
        return False, 0
    for i, e in enumerate(exported):
        if not isinstance(e, dict) or not isinstance(e.get("details", {}), dict) or not isinstance(e.get("step", ""), str):
            return False, i
        if e.get("seq") != i or e.get("prev_hash") != prev:
            return False, i
        if _hash(prev, i, e.get("step", ""), e.get("details", {})) != e.get("entry_hash"):
            return False, i
        prev = e["entry_hash"]
    if expected_head is not None and prev != expected_head:
        return False, len(exported)
    return True, None


__all__ = ["GENESIS_HASH", "Ledger", "LedgerEntry", "verify_chain"]
