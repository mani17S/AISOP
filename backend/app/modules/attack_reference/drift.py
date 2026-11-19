"""
Report-only drift classification of coded ATT&CK mappings against the pinned local catalogue.

Input: a sequence of ``MappingOccurrence`` records describing identifiers that application code carries
(an inventory is produced elsewhere, by reading source, never by importing or changing it).
Output: classification rows and a deterministic Markdown rendering. Nothing here changes a mapping, a label, a
severity or a record, substitutes a successor, writes a catalogue or persists anything.

A classification describes taxonomy validity and label drift only. It is not an incident severity and it does not
say a technique occurred. Vendor-supplied tags can be checked for existence here; the catalogue never asserts that a
vendor's claim is evidentially correct.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Optional, Sequence

from pydantic import BaseModel, ConfigDict

from app.modules.attack_reference.models import (
    AttackReferenceCatalogue,
    CatalogueMeta,
    ReferenceStatus,
    TACTIC_ID_RE,
    TacticRecord,
    TechniqueRecord,
)


class DriftClass(StrEnum):
    CURRENT_VALID = "CURRENT_VALID"
    STALE_NAME = "STALE_NAME"
    STALE_TACTIC_LABEL = "STALE_TACTIC_LABEL"
    REVOKED_WITH_SUCCESSOR = "REVOKED_WITH_SUCCESSOR"
    DEPRECATED = "DEPRECATED"
    UNKNOWN_ID = "UNKNOWN_ID"
    INVALID_ID_SYNTAX = "INVALID_ID_SYNTAX"
    WRONG_DOMAIN = "WRONG_DOMAIN"
    UNRESOLVED = "UNRESOLVED"


class OccurrenceKind(StrEnum):
    RULE_TABLE = "rule_table"
    ADAPTER_DEFAULT = "adapter_default"
    GUARDRAIL_REFERENCE = "guardrail_reference"
    PROMPT_REFERENCE = "prompt_reference"
    DEMO_DATA = "demo_data"
    OTHER_LITERAL = "other_literal"


_FROZEN = ConfigDict(frozen=True, extra="forbid")


class MappingOccurrence(BaseModel):
    """One coded identifier. ``technique_id`` is deliberately an unvalidated string: bad ids must be reportable."""

    model_config = _FROZEN

    source_file: str
    line: int
    symbol: str
    kind: OccurrenceKind
    technique_id: str
    label: Optional[str] = None
    #: tactic labels exactly as coded: slugs, display names or TA ids
    tactic_labels: tuple[str, ...] = ()


class DriftRow(BaseModel):
    model_config = _FROZEN

    occurrence: MappingOccurrence
    status: ReferenceStatus
    classification: DriftClass
    canonical_name: Optional[str] = None
    lifecycle: Optional[str] = None
    tactic_ids: tuple[str, ...] = ()
    tactic_names: tuple[str, ...] = ()
    parent_id: Optional[str] = None
    successors: tuple[str, ...] = ()
    name_drift: bool = False
    tactic_label_drift: bool = False
    notes: tuple[str, ...] = ()


def _resolve_tactic(cat: AttackReferenceCatalogue, label: str) -> Optional[TacticRecord]:
    if TACTIC_ID_RE.fullmatch(label):
        return cat.lookup_tactic(label)
    by_short = cat.tactic_by_shortname(label)
    if by_short is not None:
        return by_short
    for tactic in cat.tactics():
        if tactic.name == label:
            return tactic
    return None


def _accepted_names(cat: AttackReferenceCatalogue, rec: TechniqueRecord) -> set[str]:
    accepted = {rec.name}
    parent = cat.parent_of(rec.attack_id)
    if parent is not None:
        accepted.add(f"{parent.name}: {rec.name}")   # the 'Parent: Sub-technique' display convention
    return accepted


def classify_occurrence(cat: AttackReferenceCatalogue, occ: MappingOccurrence) -> DriftRow:
    lookup = cat.lookup_technique(occ.technique_id)
    status = lookup.status
    if status == ReferenceStatus.INVALID_SYNTAX:
        return DriftRow(occurrence=occ, status=status, classification=DriftClass.INVALID_ID_SYNTAX)
    if status == ReferenceStatus.WRONG_DOMAIN:
        return DriftRow(occurrence=occ, status=status, classification=DriftClass.WRONG_DOMAIN)
    if status == ReferenceStatus.UNKNOWN or lookup.record is None:
        return DriftRow(occurrence=occ, status=status, classification=DriftClass.UNKNOWN_ID)

    rec = lookup.record
    notes: list[str] = []
    name_drift = occ.label is not None and occ.label not in _accepted_names(cat, rec)
    if name_drift:
        notes.append("coded name differs from the official name")

    tactic_drift = False
    for label in occ.tactic_labels:
        resolved = _resolve_tactic(cat, label)
        if resolved is None:
            tactic_drift = True
            notes.append(f"tactic label {label!r} does not resolve to a current tactic")
        elif resolved.tactic_id not in rec.tactic_ids:
            notes.append(f"tactic {resolved.tactic_id} is not associated with this technique in the pinned release")
    tactic_names = tuple(cat.lookup_tactic(t).name for t in rec.tactic_ids if cat.lookup_tactic(t) is not None)

    if rec.revoked:
        if rec.replaced_by:
            cls = DriftClass.REVOKED_WITH_SUCCESSOR
            if rec.unresolved_successor_refs:
                notes.append("some revoked-by targets do not resolve to an Enterprise technique")
        else:
            cls = DriftClass.UNRESOLVED
            notes.append("revoked with no explicit successor in the pinned release")
        if rec.deprecated:
            notes.append("also marked deprecated")
    elif rec.deprecated:
        cls = DriftClass.DEPRECATED
    elif name_drift:
        cls = DriftClass.STALE_NAME
    elif tactic_drift:
        cls = DriftClass.STALE_TACTIC_LABEL
    else:
        cls = DriftClass.CURRENT_VALID

    return DriftRow(
        occurrence=occ, status=status, classification=cls, canonical_name=rec.name, lifecycle=rec.lifecycle.value,
        tactic_ids=rec.tactic_ids, tactic_names=tactic_names, parent_id=rec.parent_id, successors=rec.replaced_by,
        name_drift=name_drift, tactic_label_drift=tactic_drift, notes=tuple(notes),
    )


def classify_all(cat: AttackReferenceCatalogue, occurrences: Sequence[MappingOccurrence]) -> tuple[DriftRow, ...]:
    rows = [classify_occurrence(cat, o) for o in occurrences]
    rows.sort(key=lambda r: (r.occurrence.source_file, r.occurrence.line, r.occurrence.symbol, r.occurrence.technique_id))
    return tuple(rows)


def summarize(rows: Sequence[DriftRow]) -> dict[str, int]:
    out: dict[str, int] = {c.value: 0 for c in DriftClass}
    for r in rows:
        out[r.classification.value] += 1
    out["name_drift_flags"] = sum(1 for r in rows if r.name_drift)
    out["tactic_label_drift_flags"] = sum(1 for r in rows if r.tactic_label_drift)
    out["occurrences"] = len(rows)
    out["distinct_ids"] = len({r.occurrence.technique_id for r in rows})
    return out


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _join(values: Sequence[str]) -> str:
    return ", ".join(values) if values else "-"


def render_drift_markdown(
    rows: Sequence[DriftRow],
    meta: CatalogueMeta,
    *,
    title: str = "ATT&CK mapping drift report (report-only)",
    sections_after: Sequence[str] = (),
    generated_at: Optional[str] = None,
) -> str:
    """
    Deterministic for identical rows and catalogue metadata. A timestamp, when given, appears only in the final
    metadata block, which is excluded from any comparison of substantive content.
    """
    totals = summarize(rows)
    lines: list[str] = [f"# {title}", ""]
    lines += [
        "Report-only: no mapping, label, severity or record was changed. A classification is taxonomy validity and "
        "label drift only; it is not incident severity and does not show that a technique occurred.",
        "",
        "## Reference catalogue",
        "| Field | Value |", "|---|---|",
        f"| Release | {_cell(meta.release_version)} ({_cell(meta.collection_name)}) |",
        f"| Domain | {_cell(meta.domain)} |",
        f"| Source SHA-256 (verified before parsing) | `{meta.sha256}` |",
        f"| Source size | {meta.size_bytes} bytes |",
        f"| Loader | {_cell(meta.loader_version)} |",
        f"| STIX objects in file | {meta.object_count} |",
        f"| Enterprise techniques / sub-techniques | {meta.technique_count} |",
        f"| Enterprise tactics | {meta.tactic_count} |",
        f"| Revoked / deprecated | {meta.revoked_count} / {meta.deprecated_count} |",
        f"| Resolved / unresolved revoked-by pointers | {meta.replacement_relationship_count} / {meta.unresolved_replacement_count} |",
        f"| Non-Enterprise techniques excluded | {meta.excluded_other_domain_technique_count} |",
        "",
        "Pydantic validated AISOP's minimal projection. This is not a complete STIX 2.1 schema validation.",
        "",
        "## Totals by classification (one primary class per occurrence)",
        "| Classification | Occurrences |", "|---|---|",
    ]
    for c in DriftClass:
        lines.append(f"| {c.value} | {totals[c.value]} |")
    lines += [
        f"| **Total occurrences** | {totals['occurrences']} |",
        f"| Distinct identifiers | {totals['distinct_ids']} |",
        f"| Name drift flags (independent of the primary class) | {totals['name_drift_flags']} |",
        f"| Tactic-label drift flags (independent of the primary class) | {totals['tactic_label_drift_flags']} |",
        "",
    ]

    by_id: dict[str, list[DriftRow]] = {}
    for r in rows:
        by_id.setdefault(r.occurrence.technique_id, []).append(r)
    lines += [
        "## Distinct identifiers",
        "| ID | Primary class(es) | Official name | State | Tactics (current) | Parent | Explicit successors | Occurrences | Name drift | Tactic drift |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for tid in sorted(by_id):
        group = by_id[tid]
        first = group[0]
        classes = sorted({g.classification.value for g in group})
        tactics = [f"{i} {n}" for i, n in zip(first.tactic_ids, first.tactic_names)]
        lines.append(
            f"| {_cell(tid)} | {_cell(_join(classes))} | {_cell(first.canonical_name)} | {_cell(first.lifecycle or first.status.value)} | "
            f"{_cell(_join(tactics))} | {_cell(first.parent_id)} | {_cell(_join(first.successors))} | {len(group)} | "
            f"{'yes' if any(g.name_drift for g in group) else 'no'} | {'yes' if any(g.tactic_label_drift for g in group) else 'no'} |"
        )
    lines += [
        "",
        "## Occurrences",
        "| Source | Line | Symbol | Kind | ID | Coded name | Coded tactic labels | Class | Official name | State | Current tactics | Successors | Notes |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        o = r.occurrence
        tactics = [f"{i} {n}" for i, n in zip(r.tactic_ids, r.tactic_names)]
        lines.append(
            f"| {_cell(o.source_file)} | {o.line} | {_cell(o.symbol)} | {o.kind.value} | {_cell(o.technique_id)} | {_cell(o.label)} | "
            f"{_cell(_join(o.tactic_labels))} | {r.classification.value} | {_cell(r.canonical_name)} | {_cell(r.lifecycle or r.status.value)} | "
            f"{_cell(_join(tactics))} | {_cell(_join(r.successors))} | {_cell('; '.join(r.notes))} |"
        )
    lines.append("")
    for section in sections_after:
        lines += [section.rstrip(), ""]
    if generated_at is not None:
        lines += ["## Run metadata (excluded from deterministic comparison)", f"- Generated at: {_cell(generated_at)}", ""]
    return "\n".join(lines)
