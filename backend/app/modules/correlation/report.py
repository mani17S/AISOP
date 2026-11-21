"""
AISOP analyst-facing investigation report renderer (Stage 3C-R vertical slice, ADR-009).

Renders deterministic Markdown for one incident (or for an abstention when no incident could be
formed). The report is complete without an LLM; when an LLM investigation was requested its
verified claims are appended with their grounding status. The evidence-sufficiency verdict and
every limitation are printed in plain language in the report body, not only in metadata.

AiSOC concept adapted: the deterministic correlation narrative that is useful without an LLM
(``services/fusion/app/services/narrative.py``). No timestamps of generation, no randomness: the
same input produces byte-identical output.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.schemas.report_terminology import (
    CLAIMS_VALIDATED_DEFINITION,
    MODEL_REPORTED_CONFIDENCE_DEFINITION,
)
from app.schemas.sufficiency import SufficiencyVerdict

if TYPE_CHECKING:  # pragma: no cover
    from app.modules.correlation.workflow import IncidentAnalysis, WorkflowResult

REASON_EXPLANATIONS = {
    "NO_EVIDENCE": "No usable evidence was available.",
    "NO_RELEVANT_EVIDENCE": "Evidence exists but none of it is relevant to the investigation question (time window / host / entity relation).",
    "EVIDENCE_TRUNCATED": "Some evidence was omitted by the size budget; conclusions may be incomplete.",
    "ROOT_ABSENT": "The event the investigation was anchored on is not part of the evidence.",
    "ROOT_PROVENANCE_MISSING": "The anchor event has no well-formed raw-evidence digest (digest format check only; the payload is not re-hashed).",
    "PROVENANCE_UNVERIFIED_ALL": "No relevant event has a well-formed raw-evidence digest (digest format check only).",
    "PROVENANCE_PARTIAL": "Some relevant events lack a well-formed raw-evidence digest (digest format check only; disclosed, not fatal).",
    "UNCORROBORATED_QUESTION": "No other evidence unit under the current record-level rule (a different raw record joined by a specific artefact such as a file hash, domain, public IP, process GUID or logon session) corroborates the key event.",
    "WEAK_LINK_ONLY": "Other events are related only by host, user, internal IP or process name, which is context, not corroboration.",
    "REPEATED_OBSERVATION_ONLY": "Other events share an artefact but are repetitions of the same observation (same host, event id and action), not an independent source of proof.",
    "TEMPORAL_ANOMALY": "Some events are dated outside the investigation window or in the future.",
    "CONTRADICTORY_EVIDENCE": "Evidence contradicts itself: opposite outcomes or conflicting digests for the same event, conflicting outcomes from independent sources, or an artefact timestamped before the event that supposedly delivered it. See the contradiction section for the records, why it matters and what would resolve it.",
    "MISSING_REQUIRED_FIELD": "The anchor event lacks details its event type requires.",
    "DUPLICATE_EVIDENCE_COLLAPSED": "Duplicate, same-record or near-duplicate events were counted once.",
    "IRRELEVANT_EVIDENCE_EXCLUDED": "Some evidence was excluded as unrelated to the question.",
    "GATE_EVALUATION_ERROR": "The sufficiency check itself failed; the system abstained (fail closed).",
}


def _explain(code: str) -> str:
    return REASON_EXPLANATIONS.get(code.split(":")[0], code)


def _cell(text: object) -> str:
    """One Markdown table cell from evidence-derived text. Evidence is untrusted: HTML, link/image syntax and code spans are
    neutralised so an exported report cannot carry active markup (OWASP A03 / LLM05; probe-suite finding SEC-F1, 2026-11-20)."""
    s = str(text if text not in (None, "") else "-").replace("\r", " ").replace("\n", " ")
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "/").replace("`", "'")
    return s.replace("](", "] (").replace("![", "! [")  # link / image syntax cannot form; plain [brackets] stay readable


def render_incident_report(result: "WorkflowResult", a: "IncidentAnalysis") -> str:
    inc, assessment = a.incident, a.assessment
    sources = sorted({e.source_type for e in a.events})
    lines: list[str] = []
    add = lines.append
    add(f"# Incident {str(inc.incident_id)[:8]}: {inc.severity.upper()} severity"
        f"{' (escalated: 3+ kill-chain stages)' if inc.escalated else ''}")
    add("")
    add(f"{len(a.events)} event(s) from {len(sources)} source(s) ({', '.join(sources)}); "
        f"hosts: {_cell(', '.join(inc.hosts))}; users: {_cell(', '.join(inc.users))}; "
        f"{inc.first_seen.isoformat()} to {inc.last_seen.isoformat()}.")
    add("")
    add("## 1. Evidence sufficiency (decided before any AI is used)")
    add("")
    add(f"**Verdict: {assessment.verdict.value.upper()}** (rule table {assessment.rule_version}).")
    if assessment.verdict == SufficiencyVerdict.SUFFICIENT:
        add("The evidence meets the criteria for a model-assisted investigation. Listed limitations still apply.")
    elif assessment.verdict == SufficiencyVerdict.LIMITED:
        add("The evidence supports a **bounded** investigation only. Do not treat the findings below as definitive.")
    else:
        add("The evidence is **insufficient**. No AI analysis was run; the platform abstains.")
    add("")
    open_conflicts = [c for c in result.correlation.contradictions if set(c.event_keys) & set(inc.event_keys)]
    handled = any(c.startswith("CONTRADICTORY_EVIDENCE") for c in assessment.reason_codes)   # the gate already weighed (or disclosed) a conflict
    if open_conflicts and not handled:
        add(f"**Contradiction notice:** the correlator found {len(open_conflicts)} pair(s) of records with opposite outcomes for the same "
            "actors within seconds. The sufficiency rule table (ADR-008) did not weigh them because they come from different sensors; "
            "review the contradictions in section 5 before relying on this verdict. Conflicting records can also have been counted as "
            "corroborating each other.")
        add("")
    if assessment.reason_codes:
        add("| Reason code | Meaning |")
        add("|---|---|")
        for code in assessment.reason_codes:
            add(f"| `{code}` | {_explain(code)} |")
        add("")
    if assessment.contradictions:
        _render_contradictions(add, a)
    add(f"Evidence units after de-duplication: {assessment.effective_events} of {assessment.total_events} events; "
        f"relevant: {assessment.relevant_events}; with a well-formed digest (format check only): {assessment.attested_events}; "
        f"corroborating under the record-level rule: {assessment.corroborating_events}.")
    add("")

    add("## 2. Timeline (UTC, from preserved evidence)")
    add("")
    add("| # | Time | Source | Host | User | Event | Stage | Outcome | Severity | Membership | Raw SHA-256 (prefix) | Notes |")
    add("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for t in a.timeline:
        notes = []
        if t.duplicates_collapsed:
            notes.append(f"{t.duplicates_collapsed} duplicate/near-duplicate record(s) collapsed")
        if t.contradicts:
            notes.append("contradicted by another record")
        if t.membership == "weak_context":
            notes.append("related by host/user/internal IP only")
        add(f"| {t.position} | {t.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | {_cell(t.source_type)} | {_cell(t.host)} | "
            f"{_cell(t.user)} | {_cell(t.title)} | {_cell(t.stage)} | {_cell(t.outcome)} | {t.severity} | {t.membership} | "
            f"`{t.raw_sha256_prefix}` | {_cell('; '.join(notes))} |")
    add("")

    add("## 3. How the evidence is linked")
    add("")
    lc = inc.link_counts
    add(f"Links inside this incident: strong {lc.get('strong', 0)}, specific {lc.get('specific', 0)}, weak {lc.get('weak', 0)}. "
        "Strong (same logon session or process instance) and specific (same file hash, domain or public IP) links form the incident; "
        "weak links (same host, user, internal IP or process name) only attach a lone observation as context and are never treated as corroboration.")
    add("")
    members = {i for i in (*inc.core_clusters, *inc.weak_context_clusters)}
    shown = sorted(
        (lk for lk in result.correlation.links
         if lk.cluster_a in members and lk.cluster_b in members and lk.strength != "weak"),
        key=lambda lk: (lk.strength != "strong", lk.cluster_a, lk.cluster_b),
    )
    if shown:
        add("Strong and specific links (weak links are counted above but not listed):")
        add("")
        add("| Strength | Clusters | Shared entities |")
        add("|---|---|---|")
        for lk in shown[:25]:
            add(f"| {lk.strength} | {lk.cluster_a} - {lk.cluster_b} | {_cell(', '.join(f'{t}={v}' for t, v in lk.shared_entities[:4]))} |")
        add("")
    if inc.weakly_related:
        add("Weakly related incidents (reported, not merged): " + ", ".join(str(i)[:8] for i in inc.weakly_related) + ".")
        add("")

    add("## 4. ATT&CK mapping (deterministic rules; not a probability)")
    add("")
    if a.mitre:
        add("| Technique | Tactic(s) | Rule | Independent evidence | Source also asserted it | Limitation |")
        add("|---|---|---|---|---|---|")
        for m in a.mitre:
            add(f"| {m.technique_id} {m.technique_name} | {', '.join(m.tactics)} | `{m.rule_id}` | {m.independent_evidence_count} | "
                f"{'yes' if m.vendor_asserted else 'no'} | {_cell(m.limitation)} |")
    else:
        add("No technique could be derived by the rule table from this evidence.")
    if a.asserted_only:
        add("")
        add("Asserted by a source but NOT derived by any rule (treat as unverified): " + ", ".join(a.asserted_only) + ".")
    add("")

    if a.observations or a.analyst_notes:
        _render_domain_sections(add, a)

    add("## 5. Data-quality notes")
    add("")
    dup = sum(t.duplicates_collapsed for t in a.timeline)
    ctr = [c for c in result.correlation.contradictions if set(c.event_keys) & set(inc.event_keys)]
    add(f"- Duplicate / same-record / near-duplicate records collapsed: {dup}.")
    add(f"- Contradictions: {len(ctr)}" + (" (" + "; ".join(c.reason for c in ctr) + ")" if ctr else "") + ".")
    add(f"- Records that could not be normalized in this batch: {len(result.normalization.rejected)}.")
    add("")

    add("## 6. AI-assisted investigation")
    add("")
    if a.llm_status == "not_requested":
        add("Not requested. Everything above is deterministic and was produced without a language model.")
    elif a.llm_result is not None:
        out = a.llm_result.output
        add(f"Status: **{a.llm_status}**; guardrail decision: **{a.llm_result.decision.value}**; claims validated: {out.overall_grounding_score * 100:.1f}%.")
        add("")
        add(f"> {CLAIMS_VALIDATED_DEFINITION}")
        add(f"> {MODEL_REPORTED_CONFIDENCE_DEFINITION}")
        add("")
        add(out.investigation_summary)
        add("")
        if out.claims:
            add("| Claim | Category | Grounding | Model-reported confidence | Supporting events |")
            add("|---|---|---|---|---|")
            for c in out.claims:
                add(f"| {_cell(c.claim_text)} | {c.category.value} | {c.grounding_status.value} | {c.confidence} | "
                    f"{', '.join(str(u)[:8] for u in c.supporting_evidence_ids)} |")
            add("")
        if out.uncertainty_and_data_gaps:
            add("Uncertainty and data gaps carried into the report:")
            for u in out.uncertainty_and_data_gaps:
                add(f"- {_cell(u)}")
    add("")

    add("## 7. Provenance and reproducibility")
    add("")
    by_source: dict[str, set[str]] = {}
    for e in a.events:
        by_source.setdefault(e.source_type, set()).add(e.raw_sha256)
    add("| Source | Events | Distinct raw records |")
    add("|---|---|---|")
    for s in sources:
        add(f"| {s} | {sum(1 for e in a.events if e.source_type == s)} | {len(by_source[s])} |")
    add("")
    add(f"- Context SHA-256: `{a.context.reproducibility.context_sha256}`")
    add(f"- Sufficiency assessment SHA-256: `{assessment.assessment_sha256}`")
    add(f"- Ledger head (hash chain verified: {'yes' if result.ledger_ok else 'NO'}): `{result.ledger_head}`")
    add("")
    add("## 8. Limitations of this report")
    add("")
    add("- Mappings and links are rule-based and explainable, not probabilistic; absence of a link or technique is not evidence of absence.")
    add("- Provenance is the SHA-256 of each submitted raw record; it proves integrity since submission, not that the source was truthful.")
    add("- Only the sources, adapters and rules implemented in AISOP are covered (see the architecture document).")
    assumed = sum(1 for e in a.events if e.time_assumed_utc)
    if assumed:
        add(f"- Time zone assumed: {assumed} record(s) gave a time without a time zone; UTC was assumed, not stated by the source, so their event times are unverified.")
    undated = sum(1 for o in result.observations if o.family.value != "analyst" and o.event_time is None)
    if undated:
        add(f"- Event time unknown: {undated} preserved record(s) have no usable event time (none was invented). They are not on the timeline "
            "and take no part in ordering, temporal comparison or corroboration. Their ingestion time is stored separately and is not an event time.")
    add("")
    return "\n".join(lines)


_WHY_MATERIAL = (
    "Independent sources disagree about the same proposition and the disagreement touches the investigated hypothesis ({relation}). "
    "The pair no longer counts as corroboration and the verdict is capped at LIMITED."
)


def _why_minor(f) -> str:  # type: ignore[no-untyped-def]
    if f.explanation is not None and f.explanation.value == "timezone_assumed":
        return "A source gave no time zone, so UTC was assumed; no material time-based claim can be made. Disclosed only."
    if f.explanation is not None and f.explanation.value == "clock_skew_within_tolerance":
        return "The difference is within the approved 5-second clock-skew tolerance, so it is explained as possible clock skew. Disclosed only."
    if f.independence == "same_source":
        return "Both records come from the same source or the same upstream collection, so this is an internal inconsistency, not independent disagreement. Disclosed only."
    if f.independence == "unknown":
        return "Whether the two sources are independent could not be established (one side declares an upstream collection), so it is not treated as independent. Disclosed only."
    return "The link between the records is weak, or they are peripheral to the hypothesis. Disclosed only."


def _render_contradictions(add, a: "IncidentAnalysis") -> None:  # type: ignore[no-untyped-def]
    """ADR-013 block under the verdict: what contradicts, why it is (not) material, effect on the verdict, what would resolve it."""
    from app.modules.evidence_domains.contradictions import HINT_TEXT

    by_key = {e.event_key: e for e in a.events}

    def rec(i: int, f) -> str:  # type: ignore[no-untyped-def]
        ev = by_key.get(f.evidence_ids[i])
        kind = ev.category if ev is not None else "record"
        return f"{kind} from {f.sources[i]} at {f.times[i].strftime('%Y-%m-%d %H:%M:%S')} UTC: {f.claims[i]}"

    add("**Contradictions (ADR-013).** Observed records that conflict about the same proposition. They are reported here and are not resolved.")
    add("")
    add("| Kind | Proposition | Materiality | Affects verdict | Record 1 | Record 2 | Why | What would resolve it |")
    add("|---|---|---|---|---|---|---|---|")
    for f in a.assessment.contradictions:
        why = _WHY_MATERIAL.format(relation=f.relation.value) if f.affects_verdict else _why_minor(f)
        add(f"| {f.kind.value} | {f.proposition} | {f.materiality.value} | {'yes' if f.affects_verdict else 'no'} | {_cell(rec(0, f))} | "
            f"{_cell(rec(1, f))} | {_cell(why)} | {_cell(HINT_TEXT.get(f.resolution_hint, f.resolution_hint))} |")
    add("")


def _render_domain_sections(add, a: "IncidentAnalysis") -> None:  # type: ignore[no-untyped-def]
    """ADR-011 sections: observed typed relationships, external intelligence, analyst statements. Rendered only for domain evidence."""
    g = a.graph
    add("## 4b. Entity graph: typed relationships stated by observed evidence")
    add("")
    if g is not None and g.edges:
        add("Each relationship below is stated directly by at least one record; none was inferred. "
            "*Independent support* counts distinct evidence units (duplicates and near-duplicates count once).")
        add("")
        add("| Subject | Relationship | Object | Independent support | Sources | Trust |")
        add("|---|---|---|---|---|---|")
        for e in sorted(g.edges, key=lambda x: (-x.independent_support, x.predicate, x.subject, x.obj))[:40]:
            add(f"| {_cell(e.subject[0] + ':' + e.subject[1])} | {e.predicate} | {_cell(e.obj[0] + ':' + e.obj[1])} | "
                f"{e.independent_support} | {_cell(', '.join(sorted(e.sources)))} | {_cell(', '.join(sorted(e.trust)))} |")
        add("")
    else:
        add("No typed relationship is stated by the observed evidence in this incident.")
        add("")
    if g is not None and g.uncertainties:
        add("Uncertainty and missing information:")
        for u in g.uncertainties:
            add(f"- **{u['kind']}**: {_cell(u['detail'])}")
        add("")
    add("## 4c. External intelligence (context only, not observed evidence)")
    add("")
    if a.enrichments:
        add("| Indicator | Source | Intelligence statement | Observed in |")
        add("|---|---|---|---|")
        for en in a.enrichments:
            for m in en.matches:
                add(f"| {_cell(en.entity[0] + ':' + en.entity[1])} | {_cell(m.source)} | {_cell(m.description)} | {len(en.observed_in)} record(s) |")
        add("")
        add("Intelligence describes the indicator in general. It did not influence correlation, the sufficiency verdict or ATT&CK mapping.")
    else:
        add("No external intelligence was attached to this incident.")
    add("")
    add("## 4d. Analyst statements (context only, never corroboration)")
    add("")
    if a.analyst_notes:
        add("| Time | Statement (source-supplied, unverified) | Entities it mentions |")
        add("|---|---|---|")
        for n in a.analyst_notes:
            t = n.event_time.strftime("%Y-%m-%d %H:%M:%S") if n.event_time else "undated"
            add(f"| {t} | {_cell(n.attributes.get('statement', n.title))} | {_cell(', '.join(f'{x}:{y}' for x, y in n.entities[:4]))} |")
        add("")
        add("These statements did not count toward the sufficiency verdict or any technique mapping.")
    else:
        add("No analyst statement refers to this incident.")
    add("")


def render_abstention_report(result: "WorkflowResult") -> str:
    a = result.batch_assessment
    lines = ["# Analyst abstention: no incident could be formed", ""]
    if a is not None:
        lines += [f"**Verdict: {a.verdict.value.upper()}** (rule table {a.rule_version}). No AI analysis was run.", ""]
        lines += ["| Reason code | Meaning |", "|---|---|"]
        lines += [f"| `{c}` | {_explain(c)} |" for c in a.reason_codes]
        lines.append("")
    if result.observations:
        und = [o for o in result.observations if o.family.value != "analyst" and o.event_time is None]
        unc = [o for o in result.observations if o.family.value == "unclassified"]
        ana = [o for o in result.observations if not o.counts_for_corroboration and o.family.value == "analyst"]
        lines += ["", f"Preserved evidence not used for correlation: {len(und)} undated (no usable event time; none was invented), "
                      f"{len(unc)} unclassified (type not recognised), {len(ana)} analyst statement(s) (context only).", ""]
    kept = sum(1 for o in result.observations if not any(e.event_key == o.key for e in result.normalization.events))
    lines.append(f"Records submitted: {len(result.normalization.events) + len(result.normalization.rejected) + kept}; "
                 f"normalized: {len(result.normalization.events)}; rejected: {len(result.normalization.rejected)}"
                 + (f"; preserved but not correlated: {kept}" if kept else "") + ".")
    if result.normalization.rejected:
        lines += ["", "| Record | Reason | Raw SHA-256 (prefix) |", "|---|---|---|"]
        lines += [f"| {r.record_index} | `{r.reason}` | `{r.raw_sha256[:12]}` |" for r in result.normalization.rejected]
    lines += ["", f"Ledger head (verified: {'yes' if result.ledger_ok else 'NO'}): `{result.ledger_head}`", ""]
    return "\n".join(lines)


__all__ = ["REASON_EXPLANATIONS", "render_abstention_report", "render_incident_report"]
