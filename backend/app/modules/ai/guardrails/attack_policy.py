"""
Deterministic ATT&CK taxonomy-lifecycle and successor-evidence policy for model technique hypotheses.

Three independent questions are answered separately and never collapsed into one another:
  1. Taxonomy lifecycle   - what does the pinned local Enterprise catalogue say about this identifier?
                            (``TaxonomyState``, defined once in ``app.schemas.attack_taxonomy``)
  2. Evidence support     - does the investigation contain STRUCTURED evidence that supports this specific technique
                            assertion? (``EvidenceStatus``)
  3. AI claim handling    - applied by the validator from (1) and (2); a model can never validate or confirm itself.

Taxonomy status NEVER changes evidence confidence. A valid current identifier does not show the technique occurred. A
catalogue successor pointer is a suggestion, never evidence and never an automatic substitution. An unknown identifier
is inconclusive, not benign. Only an evidence contract that is not satisfied can lower confidence (the validator does
that, for the twelve successor techniques).

The catalogue is OPTIONAL reference data injected by the caller (``AttackReferenceCatalogue`` or a non-raising
``CatalogueLoadResult``). Nothing here loads a file, uses the network, or reads descriptions.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Optional, Sequence, Union

from pydantic import BaseModel, ConfigDict

from app.modules.attack_reference import AttackReferenceCatalogue, CatalogueLoadResult, ReferenceStatus
from app.modules.attack_reference.models import TECHNIQUE_ID_RE
from app.schemas.attack_taxonomy import SuccessorCandidate, TaxonomyState, TechniqueTaxonomyStatus
from app.schemas.investigation import ContextEventItem

#: What the caller may pass: nothing (not configured), a loaded catalogue, or the result of ``try_load_catalogue``.
AttackReferenceSource = Optional[Union[AttackReferenceCatalogue, CatalogueLoadResult]]

#: The 12 distinct current techniques that the pinned v20.1 catalogue names as explicit successors of the 14 revoked
#: identifiers (T1070.001 and the T1562 family). Only the TARGET ids are listed here, because each needs its own
#: evidence contract. The old-to-new relationships are NEVER stored here: they come from the catalogue only.
SUCCESSOR_TARGET_IDS: tuple[str, ...] = (
    "T1685", "T1685.001", "T1685.002", "T1685.003", "T1685.004", "T1685.005",
    "T1686", "T1686.001", "T1686.002", "T1688", "T1689", "T1690",
)

#: States that are acceptable to nobody as a CURRENT mapping. Consumers that decide acceptance read this set.
OBSOLETE_STATES = frozenset({TaxonomyState.REVOKED, TaxonomyState.DEPRECATED})
#: States meaning "not validated against a catalogue" (inconclusive, never benign).
UNVALIDATED_STATES = frozenset({TaxonomyState.UNKNOWN, TaxonomyState.WRONG_DOMAIN})

# Markers used in reasoning text; the validator checks them to stay idempotent on re-validation.
MARK_OBSOLETE = "[OBSOLETE_ATTACK_ID:"
MARK_UNVALIDATED = "[ATTACK_ID_UNVALIDATED:"
MARK_UNAVAILABLE = "[ATTACK_REFERENCE_UNAVAILABLE:"
MARK_UNSUPPORTED = "[UNSUPPORTED_ATTACK_CLAIM:"

RULE_OBSOLETE = "SEC-GR-ATTACK-OBSOLETE-ID"
RULE_UNVALIDATED = "SEC-GR-ATTACK-UNVALIDATED-ID"
RULE_UNAVAILABLE = "SEC-GR-ATTACK-REFERENCE-UNAVAILABLE"
RULE_UNSUPPORTED = "SEC-GR-ATTACK-UNSUPPORTED-CLAIM"


class ReferenceState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"            # a catalogue was requested but could not be loaded: explicit, never "valid"
    NOT_CONFIGURED = "not_configured"      # the default: behaviour as before this policy existed


class EvidenceStatus(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    NOT_ASSESSED = "not_assessed"          # no evidence contract exists for this identifier (existing policy applies)


_FROZEN = ConfigDict(frozen=True, extra="forbid")


class AttackTechniqueAssessment(BaseModel):
    """Structured, deterministic outcome for one technique identifier: taxonomy and evidence, kept separate."""

    model_config = _FROZEN

    technique_id: str
    taxonomy: TechniqueTaxonomyStatus
    evidence_status: EvidenceStatus = EvidenceStatus.NOT_ASSESSED
    evidence_requirement: Optional[str] = None
    evidence_event_uuids: tuple[uuid.UUID, ...] = ()
    missing_prerequisite: Optional[str] = None
    #: True when the outcome is inconclusive (unvalidated, unavailable or unsupported). Never "benign".
    inconclusive: bool = False

    @property
    def taxonomy_status(self) -> TaxonomyState:
        return self.taxonomy.state

    @property
    def successors(self) -> tuple[SuccessorCandidate, ...]:
        return self.taxonomy.successors

    @property
    def catalogue_lifecycle(self) -> Optional[str]:
        return self.taxonomy.lifecycle

    @property
    def catalogue_release(self) -> Optional[str]:
        return self.taxonomy.catalogue_release


@dataclass(frozen=True)
class EvidenceContract:
    """What structured evidence a specific technique claim needs, and whether current telemetry can supply it."""

    technique_id: str
    required_observable: str
    required_fields: str
    scope_limit: str
    predicate: Optional[Callable[[ContextEventItem], bool]] = None
    missing_prerequisite: Optional[str] = None


def _windows_security_audit_log_cleared(ev: ContextEventItem) -> bool:
    """
    Structured signal for a cleared Windows Security audit log, from fields that exist today: an alert normalised by
    the Windows Security adapter (``source_type == "windows_security"``) whose stored vendor event id is 1102
    (``custom_fields.event_id``). Free text, titles and keywords are deliberately NOT used. The adapter does not verify
    the channel or provider itself, so this supports only "the adapter reported event 1102".
    """
    try:
        attrs = ev.attributes or {}
        custom = attrs.get("custom_fields")
        native = custom.get("event_id") if isinstance(custom, dict) else None
        return attrs.get("source_type") == "windows_security" and str(native) == "1102"
    except Exception:  # noqa: BLE001 - never let a malformed attribute break validation
        return False


_NO_TELEMETRY = (
    "No adapter, observation type or normalised field in the current tree reports this behaviour "
    "(searched backend/app for the relevant telemetry); a separately approved telemetry/schema change is required."
)

EVIDENCE_CONTRACTS: dict[str, EvidenceContract] = {c.technique_id: c for c in (
    EvidenceContract("T1685", "a security tool or control disabled or modified", "a normalised tool-tampering event",
                     "A sub-technique event does not establish this parent-level claim",
                     missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract("T1685.001", "Windows event-log service or configuration disabled/modified",
                     "a normalised Windows event-log service/configuration change event",
                     "The Windows Security adapter handles only event ids 4624, 4625, 4688, 4720, 4738 and 1102",
                     missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract("T1685.002", "cloud logging disabled or modified", "a normalised cloud logging-disable API observation",
                     "Cloud audit telemetry currently covers account/role/MFA events only",
                     missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract("T1685.003", "a security tool's UI or alerting modified or spoofed", "a normalised tool-UI/alert-spoofing event",
                     "none", missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract("T1685.004", "Linux audit system or audit log modified", "a normalised audit-configuration change event",
                     "The Linux auth adapter reads authentication events only",
                     missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract(
        "T1685.005", "Windows Security audit log cleared",
        "attributes.source_type == 'windows_security' and attributes.custom_fields.event_id == '1102' on a cited event",
        "Supports only that the Windows Security adapter reported event 1102. It does not show how the log was cleared, "
        "by whom, with what intent, or that System/Application logs were cleared; the adapter does not verify channel/provider",
        predicate=_windows_security_audit_log_cleared),
    EvidenceContract("T1686", "a system firewall disabled or modified", "a normalised firewall-configuration change event",
                     "The firewall/IDS adapter ingests intrusion alerts, not configuration changes",
                     missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract("T1686.001", "a cloud firewall disabled or modified", "a normalised cloud firewall change observation",
                     "none", missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract("T1686.002", "a network-device firewall disabled or modified", "a normalised network-device firewall change event",
                     "The firewall/IDS adapter ingests intrusion alerts, not configuration changes",
                     missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract("T1688", "safe-mode boot configured", "a normalised boot-configuration change event",
                     "none", missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract("T1689", "a security feature or protocol downgraded", "a normalised downgrade/version-change event",
                     "none", missing_prerequisite=_NO_TELEMETRY),
    EvidenceContract("T1690", "command-history logging disabled or prevented", "a normalised history-logging change event",
                     "none", missing_prerequisite=_NO_TELEMETRY),
)}


def resolve_reference(source: AttackReferenceSource) -> tuple[ReferenceState, Optional[AttackReferenceCatalogue]]:
    """Normalise what the caller supplied into an explicit state. Anything else is a programming error."""
    if source is None:
        return ReferenceState.NOT_CONFIGURED, None
    if isinstance(source, AttackReferenceCatalogue):
        return ReferenceState.AVAILABLE, source
    if isinstance(source, CatalogueLoadResult):
        if source.catalogue is not None:
            return ReferenceState.AVAILABLE, source.catalogue
        return ReferenceState.UNAVAILABLE, None
    raise TypeError("attack_reference must be None, an AttackReferenceCatalogue or a CatalogueLoadResult")


def _successors(cat: AttackReferenceCatalogue, attack_id: str) -> tuple[tuple[SuccessorCandidate, ...], int]:
    rec = cat.get_technique(attack_id)
    if rec is None:
        return (), 0
    out = []
    for s in cat.successors_of(attack_id):
        shared = tuple(sorted(t.attack_id for t in cat.techniques() if s.attack_id in t.replaced_by and t.attack_id != attack_id))
        out.append(SuccessorCandidate(attack_id=s.attack_id, name=s.name, lifecycle=s.lifecycle.value, shared_with=shared))
    return tuple(out), len(rec.unresolved_successor_refs)


def _taxonomy(
    technique_id: str,
    catalogue: Optional[AttackReferenceCatalogue],
    reference_state: ReferenceState,
) -> TechniqueTaxonomyStatus:
    """Map the loader's lifecycle vocabulary onto the eight explicit taxonomy states (one place, no second enum)."""
    if TECHNIQUE_ID_RE.fullmatch(technique_id) is None:
        return TechniqueTaxonomyStatus(state=TaxonomyState.INVALID, reason_code="INVALID_SYNTAX")
    if catalogue is None:
        unavailable = reference_state == ReferenceState.UNAVAILABLE
        return TechniqueTaxonomyStatus(
            state=TaxonomyState.CATALOGUE_UNAVAILABLE if unavailable else TaxonomyState.NOT_CONFIGURED,
            technique_id=technique_id,
            reason_code="CATALOGUE_UNAVAILABLE" if unavailable else "NO_CATALOGUE_CONFIGURED",
        )
    meta = catalogue.meta
    base = dict(technique_id=technique_id, catalogue_domain=meta.domain, catalogue_release=meta.release_version,
                catalogue_sha256=meta.sha256)
    look = catalogue.lookup_technique(technique_id)
    rec = look.record
    if look.status == ReferenceStatus.CURRENT and rec is not None:
        return TechniqueTaxonomyStatus(state=TaxonomyState.CURRENT_VALID, canonical_name=rec.name, lifecycle=rec.lifecycle.value,
                                       reason_code="CATALOGUE_CURRENT", **base)
    if rec is not None and look.status in (ReferenceStatus.REVOKED, ReferenceStatus.DEPRECATED, ReferenceStatus.REVOKED_AND_DEPRECATED):
        successors, unresolved = _successors(catalogue, technique_id)
        revoked = look.status != ReferenceStatus.DEPRECATED
        return TechniqueTaxonomyStatus(
            state=TaxonomyState.REVOKED if revoked else TaxonomyState.DEPRECATED, canonical_name=rec.name,
            lifecycle=rec.lifecycle.value, successors=successors,
            successor_ambiguous=len(successors) > 1 or any(s.shared_with for s in successors),
            unresolved_successor_refs=unresolved,
            reason_code="CATALOGUE_REVOKED" if revoked else "CATALOGUE_DEPRECATED", **base)
    if look.status == ReferenceStatus.WRONG_DOMAIN:
        return TechniqueTaxonomyStatus(state=TaxonomyState.WRONG_DOMAIN, reason_code="OTHER_DOMAIN", **base)
    return TechniqueTaxonomyStatus(state=TaxonomyState.UNKNOWN, reason_code="NOT_IN_PINNED_ENTERPRISE_CATALOGUE", **base)


def assess_attack_technique(
    technique_id: str,
    cited_events: Sequence[ContextEventItem],
    catalogue: Optional[AttackReferenceCatalogue],
    *,
    reference_state: ReferenceState = ReferenceState.NOT_CONFIGURED,
) -> AttackTechniqueAssessment:
    """
    Pure and deterministic: identical inputs and an identical pinned catalogue give an identical assessment.
    ``cited_events`` are the events the hypothesis cites that exist in the verified context (never model text).
    Taxonomy and evidence are computed independently: neither is an input to the other.
    """
    taxonomy = _taxonomy(technique_id, catalogue, reference_state)
    state = taxonomy.state

    evidence = EvidenceStatus.NOT_ASSESSED
    requirement: Optional[str] = None
    refs: tuple[uuid.UUID, ...] = ()
    missing: Optional[str] = None
    contract = EVIDENCE_CONTRACTS.get(technique_id)
    if contract is not None and state not in OBSOLETE_STATES and state != TaxonomyState.INVALID:
        requirement = f"{contract.required_observable} ({contract.required_fields})"
        if contract.predicate is not None:
            refs = tuple(ev.event_uuid for ev in cited_events if contract.predicate(ev))
        evidence = EvidenceStatus.SUPPORTED if refs else EvidenceStatus.UNSUPPORTED
        if not refs and contract.predicate is None:
            missing = contract.missing_prerequisite

    inconclusive = (
        state in UNVALIDATED_STATES
        or state in (TaxonomyState.NOT_CONFIGURED, TaxonomyState.CATALOGUE_UNAVAILABLE, TaxonomyState.INVALID)
        or evidence == EvidenceStatus.UNSUPPORTED
    )
    return AttackTechniqueAssessment(
        technique_id=technique_id, taxonomy=taxonomy, evidence_status=evidence, evidence_requirement=requirement,
        evidence_event_uuids=refs, missing_prerequisite=missing, inconclusive=inconclusive,
    )


# ── text helpers (identifiers come from validated syntax or the pinned catalogue; no untrusted free text is echoed) ──
def _succ_text(a: AttackTechniqueAssessment) -> str:
    if not a.successors:
        return "no explicit successor declared"
    parts = []
    for s in a.successors:
        extra = f" [shared with {', '.join(s.shared_with)}: analyst choice required]" if s.shared_with else ""
        parts.append(f"{s.attack_id}{extra}")
    return ", ".join(parts)


def obsolete_tag(a: AttackTechniqueAssessment) -> str:
    return (f"{MARK_OBSOLETE} {a.technique_id} is {a.catalogue_lifecycle} in ATT&CK {a.catalogue_release} Enterprise and is not accepted "
            f"as a current mapping (its evidence confidence is unchanged); catalogue successor suggestion "
            f"(not evidence, not substituted): {_succ_text(a)}]")


def obsolete_description(a: AttackTechniqueAssessment) -> str:
    return (f"Technique {a.technique_id} is {a.catalogue_lifecycle} in the pinned ATT&CK {a.catalogue_release} Enterprise catalogue. "
            f"Successor suggestion (catalogue relationship only, not evidence): {_succ_text(a)}")


def unvalidated_tag(a: AttackTechniqueAssessment) -> str:
    return (f"{MARK_UNVALIDATED} {a.technique_id} is not a current Enterprise technique in the pinned ATT&CK "
            f"{a.catalogue_release} catalogue; inconclusive, not benign]")


def unavailable_tag(a: AttackTechniqueAssessment) -> str:
    return f"{MARK_UNAVAILABLE} ATT&CK taxonomy for {a.technique_id} could not be validated; inconclusive, not benign]"


def unsupported_tag(a: AttackTechniqueAssessment) -> str:
    return (f"{MARK_UNSUPPORTED} {a.technique_id} requires structured evidence ({a.evidence_requirement}); "
            f"none of the cited events supplies it; inconclusive]")


def unsupported_description(a: AttackTechniqueAssessment) -> str:
    tail = f" Missing prerequisite: {a.missing_prerequisite}" if a.missing_prerequisite else ""
    return f"{a.technique_id} claim lacks the required structured evidence: {a.evidence_requirement}.{tail}"
