"""
AISOP Structured Investigation Response Parser.

Parses, validates, and grounds LLM responses into typed StructuredInvestigationOutput contracts.
Adheres to AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001 and P2-H4 Task 2.3 specifications:
- Safe JSON text extraction (stripping outer markdown code fences only).
- Bounded validation against StructuredInvestigationOutput (extra="forbid").
- Strict investigation_id verification against context.
- Tier 1 event reference existence validation for claims and MITRE hypotheses.
- Grounding score recomputation.
- Rejection of truncated responses (finish_reason == "length").
- Deterministic factual fallback generator.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
import uuid

from loguru import logger
from pydantic import ValidationError

from app.schemas.ai import LLMResponse
from app.schemas.sufficiency import EvidenceSufficiencyAssessment
from app.schemas.investigation import (
    FactualClaimItem,
    GroundingStatus,
    InvestigationContext,
    MitreAttackHypothesis,
    StructuredInvestigationOutput,
)


class ResponseParsingError(Exception):
    """Raised when an LLM response cannot be parsed or validated into StructuredInvestigationOutput."""
    pass


class InvestigationResponseParser:
    """
    Parses and preliminarily validates LLM responses into StructuredInvestigationOutput.
    """

    def __init__(self) -> None:
        self.last_normalized_claim_ids: dict[int, dict[str, Any]] = {}

    def normalize_claim_identifier(
        self,
        raw_id: Any,
        claim_index: int,
        investigation_id: uuid.UUID,
        seen_claim_ids: set[uuid.UUID],
    ) -> uuid.UUID:
        """
        Deterministically normalize a factual claim identifier into a valid, unique RFC 4122 UUID.

        Contract (AISOP Gate D.2.5.32):
        1. Valid unique UUID: If raw_id is a valid UUID or UUID string not yet assigned to another
           claim in this response, preserve the exact UUID value unchanged.
        2. Missing, null, empty, or malformed identifier: Generate a deterministic UUIDv5 using
           investigation_id as namespace and a stable name incorporating the claim's position
           and original identifier token (f"claim:{claim_index}:{token}").
        3. Duplicate identifiers: Explicitly detect duplicates. If a valid UUID or generated UUIDv5
           has already been assigned to another claim in this investigation output, resolve the
           collision deterministically using a salted UUIDv5 name (f"claim:{claim_index}:duplicate:{token}:{counter}")
           so that every claim receives a unique, collision-free UUID without silently overwriting.
        4. Internal Surrogate Scope: A normalized claim ID is an internal identifier only. It does not
           establish the truth of a claim, validate its evidence, or alter its grounding score.
        """
        is_valid_uuid = False
        parsed_uuid: uuid.UUID | None = None

        if isinstance(raw_id, uuid.UUID):
            is_valid_uuid = True
            parsed_uuid = raw_id
        elif isinstance(raw_id, str):
            stripped = raw_id.strip()
            if stripped:
                try:
                    parsed_uuid = uuid.UUID(stripped)
                    is_valid_uuid = True
                except (ValueError, TypeError, AttributeError):
                    is_valid_uuid = False

        if is_valid_uuid and parsed_uuid is not None:
            if parsed_uuid not in seen_claim_ids:
                seen_claim_ids.add(parsed_uuid)
                return parsed_uuid
            else:
                # Collision: duplicate valid UUID across claims
                token = str(parsed_uuid)
                candidate = uuid.uuid5(investigation_id, f"claim:{claim_index}:duplicate:{token}")
                counter = 1
                while candidate in seen_claim_ids:
                    candidate = uuid.uuid5(investigation_id, f"claim:{claim_index}:duplicate:{token}:{counter}")
                    counter += 1
                seen_claim_ids.add(candidate)
                self.last_normalized_claim_ids[claim_index] = {
                    "original": raw_id,
                    "normalized": candidate,
                    "action": "disambiguated_duplicate_uuid",
                }
                logger.debug(
                    "Disambiguated duplicate valid claim UUID",
                    claim_index=claim_index,
                    original_uuid=str(parsed_uuid),
                    normalized_uuid=str(candidate),
                )
                return candidate

        # Missing, null, empty, or malformed identifier
        if raw_id is None:
            token = "none"
            action = "normalized_missing_id"
        elif isinstance(raw_id, str) and not raw_id.strip():
            token = "empty"
            action = "normalized_empty_id"
        else:
            token = str(raw_id).strip()[:100]
            action = "normalized_malformed_id"

        candidate = uuid.uuid5(investigation_id, f"claim:{claim_index}:{token}")
        counter = 1
        while candidate in seen_claim_ids:
            candidate = uuid.uuid5(investigation_id, f"claim:{claim_index}:{token}:collision:{counter}")
            counter += 1

        seen_claim_ids.add(candidate)
        self.last_normalized_claim_ids[claim_index] = {
            "original": raw_id,
            "normalized": candidate,
            "action": action,
        }
        logger.debug(
            "Normalized malformed or missing claim identifier",
            claim_index=claim_index,
            original_raw_id=str(raw_id)[:50] if raw_id is not None else "None",
            normalized_uuid=str(candidate),
            action=action,
        )
        return candidate

    def clean_json_text(self, raw_content: str) -> str:
        """
        Strip outer markdown code fences (```json ... ``` or ``` ... ```) and whitespace.

        Does not use broad regex extraction to avoid converting malformed output
        into valid-looking JSON.
        """
        text = raw_content.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) >= 2:
                first_line = lines[0].strip()
                last_line = lines[-1].strip()
                if first_line.startswith("```") and last_line == "```":
                    fence_tag = first_line[3:].strip().lower()
                    if fence_tag in ("", "json"):
                        text = "\n".join(lines[1:-1]).strip()
        return text

    def parse(
        self,
        raw_response: LLMResponse,
        context: InvestigationContext,
    ) -> StructuredInvestigationOutput:
        """
        Parse and validate raw LLMResponse into StructuredInvestigationOutput.

        Enforces:
        - Rejection of truncated responses (finish_reason == "length").
        - Strict JSON parsing.
        - Matching investigation_id.
        - Reference existence validation for claims and hypotheses.
        - Grounding score consistency.
        """
        # 0. Diagnostic state initialization
        self.last_normalized_claim_ids = {}

        # 1. Truncation rejection
        is_length_truncated = (
            getattr(raw_response, "finish_reason", None) == "length"
            or (
                isinstance(raw_response.raw_response, dict)
                and (
                    raw_response.raw_response.get("done_reason") == "length"
                    or raw_response.raw_response.get("finish_reason") == "length"
                )
            )
        )
        if is_length_truncated:
            raise ResponseParsingError(
                "Response was truncated by the LLM provider due to length limit (finish_reason='length')"
            )

        # 2. Extract and parse JSON
        cleaned = self.clean_json_text(raw_response.content)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise ResponseParsingError(f"Malformed JSON returned by model: {exc}") from exc

        if not isinstance(data, dict):
            raise ResponseParsingError(f"Expected JSON object, got {type(data).__name__}")

        # 3. Investigation ID verification
        res_id = data.get("investigation_id")
        if not res_id:
            raise ResponseParsingError("Missing required field 'investigation_id' in response")

        try:
            parsed_res_id = uuid.UUID(str(res_id))
        except (ValueError, TypeError) as exc:
            raise ResponseParsingError(f"Invalid UUID for investigation_id: {res_id!r}") from exc

        if parsed_res_id != context.investigation_id:
            raise ResponseParsingError(
                f"Returned investigation_id '{parsed_res_id}' does not match context.investigation_id '{context.investigation_id}'"
            )

        # 4. Enforce authoritative provider provenance over untrusted model generation
        provider_model = getattr(raw_response, "model", None)
        if provider_model and str(provider_model).strip():
            authoritative_model = str(provider_model).strip()
        elif (
            getattr(context, "reproducibility", None)
            and getattr(context.reproducibility, "model_name", None)
            and str(context.reproducibility.model_name).strip()
        ):
            authoritative_model = str(context.reproducibility.model_name).strip()
        else:
            authoritative_model = "unknown_model"

        data["model_identifier"] = authoritative_model
        if not data.get("generated_at"):
            data["generated_at"] = datetime.now(timezone.utc).isoformat()

        # 5. Evidence Reference Existence Validation (Tier 1) & Claim-ID Normalization
        context_event_uuids = {e.event_uuid for e in context.events}

        # Validate factual claims
        raw_claims = data.get("claims", [])
        if not isinstance(raw_claims, list):
            raise ResponseParsingError(f"Field 'claims' must be a list, got {type(raw_claims).__name__}")

        seen_claim_ids: set[uuid.UUID] = set()

        for idx, claim in enumerate(raw_claims):
            if not isinstance(claim, dict):
                raise ResponseParsingError(f"Claim item must be a dictionary, got {type(claim).__name__}")

            # 5A. Deterministic Claim Identifier Normalization (AISOP Gate D.2.5.32)
            raw_claim_id = claim.get("claim_id")
            normalized_claim_id = self.normalize_claim_identifier(
                raw_id=raw_claim_id,
                claim_index=idx,
                investigation_id=context.investigation_id,
                seen_claim_ids=seen_claim_ids,
            )
            claim["claim_id"] = normalized_claim_id
            # Task 1: ``verification`` is computed by the platform. A model can never supply (or pre-claim) a verification result.
            claim.pop("verification", None)

            # 5B. Evidence Reference Existence Validation (Tier 1)
            supporting_ids = claim.get("supporting_evidence_ids", [])
            if not isinstance(supporting_ids, list):
                raise ResponseParsingError(
                    f"Field 'supporting_evidence_ids' must be a list, got {type(supporting_ids).__name__}"
                )

            parsed_ids: list[uuid.UUID] = []
            all_valid_and_present = bool(supporting_ids)
            for ev_id in supporting_ids:
                try:
                    u = uuid.UUID(str(ev_id))
                    parsed_ids.append(u)
                    if u not in context_event_uuids:
                        all_valid_and_present = False
                except (ValueError, TypeError):
                    all_valid_and_present = False

            claim["supporting_evidence_ids"] = parsed_ids
            if not all_valid_and_present:
                claim["references_exist"] = False
                claim["grounding_status"] = GroundingStatus.UNSUPPORTED.value
                claim["confidence"] = 0.0
                notes = claim.get("analyst_notes") or ""
                claim["analyst_notes"] = (notes + " [UNSUPPORTED: Cited evidence UUIDs not found in context]").strip()
            else:
                claim["references_exist"] = True

        # Validate MITRE ATT&CK hypotheses
        raw_hypotheses = data.get("mitre_attack_hypotheses", [])
        if isinstance(raw_hypotheses, list):
            for hyp in raw_hypotheses:
                if isinstance(hyp, dict):
                    supporting_uuids = hyp.get("supporting_event_uuids", [])
                    if isinstance(supporting_uuids, list):
                        parsed_uuids: list[uuid.UUID] = []
                        all_exist = bool(supporting_uuids)
                        for ev_id in supporting_uuids:
                            try:
                                u = uuid.UUID(str(ev_id))
                                if u in context_event_uuids:
                                    parsed_uuids.append(u)
                                else:
                                    all_exist = False
                            except (ValueError, TypeError):
                                all_exist = False

                        if not all_exist:
                            hyp["confidence"] = 0.0
                            reasoning = hyp.get("reasoning", "")
                            hyp["reasoning"] = f"{reasoning} [UNSUPPORTED: Cited event UUIDs not found in context]".strip()
                            hyp["supporting_event_uuids"] = parsed_uuids
                        else:
                            hyp["supporting_event_uuids"] = parsed_uuids

        # 6. Recompute overall_grounding_score
        if raw_claims:
            validated_count = sum(
                1 for c in raw_claims
                if c.get("grounding_status") in (
                    GroundingStatus.VALIDATED_REFERENCE,
                    GroundingStatus.VALIDATED_REFERENCE.value,
                    "validated_reference",
                )
            )
            data["overall_grounding_score"] = validated_count / len(raw_claims)
        else:
            data["overall_grounding_score"] = 0.0

        # 7. Model validation against Pydantic contract
        try:
            return StructuredInvestigationOutput.model_validate(data)
        except ValidationError as exc:
            raise ResponseParsingError(f"Response failed schema validation: {exc}") from exc

    def build_deterministic_fallback(
        self,
        context: InvestigationContext,
        failure_reason: str,
        assessment: "EvidenceSufficiencyAssessment | None" = None,
    ) -> StructuredInvestigationOutput:
        """
        Construct an objective, factually grounded fallback report directly from InvestigationContext.

        Used when LLM inference fails, times out, or returns unparseable content.
        Does not invent claims, IOCs, ATT&CK techniques, or imply a benign verdict.

        When an INSUFFICIENT evidence-sufficiency ``assessment`` is supplied (Stage 3C,
        ADR-008) the report is an explicit, auditable abstention: it states that no model
        was invoked, lists only fixed-vocabulary reason codes, and never implies a verdict.
        """
        if assessment is not None and assessment.abstain:
            return self._build_abstention_output(context, assessment)

        clean_reason = failure_reason.strip()[:200]
        hosts_str = ", ".join(sorted(context.target_hosts)) if context.target_hosts else "unspecified"

        summary = (
            f"Automated AI investigation synthesis was unavailable ({clean_reason}). "
            f"Deterministic factual scope: {len(context.events)} events analyzed across "
            f"{len(context.target_hosts)} host(s) ({hosts_str}). "
            f"Total events in window: {context.budget_metrics.total_events_in_scope}."
        )

        flags = list(context.uncertainty_flags)
        flags.append(f"SYNTHESIS_FAILURE: AI synthesis unavailable ({clean_reason})")
        clean_flags = sorted(set(f.strip() for f in flags if f.strip()))

        return StructuredInvestigationOutput(
            investigation_id=context.investigation_id,
            generated_at=datetime.now(timezone.utc),
            model_identifier="deterministic_fallback",
            investigation_summary=summary,
            claims=[],
            mitre_attack_hypotheses=[],
            alternative_explanations=[],
            recommended_analyst_actions=[
                "Review raw telemetry and audit logs directly for the target hosts; automated AI synthesis was unavailable."
            ],
            uncertainty_and_data_gaps=clean_flags,
            overall_grounding_score=0.0,
        )

    def _build_abstention_output(
        self,
        context: InvestigationContext,
        assessment: "EvidenceSufficiencyAssessment",
    ) -> StructuredInvestigationOutput:
        """
        Explicit analyst abstention for INSUFFICIENT evidence (ADR-008). Uses only the
        fixed-vocabulary reason codes and counts: no evidence text, no claims, no
        hypotheses, and no implication that the activity is benign or malicious.
        """
        codes = ", ".join(assessment.reason_codes) if assessment.reason_codes else "NONE"
        summary = (
            "Automated AI investigation synthesis was unavailable because the available evidence is "
            f"insufficient (analyst abstention; reason codes: {codes}); no AI synthesis was invoked. "
            f"Deterministic scope: {assessment.total_events} event(s) in context, "
            f"{assessment.relevant_events} relevant to the investigation question. "
            "No conclusion about the nature of the observed activity is made."
        )
        flags = list(context.uncertainty_flags)
        flags.extend(assessment.disclosure_flags())
        flags.append(f"ABSTENTION: Evidence assessed INSUFFICIENT ({codes}); AI synthesis not invoked")
        clean_flags = sorted(set(f.strip() for f in flags if f.strip()))
        return StructuredInvestigationOutput(
            investigation_id=context.investigation_id,
            generated_at=datetime.now(timezone.utc),
            model_identifier="deterministic_fallback",
            investigation_summary=summary,
            claims=[],
            mitre_attack_hypotheses=[],
            alternative_explanations=[],
            recommended_analyst_actions=[
                "Collect or link the missing evidence indicated by the reason codes, or review the raw "
                "telemetry directly; the platform abstained because the evidence is insufficient."
            ],
            uncertainty_and_data_gaps=clean_flags,
            overall_grounding_score=0.0,
        )
