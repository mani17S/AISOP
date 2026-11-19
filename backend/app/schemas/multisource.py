"""
AISOP multi-source investigation API schemas (Stage 4, ADR-010).

The stored/returned investigation result is a JSON document (``dict``) whose shape is produced by
``MultiSourceInvestigationService.build_payload`` and documented in
``docs/05_Backend/Multi_Source_Investigation_API.md``. Only the request and the section selector are
strict models: everything the analyst submits is validated here.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MultiSourceInvestigationRequest(BaseModel):
    """Body of POST /cases/{case_id}/investigations/multisource (human-initiated)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    use_llm: bool = Field(
        default=False,
        description="Also run the optional gated LLM investigation. Default false: the deterministic workflow needs no model.",
    )
    force: bool = Field(
        default=False,
        description="Run again even if an investigation for the identical evidence set already exists (appends a new audit record).",
    )


class DomainEvidenceImportRequest(BaseModel):
    """Body of POST /cases/{case_id}/evidence/domain: ``aisop.evidence/1`` envelopes (validated per record by the adapters)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    records: list[dict] = Field(min_length=1, max_length=500, description="Evidence envelopes; malformed ones are quarantined, not stored")


class MultiSourceSection(StrEnum):
    """Retrievable views of the latest stored investigation."""

    STATUS = "status"
    TIMELINE = "timeline"
    CORRELATION = "correlation"
    ATTACK = "attack"
    SUFFICIENCY = "sufficiency"
    REPORT = "report"
    GRAPH = "graph"        # ADR-011: entity graph, correlation rationale, TI context, analyst statements
    EVIDENCE = "evidence"  # ADR-011: per-record classification, source identity, time status, trust class
