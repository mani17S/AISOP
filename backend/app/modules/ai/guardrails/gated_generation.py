"""
AISOP Gated Generation (Stage 3C, ADR-008).

``GatedGenerator.generate`` is the ONLY approved caller of ``LLMProvider.generate``
in production code. It refuses to invoke the provider unless it is given an
EvidenceSufficiencyAssessment whose verdict permits a model call and whose
context digest matches the context being investigated. An architecture test
(``test_sufficiency_gated_generation.py``) fails if any other ``.generate(`` call
appears in ``backend/app`` or ``backend/scripts`` outside the allow-list.
"""

from __future__ import annotations

from typing import Any, Optional

from app.schemas.investigation import InvestigationContext
from app.schemas.sufficiency import EvidenceSufficiencyAssessment


class SufficiencyGateViolation(RuntimeError):
    """Raised when a model invocation is attempted without a permitting assessment."""


class GatedGenerator:
    """Single choke point for production LLM generation."""

    @staticmethod
    async def generate(
        provider: Any,
        request: Any,
        assessment: Optional[EvidenceSufficiencyAssessment],
        context: Optional[InvestigationContext],
    ) -> Any:
        if not isinstance(assessment, EvidenceSufficiencyAssessment):
            raise SufficiencyGateViolation("Model invocation refused: no sufficiency assessment supplied")
        if assessment.abstain:
            raise SufficiencyGateViolation("Model invocation refused: evidence assessed INSUFFICIENT")
        if context is None or assessment.context_sha256 != context.reproducibility.context_sha256:
            raise SufficiencyGateViolation("Model invocation refused: assessment does not match the context")
        return await provider.generate(request)
