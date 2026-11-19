"""Single source for the report wording of the two model-related metrics (Phase 2.1).

Labels and definitions only. No calculation lives here: the machine-readable fields
(``overall_grounding_score`` and per-claim ``confidence``) keep their names and values.
"""

from __future__ import annotations

CLAIMS_VALIDATED_LABEL = "Claims validated"
MODEL_REPORTED_CONFIDENCE_LABEL = "Model-reported confidence"

CLAIMS_VALIDATED_DEFINITION = (
    "Claims validated: the percentage of claims whose citations passed the configured validation checks. "
    "It is not evidence strength, and it does not establish that a cited source is truthful or that a claim is factually correct."
)
MODEL_REPORTED_CONFIDENCE_DEFINITION = (
    "Model-reported confidence: a value reported by the language model and only capped by guardrails. "
    "It is not independently measured evidence strength."
)
