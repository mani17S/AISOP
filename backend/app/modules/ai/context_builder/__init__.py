"""
AISOP AI Context Builder Package.
"""

from app.modules.ai.context_builder.context_builder import (
    MAX_CONTEXT_CHARS,
    IncompleteContextOverflowError,
    InvestigationContextBuilder,
    aggregate_context_entities,
    build_investigation_context,
    prune_to_evidence_budget,
    resolve_causal_lineage,
)
from app.modules.ai.context_builder.hasher import (
    CANONICALIZATION_ALGORITHM_IDENTIFIER,
    CanonicalSerializationError,
    CanonicalSerializationTypeError,
    CanonicalSerializationValueError,
    canonicalize_payload,
    compute_context_sha256,
    filter_canonical_payload,
)

__all__ = [
    "InvestigationContextBuilder",
    "IncompleteContextOverflowError",
    "MAX_CONTEXT_CHARS",
    "build_investigation_context",
    "resolve_causal_lineage",
    "aggregate_context_entities",
    "prune_to_evidence_budget",
    "CANONICALIZATION_ALGORITHM_IDENTIFIER",
    "CanonicalSerializationError",
    "CanonicalSerializationTypeError",
    "CanonicalSerializationValueError",
    "canonicalize_payload",
    "compute_context_sha256",
    "filter_canonical_payload",
]
