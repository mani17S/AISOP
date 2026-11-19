"""
Local ATT&CK reference loader and report-only drift classification (reference data, not an engine).

Optional and uninstantiated by application startup: nothing in the live application imports this package. It reads a
pinned, already-acquired local file, never uses the network or a database, and is not a threat-intelligence
provider, evidence source, corroboration source or severity input.
"""

from app.modules.attack_reference.drift import (
    DriftClass,
    DriftRow,
    MappingOccurrence,
    OccurrenceKind,
    classify_all,
    classify_occurrence,
    render_drift_markdown,
    summarize,
)
from app.modules.attack_reference.loader import (
    DEFAULT_DATASET_PATH,
    ENTERPRISE_V20_1,
    AttackReferenceError,
    CatalogueLoadResult,
    ErrorCode,
    PinnedRelease,
    catalogue_from_document,
    load_catalogue,
    try_load_catalogue,
)
from app.modules.attack_reference.models import (
    AttackReferenceCatalogue,
    CatalogueMeta,
    Lifecycle,
    ReferenceStatus,
    TacticRecord,
    TechniqueLookup,
    TechniqueRecord,
)

__all__ = [
    "AttackReferenceCatalogue", "AttackReferenceError", "CatalogueLoadResult", "CatalogueMeta", "DEFAULT_DATASET_PATH",
    "DriftClass", "DriftRow", "ENTERPRISE_V20_1", "ErrorCode", "Lifecycle", "MappingOccurrence", "OccurrenceKind",
    "PinnedRelease", "ReferenceStatus", "TacticRecord", "TechniqueLookup", "TechniqueRecord", "catalogue_from_document",
    "classify_all", "classify_occurrence", "load_catalogue", "render_drift_markdown", "summarize", "try_load_catalogue",
]
