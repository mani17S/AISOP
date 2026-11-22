"""
Optional, offline MITRE D3FEND reference: ATT&CK technique -> related defensive techniques, shown beside (never instead of)
the evidence-backed ATT&CK mapping. Reference data only: not evidence, not corroboration, not a severity or verdict input.
"""

from app.modules.defense_reference.loader import (
    D3FEND_1_6_0,
    Category,
    DefenseCatalogue,
    DefenseLoadResult,
    DefenseReferenceError,
    DefensiveTechnique,
    ErrorCode,
    PinnedD3fend,
    load_defense_catalogue,
    try_load_defense_catalogue,
)
from app.modules.defense_reference.section import (
    SECTION_TITLE,
    DefenseReferenceProvider,
    default_provider,
    render_section,
)

__all__ = [
    "D3FEND_1_6_0", "SECTION_TITLE", "Category", "DefenseCatalogue", "DefenseLoadResult", "DefenseReferenceError",
    "DefenseReferenceProvider", "DefensiveTechnique", "ErrorCode", "PinnedD3fend", "default_provider",
    "load_defense_catalogue", "render_section", "try_load_defense_catalogue",
]
