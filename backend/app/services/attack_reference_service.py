"""
Composition point for the OPTIONAL local ATT&CK reference used by the deterministic output validator.

One cached provider per process (the project's ``get_settings`` convention: ``lru_cache``). It is created and
resolved lazily, only when a live validation path asks for it; application startup never touches it, and a missing,
corrupt or mismatching dataset degrades to an explicit ``unavailable`` state instead of failing anything.

``ATTACK_REFERENCE_PATH`` unset means NOT_CONFIGURED: the validator behaves exactly as before. Set it to the approved
local file to activate lifecycle validation. There is no network access and no automatic update.
"""

from __future__ import annotations

from functools import lru_cache

from app.core.config import get_settings
from app.modules.ai.guardrails.attack_policy import AttackReferenceSource
from app.modules.attack_reference.provider import AttackCatalogueProvider


@lru_cache(maxsize=1)
def get_attack_reference_provider() -> AttackCatalogueProvider:
    """Process-scope provider. Tests replace the settings getter and call ``cache_clear()``; they never share state."""
    return AttackCatalogueProvider(get_settings().ATTACK_REFERENCE_PATH)


def resolve_attack_reference() -> AttackReferenceSource:
    """What a live validator construction should receive: ``None`` (not configured) or a cached ``CatalogueLoadResult``."""
    return get_attack_reference_provider().resolve()
