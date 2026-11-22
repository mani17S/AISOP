"""
Deterministic report section "Defensive countermeasures (MITRE D3FEND reference)" and the lazy once-per-process provider.

Optional and offline. ``DEFENSE_REFERENCE_PATH`` unset -> ``render_section`` returns no lines and the report is unchanged.
Configured but unreadable/tampered -> a one-line unavailable note (never presented as valid, never partial).
The section is built from the loaded reference only; no language model writes or edits it.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional, Sequence

from app.modules.defense_reference.loader import (
    Category,
    DefenseLoadResult,
    DefensiveTechnique,
    try_load_defense_catalogue,
)

SECTION_TITLE = "Defensive countermeasures (MITRE D3FEND reference)"
DISCLAIMER = (
    "Reference suggestions for the analyst, derived from the MITRE D3FEND technique mapping for the ATT&CK techniques mapped above. "
    "They are NOT observed evidence, were not derived from this incident's data, and are NOT a statement that a control is missing, "
    "disabled or failed. D3FEND relates techniques through the digital artifacts they act on; the list is not exhaustive or ranked and "
    "does not claim that any technique would have prevented or detected this activity. No language model wrote this section."
)


class DefenseReferenceProvider:
    """Loads the pinned reference at most once (a failure is cached too); a restart is the explicit retry."""

    def __init__(self, path: Optional[str], loader: Callable[[str], DefenseLoadResult] = try_load_defense_catalogue) -> None:
        text = str(path).strip() if path is not None else ""
        self._path: Optional[str] = text or None
        self._loader = loader
        self._lock = threading.Lock()
        self._result: Optional[DefenseLoadResult] = None

    @property
    def configured(self) -> bool:
        return self._path is not None

    def resolve(self) -> Optional[DefenseLoadResult]:
        """``None`` when not configured; otherwise the cached load result (loaded on first use)."""
        if self._path is None:
            return None
        with self._lock:
            if self._result is None:
                self._result = self._loader(self._path)
            return self._result


_default: Optional[DefenseReferenceProvider] = None
_default_path: Optional[str] = None


def default_provider() -> DefenseReferenceProvider:
    """Provider for the configured ``DEFENSE_REFERENCE_PATH``; rebuilt only if the configured path changes."""
    global _default, _default_path
    from app.core.config import get_settings  # local: keep the loader importable without settings

    path = get_settings().DEFENSE_REFERENCE_PATH
    if _default is None or _default_path != path:
        _default, _default_path = DefenseReferenceProvider(path), path
    return _default


def _group(techs: Sequence[DefensiveTechnique]) -> list[str]:
    lines = []
    for cat in Category:
        names = [f"{t.name} ({t.d3fend_id})" for t in techs if t.category == cat]
        if names:
            lines.append(f"  - {cat.value}: {', '.join(names)}")
    return lines


def render_section(
    technique_ids: Sequence[str], technique_names: Optional[dict[str, str]] = None, provider: Optional[DefenseReferenceProvider] = None
) -> list[str]:
    """
    Markdown lines for the report (empty list = no section). ``technique_ids`` must be the ATT&CK techniques the
    deterministic rules already mapped; nothing here adds a technique. ``technique_names`` are those rules' own names.
    """
    if not technique_ids:
        return []
    result = (provider or default_provider()).resolve()
    if result is None:
        return []
    lines = [f"## 4a. {SECTION_TITLE}", ""]
    if result.catalogue is None:
        lines += [f"The D3FEND reference is configured but unavailable ({result.error_code.value if result.error_code else 'error'}); "
                  "no defensive techniques are shown. This is not a finding about the incident.", ""]
        return lines
    cat = result.catalogue
    lines += [DISCLAIMER, ""]
    found = cat.lookup(list(technique_ids))
    names = technique_names or {}
    for tid in dict.fromkeys(str(t).strip().upper() for t in technique_ids):
        label = f"{tid} {names[tid]}" if tid in names else tid
        if tid in found:
            lines.append(f"- **{label}**: {len(found[tid])} related D3FEND technique(s)")
            lines += _group(found[tid])
        else:
            lines.append(f"- **{label}**: no D3FEND technique is mapped to this exact ATT&CK technique in the pinned reference.")
    lines += ["", f"Source: MITRE D3FEND ontology {cat.d3fend_version}, offline, hash-verified "
                  f"(mapping SHA-256 `{cat.mappings_sha256[:16]}`). Sub-techniques are not resolved through their parent technique.", ""]
    return lines
