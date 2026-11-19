"""
Lazy, once-per-provider holder for the OPTIONAL pinned ATT&CK catalogue (composition aid, not a second loader).

It wraps the existing ``try_load_catalogue`` and adds only what composition needs:
  * explicit states - ``NOT_CONFIGURED`` (no path), ``NOT_LOADED`` (configured, not yet needed), ``AVAILABLE`` and
    ``UNAVAILABLE`` (a load was attempted and failed: hash/version/path/structure; never presented as valid);
  * the dataset is parsed AT MOST ONCE per provider instance, on first use, under a lock, so concurrent callers never
    trigger duplicate loads; a failure is cached too, so a missing or corrupt file is never re-read in a tight loop
    (a new provider instance, i.e. a process restart, is the explicit retry);
  * the loaded catalogue is immutable, so sharing it between requests is safe. Each worker process keeps its own copy.

No network, no database, no persistence, no environment or settings access here, no startup hook. Whoever composes the
application decides whether a provider exists and what path it receives.
"""

from __future__ import annotations

import threading
from enum import StrEnum
from pathlib import Path
from typing import Callable, Optional

from app.modules.attack_reference.loader import ENTERPRISE_V20_1, CatalogueLoadResult, PinnedRelease, try_load_catalogue
from app.modules.attack_reference.models import AttackReferenceCatalogue


class ProviderState(StrEnum):
    NOT_CONFIGURED = "not_configured"
    NOT_LOADED = "not_loaded"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class AttackCatalogueProvider:
    def __init__(
        self,
        path: Optional[Path | str] = None,
        expected: PinnedRelease = ENTERPRISE_V20_1,
        *,
        loader: Callable[..., CatalogueLoadResult] = try_load_catalogue,
    ) -> None:
        text = str(path).strip() if path is not None else ""
        self._path: Optional[str] = text or None
        self._expected = expected
        self._loader = loader
        self._lock = threading.Lock()
        self._result: Optional[CatalogueLoadResult] = None
        self._load_count = 0

    @classmethod
    def from_catalogue(cls, source: AttackReferenceCatalogue | CatalogueLoadResult) -> "AttackCatalogueProvider":
        """A provider that is already resolved (tests, or a caller that loaded the catalogue itself). Never loads."""
        provider = cls(path=None)
        provider._result = source if isinstance(source, CatalogueLoadResult) else CatalogueLoadResult(catalogue=source)
        return provider

    @property
    def state(self) -> ProviderState:
        """Never triggers a load."""
        if self._result is not None:
            return ProviderState.AVAILABLE if self._result.available else ProviderState.UNAVAILABLE
        return ProviderState.NOT_LOADED if self._path is not None else ProviderState.NOT_CONFIGURED

    @property
    def load_count(self) -> int:
        """How many times the dataset was parsed by this provider (0 or 1)."""
        return self._load_count

    def resolve(self) -> Optional[CatalogueLoadResult]:
        """
        ``None`` when not configured (the validator then reports NOT_CONFIGURED); otherwise the cached load result,
        loading once on first use. The first call blocks for the load (about half a second for the pinned file).
        """
        if self._result is not None:
            return self._result
        if self._path is None:
            return None
        with self._lock:
            if self._result is None:
                self._load_count += 1
                self._result = self._loader(self._path, self._expected)
            return self._result
