"""
AISOP Threat Intelligence In-Memory TTL Cache.

Provides deterministic, time-travel capable, thread-safe in-memory caching
for threat intelligence lookup results with type-isolated keys and batch invalidation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import threading
from typing import Callable

from app.modules.threatintel.feeds.models import LocalIndicatorRecord
from app.modules.threatintel.models import ObservableType, ThreatIntelResult


class ThreatIntelMemoryCache:
    """
    Deterministic in-memory cache for threat intelligence lookups.

    Features:
    - Thread-safe reads, writes, and batch invalidation using reentrant locking.
    - Type-isolated composite keys: `(observable_type, normalized_value)`.
    - Pluggable `now_fn` for millisecond-accurate, deterministic unit testing without sleeps.
    - Explicit TTL retention for indicator records and normalized results.
    - Granular single-key and batch-key invalidation.
    """

    def __init__(
        self,
        default_ttl_seconds: float = 3600.0,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._store: dict[
            tuple[str, str],
            tuple[datetime, list[LocalIndicatorRecord], ThreatIntelResult | None],
        ] = {}

    def _get_key(
        self,
        observable_type: ObservableType | str,
        normalized_value: str,
    ) -> tuple[str, str]:
        type_str = observable_type.value if isinstance(observable_type, ObservableType) else str(observable_type).lower()
        return (type_str, normalized_value)

    def get(
        self,
        observable_type: ObservableType | str,
        normalized_value: str,
    ) -> tuple[list[LocalIndicatorRecord], ThreatIntelResult | None] | None:
        """
        Retrieve cached indicator records and optional synthesized result.
        Returns None if key is absent or expired.
        """
        key = self._get_key(observable_type, normalized_value)
        with self._lock:
            if key not in self._store:
                return None

            expires_at, records, result = self._store[key]
            current_time = self.now_fn()
            if current_time.tzinfo is None:
                current_time = current_time.replace(tzinfo=timezone.utc)

            if current_time >= expires_at:
                del self._store[key]
                return None

            return records, result

    def set(
        self,
        observable_type: ObservableType | str,
        normalized_value: str,
        records: list[LocalIndicatorRecord],
        result: ThreatIntelResult | None = None,
        ttl_seconds: float | None = None,
    ) -> None:
        """
        Store indicator records and optional result with explicit TTL.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        current_time = self.now_fn()
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)

        expires_at = current_time + timedelta(seconds=ttl)
        key = self._get_key(observable_type, normalized_value)
        with self._lock:
            self._store[key] = (expires_at, records, result)

    def invalidate(
        self,
        observable_type: ObservableType | str,
        normalized_value: str,
    ) -> bool:
        """Remove a specific indicator from the cache."""
        key = self._get_key(observable_type, normalized_value)
        with self._lock:
            return self._store.pop(key, None) is not None

    def invalidate_keys(self, keys: set[tuple[str, str]]) -> int:
        """
        Remove a batch of indicator keys from the cache.
        Returns count of keys successfully removed.
        """
        removed = 0
        with self._lock:
            for k in keys:
                type_str = k[0].value if isinstance(k[0], ObservableType) else str(k[0]).lower()
                val = str(k[1])
                if self._store.pop((type_str, val), None) is not None:
                    removed += 1
        return removed

    def cleanup_expired(self) -> int:
        """Purge all expired cache entries and return count purged."""
        current_time = self.now_fn()
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)

        with self._lock:
            expired_keys = [
                k for k, (expires_at, _, _) in self._store.items() if current_time >= expires_at
            ]
            for k in expired_keys:
                del self._store[k]
            return len(expired_keys)

    def size(self) -> int:
        """Count of unexpired items in cache."""
        with self._lock:
            self.cleanup_expired()
            return len(self._store)

    def clear(self) -> None:
        """Flush the entire cache."""
        with self._lock:
            self._store.clear()
