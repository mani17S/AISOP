"""
AISOP Local Threat Intelligence Engine.

Implements the offline-first, zero-cost ThreatIntelProvider interface
backed by deterministic local feed parsers and thread-safe TTL caching.
"""

from __future__ import annotations

from typing import Any

from app.modules.threatintel.cache.memory_cache import ThreatIntelMemoryCache
from app.modules.threatintel.exceptions import InvalidObservableError
from app.modules.threatintel.feeds.manager import LocalFeedManager
from app.modules.threatintel.models import (
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatVerdict,
)
from app.modules.threatintel.protocol import ThreatIntelProvider
from app.modules.threatintel.validation import normalize_observable


class LocalThreatIntelEngine:
    """
    Offline local threat intelligence engine conforming to ThreatIntelProvider.

    Guarantees:
    - Zero external network requests: 100% offline, local-first execution.
    - Safety invariant: A feed non-match returns NOT_FOUND with UNKNOWN verdict.
      Never produces BENIGN by default.
    - Distinguishable states: An empty/uninitialized engine returns PROVIDER_FAILURE,
      distinct from a healthy feed querying a non-matching observable (NOT_FOUND).
    - Multi-source correlation: Preserves distinct provenance when multiple local
      feeds report the same observable.
    - Documented conflict policy:
      * MALICIOUS evidence is never overridden by BENIGN or SUSPICIOUS.
      * SUSPICIOUS context is distinct from MALICIOUS and cannot be overridden by BENIGN.
      * BENIGN is returned only if all matching sources report BENIGN.
    - Stale intelligence transparency: Stale matches are tagged with 'stale_feed'
      and enumerated in raw_data['stale_feeds'].
    - Automatic cache consistency: Feed updates automatically invalidate affected
      positive and negative cache entries.
    """

    def __init__(
        self,
        feed_manager: LocalFeedManager | None = None,
        cache: ThreatIntelMemoryCache | None = None,
        cache_ttl_seconds: float = 3600.0,
        negative_cache_ttl_seconds: float = 300.0,
    ) -> None:
        self.feed_manager = feed_manager or LocalFeedManager()
        self.cache = cache or ThreatIntelMemoryCache(default_ttl_seconds=cache_ttl_seconds)
        self.cache_ttl_seconds = cache_ttl_seconds
        self.negative_cache_ttl_seconds = negative_cache_ttl_seconds

        # Auto-register cache invalidation callback so feed updates automatically purge stale cache entries
        def _on_feed_changed(affected_keys: set[tuple[str, str]] | None) -> None:
            if affected_keys is None:
                self.cache.clear()
            else:
                self.cache.invalidate_keys(affected_keys)

        self.feed_manager.register_invalidation_callback(_on_feed_changed)

    @property
    def provider_name(self) -> str:
        return "local_intelligence"

    @property
    def supported_observable_types(self) -> frozenset[ObservableType]:
        return frozenset(
            {
                ObservableType.IPV4,
                ObservableType.IPV6,
                ObservableType.DOMAIN,
                ObservableType.MD5,
                ObservableType.SHA1,
                ObservableType.SHA256,
            }
        )

    async def lookup(self, request: ThreatIntelRequest) -> ThreatIntelResult:
        """
        Execute deterministic local threat intelligence lookup.
        """
        # 1. Normalize and strictly validate observable
        try:
            observable = normalize_observable(
                request.observable, request.observable_type
            )
        except InvalidObservableError as exc:
            obs_type: ObservableType
            if isinstance(request.observable_type, ObservableType):
                obs_type = request.observable_type
            elif exc.observable_type and exc.observable_type in ObservableType._value2member_map_:
                obs_type = ObservableType(exc.observable_type)
            else:
                obs_type = ObservableType.DOMAIN

            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=obs_type,
                raw_observable=request.observable,
                normalized_observable=request.observable,
                status=ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE,
                verdict=ThreatVerdict.UNKNOWN,
                error_message=f"Observable validation failed: {exc.message}",
            )

        # 2. Check feed availability (Do not return NOT_FOUND if zero feeds are loaded)
        if self.feed_manager.total_indicators() == 0:
            return ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.PROVIDER_FAILURE,
                verdict=ThreatVerdict.UNKNOWN,
                error_message="Local threat intelligence engine has no feeds loaded or configured",
                raw_data={
                    "match_count": 0,
                    "feeds_active": 0,
                    "total_indicators_indexed": 0,
                },
            )

        # 3. Check in-memory cache
        cached_entry = self.cache.get(observable.type, observable.normalized_value)
        if cached_entry is not None:
            _, cached_result = cached_entry
            if cached_result is not None:
                return cached_result

        # 4. Query local feed manager
        records = self.feed_manager.get_indicators(
            observable.type, observable.normalized_value
        )

        # 5. Handle match
        if records:
            # Multi-source verdict resolution hierarchy:
            # MALICIOUS > SUSPICIOUS > BENIGN > UNKNOWN
            has_malicious = any(r.verdict == ThreatVerdict.MALICIOUS for r in records)
            has_suspicious = any(r.verdict == ThreatVerdict.SUSPICIOUS for r in records)
            all_benign = all(r.verdict == ThreatVerdict.BENIGN for r in records)

            if has_malicious:
                verdict = ThreatVerdict.MALICIOUS
            elif has_suspicious:
                verdict = ThreatVerdict.SUSPICIOUS
            elif all_benign:
                verdict = ThreatVerdict.BENIGN
            else:
                verdict = ThreatVerdict.UNKNOWN

            # Staleness inspection
            stale_feeds = [
                r.source_feed for r in records if self.feed_manager.is_stale(r.source_feed)
            ]
            any_stale = bool(stale_feeds)

            tags: set[str] = set()
            for r in records:
                tags.update(r.tags)
                if r.threat_category:
                    tags.add(r.threat_category)
                if r.malware_family:
                    tags.add(r.malware_family.lower())

            if any_stale:
                tags.add("stale_feed")

            raw_data: dict[str, Any] = {
                "match_count": len(records),
                "is_stale": any_stale,
                "stale_feeds": stale_feeds,
                "sources": [
                    {
                        "source_feed": r.source_feed,
                        "verdict": r.verdict.value,
                        "threat_category": r.threat_category,
                        "malware_family": r.malware_family,
                        "confidence": r.confidence,
                        "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                        "feed_retrieved_at": r.feed_retrieved_at.isoformat(),
                        "source_reference": r.source_reference,
                        "licence": r.licence,
                        "metadata": r.metadata,
                    }
                    for r in records
                ],
            }

            result = ThreatIntelResult(
                provider_name=self.provider_name,
                observable_type=observable.type,
                raw_observable=observable.raw_value,
                normalized_observable=observable.normalized_value,
                status=ThreatIntelLookupStatus.SUCCESS,
                verdict=verdict,
                tags=sorted(tags),
                raw_data=raw_data,
            )
            self.cache.set(
                observable.type,
                observable.normalized_value,
                records,
                result=result,
                ttl_seconds=self.cache_ttl_seconds,
            )
            return result

        # 6. Handle non-match: NEVER mark BENIGN
        not_found_result = ThreatIntelResult(
            provider_name=self.provider_name,
            observable_type=observable.type,
            raw_observable=observable.raw_value,
            normalized_observable=observable.normalized_value,
            status=ThreatIntelLookupStatus.NOT_FOUND,
            verdict=ThreatVerdict.UNKNOWN,
            error_message="Observable not found in local threat intelligence feeds",
            raw_data={
                "match_count": 0,
                "feeds_active": len(self.feed_manager.list_feed_metadata()),
                "total_indicators_indexed": self.feed_manager.total_indicators(),
            },
        )
        self.cache.set(
            observable.type,
            observable.normalized_value,
            [],
            result=not_found_result,
            ttl_seconds=self.negative_cache_ttl_seconds,
        )
        return not_found_result

    async def aclose(self) -> None:
        """Release local cache resources."""
        self.cache.clear()
