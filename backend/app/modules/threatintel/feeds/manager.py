"""
AISOP Threat Intelligence Local Feed Manager.

Maintains active in-memory indicator collections, tracks source metadata,
enforces atomic feed updates with Last-Known-Good preservation, and supports
thread-safe invalidation callbacks for cache consistency.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import threading
from typing import Any, Callable

from app.modules.threatintel.feeds.models import (
    FeedMetadata,
    FeedParseResult,
    LocalIndicatorRecord,
)
from app.modules.threatintel.feeds.parsers import BaseFeedParser
from app.modules.threatintel.models import ObservableType

logger = logging.getLogger(__name__)


class LocalFeedManager:
    """
    Manages collection of local threat intelligence feeds.

    Guarantees:
    - Thread-safe feed mutations and reads using an internal reentrant lock.
    - Atomic updates: Ingesting a new feed snapshot completely replaces previous
      indicators for that feed without leaving intermediate partial states.
    - Last-Known-Good (LKG) preservation: If a feed update payload fails validation
      or contains zero valid indicators, the existing dataset for that feed is preserved.
    - Invalidation hooks: Dispatches affected indicator keys to registered callbacks
      so caching layers maintain immediate consistency without polling.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._feed_records: dict[str, dict[tuple[str, str], LocalIndicatorRecord]] = {}
        self._feed_metadata: dict[str, FeedMetadata] = {}
        self._invalidation_callbacks: list[Callable[[set[tuple[str, str]] | None], None]] = []

    def register_invalidation_callback(
        self,
        callback: Callable[[set[tuple[str, str]] | None], None],
    ) -> None:
        """
        Register a callback invoked when feeds are updated or cleared.
        Callback receives set of affected (observable_type, normalized_value) keys,
        or None if all feeds/keys are cleared.
        """
        with self._lock:
            if callback not in self._invalidation_callbacks:
                self._invalidation_callbacks.append(callback)

    def unregister_invalidation_callback(
        self,
        callback: Callable[[set[tuple[str, str]] | None], None],
    ) -> None:
        """Unregister a previously registered invalidation callback."""
        with self._lock:
            if callback in self._invalidation_callbacks:
                self._invalidation_callbacks.remove(callback)

    def _notify_invalidation(self, affected_keys: set[tuple[str, str]] | None) -> None:
        """Invoke all registered invalidation callbacks safely."""
        for cb in list(self._invalidation_callbacks):
            try:
                cb(affected_keys)
            except Exception as exc:
                logger.warning("Feed invalidation callback failed: %s", exc)

    def update_feed(
        self,
        parser: BaseFeedParser,
        raw_content: str,
        retrieved_at: datetime | None = None,
        max_age_seconds: float = 86400.0,
    ) -> FeedParseResult:
        """
        Parse and atomically load a feed payload.

        If parsing fails or produces 0 valid records, retains the last-known-good dataset.
        Notifies all registered invalidation callbacks of modified indicator keys.
        """
        feed_name = parser.feed_name
        parse_result = parser.parse(
            raw_content,
            retrieved_at=retrieved_at,
            max_age_seconds=max_age_seconds,
        )

        with self._lock:
            if len(parse_result.records) == 0:
                logger.error(
                    "Feed parsing produced 0 valid records; retaining last-known-good dataset (feed=%s, malformed=%d)",
                    feed_name,
                    parse_result.malformed_count,
                )
                existing_meta = self._feed_metadata.get(feed_name)
                if existing_meta:
                    existing_meta.last_error = f"Parse failed: {parse_result.errors[0] if parse_result.errors else 'no valid records'}"
                return parse_result

            new_records: dict[tuple[str, str], LocalIndicatorRecord] = {}
            for rec in parse_result.records:
                key = (rec.observable_type.value, rec.normalized_value)
                new_records[key] = rec

            old_records = self._feed_records.get(feed_name, {})
            old_keys = set(old_records.keys())
            new_keys = set(new_records.keys())

            self._feed_records[feed_name] = new_records
            self._feed_metadata[feed_name] = parse_result.metadata

            # Invalidate all keys that existed previously or exist now in this feed
            affected_keys = old_keys.union(new_keys)
            self._notify_invalidation(affected_keys)

            logger.info(
                "Successfully updated local threat intelligence feed (feed=%s, records=%d, duplicates=%d, malformed=%d)",
                feed_name,
                len(new_records),
                parse_result.duplicate_count,
                parse_result.malformed_count,
            )
            return parse_result

    def get_indicators(
        self,
        observable_type: ObservableType | str,
        normalized_value: str,
    ) -> list[LocalIndicatorRecord]:
        """
        Query all active feeds for matching indicators.
        Returns all source records matching the indicator.
        """
        type_str = observable_type.value if isinstance(observable_type, ObservableType) else str(observable_type).lower()
        key = (type_str, normalized_value)
        matches: list[LocalIndicatorRecord] = []

        with self._lock:
            for feed_name, record_map in self._feed_records.items():
                meta = self._feed_metadata.get(feed_name)
                if meta and not meta.is_active:
                    continue
                if key in record_map:
                    matches.append(record_map[key])

        return matches

    def get_feed_metadata(self, feed_name: str) -> FeedMetadata | None:
        """Retrieve metadata for a specific feed."""
        with self._lock:
            return self._feed_metadata.get(feed_name)

    def list_feed_metadata(self) -> list[FeedMetadata]:
        """List metadata across all registered feeds."""
        with self._lock:
            return list(self._feed_metadata.values())

    def is_stale(self, feed_name: str, now: datetime | None = None) -> bool:
        """Check whether a specific feed has exceeded its freshness lifetime."""
        with self._lock:
            meta = self._feed_metadata.get(feed_name)
            if not meta:
                return True
            return meta.is_stale(now)

    def total_indicators(self) -> int:
        """Total number of indicators currently loaded across all feeds."""
        with self._lock:
            return sum(len(records) for records in self._feed_records.values())

    
    def load_feeds_from_directory(
        self,
        feed_dir: str | Any,
        max_age_seconds: float = 86400.0,
    ) -> dict[str, FeedParseResult]:
        """
        Scan a local directory for known threat intelligence feed files and load them.

        Supported feeds by filename pattern:
        - Files containing 'feodo' (e.g. feodo_tracker.csv, feodo.csv) -> FeodoTrackerParser
        - Files containing 'tor' or 'exit' (e.g. tor_exit_nodes.txt, tor_exits.txt) -> TorExitNodeParser

        Derives retrieved_at timestamp from the file modification time to enable
        accurate staleness detection without external network timestamps.

        Conservative error handling:
        - Missing or inaccessible directory returns empty dict without throwing.
        - Corrupt, invalid, or empty files log warnings and do not overwrite last-known-good datasets.
        """
        from pathlib import Path
        from app.modules.threatintel.feeds.parsers import FeodoTrackerParser, TorExitNodeParser

        path = Path(feed_dir)
        results: dict[str, FeedParseResult] = {}

        if not path.exists():
            logger.warning("Local threat intelligence feed directory '%s' does not exist; no feeds loaded.", path)
            return results

        if not path.is_dir():
            logger.warning("Local threat intelligence feed path '%s' is not a directory; no feeds loaded.", path)
            return results

        parser_specs: list[tuple[Callable[[str], bool], BaseFeedParser]] = [
            (lambda name: "feodo" in name.lower(), FeodoTrackerParser()),
            (lambda name: "tor" in name.lower() or "exit" in name.lower(), TorExitNodeParser()),
        ]

        try:
            entries = list(path.iterdir())
        except Exception as exc:
            logger.error("Failed to list feed directory '%s': %s", path, exc)
            return results

        for file_entry in entries:
            if not file_entry.is_file():
                continue

            matched_parser: BaseFeedParser | None = None
            for matcher, parser_instance in parser_specs:
                if matcher(file_entry.name):
                    matched_parser = parser_instance
                    break

            if matched_parser is None:
                continue

            try:
                raw_text = file_entry.read_text(encoding="utf-8", errors="replace")
                mtime = file_entry.stat().st_mtime
                retrieved_at = datetime.fromtimestamp(mtime, tz=timezone.utc)
                parse_result = self.update_feed(
                    matched_parser,
                    raw_text,
                    retrieved_at=retrieved_at,
                    max_age_seconds=max_age_seconds,
                )
                results[matched_parser.feed_name] = parse_result
                logger.info(
                    "Loaded local threat feed '%s' from '%s' (%d valid indicators)",
                    matched_parser.feed_name,
                    file_entry.name,
                    len(parse_result.records),
                )
            except Exception as exc:
                logger.error("Failed to read local feed file '%s': %s", file_entry, exc)

        return results

    def clear(self) -> None:
        """Reset all in-memory feeds and notify invalidation callbacks."""
        with self._lock:
            self._feed_records.clear()
            self._feed_metadata.clear()
            self._notify_invalidation(None)
