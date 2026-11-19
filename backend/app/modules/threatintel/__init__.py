"""
AISOP Threat Intelligence Foundation & Local-First Engine.

In accordance with ADR-001 (Direct Lightweight Abstraction):
Provides a provider-neutral, typed contract, strict observable validation,
asynchronous provider protocol, base adapter implementation, and local offline
threat intelligence engine with deterministic in-memory caching.
"""

from __future__ import annotations

from app.modules.threatintel.base import BaseThreatIntelProvider
from app.modules.threatintel.cache.memory_cache import ThreatIntelMemoryCache
from app.modules.threatintel.exceptions import (
    InvalidObservableError,
    ThreatIntelAuthenticationError,
    ThreatIntelConnectionError,
    ThreatIntelError,
    ThreatIntelRateLimitError,
    ThreatIntelResponseError,
    ThreatIntelTimeoutError,
    UnsupportedObservableError,
)
from app.modules.threatintel.feeds.manager import LocalFeedManager
from app.modules.threatintel.feeds.models import (
    FeedMetadata,
    FeedParseResult,
    LocalIndicatorRecord,
)
from app.modules.threatintel.feeds.parsers import (
    BaseFeedParser,
    FeodoTrackerParser,
    TorExitNodeParser,
)
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.modules.threatintel.models import (
    Observable,
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelRequest,
    ThreatIntelResult,
    ThreatVerdict,
)
from app.modules.threatintel.protocol import ThreatIntelProvider
from app.modules.threatintel.validation import (
    detect_observable_type,
    from_extracted_entity,
    normalize_observable,
    validate_domain,
    validate_hash,
    validate_ipv4,
    validate_ipv6,
    validate_md5,
    validate_sha1,
    validate_sha256,
)

__all__ = [
    # Models & Enums
    "ObservableType",
    "ThreatIntelLookupStatus",
    "ThreatVerdict",
    "Observable",
    "ThreatIntelRequest",
    "ThreatIntelResult",
    # Protocol & Providers
    "ThreatIntelProvider",
    "BaseThreatIntelProvider",
    "LocalThreatIntelEngine",
    # Feeds & Cache
    "LocalIndicatorRecord",
    "FeedMetadata",
    "FeedParseResult",
    "BaseFeedParser",
    "FeodoTrackerParser",
    "TorExitNodeParser",
    "LocalFeedManager",
    "ThreatIntelMemoryCache",
    # Validation & Normalization
    "validate_ipv4",
    "validate_ipv6",
    "validate_domain",
    "validate_hash",
    "validate_md5",
    "validate_sha1",
    "validate_sha256",
    "detect_observable_type",
    "normalize_observable",
    "from_extracted_entity",
    # Exceptions
    "ThreatIntelError",
    "InvalidObservableError",
    "UnsupportedObservableError",
    "ThreatIntelConnectionError",
    "ThreatIntelTimeoutError",
    "ThreatIntelRateLimitError",
    "ThreatIntelAuthenticationError",
    "ThreatIntelResponseError",
]
