"""
Unit tests for AISOP TI-2 Local-First Threat Intelligence Engine.

Validates:
- Feodo Tracker parsing (valid CSV, valid IP list, malformed rows, comments, whitespace, duplicates).
- Tor Exit Node parsing (valid block format, valid IP list, IPv4 & IPv6, malformed lines, duplicates).
- Safe feed update service with Last-Known-Good dataset preservation on empty or corrupt updates.
- Feed staleness detection and freshness tracking.
- In-memory cache deterministic TTL expiration and time-travel testing via now_fn.
- Type-isolated cache keys (e.g. ('ipv4', '1.1.1.1') vs ('domain', '1.1.1.1')).
- LocalThreatIntelEngine offline lookups with source attribution.
- Invariant: Non-matching lookups strictly return NOT_FOUND with ThreatVerdict.UNKNOWN (never BENIGN).
- Multi-source correlation: Multiple feeds reporting the same indicator preserve distinct provenance.
- Contradictory evidence: Deterministic verdict hierarchy without score averaging.
- Protocol conformance: isinstance(engine, ThreatIntelProvider).
- Integration with from_extracted_entity bridge.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from app.modules.evidence.entity_extractor import ExtractedEntityRecord
from app.modules.threatintel import (
    FeodoTrackerParser,
    LocalFeedManager,
    LocalIndicatorRecord,
    LocalThreatIntelEngine,
    ObservableType,
    ThreatIntelLookupStatus,
    ThreatIntelMemoryCache,
    ThreatIntelProvider,
    ThreatIntelRequest,
    ThreatVerdict,
    TorExitNodeParser,
    from_extracted_entity,
)

# ==============================================================================
# Synthetic Fixtures
# ==============================================================================

SYNTHETIC_FEODO_CSV = """# Abuse.ch Feodo Tracker IP Blocklist (Synthetic Test)
# Firstseen_UTC,DstIP,DstPort,C2Status,LastOnline,Malware
2026-10-20 10:00:00,198.51.100.1,443,online,2026-10-21,QakBot
2026-10-20 11:00:00,198.51.100.2,8080,online,2026-10-21,Emotet
# Duplicate row (should be deduplicated)
2026-10-20 12:00:00,198.51.100.1,443,online,2026-10-21,QakBot
# Malformed lines
invalid_ip_row,not_an_ip,80,online,2026-10-21,Dridex
999.999.999.999,999.999.999.999,80,online,2026-10-21,Dridex
"""

SYNTHETIC_FEODO_SIMPLE = """# Simple Feodo IP blocklist
198.51.100.10
198.51.100.11
# duplicate
198.51.100.10
"""

SYNTHETIC_TOR_BLOCK = """ExitNode 00112233445566778899AABBCCDDEEFF00112233
Published 2026-10-21 08:00:00
LastStatus 2026-10-21 08:30:00
ExitAddress 203.0.113.5 2026-10-21 08:35:00
ExitNode AABBCCDDEEFF00112233445566778899AABBCCDD
Published 2026-10-21 09:00:00
LastStatus 2026-10-21 09:30:00
ExitAddress 2001:db8::5 2026-10-21 09:35:00
# Duplicate exit address
ExitAddress 203.0.113.5 2026-10-21 09:40:00
# Malformed line
ExitAddress not_a_valid_ip 2026-10-21 09:45:00
"""

SYNTHETIC_TOR_SIMPLE = """# Tor exit list
203.0.113.20
2001:db8::20
"""


# ==============================================================================
# 1. Feed Parser Tests
# ==============================================================================


def test_feodo_tracker_parser_csv():
    parser = FeodoTrackerParser()
    res = parser.parse(SYNTHETIC_FEODO_CSV)

    assert res.feed_name == "feodo_tracker"
    assert len(res.records) == 2
    assert res.duplicate_count == 1
    assert res.malformed_count == 2
    assert len(res.errors) >= 1

    rec1 = res.records[0]
    assert rec1.normalized_value == "198.51.100.1"
    assert rec1.observable_type == ObservableType.IPV4
    assert rec1.verdict == ThreatVerdict.MALICIOUS
    assert rec1.threat_category == "botnet_c2"
    assert rec1.malware_family == "QakBot"
    assert rec1.confidence == 100.0
    assert rec1.source_feed == "feodo_tracker"
    assert rec1.licence == "CC0 1.0 (Public Domain)"
    assert "qakbot" in rec1.tags
    assert rec1.metadata.get("dst_port") == 443
    assert rec1.first_seen == datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)


def test_feodo_tracker_parser_simple_ip_list():
    parser = FeodoTrackerParser()
    res = parser.parse(SYNTHETIC_FEODO_SIMPLE)

    assert len(res.records) == 2
    assert res.duplicate_count == 1
    assert res.malformed_count == 0
    assert res.records[0].normalized_value == "198.51.100.10"
    assert res.records[0].verdict == ThreatVerdict.MALICIOUS


def test_tor_exit_node_parser_block_format():
    parser = TorExitNodeParser()
    res = parser.parse(SYNTHETIC_TOR_BLOCK)

    assert res.feed_name == "tor_exit_nodes"
    assert len(res.records) == 2  # 1 IPv4, 1 IPv6
    assert res.duplicate_count == 1
    assert res.malformed_count == 1

    rec_v4 = [r for r in res.records if r.observable_type == ObservableType.IPV4][0]
    assert rec_v4.normalized_value == "203.0.113.5"
    assert rec_v4.verdict == ThreatVerdict.SUSPICIOUS
    assert rec_v4.threat_category == "anonymization_proxy"
    assert rec_v4.metadata.get("is_tor_exit") is True
    assert rec_v4.metadata.get("fingerprint") == "00112233445566778899AABBCCDDEEFF00112233"

    rec_v6 = [r for r in res.records if r.observable_type == ObservableType.IPV6][0]
    assert rec_v6.normalized_value == "2001:db8::5"
    assert rec_v6.verdict == ThreatVerdict.SUSPICIOUS


def test_tor_exit_node_parser_simple():
    parser = TorExitNodeParser()
    res = parser.parse(SYNTHETIC_TOR_SIMPLE)

    assert len(res.records) == 2
    assert {r.normalized_value for r in res.records} == {"203.0.113.20", "2001:db8::20"}
    for r in res.records:
        assert r.verdict == ThreatVerdict.SUSPICIOUS
        assert r.threat_category == "anonymization_proxy"


# ==============================================================================
# 2. LocalFeedManager & Last-Known-Good Preservation Tests
# ==============================================================================


def test_feed_manager_atomic_update_and_lookup():
    manager = LocalFeedManager()
    parser = FeodoTrackerParser()

    res = manager.update_feed(parser, SYNTHETIC_FEODO_CSV)
    assert res.metadata.record_count == 2
    assert manager.total_indicators() == 2

    # Query matching indicator
    matches = manager.get_indicators(ObservableType.IPV4, "198.51.100.1")
    assert len(matches) == 1
    assert matches[0].malware_family == "QakBot"

    # Query non-matching indicator
    no_match = manager.get_indicators(ObservableType.IPV4, "8.8.8.8")
    assert len(no_match) == 0


def test_feed_manager_last_known_good_preservation_on_empty_update():
    manager = LocalFeedManager()
    parser = FeodoTrackerParser()

    # 1. Initial valid feed
    manager.update_feed(parser, SYNTHETIC_FEODO_CSV)
    assert manager.total_indicators() == 2

    # 2. Corrupt/empty update: whitespace only
    empty_res = manager.update_feed(parser, """   \n\n  """)
    assert len(empty_res.records) == 0
    # Existing dataset is preserved!
    assert manager.total_indicators() == 2
    assert len(manager.get_indicators(ObservableType.IPV4, "198.51.100.1")) == 1


def test_feed_manager_last_known_good_preservation_on_corrupt_payload():
    manager = LocalFeedManager()
    parser = FeodoTrackerParser()

    manager.update_feed(parser, SYNTHETIC_FEODO_CSV)
    assert manager.total_indicators() == 2

    # Update with completely invalid data (all rows malformed)
    corrupt_payload = """not_an_ip
also_bad
garbage_string"""
    bad_res = manager.update_feed(parser, corrupt_payload)
    assert len(bad_res.records) == 0
    assert bad_res.malformed_count == 3
    # Existing dataset is preserved!
    assert manager.total_indicators() == 2
    assert len(manager.get_indicators(ObservableType.IPV4, "198.51.100.1")) == 1


def test_feed_staleness_detection():
    manager = LocalFeedManager()
    parser = FeodoTrackerParser()
    t_past = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)

    # Max age 1 hour (3600 seconds)
    manager.update_feed(parser, SYNTHETIC_FEODO_CSV, retrieved_at=t_past, max_age_seconds=3600.0)

    # 30 minutes later: not stale
    t_fresh = t_past + timedelta(minutes=30)
    assert manager.is_stale("feodo_tracker", now=t_fresh) is False

    # 2 hours later: stale
    t_stale = t_past + timedelta(hours=2)
    assert manager.is_stale("feodo_tracker", now=t_stale) is True


# ==============================================================================
# 3. ThreatIntelMemoryCache Tests (Deterministic Time Travel)
# ==============================================================================


def test_memory_cache_ttl_and_time_travel():
    simulated_now = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)

    def mock_now() -> datetime:
        return simulated_now

    cache = ThreatIntelMemoryCache(default_ttl_seconds=300.0, now_fn=mock_now)

    rec = LocalIndicatorRecord(
        observable_type=ObservableType.IPV4,
        normalized_value="1.2.3.4",
        raw_value="1.2.3.4",
        source_feed="test_feed",
        verdict=ThreatVerdict.MALICIOUS,
        feed_retrieved_at=simulated_now,
    )

    cache.set(ObservableType.IPV4, "1.2.3.4", [rec], ttl_seconds=300.0)
    assert cache.size() == 1

    # 1. Lookup at T+60s -> Hit
    simulated_now += timedelta(seconds=60)
    cached = cache.get(ObservableType.IPV4, "1.2.3.4")
    assert cached is not None
    assert cached[0][0].normalized_value == "1.2.3.4"

    # 2. Lookup at T+301s -> Expired
    simulated_now += timedelta(seconds=241)  # Total 301s
    expired = cache.get(ObservableType.IPV4, "1.2.3.4")
    assert expired is None
    assert cache.size() == 0


def test_memory_cache_key_type_isolation():
    cache = ThreatIntelMemoryCache(default_ttl_seconds=300.0)

    rec_v4 = LocalIndicatorRecord(
        observable_type=ObservableType.IPV4,
        normalized_value="1.1.1.1",
        raw_value="1.1.1.1",
        source_feed="feed_a",
        verdict=ThreatVerdict.SUSPICIOUS,
    )
    rec_dom = LocalIndicatorRecord(
        observable_type=ObservableType.DOMAIN,
        normalized_value="1.1.1.1.com",
        raw_value="1.1.1.1.com",
        source_feed="feed_b",
        verdict=ThreatVerdict.MALICIOUS,
    )

    cache.set(ObservableType.IPV4, "1.1.1.1", [rec_v4])
    cache.set(ObservableType.DOMAIN, "1.1.1.1", [rec_dom])

    assert cache.size() == 2
    cached_v4 = cache.get(ObservableType.IPV4, "1.1.1.1")
    cached_dom = cache.get(ObservableType.DOMAIN, "1.1.1.1")

    assert cached_v4 is not None
    assert cached_dom is not None
    assert cached_v4[0][0].observable_type == ObservableType.IPV4
    assert cached_dom[0][0].observable_type == ObservableType.DOMAIN


# ==============================================================================
# 4. LocalThreatIntelEngine Lookup & Multi-Source Tests
# ==============================================================================


def test_engine_protocol_conformance():
    engine = LocalThreatIntelEngine()
    assert isinstance(engine, ThreatIntelProvider)
    assert engine.provider_name == "local_intelligence"
    assert ObservableType.IPV4 in engine.supported_observable_types
    assert ObservableType.IPV6 in engine.supported_observable_types


@pytest.mark.anyio
async def test_engine_matching_feodo_c2():
    manager = LocalFeedManager()
    manager.update_feed(FeodoTrackerParser(), SYNTHETIC_FEODO_CSV)
    engine = LocalThreatIntelEngine(feed_manager=manager)

    req = ThreatIntelRequest(observable=" 198.51.100.1 ")
    result = await engine.lookup(req)

    assert result.status == ThreatIntelLookupStatus.SUCCESS
    assert result.verdict == ThreatVerdict.MALICIOUS
    assert result.observable_type == ObservableType.IPV4
    assert result.normalized_observable == "198.51.100.1"
    assert result.is_malicious is True
    assert "qakbot" in result.tags
    assert "botnet_c2" in result.tags
    assert result.raw_data.get("match_count") == 1
    assert result.raw_data["sources"][0]["source_feed"] == "feodo_tracker"


@pytest.mark.anyio
async def test_engine_matching_tor_exit_relay():
    manager = LocalFeedManager()
    manager.update_feed(TorExitNodeParser(), SYNTHETIC_TOR_BLOCK)
    engine = LocalThreatIntelEngine(feed_manager=manager)

    req = ThreatIntelRequest(observable="203.0.113.5")
    result = await engine.lookup(req)

    assert result.status == ThreatIntelLookupStatus.SUCCESS
    # Tor exit node is classified as SUSPICIOUS (anonymization infrastructure), NOT MALICIOUS
    assert result.verdict == ThreatVerdict.SUSPICIOUS
    assert result.is_suspicious is True
    assert result.is_malicious is False
    assert "tor" in result.tags
    assert "anonymization_proxy" in result.tags


@pytest.mark.anyio
async def test_engine_non_matching_observable_returns_unknown_never_benign():
    manager = LocalFeedManager()
    manager.update_feed(FeodoTrackerParser(), SYNTHETIC_FEODO_CSV)
    engine = LocalThreatIntelEngine(feed_manager=manager)

    # 1. Clean IP not in feed
    req = ThreatIntelRequest(observable="8.8.8.8")
    result = await engine.lookup(req)

    # CRITICAL INVARIANT: Non-match must strictly be NOT_FOUND with UNKNOWN verdict.
    # It must NEVER be marked BENIGN.
    assert result.status == ThreatIntelLookupStatus.NOT_FOUND
    assert result.verdict == ThreatVerdict.UNKNOWN
    assert result.is_success is False
    assert result.is_benign is False
    assert result.is_malicious is False
    assert result.has_threat_signal is False


@pytest.mark.anyio
async def test_engine_empty_feeds_returns_provider_failure():
    engine = LocalThreatIntelEngine()  # Zero feeds loaded
    req = ThreatIntelRequest(observable="1.1.1.1")
    result = await engine.lookup(req)

    assert result.status == ThreatIntelLookupStatus.PROVIDER_FAILURE
    assert result.verdict == ThreatVerdict.UNKNOWN
    assert "no feeds loaded or configured" in (result.error_message or "").lower()


@pytest.mark.anyio
async def test_engine_multi_source_correlation_and_hierarchy():
    manager = LocalFeedManager()
    # Feed 1: Feodo (MALICIOUS)
    manager.update_feed(FeodoTrackerParser(), "198.51.100.99,198.51.100.99,443,online,2026-10-21,Dridex")
    # Feed 2: Tor (SUSPICIOUS)
    manager.update_feed(TorExitNodeParser(), "198.51.100.99")

    engine = LocalThreatIntelEngine(feed_manager=manager)
    req = ThreatIntelRequest(observable="198.51.100.99")
    result = await engine.lookup(req)

    assert result.status == ThreatIntelLookupStatus.SUCCESS
    # Hierarchy: MALICIOUS takes precedence over SUSPICIOUS
    assert result.verdict == ThreatVerdict.MALICIOUS
    assert result.raw_data.get("match_count") == 2

    # Preserves distinct provenance for BOTH sources
    sources = result.raw_data.get("sources", [])
    assert len(sources) == 2
    feeds_present = {s["source_feed"] for s in sources}
    assert feeds_present == {"feodo_tracker", "tor_exit_nodes"}

    # Both categories preserved
    assert "botnet_c2" in result.tags
    assert "anonymization_proxy" in result.tags


@pytest.mark.anyio
async def test_engine_cached_lookup():
    manager = LocalFeedManager()
    manager.update_feed(FeodoTrackerParser(), SYNTHETIC_FEODO_CSV)
    cache = ThreatIntelMemoryCache()
    engine = LocalThreatIntelEngine(feed_manager=manager, cache=cache)

    req = ThreatIntelRequest(observable="198.51.100.1")
    res1 = await engine.lookup(req)
    assert res1.status == ThreatIntelLookupStatus.SUCCESS
    assert cache.size() == 1

    # Second lookup served directly from memory cache
    res2 = await engine.lookup(req)
    assert res2.status == ThreatIntelLookupStatus.SUCCESS
    assert res2.verdict == res1.verdict
    assert res2.normalized_observable == res1.normalized_observable


@pytest.mark.anyio
async def test_engine_malformed_observable_rejected():
    engine = LocalThreatIntelEngine()
    req = ThreatIntelRequest(observable="completely_invalid_indicator!!!")
    result = await engine.lookup(req)

    assert result.status == ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE
    assert result.verdict == ThreatVerdict.UNKNOWN
    assert "validation failed" in (result.error_message or "").lower()


def test_extracted_entity_record_bridge_to_engine():
    # Verify ExtractedEntityRecord can be normalized and passed to local engine
    ip_rec = ExtractedEntityRecord(
        entity_type="ip",
        entity_value="198.51.100.1",
        role="destination",
        attributes={"port": 443},
    )
    obs = from_extracted_entity(ip_rec)
    req = ThreatIntelRequest(
        observable=obs.normalized_value,
        observable_type=obs.type,
    )
    assert req.observable == "198.51.100.1"
    assert req.observable_type == ObservableType.IPV4


# ==============================================================================
# TI-2.2 Regression Hardening Tests
# ==============================================================================

@pytest.mark.anyio
async def test_regression_negative_cache_invalidated_on_feed_update_addition():
    """Verify that a negative cache entry is invalidated when a feed update adds the indicator."""
    manager = LocalFeedManager()
    parser = FeodoTrackerParser()
    cache = ThreatIntelMemoryCache()
    engine = LocalThreatIntelEngine(feed_manager=manager, cache=cache)

    # 1. Populate initial feed
    manager.update_feed(parser, "2026-10-22,198.51.100.1,443,online,QakBot")

    # 2. Lookup unlisted IP 198.51.100.2 -> NOT_FOUND cached
    req = ThreatIntelRequest(observable="198.51.100.2", observable_type=ObservableType.IPV4)
    res1 = await engine.lookup(req)
    assert res1.status == ThreatIntelLookupStatus.NOT_FOUND
    assert res1.verdict == ThreatVerdict.UNKNOWN

    # Confirm it is in cache
    cached_val = cache.get(ObservableType.IPV4, "198.51.100.2")
    assert cached_val is not None
    assert cached_val[1].status == ThreatIntelLookupStatus.NOT_FOUND

    # 3. Feed update adds 198.51.100.2
    manager.update_feed(
        parser,
        "2026-10-22,198.51.100.1,443,online,QakBot\n2026-10-22,198.51.100.2,443,online,2026-10-22,Emotet",
    )

    # Cache must be invalidated for 198.51.100.2
    assert cache.get(ObservableType.IPV4, "198.51.100.2") is None

    # 4. Subsequent lookup returns newly added MALICIOUS intelligence
    res2 = await engine.lookup(req)
    assert res2.status == ThreatIntelLookupStatus.SUCCESS
    assert res2.verdict == ThreatVerdict.MALICIOUS
    assert "emotet" in res2.tags
    assert res2.raw_data["sources"][0]["malware_family"] == "Emotet"


@pytest.mark.anyio
async def test_regression_positive_cache_invalidated_on_feed_update_removal():
    """Verify that a positive cache entry is invalidated when a feed update removes the indicator."""
    manager = LocalFeedManager()
    parser = FeodoTrackerParser()
    cache = ThreatIntelMemoryCache()
    engine = LocalThreatIntelEngine(feed_manager=manager, cache=cache)

    # 1. Populate feed with two IPs
    manager.update_feed(
        parser,
        "2026-10-22,198.51.100.1,443,online,QakBot\n2026-10-22,198.51.100.2,443,online,2026-10-22,Emotet",
    )

    # 2. Lookup 198.51.100.2 -> SUCCESS cached
    req = ThreatIntelRequest(observable="198.51.100.2", observable_type=ObservableType.IPV4)
    res1 = await engine.lookup(req)
    assert res1.status == ThreatIntelLookupStatus.SUCCESS
    assert res1.verdict == ThreatVerdict.MALICIOUS

    # 3. Feed update removes 198.51.100.2 (only retains 198.51.100.1)
    manager.update_feed(parser, "2026-10-22,198.51.100.1,443,online,QakBot")

    # Cache for 198.51.100.2 must be invalidated
    assert cache.get(ObservableType.IPV4, "198.51.100.2") is None

    # 4. Subsequent lookup returns NOT_FOUND / UNKNOWN
    res2 = await engine.lookup(req)
    assert res2.status == ThreatIntelLookupStatus.NOT_FOUND
    assert res2.verdict == ThreatVerdict.UNKNOWN


@pytest.mark.anyio
async def test_regression_clearing_feeds_invalidates_cache():
    """Verify that clearing feeds invalidates all cached decisions."""
    manager = LocalFeedManager()
    parser = FeodoTrackerParser()
    cache = ThreatIntelMemoryCache()
    engine = LocalThreatIntelEngine(feed_manager=manager, cache=cache)

    manager.update_feed(parser, "2026-10-22,198.51.100.1,443,online,QakBot")
    req = ThreatIntelRequest(observable="198.51.100.1", observable_type=ObservableType.IPV4)
    res1 = await engine.lookup(req)
    assert res1.status == ThreatIntelLookupStatus.SUCCESS
    assert cache.size() > 0

    # Clear feeds
    manager.clear()
    assert cache.size() == 0

    # Querying now reflects empty feeds
    res2 = await engine.lookup(req)
    assert res2.status == ThreatIntelLookupStatus.PROVIDER_FAILURE


@pytest.mark.anyio
async def test_regression_unusable_feed_distinguishable_from_no_match():
    """Verify that an uninitialized feed returns PROVIDER_FAILURE while active feed returns NOT_FOUND."""
    # Engine A: zero feeds loaded
    empty_engine = LocalThreatIntelEngine()
    req = ThreatIntelRequest(observable="198.51.100.42", observable_type=ObservableType.IPV4)
    res_empty = await empty_engine.lookup(req)
    assert res_empty.status == ThreatIntelLookupStatus.PROVIDER_FAILURE
    assert res_empty.verdict == ThreatVerdict.UNKNOWN
    assert "no feeds loaded" in res_empty.error_message.lower()

    # Engine B: healthy feed loaded, but observable unlisted
    manager = LocalFeedManager()
    manager.update_feed(FeodoTrackerParser(), "2026-10-22,198.51.100.1,443,online,QakBot")
    healthy_engine = LocalThreatIntelEngine(feed_manager=manager)
    res_nomatch = await healthy_engine.lookup(req)
    assert res_nomatch.status == ThreatIntelLookupStatus.NOT_FOUND
    assert res_nomatch.verdict == ThreatVerdict.UNKNOWN
    assert "not found in local threat intelligence feeds" in res_nomatch.error_message.lower()


@pytest.mark.anyio
async def test_regression_stale_matched_result_has_explicit_tag_and_warning():
    """Verify that stale feed matches are tagged with 'stale_feed' and list stale feeds in raw_data."""
    manager = LocalFeedManager()
    # Create indicator with timestamp 48h in the past
    stale_time = datetime.now(timezone.utc) - timedelta(hours=48)
    parser = FeodoTrackerParser()
    res = parser.parse("2026-10-22,198.51.100.1,443,online,QakBot", retrieved_at=stale_time)
    
    # Store directly with stale retrieved_at
    manager._feed_records[parser.feed_name] = {
        (ObservableType.IPV4.value, "198.51.100.1"): res.records[0]
    }
    manager._feed_metadata[parser.feed_name] = res.metadata

    assert manager.is_stale(parser.feed_name) is True

    engine = LocalThreatIntelEngine(feed_manager=manager)
    lookup_res = await engine.lookup(ThreatIntelRequest(observable="198.51.100.1", observable_type=ObservableType.IPV4))

    assert lookup_res.status == ThreatIntelLookupStatus.SUCCESS
    assert lookup_res.verdict == ThreatVerdict.MALICIOUS  # Underlying verdict preserved!
    assert "stale_feed" in lookup_res.tags  # Explicit structured tag
    assert lookup_res.raw_data["is_stale"] is True
    assert parser.feed_name in lookup_res.raw_data["stale_feeds"]


@pytest.mark.anyio
async def test_regression_conflicting_verdict_synthesis_hierarchy():
    """Verify conflict resolution: MALICIOUS > SUSPICIOUS > BENIGN > UNKNOWN."""
    manager = LocalFeedManager()

    # 1. Allowlist only: produces BENIGN
    benign_rec = LocalIndicatorRecord(
        observable_type=ObservableType.IPV4,
        normalized_value="198.51.100.10",
        raw_value="198.51.100.10",
        source_feed="allowlist_feed",
        verdict=ThreatVerdict.BENIGN,
        threat_category="trusted_partner",
        retrieved_at=datetime.now(timezone.utc),
    )
    from app.modules.threatintel.feeds.models import FeedMetadata
    manager._feed_records["allowlist_feed"] = {
        (ObservableType.IPV4.value, "198.51.100.10"): benign_rec
    }
    manager._feed_metadata["allowlist_feed"] = FeedMetadata(
        feed_name="allowlist_feed",
        retrieved_at=datetime.now(timezone.utc),
        record_count=1,
        checksum="aaa",
        source_url="http://internal",
        licence="internal",
    )

    engine = LocalThreatIntelEngine(feed_manager=manager)
    res_benign = await engine.lookup(ThreatIntelRequest(observable="198.51.100.10", observable_type=ObservableType.IPV4))
    assert res_benign.verdict == ThreatVerdict.BENIGN

    # 2. Add SUSPICIOUS feed match for same indicator -> SUSPICIOUS overrides BENIGN
    suspicious_rec = LocalIndicatorRecord(
        observable_type=ObservableType.IPV4,
        normalized_value="198.51.100.10",
        raw_value="198.51.100.10",
        source_feed="tor_feed",
        verdict=ThreatVerdict.SUSPICIOUS,
        threat_category="anonymization_proxy",
        retrieved_at=datetime.now(timezone.utc),
    )
    manager._feed_records["tor_feed"] = {
        (ObservableType.IPV4.value, "198.51.100.10"): suspicious_rec
    }
    manager._feed_metadata["tor_feed"] = FeedMetadata(
        feed_name="tor_feed",
        retrieved_at=datetime.now(timezone.utc),
        record_count=1,
        checksum="bbb",
        source_url="http://internal",
        licence="internal",
    )

    # Invalidate cache for new lookup
    engine.cache.clear()
    res_susp = await engine.lookup(ThreatIntelRequest(observable="198.51.100.10", observable_type=ObservableType.IPV4))
    assert res_susp.verdict == ThreatVerdict.SUSPICIOUS

    # 3. Add MALICIOUS feed match for same indicator -> MALICIOUS overrides SUSPICIOUS and BENIGN
    malicious_rec = LocalIndicatorRecord(
        observable_type=ObservableType.IPV4,
        normalized_value="198.51.100.10",
        raw_value="198.51.100.10",
        source_feed="c2_feed",
        verdict=ThreatVerdict.MALICIOUS,
        threat_category="botnet_c2",
        malware_family="QakBot",
        retrieved_at=datetime.now(timezone.utc),
    )
    manager._feed_records["c2_feed"] = {
        (ObservableType.IPV4.value, "198.51.100.10"): malicious_rec
    }
    manager._feed_metadata["c2_feed"] = FeedMetadata(
        feed_name="c2_feed",
        retrieved_at=datetime.now(timezone.utc),
        record_count=1,
        checksum="ccc",
        source_url="http://internal",
        licence="internal",
    )

    engine.cache.clear()
    res_mal = await engine.lookup(ThreatIntelRequest(observable="198.51.100.10", observable_type=ObservableType.IPV4))
    assert res_mal.verdict == ThreatVerdict.MALICIOUS
    # Sources list retains all 3 distinct sources!
    assert len(res_mal.raw_data["sources"]) == 3


@pytest.mark.anyio
async def test_regression_malformed_observables_distinguishable_from_valid_no_match():
    """Verify that malformed observables produce UNSUPPORTED_OBSERVABLE rather than NOT_FOUND."""
    manager = LocalFeedManager()
    manager.update_feed(FeodoTrackerParser(), "2026-10-22,198.51.100.1,443,online,QakBot")
    engine = LocalThreatIntelEngine(feed_manager=manager)

    # Malformed IP (out of range octet)
    bad_req = ThreatIntelRequest(observable="999.999.999.999", observable_type=ObservableType.IPV4)
    bad_res = await engine.lookup(bad_req)
    assert bad_res.status == ThreatIntelLookupStatus.UNSUPPORTED_OBSERVABLE
    assert bad_res.verdict == ThreatVerdict.UNKNOWN
    assert "Observable validation failed" in bad_res.error_message

    # Valid IP not in feed
    valid_req = ThreatIntelRequest(observable="198.51.100.200", observable_type=ObservableType.IPV4)
    valid_res = await engine.lookup(valid_req)
    assert valid_res.status == ThreatIntelLookupStatus.NOT_FOUND
    assert valid_res.verdict == ThreatVerdict.UNKNOWN
