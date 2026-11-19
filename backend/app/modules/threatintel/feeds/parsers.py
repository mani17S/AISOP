"""
AISOP Local Threat Intelligence Feed Parsers.

Implements deterministic, offline parsers for open threat intelligence feeds:
- FeodoTrackerParser: abuse.ch Feodo Tracker botnet C2 IP blocklist (CC0 1.0).
- TorExitNodeParser: Tor Project exit relay address list.
"""

from __future__ import annotations

import csv
import hashlib
import io
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from app.modules.threatintel.exceptions import InvalidObservableError
from app.modules.threatintel.feeds.models import (
    FeedMetadata,
    FeedParseResult,
    LocalIndicatorRecord,
)
from app.modules.threatintel.models import ObservableType, ThreatVerdict
from app.modules.threatintel.validation import validate_ipv4, validate_ipv6


class BaseFeedParser(ABC):
    """Abstract base class for feed parsing implementations."""

    @property
    @abstractmethod
    def feed_name(self) -> str:
        """Canonical identifier of the feed."""
        ...

    @property
    @abstractmethod
    def default_source_url(self) -> str:
        """Official source URL for the feed data."""
        ...

    @property
    @abstractmethod
    def licence(self) -> str:
        """Attribution and redistribution terms."""
        ...

    @abstractmethod
    def parse(
        self,
        raw_content: str,
        retrieved_at: datetime | None = None,
        max_age_seconds: float = 86400.0,
    ) -> FeedParseResult:
        """Parse raw feed text into validated LocalIndicatorRecords."""
        ...


class FeodoTrackerParser(BaseFeedParser):
    """
    Parser for abuse.ch Feodo Tracker botnet C2 IP lists.

    Supports both:
    1. CSV format with headers:
       `# Firstseen_UTC,DstIP,DstPort,C2Status,LastOnline,Malware`
    2. Simple plain IP list format:
       Lines starting with '#' are ignored; other lines contain one IP address.

    Semantic classification:
    - Feodo Tracker tracks confirmed C2 nodes of banking trojans (QakBot, Emotet, Dridex).
    - Verdict: ThreatVerdict.MALICIOUS.
    - Threat category: 'botnet_c2'.
    - Licence: CC0 1.0 (Public Domain).
    """

    @property
    def feed_name(self) -> str:
        return "feodo_tracker"

    @property
    def default_source_url(self) -> str:
        return "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

    @property
    def licence(self) -> str:
        return "CC0 1.0 (Public Domain)"

    def parse(
        self,
        raw_content: str,
        retrieved_at: datetime | None = None,
        max_age_seconds: float = 86400.0,
    ) -> FeedParseResult:
        retrieval_time = retrieved_at or datetime.now(timezone.utc)
        if retrieval_time.tzinfo is None:
            retrieval_time = retrieval_time.replace(tzinfo=timezone.utc)

        checksum = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
        records: list[LocalIndicatorRecord] = []
        seen_ips: set[str] = set()
        malformed = 0
        duplicates = 0
        errors: list[str] = []

        lines = [line.strip() for line in raw_content.splitlines()]

        for line_idx, line in enumerate(lines, start=1):
            if not line or line.startswith("#"):
                continue

            if "," in line:
                reader = csv.reader(io.StringIO(line))
                try:
                    row = next(reader)
                except Exception as exc:
                    malformed += 1
                    errors.append(f"Line {line_idx}: CSV parse failed: {exc}")
                    continue

                if not row:
                    continue

                if any("dstip" in col.lower() or "firstseen" in col.lower() for col in row):
                    continue

                ip_raw = row[1].strip() if len(row) > 1 else row[0].strip()
                first_seen_str = row[0].strip() if len(row) > 0 else None
                port_str = row[2].strip() if len(row) > 2 else None
                status_str = row[3].strip() if len(row) > 3 else None
                last_seen_str = row[4].strip() if len(row) > 4 else None
                malware_name = row[5].strip() if len(row) > 5 else None
            else:
                ip_raw = line.split()[0]
                first_seen_str = None
                port_str = None
                status_str = None
                last_seen_str = None
                malware_name = None

            try:
                norm_ip = validate_ipv4(ip_raw)
            except InvalidObservableError as exc:
                malformed += 1
                errors.append(f"Line {line_idx}: Invalid IPv4 '{ip_raw}': {exc.message}")
                continue

            if norm_ip in seen_ips:
                duplicates += 1
                continue
            seen_ips.add(norm_ip)

            first_seen_dt: datetime | None = None
            if first_seen_str:
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                    try:
                        first_seen_dt = datetime.strptime(first_seen_str, fmt).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        pass

            last_seen_dt: datetime | None = None
            if last_seen_str:
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                    try:
                        last_seen_dt = datetime.strptime(last_seen_str, fmt).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        pass

            tags = ["c2", "botnet"]
            if malware_name:
                tags.append(malware_name.lower())

            metadata: dict[str, Any] = {"feed": self.feed_name}
            if port_str:
                try:
                    metadata["dst_port"] = int(port_str)
                except ValueError:
                    metadata["dst_port"] = port_str
            if status_str:
                metadata["c2_status"] = status_str

            rec = LocalIndicatorRecord(
                observable_type=ObservableType.IPV4,
                normalized_value=norm_ip,
                raw_value=ip_raw,
                source_feed=self.feed_name,
                verdict=ThreatVerdict.MALICIOUS,
                threat_category="botnet_c2",
                malware_family=malware_name,
                confidence=100.0,
                first_seen=first_seen_dt,
                last_seen=last_seen_dt,
                feed_retrieved_at=retrieval_time,
                feed_checksum=checksum,
                source_reference=self.default_source_url,
                licence=self.licence,
                tags=tags,
                metadata=metadata,
            )
            records.append(rec)

        metadata_obj = FeedMetadata(
            feed_name=self.feed_name,
            retrieved_at=retrieval_time,
            record_count=len(records),
            checksum=checksum,
            source_url=self.default_source_url,
            licence=self.licence,
            max_age_seconds=max_age_seconds,
            last_error=errors[0] if errors and not records else None,
        )

        return FeedParseResult(
            feed_name=self.feed_name,
            records=records,
            malformed_count=malformed,
            duplicate_count=duplicates,
            errors=errors[:10],
            metadata=metadata_obj,
        )


class TorExitNodeParser(BaseFeedParser):
    """
    Parser for Tor Project exit-address lists.

    Supports:
    1. Official Tor Project exit-addresses block format:
       ExitNode <fingerprint>
       Published <YYYY-MM-DD HH:MM:SS>
       LastStatus <YYYY-MM-DD HH:MM:SS>
       ExitAddress <IP> <YYYY-MM-DD HH:MM:SS>
    2. Simple plain IP list format (one IPv4 or IPv6 per line).

    Semantic classification:
    - Tor exit nodes represent anonymization infrastructure context, NOT confirmed malware.
    - Verdict: ThreatVerdict.SUSPICIOUS.
    - Threat category: 'anonymization_proxy'.
    - Licence: Tor Project Open Data.
    """

    @property
    def feed_name(self) -> str:
        return "tor_exit_nodes"

    @property
    def default_source_url(self) -> str:
        return "https://check.torproject.org/exit-addresses"

    @property
    def licence(self) -> str:
        return "Tor Project Open Data"

    def parse(
        self,
        raw_content: str,
        retrieved_at: datetime | None = None,
        max_age_seconds: float = 86400.0,
    ) -> FeedParseResult:
        retrieval_time = retrieved_at or datetime.now(timezone.utc)
        if retrieval_time.tzinfo is None:
            retrieval_time = retrieval_time.replace(tzinfo=timezone.utc)

        checksum = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
        records: list[LocalIndicatorRecord] = []
        seen_ips: set[str] = set()
        malformed = 0
        duplicates = 0
        errors: list[str] = []

        current_node: str | None = None
        current_published: datetime | None = None

        for line_idx, line in enumerate(raw_content.splitlines(), start=1):
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue

            parts = cleaned.split()

            if parts[0] == "ExitNode" and len(parts) >= 2:
                current_node = parts[1]
                continue
            elif parts[0] == "Published" and len(parts) >= 3:
                try:
                    dt_str = f"{parts[1]} {parts[2]}"
                    current_published = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    current_published = None
                continue
            elif parts[0] == "LastStatus":
                continue
            elif parts[0] == "ExitAddress" and len(parts) >= 2:
                ip_raw = parts[1]
                exit_seen_dt: datetime | None = None
                if len(parts) >= 4:
                    try:
                        exit_dt_str = f"{parts[2]} {parts[3]}"
                        exit_seen_dt = datetime.strptime(exit_dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass
            else:
                ip_raw = parts[0]
                exit_seen_dt = None

            obs_type: ObservableType
            norm_ip: str
            try:
                norm_ip = validate_ipv4(ip_raw)
                obs_type = ObservableType.IPV4
            except InvalidObservableError:
                try:
                    norm_ip = validate_ipv6(ip_raw)
                    obs_type = ObservableType.IPV6
                except InvalidObservableError as exc:
                    malformed += 1
                    errors.append(f"Line {line_idx}: Invalid IP '{ip_raw}': {exc.message}")
                    continue

            if norm_ip in seen_ips:
                duplicates += 1
                continue
            seen_ips.add(norm_ip)

            metadata: dict[str, Any] = {
                "feed": self.feed_name,
                "is_tor_exit": True,
            }
            if current_node:
                metadata["fingerprint"] = current_node

            rec = LocalIndicatorRecord(
                observable_type=obs_type,
                normalized_value=norm_ip,
                raw_value=ip_raw,
                source_feed=self.feed_name,
                verdict=ThreatVerdict.SUSPICIOUS,
                threat_category="anonymization_proxy",
                malware_family=None,
                confidence=None,
                first_seen=current_published,
                last_seen=exit_seen_dt or current_published,
                feed_retrieved_at=retrieval_time,
                feed_checksum=checksum,
                source_reference=self.default_source_url,
                licence=self.licence,
                tags=["tor", "exit_relay", "proxy"],
                metadata=metadata,
            )
            records.append(rec)

        metadata_obj = FeedMetadata(
            feed_name=self.feed_name,
            retrieved_at=retrieval_time,
            record_count=len(records),
            checksum=checksum,
            source_url=self.default_source_url,
            licence=self.licence,
            max_age_seconds=max_age_seconds,
            last_error=errors[0] if errors and not records else None,
        )

        return FeedParseResult(
            feed_name=self.feed_name,
            records=records,
            malformed_count=malformed,
            duplicate_count=duplicates,
            errors=errors[:10],
            metadata=metadata_obj,
        )
