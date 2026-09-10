"""
Unit tests for CanonicalEvent schema and typed entities.
"""

from datetime import datetime, timezone
import pytest
from app.schemas.entities import HostEntity, ProcessEntity, UserEntity
from app.schemas.normalized_event import CanonicalEvent


def test_canonical_event_defaults():
    event = CanonicalEvent(
        event_id="1",
        event_type="process_creation",
        raw_ref="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert event.event_id == "1"
    assert event.event_type == "process_creation"
    assert event.outcome == "success"
    assert event.severity == "informational"
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo is not None


def test_canonical_event_with_entities():
    proc = ProcessEntity(
        image_path="C:\\Windows\\System32\\cmd.exe",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        pid=1234,
        ppid=5678,
        hashes={"SHA256": "abcdef123456"},
    )
    user = UserEntity(username="analyst", domain="CORP")
    host = HostEntity(hostname="WORKSTATION-01")

    event = CanonicalEvent(
        event_id="1",
        event_type="process_creation",
        raw_ref="sha256_dummy",
        process=proc,
        user=user,
        host=host,
    )

    assert event.process is not None
    assert event.process.command_line == "cmd.exe /c whoami"
    assert event.user is not None
    assert event.user.username == "analyst"
    assert event.host is not None
    assert event.host.hostname == "WORKSTATION-01"
