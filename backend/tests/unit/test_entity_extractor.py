"""
Unit tests for atomic entity extractor.
"""

from app.modules.evidence.entity_extractor import extract_entities
from app.modules.evidence.sysmon_parser import SysmonParser


def test_extract_entities_from_process_event():
    raw_event = {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Computer": "VICTIM-PC",
        "User": "CORP\\alice",
        "Hashes": "SHA256=1122334455667788",
    }
    parser = SysmonParser()
    events = parser.parse(raw_event)
    assert len(events) == 1

    entities = extract_entities(events[0])
    types = [e.entity_type for e in entities]
    values = [e.entity_value for e in entities]

    assert "host" in types
    assert "VICTIM-PC" in values

    assert "user" in types
    assert "corp\\alice" in values

    assert "process" in types
    assert "cmd.exe" in values
    assert "explorer.exe" in values

    assert "file_hash" in types
    assert "1122334455667788" in values


def test_extract_entities_from_network_event():
    raw_event = {
        "EventID": 3,
        "SourceIp": "10.0.0.5",
        "DestinationIp": "198.51.100.1",
        "DestinationHostname": "evil.com",
        "Computer": "HOST-01",
    }
    parser = SysmonParser()
    events = parser.parse(raw_event)
    entities = extract_entities(events[0])

    ip_entities = [e.entity_value for e in entities if e.entity_type == "ip"]
    assert "10.0.0.5" in ip_entities
    assert "198.51.100.1" in ip_entities

    domain_entities = [e.entity_value for e in entities if e.entity_type == "domain"]
    assert "evil.com" in domain_entities
