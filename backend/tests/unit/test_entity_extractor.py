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


def test_extract_entities_from_remote_thread_event():
    raw_event = {
        "EventID": 8,
        "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "SourceProcessId": 5412,
        "SourceProcessGuid": "{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}",
        "TargetImage": "C:\\Windows\\System32\\notepad.exe",
        "TargetProcessId": 1024,
        "TargetProcessGuid": "{F0E1D2C3-B4A5-6789-0123-456789ABCDEF}",
        "NewThreadId": 8920,
        "Computer": "HOST-01",
    }
    parser = SysmonParser()
    events = parser.parse(raw_event)
    entities = extract_entities(events[0])

    process_entities = [e for e in entities if e.entity_type == "process"]
    assert len(process_entities) == 2

    source_proc = next(e for e in process_entities if e.role == "source")
    assert source_proc.entity_value == "powershell.exe"
    assert source_proc.attributes["pid"] == 5412
    assert (
        source_proc.attributes["process_guid"]
        == "{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}"
    )

    target_proc = next(e for e in process_entities if e.role == "target")
    assert target_proc.entity_value == "notepad.exe"
    assert target_proc.attributes["pid"] == 1024
    assert (
        target_proc.attributes["process_guid"]
        == "{F0E1D2C3-B4A5-6789-0123-456789ABCDEF}"
    )
    assert target_proc.attributes["new_thread_id"] == 8920


def test_extract_entities_from_process_access_event():
    raw_event = {
        "EventID": 10,
        "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "SourceProcessId": 5412,
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "TargetProcessId": 648,
        "TargetProcessGUID": "{E5F6A1B2-C3D4-7890-5678-9ABCDEF01234}",
        "GrantedAccess": "0x1010",
        "Computer": "HOST-01",
    }
    parser = SysmonParser()
    events = parser.parse(raw_event)
    entities = extract_entities(events[0])

    process_entities = [e for e in entities if e.entity_type == "process"]
    assert len(process_entities) == 2

    source_proc = next(e for e in process_entities if e.role == "source")
    assert source_proc.entity_value == "powershell.exe"

    target_proc = next(e for e in process_entities if e.role == "target")
    assert target_proc.entity_value == "lsass.exe"
    assert target_proc.attributes["pid"] == 648
    assert target_proc.attributes["granted_access"] == "0x1010"


def test_extract_entities_from_file_stream_and_delete_events():
    # Event 15
    raw_15 = {
        "EventID": 15,
        "TargetFilename": "C:\\Downloads\\payload.exe:Zone.Identifier",
        "Hash": "SHA256=1111222233334444555566667777888811112222333344445555666677778888",
        "Computer": "HOST-01",
    }
    parser = SysmonParser()
    events_15 = parser.parse(raw_15)
    entities_15 = extract_entities(events_15[0])

    file_15 = next(e for e in entities_15 if e.entity_type == "file")
    assert file_15.entity_value == "payload.exe:zone.identifier"
    hash_15 = next(e for e in entities_15 if e.entity_type == "file_hash")
    assert (
        hash_15.entity_value
        == "1111222233334444555566667777888811112222333344445555666677778888"
    )

    # Event 23
    raw_23 = {
        "EventID": 23,
        "TargetFilename": "C:\\Windows\\Temp\\dropper.exe",
        "Hashes": "SHA256=9999888877776666555544443333222299998888777766665555444433332222",
        "Computer": "HOST-01",
    }
    events_23 = parser.parse(raw_23)
    entities_23 = extract_entities(events_23[0])

    file_23 = next(e for e in entities_23 if e.entity_type == "file")
    assert file_23.entity_value == "dropper.exe"
    hash_23 = next(e for e in entities_23 if e.entity_type == "file_hash")
    assert (
        hash_23.entity_value
        == "9999888877776666555544443333222299998888777766665555444433332222"
    )
