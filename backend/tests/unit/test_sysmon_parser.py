"""
Unit tests for Sysmon JSON parser.
"""

from app.modules.evidence.sysmon_parser import SysmonParser


def test_sysmon_parser_can_parse():
    parser = SysmonParser()
    assert parser.parser_name() == "sysmon"

    event_with_provider = {"Provider": "Microsoft-Windows-Sysmon", "EventID": 1}
    assert parser.can_parse(event_with_provider) is True

    event_with_sysmon_fields = {
        "EventID": 1,
        "ProcessGuid": "{1234-5678}",
        "Image": "cmd.exe",
    }
    assert parser.can_parse(event_with_sysmon_fields) is True

    irrelevant_event = {"something": "random", "no_id": 123}
    assert parser.can_parse(irrelevant_event) is False


def test_sysmon_event_1_process_creation():
    raw_event = {
        "EventID": 1,
        "UtcTime": "2026-09-09 12:00:00.000",
        "ProcessId": 4560,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c powershell.exe -enc AAAA",
        "CurrentDirectory": "C:\\Windows\\System32\\",
        "User": "CORP\\analyst",
        "ParentProcessId": 1120,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Hashes": "SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855,MD5=D41D8CD98F00B204E9800998ECF8427E",
        "Computer": "SEC-OPS-01",
    }
    parser = SysmonParser()
    events = parser.parse(raw_event, raw_ref="test_ref_hash")

    assert len(events) == 1
    ev = events[0]
    assert ev.event_id == "1"
    assert ev.event_type == "process_creation"
    assert ev.action == "started"
    assert ev.raw_ref == "test_ref_hash"

    assert ev.host is not None
    assert ev.host.hostname == "SEC-OPS-01"

    assert ev.user is not None
    assert ev.user.domain == "CORP"
    assert ev.user.username == "analyst"

    assert ev.process is not None
    assert ev.process.process_name == "cmd.exe"
    assert ev.process.pid == 4560
    assert ev.process.ppid == 1120
    assert ev.process.command_line == "cmd.exe /c powershell.exe -enc AAAA"
    assert (
        ev.process.hashes.get("SHA256")
        == "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    )
    assert ev.process.hashes.get("MD5") == "D41D8CD98F00B204E9800998ECF8427E"


def test_sysmon_event_3_network_connection():
    raw_event = {
        "EventID": 3,
        "UtcTime": "2026-09-09 12:01:00.000",
        "ProcessId": 2040,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "SourceIp": "192.168.1.50",
        "SourcePort": 51234,
        "DestinationIp": "198.51.100.25",
        "DestinationPort": 443,
        "DestinationHostname": "c2.malicious-domain.com",
        "Protocol": "tcp",
        "Initiated": "true",
        "Computer": "SEC-OPS-01",
    }
    parser = SysmonParser()
    events = parser.parse(raw_event)

    assert len(events) == 1
    ev = events[0]
    assert ev.event_id == "3"
    assert ev.event_type == "network_connection"
    assert ev.network is not None
    assert ev.network.source_ip == "192.168.1.50"
    assert ev.network.destination_ip == "198.51.100.25"
    assert ev.network.destination_port == 443
    assert ev.network.destination_hostname == "c2.malicious-domain.com"
    assert ev.network.direction == "outbound"
    assert ev.process is not None
    assert ev.process.process_name == "powershell.exe"


def test_sysmon_event_22_dns_query():
    raw_event = {
        "EventID": 22,
        "UtcTime": "2026-09-09 12:02:00.000",
        "ProcessId": 3100,
        "Image": "C:\\Windows\\System32\\curl.exe",
        "QueryName": "api.github.com",
        "QueryStatus": "0",
        "QueryResults": "140.82.121.4;140.82.121.3",
        "Computer": "SEC-OPS-01",
    }
    parser = SysmonParser()
    events = parser.parse(raw_event)

    assert len(events) == 1
    ev = events[0]
    assert ev.event_id == "22"
    assert ev.event_type == "dns_query"
    assert ev.dns is not None
    assert ev.dns.query_name == "api.github.com"
    assert "140.82.121.4" in ev.dns.resolved_ips


def test_sysmon_nested_event_structure():
    raw_nested = {
        "Event": {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 11,
                "TimeCreated": {"@SystemTime": "2026-09-09T12:05:00.000Z"},
                "Computer": "SERVER-01",
            },
            "EventData": {
                "TargetFilename": "C:\\Users\\Public\\malware.exe",
                "Hashes": "SHA256=1111222233334444",
                "ProcessId": "900",
            },
        }
    }
    parser = SysmonParser()
    assert parser.can_parse(raw_nested) is True

    events = parser.parse(raw_nested)
    assert len(events) == 1
    ev = events[0]
    assert ev.event_id == "11"
    assert ev.event_type == "file_create"
    assert ev.host is not None and ev.host.hostname == "SERVER-01"
    assert ev.file is not None and ev.file.filename == "malware.exe"


def _load_fixture(filename: str) -> dict:
    import json
    from pathlib import Path

    fixture_path = (
        Path(__file__).resolve().parent.parent.parent.parent
        / "datasets"
        / "samples"
        / "sysmon"
        / filename
    )
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_sysmon_can_parse_new_events():
    parser = SysmonParser()

    # Event 8 with SourceProcessGuid and TargetProcessGuid
    ev8 = {
        "EventID": 8,
        "SourceProcessGuid": "{1234-5678}",
        "TargetProcessGuid": "{8765-4321}",
    }
    assert parser.can_parse(ev8) is True

    # Event 10 with GrantedAccess and CallTrace
    ev10 = {"EventID": 10, "GrantedAccess": "0x1010", "CallTrace": "ntdll.dll+123"}
    assert parser.can_parse(ev10) is True

    # Event 15 with TargetFilename
    ev15 = {"EventID": 15, "TargetFilename": "C:\\test.txt:stream"}
    assert parser.can_parse(ev15) is True

    # Event 23 with TargetFilename
    ev23 = {"EventID": 23, "TargetFilename": "C:\\test.txt"}
    assert parser.can_parse(ev23) is True


def test_sysmon_event_8_create_remote_thread():
    raw = _load_fixture("sysmon_create_remote_thread.json")
    parser = SysmonParser()
    events = parser.parse(raw)

    assert len(events) == 1
    ev = events[0]

    # Canonical identification
    assert ev.event_id == "8"
    assert ev.event_type == "create_remote_thread"
    assert ev.action == "created"
    assert ev.provider == "Microsoft-Windows-Sysmon"
    assert ev.outcome == "success"
    assert ev.severity == "informational"

    # Host & user
    assert ev.host is not None
    assert ev.host.hostname == "CORP-FIN-WS01"
    assert ev.user is not None
    assert ev.user.domain == "CORP"
    assert ev.user.username == "victim_user"

    # Source process
    assert ev.process is not None
    assert ev.process.pid == 5412
    assert ev.process.process_name == "powershell.exe"
    assert (
        ev.process.image_path
        == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )
    assert ev.process.process_guid == "{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}"
    assert ev.process.user == "CORP\\victim_user"

    # Target process and injection details preserved in custom_fields
    assert ev.custom_fields.get("target_process_id") == 1024
    assert ev.custom_fields.get("target_image") == "C:\\Windows\\System32\\notepad.exe"
    assert ev.custom_fields.get("target_process_name") == "notepad.exe"
    assert (
        ev.custom_fields.get("target_process_guid")
        == "{F0E1D2C3-B4A5-6789-0123-456789ABCDEF}"
    )
    assert ev.custom_fields.get("new_thread_id") == 8920
    assert ev.custom_fields.get("start_address") == "0x00007FFB34121000"
    assert ev.custom_fields.get("start_module") == "C:\\Windows\\System32\\kernel32.dll"
    assert ev.custom_fields.get("start_function") == "LoadLibraryA"

    # Entity extraction check
    from app.modules.evidence.entity_extractor import extract_entities

    entities = extract_entities(ev)
    roles = {e.role: e for e in entities if e.entity_type == "process"}
    assert "source" in roles
    assert roles["source"].entity_value == "powershell.exe"
    assert roles["source"].attributes.get("pid") == 5412
    assert (
        roles["source"].attributes.get("process_guid")
        == "{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}"
    )

    assert "target" in roles
    assert roles["target"].entity_value == "notepad.exe"
    assert roles["target"].attributes.get("pid") == 1024
    assert (
        roles["target"].attributes.get("process_guid")
        == "{F0E1D2C3-B4A5-6789-0123-456789ABCDEF}"
    )
    assert roles["target"].attributes.get("new_thread_id") == 8920


def test_sysmon_event_10_process_access():
    raw = _load_fixture("sysmon_process_access.json")
    parser = SysmonParser()
    events = parser.parse(raw)

    assert len(events) == 1
    ev = events[0]

    # Canonical identification
    assert ev.event_id == "10"
    assert ev.event_type == "process_access"
    assert ev.action == "accessed"

    # Source process
    assert ev.process is not None
    assert ev.process.pid == 5412
    assert ev.process.process_name == "powershell.exe"
    assert ev.process.process_guid == "{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}"

    # Target process and access rights
    assert ev.custom_fields.get("target_process_id") == 648
    assert ev.custom_fields.get("target_process_name") == "lsass.exe"
    assert ev.custom_fields.get("target_image") == "C:\\Windows\\System32\\lsass.exe"
    assert (
        ev.custom_fields.get("target_process_guid")
        == "{E5F6A1B2-C3D4-7890-5678-9ABCDEF01234}"
    )
    assert ev.custom_fields.get("granted_access") == "0x1010"
    assert "KERNELBASE.dll" in ev.custom_fields.get("call_trace", "")
    assert ev.custom_fields.get("source_thread_id") == 6780

    # Entity extraction check
    from app.modules.evidence.entity_extractor import extract_entities

    entities = extract_entities(ev)
    roles = {e.role: e for e in entities if e.entity_type == "process"}
    assert "source" in roles
    assert roles["source"].entity_value == "powershell.exe"

    assert "target" in roles
    assert roles["target"].entity_value == "lsass.exe"
    assert roles["target"].attributes.get("pid") == 648
    assert roles["target"].attributes.get("granted_access") == "0x1010"


def test_sysmon_event_15_file_create_stream_hash():
    raw = _load_fixture("sysmon_file_create_stream_hash.json")
    parser = SysmonParser()
    events = parser.parse(raw)

    assert len(events) == 1
    ev = events[0]

    # Canonical identification
    assert ev.event_id == "15"
    assert ev.event_type == "file_create_stream_hash"
    assert ev.action == "created"

    # File entity and hash preservation
    assert ev.file is not None
    assert (
        ev.file.path == "C:\\Users\\victim_user\\Downloads\\invoice.pdf:Zone.Identifier"
    )
    assert ev.file.filename == "invoice.pdf:Zone.Identifier"
    assert (
        ev.file.hashes.get("SHA256")
        == "2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE"
    )
    assert ev.file.hashes.get("MD5") == "900150983CD24FB0D6963F7D28E17F72"

    # Creation time preserved
    assert ev.custom_fields.get("creation_utc_time") == "2026-09-09 14:15:35.700"

    # Process context
    assert ev.process is not None
    assert ev.process.pid == 3204
    assert ev.process.process_name == "browser.exe"
    assert ev.process.process_guid == "{B2C3D4E5-F6A1-7890-2345-6789ABCDEF01}"

    # Entity extraction check
    from app.modules.evidence.entity_extractor import extract_entities

    entities = extract_entities(ev)
    file_entities = [e for e in entities if e.entity_type == "file"]
    assert len(file_entities) >= 1
    assert file_entities[0].entity_value == "invoice.pdf:zone.identifier"

    hash_entities = [e for e in entities if e.entity_type == "file_hash"]
    hash_values = [h.entity_value for h in hash_entities]
    assert (
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        in hash_values
    )
    assert "900150983cd24fb0d6963f7d28e17f72" in hash_values


def test_sysmon_event_23_file_delete():
    raw = _load_fixture("sysmon_file_delete.json")
    parser = SysmonParser()
    events = parser.parse(raw)

    assert len(events) == 1
    ev = events[0]

    # Canonical identification
    assert ev.event_id == "23"
    assert ev.event_type == "file_delete"
    assert ev.action == "deleted"
    assert ev.severity == "informational"  # Non-destructive evidence handling

    # File entity and hash
    assert ev.file is not None
    assert ev.file.path == "C:\\Users\\Public\\mimikatz.exe"
    assert ev.file.filename == "mimikatz.exe"
    assert (
        ev.file.hashes.get("SHA256")
        == "17565FE8A1553835B19FA865BEFA0DF85FA3EC04B9741D8B4D445F0F5CC054D6"
    )

    # Boolean normalization
    assert ev.custom_fields.get("is_executable") is True
    assert ev.custom_fields.get("archived") is False

    # Process context
    assert ev.process is not None
    assert ev.process.pid == 5412
    assert ev.process.process_name == "powershell.exe"
    assert ev.process.process_guid == "{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}"


def test_sysmon_missing_optional_fields_safety():
    parser = SysmonParser()

    # Event 8 with minimal fields
    minimal_8 = {"EventID": 8, "SourceImage": "cmd.exe", "TargetImage": "calc.exe"}
    events8 = parser.parse(minimal_8)
    assert len(events8) == 1
    assert events8[0].event_id == "8"
    assert events8[0].process.process_name == "cmd.exe"
    assert events8[0].custom_fields.get("target_process_name") == "calc.exe"
    assert events8[0].custom_fields.get("new_thread_id") is None

    # Event 10 with minimal fields
    minimal_10 = {
        "EventID": 10,
        "SourceImage": "taskmgr.exe",
        "TargetImage": "lsass.exe",
    }
    events10 = parser.parse(minimal_10)
    assert len(events10) == 1
    assert events10[0].event_id == "10"
    assert events10[0].custom_fields.get("granted_access") is None
    assert events10[0].custom_fields.get("call_trace") is None

    # Event 15 with minimal fields
    minimal_15 = {"EventID": 15, "TargetFilename": "C:\\temp\\file.txt"}
    events15 = parser.parse(minimal_15)
    assert len(events15) == 1
    assert events15[0].file.filename == "file.txt"
    assert events15[0].file.hashes == {}

    # Event 23 with minimal fields
    minimal_23 = {"EventID": 23, "TargetFilename": "C:\\temp\\deleted.log"}
    events23 = parser.parse(minimal_23)
    assert len(events23) == 1
    assert events23[0].file.filename == "deleted.log"
    assert events23[0].custom_fields.get("is_executable") is None
    assert events23[0].custom_fields.get("archived") is None


def test_sysmon_bare_hash_detection():
    parser = SysmonParser()
    sha256_bare = "17565fe8a1553835b19fa865befa0df85fa3ec04b9741d8b4d445f0f5cc054d6"
    hashes = parser._parse_hashes(sha256_bare)
    assert hashes.get("SHA256") == sha256_bare

    md5_bare = "900150983cd24fb0d6963f7d28e17f72"
    hashes_md5 = parser._parse_hashes(md5_bare)
    assert hashes_md5.get("MD5") == md5_bare

    sha1_bare = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    hashes_sha1 = parser._parse_hashes(sha1_bare)
    assert hashes_sha1.get("SHA1") == sha1_bare


def test_sysmon_boolean_normalization():
    parser = SysmonParser()
    assert parser._parse_bool("true") is True
    assert parser._parse_bool("True") is True
    assert parser._parse_bool("1") is True
    assert parser._parse_bool("yes") is True
    assert parser._parse_bool(True) is True

    assert parser._parse_bool("false") is False
    assert parser._parse_bool("False") is False
    assert parser._parse_bool("0") is False
    assert parser._parse_bool("no") is False
    assert parser._parse_bool(False) is False

    assert parser._parse_bool(None) is None
    assert parser._parse_bool("") is None
    assert parser._parse_bool("unknown") is None


def test_sysmon_unsupported_event_id_fallback():
    parser = SysmonParser()
    ev = {"EventID": 99, "ProcessId": 1234, "Image": "something.exe"}
    events = parser.parse(ev)
    assert len(events) == 1
    assert events[0].event_id == "99"
    assert events[0].event_type == "sysmon_event_99"
    assert events[0].action == "observed"
    assert events[0].process.pid == 1234


def test_sysmon_invalid_timestamp_graceful_fallback():
    parser = SysmonParser()
    ev = {"EventID": 1, "UtcTime": "invalid-timestamp-value", "Image": "test.exe"}
    events = parser.parse(ev)
    assert len(events) == 1
    assert events[0].timestamp is not None


def test_sysmon_can_parse_negative_cases():
    parser = SysmonParser()

    # Windows Security log (EventID present, but no Sysmon signature fields)
    win_sec = {
        "EventID": 4624,
        "LogonType": 2,
        "TargetUserName": "admin",
        "WorkstationName": "WS01",
    }
    assert parser.can_parse(win_sec) is False

    # Fields like TargetFilename or ProcessId present, but NO EventID
    no_event_id = {"TargetFilename": "C:\\temp\\file.txt", "ProcessId": 1234}
    assert parser.can_parse(no_event_id) is False

    # Zeek/Suricata network record without EventID
    network_log = {"proto": "tcp", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2"}
    assert parser.can_parse(network_log) is False

    # EventID present, but completely arbitrary non-Sysmon payload
    arbitrary_log = {"EventID": 999, "foo": "bar", "temperature": 72.5}
    assert parser.can_parse(arbitrary_log) is False

    # Empty payload
    assert parser.can_parse({}) is False
    assert parser.can_parse("") is False


def test_sysmon_hash_parsing_edge_cases():
    parser = SysmonParser()

    # Non-hex string of length 64 (should NOT be inferred as SHA256)
    non_hex_64 = "g" * 64
    assert parser._parse_hashes(non_hex_64) == {}

    # Hex string of unsupported length (e.g. 16 or 24 chars)
    hex_16 = "a1b2c3d4e5f60718"
    assert parser._parse_hashes(hex_16) == {}

    # Malformed key-value tokens (empty keys or values)
    assert parser._parse_hashes("=value") == {}
    assert parser._parse_hashes("key=") == {}
    assert parser._parse_hashes("=") == {}

    # Mixed valid and invalid tokens
    mixed = "SHA256=1111222233334444555566667777888811112222333344445555666677778888,=bad,invalid_bare"
    res = parser._parse_hashes(mixed)
    assert len(res) == 1
    assert (
        res.get("SHA256")
        == "1111222233334444555566667777888811112222333344445555666677778888"
    )
