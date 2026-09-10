"""
Unit tests for Sysmon JSON parser.
"""

from app.modules.evidence.sysmon_parser import SysmonParser


def test_sysmon_parser_can_parse():
    parser = SysmonParser()
    assert parser.parser_name() == "sysmon"

    event_with_provider = {"Provider": "Microsoft-Windows-Sysmon", "EventID": 1}
    assert parser.can_parse(event_with_provider) is True

    event_with_sysmon_fields = {"EventID": 1, "ProcessGuid": "{1234-5678}", "Image": "cmd.exe"}
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
    assert ev.process.hashes.get("SHA256") == "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
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
