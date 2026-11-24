r"""
Deterministic ATT&CK rules for endpoint telemetry (table ``endpoint-attack-v1``), same contract as ``mitre`` (attack-map-v1, ADR-009).

Why a third table: the original six rules recovered 0 of 50 techniques documented by the authors of public attack captures (OTRF Security-Datasets,
2026-11-24 baseline, docs/10_Research/Detection_Engineering_Evaluation.md). This table is written from the public definitions of each technique (what the
technique IS and the canonical way it appears in process and registry telemetry), NOT from tool names. It was developed on one half of the public datasets and
scored once on the other half after being frozen.

Rule kinds, stated so a reader knows how much each one proves:
* command-line rules: a named system binary run with arguments that are the technique's defining form (``schtasks /create``, ``reg save hklm\sam``). They
  prove the command was run, not who ran it or why; administrators run many of these. Source-agnostic: any record with a process name and command line.
* typed-field rules: a Sysmon or Windows Security event type plus whitelisted typed fields (``source_fields``), for example a process-access event against
  LSASS with the read-memory right. These need that telemetry to be collected, and they carry the allow-lists named in each limitation.

Every rule reports "rule R fired on these evidence items", never a probability and never a claim that the technique succeeded. A rule that cannot be
justified from the technique definition is not added.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from app.modules.correlation.mitre import Rule, map_techniques
from app.modules.correlation.models import CorrelationEvent, MitreMapping

ENDPOINT_MAPPING_VERSION = "endpoint-attack-v1"

_Match = Callable[[list[CorrelationEvent]], list[CorrelationEvent]]
_I = re.IGNORECASE
_PROC_CREATE = (("sysmon", "1"), ("windows_security", "4688"))
_SYSTEM_DIRS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\", "c:\\programdata\\microsoft\\windows defender\\", "c:\\program files\\windows defender\\")
_OS_PROCESSES = frozenset({"csrss.exe", "wininit.exe", "services.exe", "svchost.exe", "smss.exe", "lsm.exe", "wmiprvse.exe", "wsmprovhost.exe",
                           "msmpeng.exe", "werfault.exe", "taskmgr.exe", "winlogon.exe", "vboxservice.exe"})
_RUNKEY_WRITER_OS = frozenset({"msmpeng.exe", "svchost.exe", "services.exe", "msiexec.exe", "trustedinstaller.exe", "tiworker.exe", "setup.exe"})
_VM_READ = 0x0010


def _sf(e: CorrelationEvent, key: str) -> str:
    for k, v in e.source_fields:
        if k == key:
            return v
    return ""


def _is(e: CorrelationEvent, source_type: str, event_id: str) -> bool:
    return e.source_type == source_type and e.source_event_id == event_id


def _cmd(exes: frozenset[str], pattern: str) -> _Match:
    rx = re.compile(pattern, _I)
    return lambda evs: [e for e in evs if e.process_name in exes and e.command_line and rx.search(e.command_line)]


def _any_cmd(pattern: str) -> _Match:
    rx = re.compile(pattern, _I)
    return lambda evs: [e for e in evs if e.command_line and rx.search(e.command_line)]


def _proc(exes: frozenset[str]) -> _Match:
    return lambda evs: [e for e in evs if e.process_name in exes and any(_is(e, s, i) for s, i in _PROC_CREATE)]


def _either(*matchers: _Match) -> _Match:
    def run(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
        seen: set = set()
        out: list[CorrelationEvent] = []
        for m in matchers:
            for e in m(evs):
                if e.event_key not in seen:
                    seen.add(e.event_key)
                    out.append(e)
        return out
    return run


def _under_system_dirs(path: str) -> bool:
    low = path.lower()
    return any(low.startswith(d) for d in _SYSTEM_DIRS)


def _lsass_read(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
    """Sysmon process access to lsass.exe with the read-memory right, from a process that is not a known OS component running from an OS directory."""
    out = []
    for e in evs:
        if not _is(e, "sysmon", "10") or not _sf(e, "TargetImage").lower().endswith("\\lsass.exe"):
            continue
        try:
            mask = int(_sf(e, "GrantedAccess"), 16)
        except ValueError:
            continue
        if not mask & _VM_READ:
            continue
        src = _sf(e, "SourceImage")
        if _under_system_dirs(src) and src.lower().rsplit("\\", 1)[-1] in _OS_PROCESSES:
            continue
        out.append(e)
    return out


def _remote_thread(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
    """Sysmon CreateRemoteThread from a process that is not csrss, wininit or services running from an OS directory."""
    out = []
    for e in evs:
        if not _is(e, "sysmon", "8"):
            continue
        src = _sf(e, "SourceImage")
        if _under_system_dirs(src) and src.lower().rsplit("\\", 1)[-1] in {"csrss.exe", "wininit.exe", "services.exe"}:
            continue
        out.append(e)
    return out


_RUN_KEY = re.compile(r"(?i)\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\run(?:once)?(?:ex)?\\")
_STARTUP = re.compile(r"(?i)\\start menu\\programs\\startup\\[^\\]+\.(?:exe|dll|bat|cmd|vbs|vbe|js|jse|hta|ps1|scr)$")


def _run_key_value(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
    out = []
    for e in evs:
        if _is(e, "sysmon", "13") and _RUN_KEY.search(_sf(e, "TargetObject")) and (e.process_name or "") not in _RUNKEY_WRITER_OS:
            out.append(e)
        elif _is(e, "sysmon", "11") and _STARTUP.search(_sf(e, "TargetFilename")) and (e.process_name or "") not in _RUNKEY_WRITER_OS | {"explorer.exe"}:
            out.append(e)
    return out


_UAC_HIJACK = re.compile(r"(?i)\\software\\classes\\(?:ms-settings|mscfile|exefile|folder|ms-windows-store)\\shell\\open\\command")


def _registry_value(pattern: re.Pattern[str]) -> _Match:
    return lambda evs: [e for e in evs if _is(e, "sysmon", "13") and pattern.search(_sf(e, "TargetObject"))]


def _security_event(event_id: str) -> _Match:
    return lambda evs: [e for e in evs if e.source_type == "windows_security" and e.source_event_id == event_id]


def _wmi_spawn(evs: list[CorrelationEvent]) -> list[CorrelationEvent]:
    interpreters = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
    return [e for e in evs if _is(e, "sysmon", "1") and e.process_name in interpreters and _sf(e, "ParentImage").lower().endswith("\\wmiprvse.exe")]


_NET = frozenset({"net.exe", "net1.exe"})
_PS = frozenset({"powershell.exe", "pwsh.exe"})
_REG = frozenset({"reg.exe"})
_SC = frozenset({"sc.exe"})
_TACT_PROXY = ("defense-evasion",)
_PROXY = "System Binary Proxy Execution: "


def _R(rule_id: str, tid: str, name: str, tactics: tuple[str, ...], limitation: str, match: _Match) -> Rule:
    return Rule(rule_id, tid, name, tactics, limitation, match)


ENDPOINT_RULES: tuple[Rule, ...] = (
    # ---- credential access
    _R("EP-T1003.001-LSASS-MEMORY-READ", "T1003.001", "OS Credential Dumping: LSASS Memory", ("credential-access",),
       "A process outside the OS-component allow-list opened lsass.exe with the read-memory right (Sysmon event 10). Needs process-access telemetry; a backup or security "
       "product also does this; a process hidden behind an allow-listed name from an OS directory is not seen.", _lsass_read),
    _R("EP-T1003.001-DUMP-COMMAND", "T1003.001", "OS Credential Dumping: LSASS Memory", ("credential-access",),
       "A dump tool pointed at lsass (procdump on lsass, comsvcs MiniDump) or the sekurlsa module syntax; shows the command, not that a dump succeeded.",
       _either(_cmd(frozenset({"procdump.exe", "procdump64.exe"}), r"\blsass(?:\.exe)?\b"), _cmd(frozenset({"rundll32.exe"}), r"comsvcs(?:\.dll)?\W+.*minidump"),
               _any_cmd(r"\bsekurlsa::"))),
    _R("EP-T1003.002-REG-SAVE-HIVE", "T1003.002", "OS Credential Dumping: Security Account Manager", ("credential-access",),
       "reg.exe saved or exported the SAM, SECURITY or SYSTEM hive itself (not a key beneath it); backup tooling can do this, and nothing shows the hive was read afterwards.",
       _cmd(_REG, r"\b(?:save|export)\s+\"?(?:hklm|hkey_local_machine)\\(?:sam|security|system)(?=[\s\"']|$)")),
    _R("EP-T1003.003-NTDS-ACCESS", "T1003.003", "OS Credential Dumping: NTDS", ("credential-access",),
       "ntdsutil in install-from-media mode, or any command line naming ntds.dit; domain-controller backup tooling does this legitimately.",
       _either(_cmd(frozenset({"ntdsutil.exe"}), r"\b(?:ifm|ac\s+i\s+ntds|activate\s+instance\s+ntds)\b"), _any_cmd(r"\bntds\.dit\b"))),
    # ---- execution and proxy execution
    _R("EP-T1059.001-POWERSHELL-DOWNLOAD-OR-BYPASS", "T1059.001", "Command and Scripting Interpreter: PowerShell", ("execution",),
       "PowerShell with download-cradle, invoke-expression or execution-policy-bypass arguments; management scripts use these too, and what the script did is not established.",
       _cmd(_PS, r"\b(?:invoke-expression|iex)\b|downloadstring|downloadfile|net\.webclient|-(?:ep|exec\w*)\s+bypass")),
    _R("EP-T1218.005-MSHTA-SCRIPT-OR-REMOTE", "T1218.005", _PROXY + "Mshta", _TACT_PROXY,
       "mshta.exe given a script URI, a remote URL or an .hta file; some line-of-business applications are .hta files.",
       _cmd(frozenset({"mshta.exe"}), r"(?:vbscript|javascript):|https?://|\.hta\b")),
    _R("EP-T1218.010-REGSVR32-SCRIPTLET", "T1218.010", _PROXY + "Regsvr32", _TACT_PROXY,
       "regsvr32.exe with a scriptlet argument (/i:, scrobj) or a URL; ordinary DLL registration does not look like this, but installers vary.",
       _cmd(frozenset({"regsvr32.exe"}), r"/i:|scrobj(?:\.dll)?|https?://")),
    _R("EP-T1218.011-RUNDLL32-SCRIPT-OR-REMOTE", "T1218.011", _PROXY + "Rundll32", _TACT_PROXY,
       "rundll32.exe running a script URI, mshtml HTML application or a URL.",
       _cmd(frozenset({"rundll32.exe"}), r"javascript:|vbscript:|mshtml\W+runhtmlapplication|https?://")),
    _R("EP-T1218.002-CONTROL-PANEL-ITEM", "T1218.002", _PROXY + "Control Panel", _TACT_PROXY,
       "control.exe or rundll32 Control_RunDLL loading a .cpl from a path that is not an OS directory.",
       _either(_cmd(frozenset({"control.exe"}), r"(?<!system32)[\\/][^\\/\s\"]+\.cpl\b"), _cmd(frozenset({"rundll32.exe"}), r"shell32(?:\.dll)?\"?\W+control_rundll\w*\s+\"?(?![a-z]:\\windows\\system32\\)[^\s]*\.cpl"))),
    _R("EP-T1218.004-INSTALLUTIL", "T1218.004", _PROXY + "InstallUtil", _TACT_PROXY,
       "InstallUtil.exe with uninstall or logging switches against an assembly; developer and deployment tools run it too.",
       _cmd(frozenset({"installutil.exe"}), r"/u\b|/logfile|/logtoconsole")),
    _R("EP-T1218.001-COMPILED-HTML", "T1218.001", _PROXY + "Compiled HTML File", _TACT_PROXY,
       "hh.exe opening a .chm file, an ms-its URI or a URL; help files are legitimate, the rule cannot tell whether the file contains script.",
       _cmd(frozenset({"hh.exe"}), r"\.chm\b|ms-its:|https?://")),
    _R("EP-T1218.007-MSIEXEC-REMOTE", "T1218.007", _PROXY + "Msiexec", _TACT_PROXY,
       "msiexec.exe given a remote URL; software deployment does this too.", _cmd(frozenset({"msiexec.exe"}), r"https?://")),
    _R("EP-T1218.009-REGASM-REGSVCS", "T1218.009", _PROXY + "Regsvcs/Regasm", _TACT_PROXY,
       "regasm.exe or regsvcs.exe run on a DLL; .NET developers do this.", _cmd(frozenset({"regasm.exe", "regsvcs.exe"}), r"\.dll\b")),
    _R("EP-T1218.003-CMSTP", "T1218.003", _PROXY + "CMSTP", _TACT_PROXY,
       "cmstp.exe in silent or no-install mode with an .inf; a VPN profile installer is the legitimate use.", _cmd(frozenset({"cmstp.exe"}), r"/(?:s|au|ni)\b")),
    _R("EP-T1218.008-ODBCCONF", "T1218.008", _PROXY + "Odbcconf", _TACT_PROXY,
       "odbcconf.exe asked to register a DLL; database administrators use odbcconf for other actions.", _cmd(frozenset({"odbcconf.exe"}), r"\s[/-]a\s*\{?(?:regsvr|configsysdsn)")),
    _R("EP-T1047-WMIC-REMOTE-OR-CREATE", "T1047", "Windows Management Instrumentation", ("execution",),
       "wmic.exe with a remote node or a process-creation call; administrators use wmic for inventory.", _cmd(frozenset({"wmic.exe"}), r"/node\s*:|process\s+call\s+create")),
    _R("EP-T1047-WMI-PROVIDER-SPAWN", "T1047", "Windows Management Instrumentation", ("execution",),
       "An interpreter started by WmiPrvSE.exe (Sysmon event 1 with ParentImage); management software also starts processes through WMI.", _wmi_spawn),
    _R("EP-T1220-XSL-SCRIPT", "T1220", "XSL Script Processing", ("defense-evasion",),
       "wmic.exe with a /format stylesheet that is a URL or an .xsl file, or msxsl.exe; the stylesheet's content is not examined.",
       _either(_cmd(frozenset({"wmic.exe"}), r"/format\s*:\s*\"?(?:https?://|[^\s\"]+\.xsl)"), _proc(frozenset({"msxsl.exe"})))),
    # ---- persistence and privilege escalation
    _R("EP-T1053.005-SCHTASKS-CREATE", "T1053.005", "Scheduled Task/Job: Scheduled Task", ("execution", "persistence", "privilege-escalation"),
       "schtasks.exe creating a task; administrators and installers create tasks, and the task's action is not judged.", _cmd(frozenset({"schtasks.exe"}), r"/create\b")),
    _R("EP-T1543.003-SERVICE-BINPATH", "T1543.003", "Create or Modify System Process: Windows Service", ("persistence", "privilege-escalation"),
       "sc.exe creating a service or changing its binary path; installers and administrators do this.", _cmd(_SC, r"\b(?:create|config)\b.*\bbinpath\s*=")),
    _R("EP-T1547.001-RUN-KEY-OR-STARTUP", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", ("persistence", "privilege-escalation"),
       "A Run or RunOnce value set by a process outside a short installer and Defender allow-list (Sysmon event 13), a script or executable created in a Startup folder "
       "(event 11), or reg.exe adding a Run value; software installers also write these.",
       _either(_run_key_value, _cmd(_REG, r"\badd\b.*\\currentversion\\run(?:once)?(?:ex)?\b"))),
    _R("EP-T1037.001-LOGON-SCRIPT", "T1037.001", "Boot or Logon Initialization Scripts: Logon Script (Windows)", ("persistence", "privilege-escalation"),
       "The UserInitMprLogonScript value set, by command line or by a Sysmon registry event.",
       _either(_any_cmd(r"userinitmprlogonscript"), _registry_value(re.compile(r"(?i)\\environment\\userinitmprlogonscript$")))),
    _R("EP-T1548.002-UAC-BYPASS-REGISTRY", "T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control", ("privilege-escalation", "defense-evasion"),
       "A per-user shell-open-command handler for ms-settings, mscfile or similar set (Sysmon event 13 or reg.exe); the hijack is the technique's canonical form.",
       _either(_registry_value(_UAC_HIJACK), _cmd(_REG, r"\\software\\classes\\(?:ms-settings|mscfile|exefile|folder|ms-windows-store)\\shell\\open\\command"))),
    _R("EP-T1055-REMOTE-THREAD", "T1055", "Process Injection", ("defense-evasion", "privilege-escalation"),
       "A Sysmon CreateRemoteThread from a process other than csrss, wininit or services; debuggers and some security software do this. Injection that avoids this API is not seen.",
       _remote_thread),
    # ---- defence evasion
    _R("EP-T1562.002-AUDIT-POLICY-CHANGED", "T1562.002", "Impair Defenses: Disable Windows Event Logging", ("defense-evasion",),
       "Windows Security event 4719 (system audit policy changed); administrators change audit policy, and the event does not say whether logging was reduced.",
       _security_event("4719")),
    _R("EP-T1562.002-LOGGING-DISABLE-COMMAND", "T1562.002", "Impair Defenses: Disable Windows Event Logging", ("defense-evasion",),
       "auditpol disabling or clearing categories, wevtutil disabling a log, stopping or disabling the EventLog service, or turning off process command-line auditing.",
       _either(_cmd(frozenset({"auditpol.exe"}), r"/(?:clear|remove)\b|/(?:success|failure)\s*:\s*disable"),
               _cmd(frozenset({"wevtutil.exe"}), r"\b(?:sl|set-log)\b.*(?:/e|/enabled)\s*:\s*false"),
               _cmd(frozenset({"sc.exe", "net.exe", "net1.exe"}), r"\b(?:stop|config)\b.*\beventlog\b"),
               _cmd(_REG, r"processcreationincludecmdline_enabled.*?/d\s+0"))),
    _R("EP-T1070.001-LOG-CLEARED", "T1070.001", "Indicator Removal: Clear Windows Event Logs", ("defense-evasion",),
       "Windows Security event 1102 (audit log cleared) or wevtutil clearing a log; administrators clear logs too.",
       _either(_security_event("1102"), _cmd(frozenset({"wevtutil.exe"}), r"\b(?:cl|clear-log)\b"))),
    _R("EP-T1490-INHIBIT-RECOVERY", "T1490", "Inhibit System Recovery", ("impact",),
       "Deleting shadow copies or backup catalogues, or disabling recovery in the boot configuration; legitimate storage maintenance deletes shadow copies.",
       _either(_cmd(frozenset({"vssadmin.exe"}), r"delete\s+shadows"), _cmd(frozenset({"wbadmin.exe"}), r"delete\s+(?:catalog|backup|systemstatebackup)"),
               _cmd(frozenset({"bcdedit.exe"}), r"recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures"), _cmd(frozenset({"wmic.exe"}), r"shadowcopy\s+delete"))),
    # ---- lateral movement
    _R("EP-T1021.006-WINRM-HOST-PROCESS", "T1021.006", "Remote Services: Windows Remote Management", ("lateral-movement",),
       "wsmprovhost.exe started on this host, which is the WinRM plugin host for an inbound remote session; administrators use remoting.", _proc(frozenset({"wsmprovhost.exe"}))),
    _R("EP-T1021.002-ADMIN-SHARE-OR-PSEXEC", "T1021.002", "Remote Services: SMB/Windows Admin Shares", ("lateral-movement",),
       "net use to an administrative share, or the PsExec service binary started on this host; administrators use both.",
       _either(_cmd(_NET, r"\buse\b\s+\\\\[^\\\s]+\\(?:admin\$|c\$|ipc\$)"), _proc(frozenset({"psexesvc.exe"})))),
    # ---- discovery
    _R("EP-T1012-REG-QUERY", "T1012", "Query Registry", ("discovery",), "reg.exe query; routine administration does this constantly.", _cmd(_REG, r"\bquery\b")),
    _R("EP-T1518-SOFTWARE-REG-QUERY", "T1518", "Software Discovery", ("discovery",),
       "reg.exe querying the Internet Explorer key or the Uninstall list; inventory tools do this.", _cmd(_REG, r"\bquery\b.*(?:internet explorer|\\uninstall)")),
    _R("EP-T1069.001-LOCAL-GROUPS", "T1069.001", "Permission Groups Discovery: Local Groups", ("discovery",),
       "net localgroup without add or delete; administrators list groups.", _cmd(_NET, r"\blocalgroup\b(?!.*\s/(?:add|delete)\b)")),
    _R("EP-T1069.002-DOMAIN-GROUPS", "T1069.002", "Permission Groups Discovery: Domain Groups", ("discovery",),
       "net group /domain; administrators list groups.", _cmd(_NET, r"\bgroup\b.*\s/domain\b")),
    _R("EP-T1087.002-DOMAIN-ACCOUNTS", "T1087.002", "Account Discovery: Domain Account", ("discovery",),
       "net user /domain without add; administrators list accounts.", _cmd(_NET, r"\buser\b(?!.*\s/add\b).*\s/domain\b")),
    _R("EP-T1136.001-LOCAL-ACCOUNT-ADDED", "T1136.001", "Create Account: Local Account", ("persistence",),
       "net user ... /add; legitimate account provisioning looks the same.", _cmd(_NET, r"\buser\b.*\s/add\b")),
    # ---- command and control
    _R("EP-T1105-CERTUTIL-DOWNLOAD", "T1105", "Ingress Tool Transfer", ("command-and-control",),
       "certutil fetching from a URL; the file's content is not examined.", _cmd(frozenset({"certutil.exe"}), r"[-/]urlcache|[-/]verifyctl")),
    _R("EP-T1140-CERTUTIL-DECODE", "T1140", "Deobfuscate/Decode Files or Information", ("defense-evasion",),
       "certutil decoding a file; legitimate certificate work rarely uses -decode.", _cmd(frozenset({"certutil.exe"}), r"[-/]decode(?:hex)?\b")),
    _R("EP-T1197-BITS-TRANSFER", "T1197", "BITS Jobs", ("defense-evasion", "persistence"),
       "bitsadmin transfer or Start-BitsTransfer; software updaters use BITS.",
       _either(_cmd(frozenset({"bitsadmin.exe"}), r"/transfer|/addfile"), _cmd(_PS, r"start-bitstransfer"))),
)


def map_endpoint_techniques(events: list[CorrelationEvent]) -> list[MitreMapping]:
    """Apply the endpoint table to the de-duplicated evidence (same de-duplication, vendor-asserted flag and evidence counts as ``map_techniques``)."""
    return map_techniques(events, rules=ENDPOINT_RULES)


__all__ = ["ENDPOINT_MAPPING_VERSION", "ENDPOINT_RULES", "map_endpoint_techniques"]
