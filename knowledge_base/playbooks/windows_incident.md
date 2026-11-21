# Windows host triage playbook

## When to use
Use this playbook when an alert names a Windows host and a suspicious process, for example an encoded PowerShell command, a script host spawning from an Office application, or a process injecting into another process.

## First questions
1. Which process ran, with which command line, under which user, and what was its parent process?
2. Was the activity observed in raw telemetry (Sysmon Event ID 1, Windows Security Event ID 4688) or only asserted by an alert title?
3. Did the same host or user show related activity within thirty minutes before and after?

## Encoded PowerShell
- Look for `powershell.exe` or `pwsh.exe` with `-enc`, `-EncodedCommand`, `-nop`, `-w hidden` or `-ep bypass` in the command line.
- Decode the Base64 payload as UTF-16LE text before judging it. A decoded download cradle (`IEX`, `Invoke-WebRequest`, `DownloadString`) is stronger evidence than the flags alone.
- Record the parent process. An Office application, a browser or `wmiprvse.exe` as parent raises concern. An administrator running a management script from a known path lowers it.
- Check network events from the same process for outbound connections to unfamiliar addresses.

## Process injection and hollowing
- Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess) with a high access mask on `lsass.exe` or on another user process are the main telemetry.
- A signed system binary started suspended with an unexpected parent is a hollowing indicator, but it needs corroboration from memory or network evidence.

## Persistence checks
- New services (Event ID 7045), scheduled tasks (Event ID 4698), Run keys and startup folder files created near the time of the alert.

## Containment decisions
AISOP does not isolate hosts or kill processes. Record the recommended action in the case and let the analyst or the incident owner carry it out.

## What to preserve
Keep the raw event payloads and their SHA-256 values, the decoded payload text, the process tree and the host name, so a reviewer can reproduce the conclusion.
