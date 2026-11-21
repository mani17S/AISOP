# ATT&CK mapping notes

AISOP maps behavior to ATT&CK only when the case evidence supports it. A technique named in an alert title is a lead, not a mapping. The reference collection used for validation is ATT&CK Enterprise v20.1.

## Mapping rule
Map a technique when an observed event shows the behavior, and cite that event. Do not map from the tool name, the alert vendor's label or threat intelligence about an address alone.

## Techniques seen in the sample alerts
- **T1059.001 PowerShell.** Evidence: a process event for `powershell.exe` or `pwsh.exe` with a command line. Strong evidence adds a decoded payload or a download cradle.
- **T1110.003 Password Spraying.** Evidence: failed authentications from one source spread across many accounts within a window.
- **T1110.001 Password Guessing.** Evidence: repeated failures against one account.
- **T1078.002 Domain Accounts, T1078.004 Cloud Accounts.** Evidence: a successful sign-in with a valid account in a context that is unusual for that account. The success alone is not the technique; the misuse is.
- **T1566.001 Spearphishing Attachment, T1566.002 Spearphishing Link.** Evidence: a delivered message with the attachment or link, plus the recipient.
- **T1071.001 Web Protocols.** Evidence: periodic HTTP or HTTPS requests from a host to one destination, tied to a process.
- **T1055.012 Process Hollowing.** Evidence: a process started suspended with its memory image replaced. Telemetry for this is hard to obtain. A vendor alert title alone is not enough.
- **T1552 Unsecured Credentials.** Evidence: access to files, registry or metadata services known to hold credentials, followed by use.

## Tactics in a typical chain
Initial access (phishing), execution (PowerShell), credential access (guessing, spraying), defense evasion (injection, hollowing), command and control (web protocols), and exfiltration. A case may cover only part of the chain. Report only the parts with evidence.

## Wording
Write "the telemetry shows X, which is consistent with technique T" and cite the event. Avoid wording that implies certainty the evidence does not give.
