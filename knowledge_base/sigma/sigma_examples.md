# Sigma rule examples

Rules are drafts for an analyst to review. AISOP never deploys a rule automatically.

## Encoded PowerShell command line

```yaml
title: Encoded PowerShell command line
status: experimental
description: Detects PowerShell started with an encoded command argument.
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_args:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection_image and selection_args
falsepositives:
  - Administration scripts that use encoded arguments
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```

## Burst of failed logons followed by a success

```yaml
title: Failed logons followed by a success from the same source
status: experimental
description: Several failed logons from one source followed by a successful logon, correlated per source address.
logsource:
  product: windows
  service: security
detection:
  failed:
    EventID: 4625
  success:
    EventID: 4624
  condition: failed | count() by IpAddress > 10 and success
falsepositives:
  - Users who mistype a password repeatedly
level: medium
tags:
  - attack.credential_access
  - attack.t1110
```

## Process access to LSASS

```yaml
title: Suspicious process access to lsass
status: experimental
description: A process opens lsass.exe with a high access mask.
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
  filter_known:
    SourceImage|endswith: '\MsMpEng.exe'
  condition: selection and not filter_known
falsepositives:
  - Security products and backup agents
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
```
