# Credential access playbook

## Patterns covered
- Many failed logons followed by a success (password guessing or spraying).
- SSH brute force against a Linux host.
- Cloud credentials used from an unexpected address.

## Failed logons then success
- Windows: Event ID 4625 (failure) repeated from one source, then Event ID 4624 (success) for the same account. Note the logon type: type 3 is network, type 10 is remote interactive.
- Count failures per account and per source over a fixed window. One source against many accounts suggests spraying. Many sources against one account suggests distributed guessing.
- A success after the failures from the same source is the key fact. Confirm that the account then did something unusual, such as creating accounts or reading sensitive files.

## SSH brute force
- Look at `Failed password` and `Invalid user` lines in the authentication log and at the source address.
- A later `Accepted password` or `Accepted publickey` from the same source is a possible compromise. Check the account's usual source addresses.
- Check whether password authentication is enabled for the account and whether rate limiting or fail2ban is in place.

## Cloud credential misuse
- Compare the source address and user agent with the principal's history. Look for API calls that enumerate resources (list, describe) shortly after a first use.
- Treat an address from threat intelligence as context, not proof. Intelligence about an address never establishes that a particular event happened.

## Evidence standard
Two alerts of the same event from different tools are one piece of evidence, not two. Corroboration needs independent observations, such as an authentication log and a network record.
