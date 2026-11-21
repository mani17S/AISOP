# Phishing and command-and-control playbook

## Phishing
1. Read the message headers. Compare the sender domain with the `Return-Path` and the `Received` chain. A display name that matches a person but a domain that does not is a common sign.
2. List every link and attachment hash. Do not open them on an analyst workstation. Record the domain, the URL path and the file SHA-256.
3. Search mail logs for other recipients of the same message and for users who clicked.
4. Check proxy or DNS records for connections to the link domain after delivery. A click with no connection record is unconfirmed.
5. If credentials were entered, check authentication logs for new sign-ins from unfamiliar addresses.

## Command and control beaconing
- Beaconing is regular outbound traffic at fixed or lightly jittered intervals to one destination. Compute the interval between connections from the same host to the same address.
- Intrusion detection signatures that name a known framework are leads. Confirm with network flow data and with the process that made the connection.
- Check the destination: first-seen time, certificate details, hosting provider, and whether other hosts in the environment contacted it.
- Data volume matters. Small regular outbound requests suggest tasking. Large outbound transfers suggest exfiltration and change the priority of the case.

## Indicators to record
Domain, IP address, URL, file hash, process name, command line and host. Each indicator must link to the event that produced it.

## Do not conclude from absence
If telemetry for a period or a host is missing, the case is limited by that gap. Say so in the report instead of declaring the activity benign.
