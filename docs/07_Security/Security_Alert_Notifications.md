# Security alert notifications

Written 2026-11-24. Status: **IMPLEMENTED and unit-tested; not exercised against a real receiver.** Off for the network by default.

## What it is
The Security page already derives platform security alerts (key guessing, probing for secrets, a key used after guessing, a key used from a new address, a burst of case creation) from what the server observed. The notification channel takes **those same alerts** (one definition, in `backend/app/services/security_alert_service.py`) and notifies:
1. **The application log, always** (a `SECURITY ALERT` warning line per new alert).
2. **One webhook, only if the operator configures it.**

It adds no detection of its own. Once a minute the server derives the alerts for the last hour and sends the ones at or above the minimum severity that it has not already notified.

## Configuration (environment, never the repository)
| Variable | Default | Meaning |
|---|---|---|
| `SECURITY_ALERT_WEBHOOK_URL` | empty | Where to POST. Empty means nothing leaves the process. `https` required; `http` only to localhost, 127.0.0.0/8 or ::1; no credentials in the URL; redirects are not followed. |
| `SECURITY_ALERT_WEBHOOK_SECRET` | none | HMAC-SHA256 signing secret, at least 16 characters. **Without it the webhook is ignored**: alerts are never sent unsigned. |
| `SECURITY_ALERT_MIN_SEVERITY` | `medium` | `medium`, `high` or `critical`. |

## Message
`POST` with `Content-Type: application/json` and headers `X-AISOP-Timestamp` (Unix seconds) and `X-AISOP-Signature: sha256=<hex>`, where the signature is HMAC-SHA256 over `timestamp + "." + raw body`. Body: `{"schema":"aisop.security_alerts.v1","instance":...,"sent_at":...,"alerts":[{id, rule, severity, title, subject, count, first_seen, last_seen, recommended_action}]}`. It carries nothing the server did not compose from cleaned values: no API key, request body, header value or path.

A receiver should check the signature in constant time, reject a timestamp older than a few minutes (replay), and treat the message as a hint to look at the Security page, not as a command.

```python
import hmac, hashlib, time
def valid(secret: str, timestamp: str, body: bytes, header: str) -> bool:
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return abs(time.time() - int(timestamp)) < 300 and hmac.compare_digest(expected, header.removeprefix("sha256="))
```

## Limits (state them)
- Each alert is notified once, and again only when new activity arrives and 30 minutes have passed, at most 20 alerts per message. A flood therefore cannot become a flood of messages, but a slow, persistent attacker produces one message every 30 minutes at most.
- No retry: a timeout or an error status is logged by type and dropped. A persistent delivery problem is visible in the log, and alerting cannot break the server.
- State is in memory. After a restart, alerts still inside the one-hour window are notified again.
- It reports what this process observed. It blocks nothing and a quiet channel does not prove nothing happened.
- A webhook receiver (chat, ticketing, SIEM) is the company's choice and was **not** tested here: the tests use a simulated receiver.
- Not covered: email or SMS delivery, acknowledgement, escalation, paging.

## Tests
`backend/tests/unit/test_security_alerts_channel.py` (24 tests): nothing leaves without a webhook; one signed message with only whitelisted fields; tampering and a wrong secret fail verification; severity filter; once-and-again-on-new-activity-after-cooldown; bounded deduplication; message cap; 500, redirect and connection failures swallowed without retry; URL validation (https only, loopback http, no credentials); missing or short secret disables the webhook; defaults send nothing; the alerts equal the Security page's derivation over the same stored rows; the background notifier never raises into the server.
