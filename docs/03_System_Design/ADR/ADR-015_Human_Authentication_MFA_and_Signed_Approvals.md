# ADR-015: Human Authentication, MFA and Signed Approvals

| Field | Value |
|---|---|
| **ID** | ADR-015 |
| **Status** | **PROPOSED**. Design only. Nothing in this document is implemented and none of it may be claimed as built. |
| **Date Proposed** | 2026-11-22 |
| **Relates to** | `backend/app/core/auth.py` (API keys), `backend/app/core/auth_throttle.py`, ADR-014 (single-tenant evidence pool), the multi-source export gate (lead approval), `docs/07_Security/OWASP_API_Top10_Review.md` |

## Context
Today every principal authenticates with an API key (256-bit random secret, SHA-256 hashed at rest, expiry, lockout after repeated rejections). The role shown in the interface is a "View as" preview; the server decides from the key. This is sound for machine clients and demo use. For human analysts it has three limits: the key is a long-lived bearer secret (whoever holds it is the analyst), there is no second factor, and an approval records who the server believes approved, with no independent proof.

The idea raised on 2026-11-22: real accounts with roles (so no role switching), MFA, a code sent to the user, signatures and HMAC.

## What MFA does and does not do (threat model)
MFA adds a layer. It does not make an account unattackable, and some of its common forms are bypassed in practice:

| Attack | Why it works against weak MFA | What actually resists it |
|---|---|---|
| **MFA fatigue / push bombing** | The attacker has the password and triggers repeated approval prompts until the user taps Accept | No push approvals. Use number matching or, better, a code the user types or a hardware or passkey assertion. Rate-limit prompts and lock after refusals |
| **Evil-proxy session theft** (adversary-in-the-middle phishing kits) | The victim completes MFA on the attacker's relay and the attacker keeps the session cookie or token | **Phishing-resistant factors** (WebAuthn / passkeys bind the assertion to the real origin, so the relay fails). Short sessions; bind a session to the device; re-authenticate for sensitive actions |
| **RAT / info-stealer on the endpoint** (AsyncRAT and similar) | Malware reads the session token or cookie after the user has authenticated, or drives the logged-in browser | MFA cannot stop this. Mitigations: short token lifetime, re-authentication before approve, close and export, device-bound tokens, endpoint controls, and an audit trail that shows where a session was used |
| **SIM swap / email takeover** | Codes sent by SMS or email are only as safe as that channel | Do not use SMS or email codes as the strong factor |
| **Downgrade to the weakest enrolled factor** | Attackers choose the weakest method offered | Offer one strong method per account; no fallback to email or SMS |

## Options
1. **Keep API keys, add step-up for sensitive actions.** A second factor (TOTP or WebAuthn) is required only to approve a report, export it, close a case or change assignments, not to log in. Smallest change; limits the damage of a stolen session.
2. **Full human login** (username, password hashed with argon2id, reset flow, lockout, TOTP or WebAuthn, session tokens). Largest surface: storage, reset, enumeration, session fixation, CSRF. Not recommended before the defence.
3. **Delegate to an identity provider** (OIDC with a hosted provider). Least custom code, strongest outcome, but needs an external account and a dependency decision.

## Recommendation
Do option 1 first, with **TOTP** (RFC 6238, offline, no email service needed) and WebAuthn as the later, phishing-resistant upgrade. Consider option 3 if AISOP is ever run for real teams. Do not build option 2.

Sensitive actions to protect: approve or reject a multi-source report, export, close or archive a case, change a case lead or assignments, issue or revoke API keys.

## Two separate integrity mechanisms (do not blur them)
- **HMAC on ingestion (sensor to API):** a shared secret per sensor signs `timestamp + nonce + body hash`. The server rejects a stale timestamp or a repeated nonce, which stops replay of a captured request. This proves the message came from the secret holder and was not changed. It is not authentication of a person.
- **Signed approvals (a person to the record):** a signature by a key the approver holds (WebAuthn assertion or a per-user key) over the digest of the exact approved result gives non-repudiation. If the **server** holds the key, the signature only proves the server recorded the approval, not that the person gave it. The existing audit hash chain already detects edits after the fact.

## Consequences if adopted
- A stolen API key alone no longer approves, exports or closes.
- A new table for enrolled factors and a nonce store for ingestion; a migration.
- Operational work: enrolment, recovery codes, key rotation (there is still no HTTP key-management endpoint).
- Residual risk stays: an attacker controlling an authenticated endpoint can act inside the session until it expires. The ADR does not claim otherwise.

## What this ADR does not decide
Whether to adopt it for the defence. It is a roadmap with a reasoned threat model. In the defence, say "designed, not built"; do not say "MFA enabled".
