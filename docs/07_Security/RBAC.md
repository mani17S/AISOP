

## Role shown in the interface (2026-11-23)

`GET /api/v1/auth/me` returns the caller's account name, global role and client name, taken from the authenticated key. It never returns a key, a hash, a key prefix or another account. A legacy machine key with no account behind it returns no username and no role.

The interface calls it when a key is set. When the server names a role, the header shows "Signed in as <account>" with the role and the "View as" selector is removed, so a person cannot present themselves as a role they do not hold. When the server cannot say (no key, a machine key, an error, a role the interface does not know) the manual "View as" preview stays, labelled as a preview. A sensor (`ingest`) is shown read-only because it has no analyst screens.

This is presentation only. Authorisation is still decided by the server on every request from the key, so changing what the screen shows grants nothing. The Security tab appears only for a real security admin identity (or the preview role when no identity is known).

