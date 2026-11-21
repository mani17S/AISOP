/**
 * Pasted API key handling (browser check, 2026-11-20).
 *
 * A key never contains whitespace, so every whitespace character is removed: a trailing newline from a clipboard, a line break
 * from a wrapped terminal, or a stray space would otherwise either make the server reject the key (401) or, for a newline inside
 * the value, make the browser refuse to send the request at all (which looked like a network error).
 * The shape hint only helps the person who pasted; it never blocks saving, because deployments may issue other key formats.
 */

const CANONICAL = /^aisop_(live|test)_[0-9a-f]{16}_[0-9a-f]{64}$/;
const CANONICAL_ANYWHERE = /aisop_(?:live|test)_[0-9a-f]{16}_[0-9a-f]{64}/g;

export function normalizeApiKey(raw: string): string {
  return raw.replace(/\s+/g, '');
}

/** A short sentence when the entered key does not look like an AISOP key; null when it does (or nothing was entered). */
export function apiKeyShapeHint(raw: string): string | null {
  const key = normalizeApiKey(raw);
  if (key === '' || CANONICAL.test(key)) return null;
  const copies = key.match(CANONICAL_ANYWHERE)?.length ?? 0;
  if (copies > 1) return `This looks like the key pasted ${copies} times (${key.length} characters). Press Clear key and paste it once.`;
  if (key.startsWith('aisop_')) return `The key has ${key.length} characters and an AISOP key has 92. Part of it may be missing or extra text may have been pasted. Press Clear key and paste it again.`;
  return `This does not look like an AISOP key (they start with aisop_live_ or aisop_test_). It can still be saved if your operator issued a different kind of key.`;
}
