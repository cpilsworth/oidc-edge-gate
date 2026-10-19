// HMAC-signed JSON cookie values (`base64url(json).base64url(hmac)`, the format
// of src/sdk/cookies.js sign/unsign). Used for both the session and the
// transient login-state cookie; one read path keeps their checks from drifting.
//
// Keyring (docs/architecture/plugins.md §14.2): a token is signed with the
// ACTIVE key only, and its payload carries `kid`, the key id of that key
// (first 8 base64url chars of SHA-256(key)). Verification tries at most two
// keys (active, then the optional verify-only previous key) by HMAC. Only once
// a key has verified the signature is the payload parsed, and its `kid` must
// then equal the id of THAT key. A `kid` never selects a key, and nothing in an
// unverified payload is trusted.

import { sign, unsign } from "../../../src/sdk/cookies.js";
import { base64UrlEncode, utf8 } from "../../../src/sdk/encoding.js";

/** Key ids are 8 base64url characters. */
export const KID_RE = /^[A-Za-z0-9_-]{8}$/;

/** Minimum key length (bytes); mirrors the active key's config-load check. */
export const MIN_KEY_BYTES = 32;

// kid per key string. The promise is cached so concurrent calls share one
// digest. Bounded like the SDK's HMAC key cache: there are at most two keys.
const KID_CACHE_MAX = 4;
const kidCache = new Map();

/**
 * Key id of an HMAC key: the first 8 base64url characters of SHA-256(key).
 * Not secret (a truncated hash of a ≥ 32-byte random key), memoized per key.
 * @param {string} key
 * @returns {Promise<string>}
 */
export function keyId(key) {
  let pending = kidCache.get(key);
  if (pending) return pending;
  if (kidCache.size >= KID_CACHE_MAX) kidCache.clear();
  pending = crypto.subtle.digest("SHA-256", utf8(key)).then((d) => base64UrlEncode(new Uint8Array(d)).slice(0, 8));
  kidCache.set(key, pending);
  pending.catch(() => {
    if (kidCache.get(key) === pending) kidCache.delete(key);
  });
  return pending;
}

/**
 * Normalize a key or key list into the verification keyring: non-empty
 * strings only, de-duplicated (a previous key equal to the active one is
 * harmless), at most two. The first entry is the active key.
 * @param {string|ReadonlyArray<string|undefined|null>} keys
 * @returns {string[]}
 */
export function toKeyring(keys) {
  const list = Array.isArray(keys) ? keys : [keys];
  const out = [];
  for (const k of list) {
    if (typeof k === "string" && k.length > 0 && !out.includes(k)) out.push(k);
    if (out.length === 2) break;
  }
  return out;
}

/**
 * The keyring for a plugin context: the given active key plus the optional
 * verify-only `session_hmac_key_previous` secret. A previous key shorter than
 * MIN_KEY_BYTES is ignored with a warning (never a weak verification key).
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} activeKey
 * @returns {string[]}
 */
export function keyringFor(ctx, activeKey) {
  const previous = ctx.secret("session_hmac_key_previous");
  if (typeof previous === "string" && previous.length > 0 && utf8(previous).length < MIN_KEY_BYTES) {
    ctx.log.warn(`oidc-auth: session_hmac_key_previous is shorter than ${MIN_KEY_BYTES} bytes; ignored`);
    return toKeyring([activeKey]);
  }
  return toKeyring([activeKey, previous]);
}

/**
 * Sign a JSON value into a cookie token.
 * @param {unknown} value
 * @param {string} key  HMAC key
 * @returns {Promise<string>}
 */
export function encodeSigned(value, key) {
  return sign(JSON.stringify(value), key);
}

/**
 * Verify and parse a token. Null when absent, tampered, not JSON, signed by a
 * key outside the keyring, carrying a `kid` other than the verifying key's, or
 * rejected by `validate`. Never throws.
 * @param {string|undefined|null} token
 * @param {string|ReadonlyArray<string|undefined|null>} keys  active key first
 * @param {(value: any) => boolean} validate
 */
export async function decodeSigned(token, keys, validate) {
  try {
    if (!token) return null;
    for (const key of toKeyring(keys)) {
      const payload = await unsign(token, key);
      if (!payload) continue;
      // Verified by `key`: from here on the payload is authentic; it must also
      // claim to be signed by this very key, else reject (no further keys).
      const value = JSON.parse(payload);
      if (!isRecord(value) || value.kid !== await keyId(key)) return null;
      return validate(value) ? value : null;
    }
    return null;
  } catch {
    return null;
  }
}

/** True for a non-null, non-array object. */
export function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
