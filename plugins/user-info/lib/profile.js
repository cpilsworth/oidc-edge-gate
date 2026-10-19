// Profile lookups: allowlisting, the KV cache (provisioned only), the
// per-request memo, and the header-safe x-user-* projection.

import { requireAuthorization, expandTemplate, getJson, LookupFailure } from "./backend.js";
import { headerNameFor } from "./options.js";

/** Longest x-user-* header value (characters, after encoding). */
export const MAX_HEADER_VALUE = 1024;
const CACHE_VERSION = 1;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/g;

/** Lowercase hex SHA-256 of a UTF-8 string (WebCrypto). */
export async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  let out = "";
  for (const b of digest) out += b.toString(16).padStart(2, "0");
  return out;
}

/** KV key for a subject's cached profile: "profile:" + hex SHA-256(sub). */
export async function profileCacheKey(sub) {
  return `profile:${await sha256Hex(sub)}`;
}

/**
 * Fingerprint of what a cached profile was built from (endpoint template and
 * field list), so one subject's entry is never served to an instance with
 * different options.
 */
async function fingerprint(options) {
  return (await sha256Hex(`${options.profile_endpoint}\n${options.profile_fields.join(",")}`)).slice(0, 16);
}

/**
 * Pick ONLY the allowlisted top-level scalar fields (string, finite number,
 * boolean) of a backend response; anything else is dropped.
 * @param {unknown} body
 * @param {ReadonlyArray<string>} fields
 * @returns {Object<string, string|number|boolean>}
 */
export function pickProfile(body, fields) {
  if (body === null || typeof body !== "object" || Array.isArray(body)) throw new LookupFailure("not_an_object");
  const entries = [];
  for (const f of fields) {
    if (!Object.prototype.hasOwnProperty.call(body, f)) continue;
    const v = body[f];
    if (typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v))) entries.push([f, v]);
  }
  return Object.fromEntries(entries);
}

/**
 * A header-safe value: control characters (CR/LF included) removed; a value
 * that contains non-ASCII characters or "%" is percent-encoded
 * (encodeURIComponent, UTF-8), so `decodeURIComponent(value)` is always the
 * original at the origin; truncated at a character boundary to
 * MAX_HEADER_VALUE characters.
 * @param {string|number|boolean} raw
 * @returns {string}
 */
export function headerValue(raw) {
  const s = String(raw).replace(CONTROL_RE, "");
  const encode = /[^\x20-\x7e]|%/.test(s);
  let out = "";
  for (const ch of s) {
    let piece = ch;
    if (encode) {
      try { piece = encodeURIComponent(ch); } catch { piece = "%EF%BF%BD"; } // lone surrogate -> U+FFFD
    }
    if (out.length + piece.length > MAX_HEADER_VALUE) break;
    out += piece;
  }
  return out.trim();
}

/** [headerName, value] pairs for the allowlisted fields present in a profile. */
export function profileHeaders(profile, fields) {
  const out = [];
  for (const f of fields) {
    if (!Object.prototype.hasOwnProperty.call(profile, f)) continue;
    const v = headerValue(profile[f]);
    if (v.length > 0) out.push([headerNameFor(f), v]);
  }
  return out;
}

const useKv = (ctx) => ctx.kv != null && ctx.platform && ctx.platform.profile === "provisioned";

/**
 * Parse a cached entry; null for anything that is not a current, matching entry.
 * @returns {Object|null}
 */
function parseCached(text, fp, fields) {
  if (typeof text !== "string") return null;
  let entry;
  try { entry = JSON.parse(text); } catch { return null; }
  if (!entry || entry.v !== CACHE_VERSION || entry.fp !== fp || !entry.profile || typeof entry.profile !== "object" || Array.isArray(entry.profile)) return null;
  try { return pickProfile(entry.profile, fields); } catch { return null; }
}

/**
 * Store an allowlisted profile in KV (provisioned only). Errors are logged
 * and never fail the request.
 * @returns {Promise<boolean>} true when the entry was written
 */
export async function cacheProfile(ctx, options, sub, profile) {
  if (!useKv(ctx)) return false;
  try {
    const key = await profileCacheKey(sub);
    const value = JSON.stringify({ v: CACHE_VERSION, fp: await fingerprint(options), profile });
    await ctx.kv.put(key, value, { ttl: options.cache_ttl_seconds });
    return true;
  } catch {
    ctx.log.warn("user-info profile cache write failed", { reason: "kv_write_error" });
    return false;
  }
}

/**
 * Delete a subject's cached profile (W2.R R13): at logout, and at a login
 * that does not re-warm the cache, so a profile never outlives the session
 * that fetched it by more than cache_ttl_seconds, and a fresh login never
 * serves an old one. No KV (or sandbox, which never uses KV) → nothing to do.
 * Errors are logged and ignored.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} sub
 */
export async function dropCachedProfile(ctx, sub) {
  if (!useKv(ctx) || typeof sub !== "string" || sub.length === 0) return;
  try {
    await ctx.kv.delete(await profileCacheKey(sub));
  } catch {
    ctx.log.warn("user-info profile cache delete failed", { reason: "kv_delete_error" });
  }
}

/**
 * The allowlisted profile of the verified identity. Order: per-request memo,
 * then (provisioned with KV) the KV cache, then the backend. A KV read error
 * falls back to a live fetch (logged). No profile_fields → {} with no fetch.
 * Throws LookupFailure on a backend failure; PluginError for misconfiguration
 * or a kernel fetch-policy violation.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {Readonly<Object>} options  validated options
 * @param {{sub: string, email?: string}} identity
 * @returns {Promise<Object<string, string|number|boolean>>}
 */
export async function loadProfile(ctx, options, identity) {
  const fields = options.profile_fields;
  if (fields.length === 0) return {};
  const fp = await fingerprint(options);
  const memoKey = `profile:${fp}`;
  if (ctx.state.has(memoKey)) return ctx.state.get(memoKey);

  if (useKv(ctx)) {
    try {
      const hit = parseCached(await ctx.kv.get(await profileCacheKey(identity.sub)), fp, fields);
      if (hit) {
        ctx.state.set(memoKey, hit);
        return hit;
      }
    } catch {
      ctx.log.warn("user-info profile cache read failed; fetching live", { reason: "kv_read_error" });
    }
  }

  const authorization = requireAuthorization(ctx);
  const url = expandTemplate(options.profile_endpoint, identity);
  const profile = pickProfile(await getJson(ctx, url, authorization, "user-info-profile"), fields);
  await cacheProfile(ctx, options, identity.sub, profile);
  ctx.state.set(memoKey, profile);
  return profile;
}
