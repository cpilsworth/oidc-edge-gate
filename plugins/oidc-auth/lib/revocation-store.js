// Revocation records in KV (docs/architecture/plugins.md §15.2). This module is
// the ONLY place that knows the key names and the record format; the request
// check (./revocation.js), logout (./logout.js), the admin route (./admin.js)
// and the webhook adapter (./webhook.js) all go through it.
//
// Keys live in the plugin's namespaced KV view (the kernel prefixes them with
// "plugin:oidc-auth:"):
//
//   rev:sid:<sid>               one session is revoked
//                               value {"at": <epoch s>}
//   rev:sub:<hex sha256(sub)>   every session of a subject issued at or before
//                               `revoked_at` is revoked (a per-user epoch)
//                               value {"revoked_at": <epoch s>}
//
// Both are stored in the same self-describing wrapper as the other oidc-auth
// KV entries (./kv.js): JSON {"value": …, "expires": <epoch ms>}, plus the
// native KV ttl. The subject is hashed so no PII (and no arbitrary bytes) ends
// up in a KV key. Any non-empty subject hashes, whatever its length, so a
// session with a long `sub` is checked like any other (W3.R R3-2);
// MAX_SUB_BYTES only bounds what the admin route and the webhook accept.
//
// Lifetime: a record only has to outlive the sessions it revokes. A session is
// valid for at most session_ttl_seconds + 60 s past its iat (session.js time
// bounds), so records live recordTtlSeconds(ttl) = ttl + 120 s.
//
// Errors: KV errors propagate, and a present-but-corrupt record throws
// RevocationRecordError. The caller decides per revocation mode (required:
// fail closed; optional: log and allow). An expired record reads as absent.

import { utf8 } from "../../../src/sdk/encoding.js";

/** Extra lifetime of a record beyond session_ttl_seconds (2 × the session clock skew). */
export const REVOCATION_TTL_MARGIN_SECONDS = 120;

const SID_RE = /^[A-Za-z0-9_-]{22}$/;
/**
 * Longest subject the admin route and the webhook accept as input (bytes,
 * UTF-8). Not a limit of the store: subKey hashes any non-empty subject.
 */
export const MAX_SUB_BYTES = 1024;

/** A revocation record that exists but cannot be read (corrupt or wrong shape). */
export class RevocationRecordError extends Error {
  constructor(message) {
    super(message);
    this.name = "RevocationRecordError";
  }
}

/** True for a well-formed session id (16 random bytes, base64url). */
export function isSessionId(sid) {
  return typeof sid === "string" && SID_RE.test(sid);
}

/** True for an admin/webhook input subject: a non-empty string of at most MAX_SUB_BYTES. */
export function isSubject(sub) {
  return typeof sub === "string" && sub.length > 0 && utf8(sub).length <= MAX_SUB_BYTES;
}

/**
 * KV key of a session record.
 * @param {string} sid
 */
export function sidKey(sid) {
  if (!isSessionId(sid)) throw new TypeError("sid must be a session id");
  return `rev:sid:${sid}`;
}

/**
 * KV key of a subject record: "rev:sub:" + lowercase hex SHA-256(sub). Any
 * non-empty string, of any length: a verified session's `sub` must always be
 * checkable (W3.R R3-2).
 * @param {string} sub
 * @returns {Promise<string>}
 */
export async function subKey(sub) {
  if (typeof sub !== "string" || sub.length === 0) throw new TypeError("sub must be a non-empty string");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(sub)));
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return `rev:sub:${hex}`;
}

/**
 * Lifetime of a revocation record for the given session TTL.
 * @param {number} sessionTtlSeconds  positive integer
 */
export function recordTtlSeconds(sessionTtlSeconds) {
  if (!Number.isInteger(sessionTtlSeconds) || sessionTtlSeconds <= 0) {
    throw new TypeError("sessionTtlSeconds must be a positive integer");
  }
  return sessionTtlSeconds + REVOCATION_TTL_MARGIN_SECONDS;
}

/**
 * Read and unwrap a record. null when absent or expired; throws
 * RevocationRecordError when present but corrupt. KV errors propagate.
 * @param {import("../../../src/sdk/index.js").KvView} kv
 * @param {string} key
 * @param {number} nowMs
 */
async function readRecord(kv, key, nowMs) {
  const raw = await kv.get(key);
  if (raw === null || raw === undefined) return null;
  let wrapped;
  try {
    wrapped = JSON.parse(raw);
  } catch {
    throw new RevocationRecordError("revocation record is not JSON");
  }
  if (wrapped === null || typeof wrapped !== "object" || Array.isArray(wrapped)
    || typeof wrapped.expires !== "number" || !Number.isFinite(wrapped.expires)
    || wrapped.value === null || typeof wrapped.value !== "object" || Array.isArray(wrapped.value)) {
    throw new RevocationRecordError("revocation record has the wrong shape");
  }
  if (wrapped.expires <= nowMs) return null;
  return wrapped.value;
}

async function writeRecord(kv, key, value, ttlSeconds, nowMs) {
  await kv.put(key, JSON.stringify({ value, expires: nowMs + ttlSeconds * 1000 }), { ttl: ttlSeconds });
}

/**
 * Is this session revoked?
 * @param {import("../../../src/sdk/index.js").KvView} kv
 * @param {string} sid
 * @param {{nowMs?: number}} [opts]
 * @returns {Promise<boolean>}
 */
export async function isSessionRevoked(kv, sid, { nowMs = Date.now() } = {}) {
  const value = await readRecord(kv, sidKey(sid), nowMs);
  if (value === null) return false;
  if (typeof value.at !== "number" || !Number.isFinite(value.at)) {
    throw new RevocationRecordError("session revocation record has no valid `at`");
  }
  return true;
}

/**
 * The subject's revocation epoch: sessions with iat <= this value are revoked.
 * null when there is no (unexpired) record.
 * @param {import("../../../src/sdk/index.js").KvView} kv
 * @param {string} sub
 * @param {{nowMs?: number}} [opts]
 * @returns {Promise<number|null>}
 */
export async function subjectRevokedAt(kv, sub, { nowMs = Date.now() } = {}) {
  const value = await readRecord(kv, await subKey(sub), nowMs);
  if (value === null) return null;
  if (!Number.isInteger(value.revoked_at) || value.revoked_at < 0) {
    throw new RevocationRecordError("subject revocation record has no valid `revoked_at`");
  }
  return value.revoked_at;
}

/**
 * Revoke one session. Idempotent.
 * @param {import("../../../src/sdk/index.js").KvView} kv
 * @param {string} sid
 * @param {{sessionTtlSeconds: number, nowMs?: number}} opts
 */
export async function revokeSession(kv, sid, { sessionTtlSeconds, nowMs = Date.now() }) {
  const key = sidKey(sid);
  await writeRecord(kv, key, { at: Math.floor(nowMs / 1000) }, recordTtlSeconds(sessionTtlSeconds), nowMs);
}

/**
 * Revoke every session of a subject issued at or before `revokedAt`.
 * The stored epoch is max(existing, min(revokedAt ?? now, now)):
 * - it only moves forward: an existing later `revoked_at` is kept, so a stale
 *   or replayed request can never re-validate sessions a newer revocation
 *   ended (a corrupt existing record is overwritten);
 * - `revokedAt` (epoch s; the admin route passes the signed request's `iat`)
 *   is clamped to now, so a replay of the same signed request asks for the
 *   same or an earlier value and changes nothing (W3.R R3-3).
 * When the existing epoch already covers the request, nothing is written: that
 * record was written at or after its own `revoked_at`, so its TTL already
 * outlives every session it revokes. Returns the stored epoch.
 * Note KV allows about one write per second per key; a second revocation of
 * the same subject within that second may be rejected by the platform (the
 * error propagates).
 * @param {import("../../../src/sdk/index.js").KvView} kv
 * @param {string} sub  any non-empty string
 * @param {{sessionTtlSeconds: number, nowMs?: number, revokedAt?: number}} opts
 * @returns {Promise<number>}
 */
export async function revokeSubject(kv, sub, { sessionTtlSeconds, nowMs = Date.now(), revokedAt }) {
  if (revokedAt !== undefined && revokedAt !== null && (!Number.isSafeInteger(revokedAt) || revokedAt < 0)) {
    throw new TypeError("revokedAt must be a non-negative integer (epoch seconds)");
  }
  const key = await subKey(sub);
  const ttl = recordTtlSeconds(sessionTtlSeconds);
  let existing = null;
  try {
    existing = await subjectRevokedAt(kv, sub, { nowMs });
  } catch (e) {
    if (!(e instanceof RevocationRecordError)) throw e;
  }
  const now = Math.floor(nowMs / 1000);
  const requested = Math.min(revokedAt ?? now, now);
  if (existing !== null && existing >= requested) return existing;
  await writeRecord(kv, key, { revoked_at: requested }, ttl, nowMs);
  return requested;
}
