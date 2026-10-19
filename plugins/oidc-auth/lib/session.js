// The gate session: the gate's OWN credential, minted once after a verified
// OIDC login and checked cheaply on every request (HMAC + embedded `exp`, no
// backend call). The IdP's ID token is deliberately not re-verified per request;
// that would hammer the JWKS endpoint and the fetch budget.
//
// Wire format v2 (docs/architecture/plugins.md §14.2):
//   cookie  __Host-edge_session=<token>; Path=/; Max-Age=<seconds>; SameSite=Lax; HttpOnly; Secure
//   token   base64url(JSON).base64url(HMAC-SHA256(JSON, session_hmac_key))
//   JSON    {"v": 2, "typ": "session", "kid", "sid", "sub", "email"?, "name"?,
//            "groups": [string], "iat", "exp"}                    (this key order)
//     kid   first 8 base64url chars of SHA-256(signing key) (./signed-cookie.js)
//     sid   16 random bytes, base64url (22 chars); minted by the callback before
//           toIdentity(), so it equals identity.sessionId
// The __Host- prefix makes the browser enforce Secure + Path=/ + no Domain.
//
// Keyring: `session_hmac_key` signs and verifies; the optional secret
// `session_hmac_key_previous` only verifies (rotation without a mass logout).
// The verifying key must match the payload's kid. v1 cookies (no v/typ/kid/sid)
// are rejected: everyone logs in once after the cutover.
//
// Lifetime: exp = min(now + ttl, identity.expiresAt). identity.expiresAt already
// carries any draft.limitLifetime() cap (src/sdk createIdentityDraft), so a
// degraded login gets a short session. writeSession clamps the cookie Max-Age
// to the payload's lifetime (exp - iat), so cookie and payload expire together.

import { createIdentity } from "../../../src/sdk/index.js";
import { base64UrlEncode } from "../../../src/sdk/encoding.js";
import { KID_RE, decodeSigned, encodeSigned, isRecord, keyId, keyringFor } from "./signed-cookie.js";

export const SESSION_COOKIE = "__Host-edge_session";
export const SESSION_VERSION = 2;
export const SESSION_TYP = "session";
/** Longest encoded session value ever set (browsers cap a cookie near 4096 bytes). */
export const MAX_SESSION_COOKIE_BYTES = 3500;

const SID_RE = /^[A-Za-z0-9_-]{22}$/;

/**
 * Thrown by writeSession when the encoded session would exceed
 * MAX_SESSION_COOKIE_BYTES (e.g. a huge group list). No cookie is set; the
 * callback turns this into a 500 auth error.
 */
export class SessionTooLargeError extends Error {
  /** @param {number} bytes */
  constructor(bytes) {
    super(`session cookie too large: ${bytes} bytes (max ${MAX_SESSION_COOKIE_BYTES})`);
    this.name = "SessionTooLargeError";
    this.bytes = bytes;
  }
}

/** A fresh session id: 16 random bytes, base64url (22 chars). */
export function newSessionId() {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

/** Clock skew tolerated on the session's time bounds (seconds). */
export const SESSION_CLOCK_SKEW_SECONDS = 60;

/**
 * Strict session shape check. v2 only; `exp` must be in the future and
 * `groups` an array. The kid-vs-verifying-key check is decodeSigned's.
 * Time bounds (W2.R R10): `iat` may not be more than 60 s in the future, and,
 * when `maxTtlSeconds` is given (readSession passes session_ttl_seconds), the
 * lifetime `exp - iat` may not exceed it by more than 60 s, so a token minted
 * with a far-future exp (a leaked key, a bug) is not honoured for longer than
 * any session the gate itself would mint.
 * @param {unknown} session
 * @param {{maxTtlSeconds?: number, now?: number}} [bounds]  now in epoch seconds
 */
export function isValidSession(session, bounds = {}) {
  if (!isRecord(session)) return false;
  if (session.v !== SESSION_VERSION || session.typ !== SESSION_TYP) return false;
  if (typeof session.kid !== "string" || !KID_RE.test(session.kid)) return false;
  if (typeof session.sid !== "string" || !SID_RE.test(session.sid)) return false;
  if (typeof session.sub !== "string" || !session.sub) return false;
  if (typeof session.iat !== "number" || !Number.isFinite(session.iat)) return false;
  if (typeof session.exp !== "number" || !Number.isFinite(session.exp)) return false;
  const now = typeof bounds.now === "number" ? bounds.now : Date.now() / 1000;
  if (session.exp <= now) return false;
  if (session.iat > now + SESSION_CLOCK_SKEW_SECONDS) return false;
  const maxTtl = bounds.maxTtlSeconds;
  if (typeof maxTtl === "number" && Number.isFinite(maxTtl) && maxTtl > 0
    && session.exp - session.iat > maxTtl + SESSION_CLOCK_SKEW_SECONDS) return false;
  if (!Array.isArray(session.groups)) return false;
  return true;
}

/**
 * Build the session payload (without `kid`, which encodeSession adds from the
 * signing key). The `sid` is the identity's `sessionId` when it has one (the
 * callback mints it with newSessionId() before toIdentity(), so
 * identity.sessionId and the cookie's sid are the same value); otherwise a
 * new one is minted here, on both platform profiles. A present `sessionId`
 * that is not a well-formed sid throws (it would never verify).
 * `exp` is now + ttl, or the identity's `expiresAt` when that is earlier.
 * @param {{sub: string, email?: string, name?: string, groups: ReadonlyArray<string>, expiresAt?: number, sessionId?: string}} who
 * @param {number} ttlSeconds
 * @param {number} [now] epoch seconds
 */
export function buildSession({ sub, email, name, groups, expiresAt, sessionId }, ttlSeconds, now = Math.floor(Date.now() / 1000)) {
  if (sessionId !== undefined && (typeof sessionId !== "string" || !SID_RE.test(sessionId))) {
    throw new TypeError("sessionId must be a session id from newSessionId()");
  }
  let exp = now + ttlSeconds;
  if (typeof expiresAt === "number" && Number.isFinite(expiresAt) && expiresAt < exp) exp = expiresAt;
  const sid = sessionId ?? newSessionId();
  return { v: SESSION_VERSION, typ: SESSION_TYP, sid, sub, email, name, groups: [...groups], iat: now, exp };
}

/**
 * Sign a session payload into a cookie token with the ACTIVE key. Only the
 * wire-format fields are serialized, in wire order, with `kid` = keyId(key).
 * @param {object} session  from buildSession()
 * @param {string} key  the active session_hmac_key
 */
export async function encodeSession(session, key) {
  const { v, typ, sid, sub, email, name, groups, iat, exp } = session;
  return encodeSigned({ v, typ, kid: await keyId(key), sid, sub, email, name, groups, iat, exp }, key);
}

/**
 * Verify a session token against a key or keyring (active first, at most two
 * keys); null when invalid, expired, out of its time bounds, v1, or
 * kid-mismatched. Never throws.
 * @param {string|undefined|null} token
 * @param {string|ReadonlyArray<string|undefined|null>} keys
 * @param {{maxTtlSeconds?: number, now?: number}} [bounds]  see isValidSession
 */
export function decodeSession(token, keys, bounds = {}) {
  return decodeSigned(token, keys, (session) => isValidSession(session, bounds));
}

/**
 * Read and verify the request's session cookie (through ctx.cookies) with the
 * keyring: `key` (active) plus the optional `session_hmac_key_previous`.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} key  the active session_hmac_key
 * @param {number} [maxTtlSeconds]  session_ttl_seconds (ctx.config.sessionTtlSeconds);
 *        bounds exp - iat (W2.R R10)
 */
export function readSession(ctx, key, maxTtlSeconds) {
  const token = ctx.cookies.get(SESSION_COOKIE);
  if (!token) return Promise.resolve(null);
  return decodeSession(token, keyringFor(ctx, key), { maxTtlSeconds });
}

/**
 * Set the session cookie on the response (through ctx.cookies). Max-Age is the
 * smaller of `ttlSeconds` and the payload's lifetime (exp - iat).
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {object} session  from buildSession()
 * @param {string} key  the active session_hmac_key
 * @param {number} ttlSeconds
 * @throws {SessionTooLargeError} when the encoded value exceeds MAX_SESSION_COOKIE_BYTES (no cookie set)
 */
export async function writeSession(ctx, session, key, ttlSeconds) {
  const token = await encodeSession(session, key);
  if (token.length > MAX_SESSION_COOKIE_BYTES) throw new SessionTooLargeError(token.length);
  const lifetime = session.exp - session.iat;
  const maxAge = Number.isFinite(lifetime) ? Math.max(0, Math.min(ttlSeconds, lifetime)) : ttlSeconds;
  ctx.cookies.set(SESSION_COOKIE, token, { maxAge });
}

/** Expire the session cookie. */
export function clearSession(ctx) {
  ctx.cookies.clear(SESSION_COOKIE);
}

/**
 * A verified session as the SDK Identity the kernel accepts. Non-string email
 * or name values are dropped; groups are normalized by createIdentity().
 * @param {{sid: string, sub: string, email?: unknown, name?: unknown, groups: unknown[], iat: number, exp: number}} session
 */
export function sessionToIdentity(session) {
  const str = (v) => (typeof v === "string" ? v : undefined);
  return createIdentity({
    sub: session.sub,
    email: str(session.email),
    name: str(session.name),
    groups: session.groups,
    method: "oidc-session",
    sessionId: session.sid,
    issuedAt: session.iat,
    expiresAt: session.exp,
  });
}
