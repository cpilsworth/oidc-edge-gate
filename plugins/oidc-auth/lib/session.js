// The gate session: the gate's OWN credential, minted once after a verified
// OIDC login and checked cheaply on every request (HMAC + embedded `exp`, no
// backend call). The IdP's ID token is deliberately not re-verified per request;
// that would hammer the JWKS endpoint and the fetch budget.
//
// Wire format (unchanged from the pre-plugin gate, so live sessions stay valid):
//   cookie  __Host-edge_session=<token>; Path=/; Max-Age=<ttl>; SameSite=Lax; HttpOnly; Secure
//   token   base64url(JSON).base64url(HMAC-SHA256(JSON, session_hmac_key))
//   JSON    {"sub", "email"?, "name"?, "groups": [string], "iat", "exp"}   (this key order)
// The __Host- prefix makes the browser enforce Secure + Path=/ + no Domain.

import { createIdentity } from "../../../src/sdk/index.js";
import { decodeSigned, encodeSigned, isRecord } from "./signed-cookie.js";

export const SESSION_COOKIE = "__Host-edge_session";

/**
 * Strict session shape check. `exp` must be in the future and `groups` an array.
 * @param {unknown} session
 */
export function isValidSession(session) {
  if (!isRecord(session)) return false;
  if (typeof session.sub !== "string" || !session.sub) return false;
  if (typeof session.iat !== "number" || !Number.isFinite(session.iat)) return false;
  if (typeof session.exp !== "number" || !Number.isFinite(session.exp)) return false;
  if (session.exp * 1000 <= Date.now()) return false;
  if (!Array.isArray(session.groups)) return false;
  return true;
}

/**
 * Build the session payload, in the wire format's key order.
 * @param {{sub: string, email?: string, name?: string, groups: ReadonlyArray<string>}} who
 * @param {number} ttlSeconds
 * @param {number} [now] epoch seconds
 */
export function buildSession({ sub, email, name, groups }, ttlSeconds, now = Math.floor(Date.now() / 1000)) {
  return { sub, email, name, groups: [...groups], iat: now, exp: now + ttlSeconds };
}

/** Sign a session payload into a cookie token. */
export function encodeSession(session, key) {
  return encodeSigned(session, key);
}

/** Verify a session token; null when invalid or expired. Never throws. */
export function decodeSession(token, key) {
  return decodeSigned(token, key, isValidSession);
}

/**
 * Read and verify the request's session cookie (through ctx.cookies).
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} key
 */
export function readSession(ctx, key) {
  return decodeSession(ctx.cookies.get(SESSION_COOKIE), key);
}

/**
 * Set the session cookie on the response (through ctx.cookies).
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {object} session  from buildSession()
 * @param {string} key
 * @param {number} ttlSeconds
 */
export async function writeSession(ctx, session, key, ttlSeconds) {
  ctx.cookies.set(SESSION_COOKIE, await encodeSession(session, key), { maxAge: ttlSeconds });
}

/** Expire the session cookie. */
export function clearSession(ctx) {
  ctx.cookies.clear(SESSION_COOKIE);
}

/**
 * A verified session as the SDK Identity the kernel accepts. Non-string email
 * or name values are dropped; groups are normalized by createIdentity().
 * @param {{sub: string, email?: unknown, name?: unknown, groups: unknown[], iat: number, exp: number}} session
 */
export function sessionToIdentity(session) {
  const str = (v) => (typeof v === "string" ? v : undefined);
  return createIdentity({
    sub: session.sub,
    email: str(session.email),
    name: str(session.name),
    groups: session.groups,
    method: "oidc-session",
    issuedAt: session.iat,
    expiresAt: session.exp,
  });
}
