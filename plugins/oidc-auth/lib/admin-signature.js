// Signing and verification for the admin revocation API
// (docs/architecture/plugins.md §15.5). Shared by the route (./admin.js) and the
// CLI (scripts/revoke.mjs) so the two can never drift.
//
// WebCrypto + TextEncoder/atob/btoa only: no Node APIs, no fastly:* modules. It
// runs unchanged on Fastly Compute and on Node ≥ 20.
//
//   authorization: Gate-Revoke-HMAC-SHA256 <base64url(HMAC-SHA256(key, raw body bytes))>
//
// - The MAC covers the EXACT raw request body bytes (no canonicalization): any
//   byte change, whitespace included, invalidates it.
// - base64url WITHOUT padding: exactly 43 characters for the 32-byte tag, in
//   canonical form (the unused low bits of the last character are zero).
// - Strict header parsing: the exact, case-sensitive scheme, exactly one space,
//   then the tag; nothing else (no list, no parameters, no surrounding space).
// - Verification uses crypto.subtle.verify (constant time).
//
// The key is the `revocation_admin_key` secret, used as its UTF-8 bytes.

import { base64UrlDecode, base64UrlEncode, utf8 } from "../../../src/sdk/encoding.js";

/** The authorization scheme (case-sensitive). */
export const ADMIN_SIGNATURE_SCHEME = "Gate-Revoke-HMAC-SHA256";
/** Body format version (`v`). */
export const ADMIN_BODY_VERSION = 1;
/** Largest accepted request body (bytes). */
export const MAX_ADMIN_BODY_BYTES = 4096;
/** Accepted |now − iat| (seconds). */
export const ADMIN_IAT_SKEW_SECONDS = 300;
/** Longest accepted `reason` (printable ASCII characters). */
export const MAX_REASON_LENGTH = 200;
/** `jti`: 22–64 base64url characters. */
export const JTI_RE = /^[A-Za-z0-9_-]{22,64}$/;
/** `reason`: printable ASCII (0x20–0x7E), at most MAX_REASON_LENGTH. */
export const REASON_RE = /^[\x20-\x7E]{0,200}$/;
/** The request scopes. */
export const ADMIN_SCOPES = Object.freeze(["session", "user"]);

/** base64url length of a 32-byte HMAC-SHA256 tag, unpadded. */
const TAG_B64_LENGTH = 43;
const HEADER_RE = new RegExp(`^${ADMIN_SIGNATURE_SCHEME} ([A-Za-z0-9_-]{${TAG_B64_LENGTH}})$`);

function toBytes(body) {
  if (typeof body === "string") return utf8(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  throw new TypeError("body must be a string, Uint8Array or ArrayBuffer");
}

function importKey(key, usage) {
  if (typeof key !== "string" || key.length === 0) throw new TypeError("admin key must be a non-empty string");
  return crypto.subtle.importKey("raw", utf8(key), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

/**
 * The `authorization` header value for a request body.
 * @param {string} key  revocation_admin_key
 * @param {string|Uint8Array|ArrayBuffer} body  the exact bytes that will be sent
 * @returns {Promise<string>}
 */
export async function signAdminBody(key, body) {
  const k = await importKey(key, "sign");
  const tag = await crypto.subtle.sign("HMAC", k, toBytes(body));
  return `${ADMIN_SIGNATURE_SCHEME} ${base64UrlEncode(new Uint8Array(tag))}`;
}

/**
 * Parse the `authorization` header into the 32-byte tag, or null when it is
 * not exactly `<scheme> <43 canonical base64url chars>`.
 * @param {unknown} header
 * @returns {Uint8Array|null}
 */
export function parseAdminAuthorization(header) {
  if (typeof header !== "string") return null;
  const m = HEADER_RE.exec(header);
  if (!m) return null;
  let tag;
  try {
    tag = base64UrlDecode(m[1]);
  } catch {
    return null;
  }
  // Canonical form only: re-encoding must give the same text, so exactly one
  // string is accepted per tag.
  if (tag.length !== 32 || base64UrlEncode(tag) !== m[1]) return null;
  return tag;
}

/**
 * Verify the `authorization` header over the exact raw body bytes. Never
 * throws; false on any malformed input.
 * @param {string} key  revocation_admin_key
 * @param {string|Uint8Array|ArrayBuffer} body
 * @param {unknown} authorizationHeader
 * @returns {Promise<boolean>}
 */
export async function verifyAdminSignature(key, body, authorizationHeader) {
  const tag = parseAdminAuthorization(authorizationHeader);
  if (!tag) return false;
  try {
    const k = await importKey(key, "verify");
    return await crypto.subtle.verify("HMAC", k, tag, toBytes(body));
  } catch {
    return false;
  }
}

/**
 * A fresh request id: 32 random bytes from crypto.getRandomValues, base64url
 * (43 characters, within the 22–64 range).
 * @returns {string}
 */
export function newJti() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return base64UrlEncode(b);
}

/**
 * Build a request body object (§15.5). Validates its arguments and throws a
 * TypeError naming the problem field (never echoing a value).
 * @param {Object} p
 * @param {string} p.aud     the gate's forwarded_host
 * @param {"session"|"user"} p.scope
 * @param {string} [p.sid]   scope "session"
 * @param {string} [p.sub]   scope "user"
 * @param {string} [p.reason]  printable ASCII, ≤ 200 characters
 * @param {number} [p.iat]   epoch seconds; default now
 * @param {string} [p.jti]   default newJti()
 * @param {number} [p.nowMs]
 * @returns {{v: 1, aud: string, iat: number, jti: string, scope: string, sid?: string, sub?: string, reason?: string}}
 */
export function buildAdminRequestBody({ aud, scope, sid, sub, reason, iat, jti, nowMs = Date.now() }) {
  if (typeof aud !== "string" || aud.length === 0) throw new TypeError("aud must be a non-empty string");
  if (!ADMIN_SCOPES.includes(scope)) throw new TypeError("scope must be session or user");
  const body = { v: ADMIN_BODY_VERSION, aud, iat: iat ?? Math.floor(nowMs / 1000), jti: jti ?? newJti(), scope };
  if (!Number.isSafeInteger(body.iat) || body.iat < 0) throw new TypeError("iat must be a non-negative integer (epoch seconds)");
  if (!JTI_RE.test(body.jti)) throw new TypeError("jti must be 22-64 base64url characters");
  if (scope === "session") {
    if (typeof sid !== "string" || sub !== undefined) throw new TypeError("scope session takes a sid and no sub");
    body.sid = sid;
  } else {
    if (typeof sub !== "string" || sid !== undefined) throw new TypeError("scope user takes a sub and no sid");
    body.sub = sub;
  }
  if (reason !== undefined) {
    if (typeof reason !== "string" || !REASON_RE.test(reason)) throw new TypeError("reason must be printable ASCII of at most 200 characters");
    body.reason = reason;
  }
  return body;
}

/**
 * Build, serialize and sign a request: the exact body string to send and its
 * `authorization` header value.
 * @param {string} key
 * @param {Parameters<typeof buildAdminRequestBody>[0]} fields
 * @returns {Promise<{body: string, authorization: string, payload: Object}>}
 */
export async function signAdminRequest(key, fields) {
  const payload = buildAdminRequestBody(fields);
  const body = JSON.stringify(payload);
  return { body, authorization: await signAdminBody(key, body), payload };
}
