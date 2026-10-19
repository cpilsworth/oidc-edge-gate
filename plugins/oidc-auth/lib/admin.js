// POST <admin_path> (default /.auth/admin/revoke): the signed, provisioned-only
// revocation API (docs/architecture/plugins.md §15.5). Request format and the
// signature scheme: ./admin-signature.js (shared with scripts/revoke.mjs).
//
// Checks, in this exact order (status):
//   1. available: profile provisioned, effective revocation mode not
//      `disabled`, secret revocation_admin_key set        else 404 not_found (any method; body unread)
//   2. method POST                                        else 405 method_not_allowed, Allow: POST
//   3. content-type application/json (parameters allowed)  else 415 unsupported_media_type
//   4. body ≤ 4096 bytes: a declared content-length over the cap is refused
//      before reading; the stream is read with a hard cap and never buffered
//      past it                                             else 413 payload_too_large
//      (a malformed content-length is 400 bad_request)
//   5. authorization signature over the exact raw bytes   else 401 unauthorized
//   6. strict JSON shape (only now is the body parsed)    else 400 bad_request
//   7. aud === forwarded_host and |now − iat| ≤ 300 s     else 401 unauthorized
//   8. ctx.kv present                                     else 503 revocation_unavailable
//   9. single-use jti marker admin:jti:<jti> (TTL 600 s)  else 409 replayed
//      (a KV error reading or writing the marker: 503 kv_write_failed)
//  10. write the record (revokeSession / revokeSubject,   else 503 kv_write_failed
//      the user epoch at the signed iat, clamped to now)
//  → 200 {"revoked":"session",...} | {"revoked":"user","revoked_at":n,...}, "propagation_seconds":60
//
// Where the no-KV 503 sits (step 8): after authentication, so an
// unauthenticated caller learns nothing about the platform's KV state and only
// a correctly signed, fresh, well-formed request reaches it; before the jti
// marker, so nothing (marker or record) is ever written without KV.
//
// jti marker: written before the record. When the record write then fails the
// marker is deleted again (best effort), so the caller can retry the very same
// signed request after ≥ 1 s instead of hitting 409. The marker is best effort
// under KV eventual consistency (§15.5); its 600 s TTL covers the whole
// ±300 s iat window.
//
// Logs: outcome, scope, jti and the (already validated printable-ASCII) reason
// on success; a reason code only on failure. Never the sub, the sid, the body or
// the authorization header.

import { errorResponse } from "../../../src/sdk/http.js";
import {
  ADMIN_BODY_VERSION, ADMIN_IAT_SKEW_SECONDS, ADMIN_SIGNATURE_SCHEME, JTI_RE, MAX_ADMIN_BODY_BYTES, REASON_RE,
  verifyAdminSignature,
} from "./admin-signature.js";
import { kvGetFresh, kvPutWithTtl } from "./kv.js";
import { effectiveRevocationMode } from "./revocation.js";
import { isSessionId, isSubject, revokeSession, revokeSubject } from "./revocation-store.js";

/** Seconds a revocation may take to reach every POP (KV eventual consistency, plan D4). */
export const PROPAGATION_SECONDS = 60;
/** Lifetime of the single-use jti marker: covers the full ±300 s iat window. */
export const JTI_MARKER_TTL_SECONDS = 600;
/** KV key of the single-use marker (inside the plugin's KV namespace). */
export const jtiKey = (jti) => `admin:jti:${jti}`;

const SESSION_KEYS = Object.freeze(["v", "aud", "iat", "jti", "scope", "sid"]);
const USER_KEYS = Object.freeze(["v", "aud", "iat", "jti", "scope", "sub"]);

/** The body exceeded the cap while being read. */
export class BodyTooLargeError extends Error {
  constructor() {
    super("request body exceeds the cap");
    this.name = "BodyTooLargeError";
  }
}

/**
 * Is the server-side revocation API available here (§15.5 availability)?
 * Shared with the webhook route (./webhook.js).
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @returns {null|"not_provisioned"|"revocation_disabled"|"no_admin_key"}  null = available, else why not
 */
export function revocationApiUnavailableReason(ctx) {
  if (!ctx.platform || ctx.platform.profile !== "provisioned") return "not_provisioned";
  if (effectiveRevocationMode(ctx) === "disabled") return "revocation_disabled";
  const key = ctx.secret("revocation_admin_key");
  if (typeof key !== "string" || key.length === 0) return "no_admin_key";
  return null;
}

/**
 * Read a request body with a hard byte cap: never buffers more than `max`
 * bytes (plus at most one chunk being inspected), cancels the stream once
 * the cap is passed, and throws BodyTooLargeError.
 * @param {Request} request
 * @param {number} max
 * @returns {Promise<Uint8Array>}
 */
export async function readBodyCapped(request, max) {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      try { await reader.cancel(); } catch { /* already errored */ }
      throw new BodyTooLargeError();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.byteLength; }
  return out;
}

/**
 * `content-type` is application/json (case-insensitive essence; parameters
 * such as charset are allowed).
 * @param {string|null} value
 */
export function isJsonContentType(value) {
  if (typeof value !== "string") return false;
  return value.split(";")[0].trim().toLowerCase() === "application/json";
}

/**
 * Parse and strictly validate a request body (§15.5 step 6). null when the
 * bytes are not UTF-8 JSON of exactly the allowed shape.
 * @param {Uint8Array} bytes
 * @returns {{v: 1, aud: string, iat: number, jti: string, scope: "session"|"user", sid?: string, sub?: string, reason?: string}|null}
 */
export function parseAdminBody(bytes) {
  let body;
  try {
    body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return null;
  const allowed = body.scope === "session" ? SESSION_KEYS : body.scope === "user" ? USER_KEYS : null;
  if (!allowed) return null;
  const keys = Object.keys(body);
  for (const k of keys) if (k !== "reason" && !allowed.includes(k)) return null;
  for (const k of allowed) if (!Object.prototype.hasOwnProperty.call(body, k)) return null;
  if (body.v !== ADMIN_BODY_VERSION) return null;
  if (typeof body.aud !== "string" || body.aud.length === 0) return null;
  if (!Number.isSafeInteger(body.iat) || body.iat < 0) return null;
  if (typeof body.jti !== "string" || !JTI_RE.test(body.jti)) return null;
  if (body.scope === "session" && !isSessionId(body.sid)) return null;
  if (body.scope === "user" && !isSubject(body.sub)) return null;
  if (Object.prototype.hasOwnProperty.call(body, "reason") && (typeof body.reason !== "string" || !REASON_RE.test(body.reason))) return null;
  return body;
}

/**
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {import("./settings.js").OidcSettings} s
 * @param {{nowMs?: () => number}} [deps]  clock injection for tests
 * @returns {Promise<Response>}
 */
export async function handleAdminRevoke(ctx, s, { nowMs = Date.now } = {}) {
  const id = ctx.requestId;
  const fail = (status, error, reason, headers = {}) => {
    const level = status >= 500 ? "error" : "warn";
    ctx.log[level]("oidc admin revoke rejected", { outcome: "rejected", status, reason });
    return errorResponse(status, { error }, { headers: { "x-auth-request-id": id, ...headers } });
  };

  // 1. availability, before anything about the request is looked at.
  const unavailable = revocationApiUnavailableReason(ctx);
  if (unavailable) {
    ctx.log.info("oidc admin revoke unavailable", { outcome: "not_found", reason: unavailable });
    return errorResponse(404, { error: "not_found" }, { headers: { "x-auth-request-id": id } });
  }
  const request = ctx.request;

  // 2. method
  if (request.method !== "POST") return fail(405, "method_not_allowed", "method", { allow: "POST" });

  // 3. media type
  if (!isJsonContentType(request.headers.get("content-type"))) return fail(415, "unsupported_media_type", "content_type");

  // 4. size: declared length first, then a capped read.
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d{1,16}$/.test(declared.trim())) return fail(400, "bad_request", "content_length");
    if (Number(declared.trim()) > MAX_ADMIN_BODY_BYTES) return fail(413, "payload_too_large", "body_too_large");
  }
  let bytes;
  try {
    bytes = await readBodyCapped(request, MAX_ADMIN_BODY_BYTES);
  } catch (e) {
    if (e instanceof BodyTooLargeError) return fail(413, "payload_too_large", "body_too_large");
    return fail(400, "bad_request", "body_unreadable");
  }

  // 5. signature over the exact raw bytes (constant time).
  const key = ctx.secret("revocation_admin_key");
  const unauthorized = (reason) => fail(401, "unauthorized", reason, { "www-authenticate": ADMIN_SIGNATURE_SCHEME });
  if (!(await verifyAdminSignature(key, bytes, request.headers.get("authorization")))) return unauthorized("bad_signature");

  // 6. only now parse.
  const body = parseAdminBody(bytes);
  if (!body) return fail(400, "bad_request", "bad_body");

  // 7. environment binding and freshness.
  if (typeof s.forwardedHost !== "string" || body.aud !== s.forwardedHost) return unauthorized("aud_mismatch");
  const nowMsValue = nowMs();
  const now = Math.floor(nowMsValue / 1000);
  if (Math.abs(now - body.iat) > ADMIN_IAT_SKEW_SECONDS) return unauthorized("iat_out_of_window");

  // 8. KV present (nothing below writes without it).
  const kv = ctx.kv;
  if (!kv) return fail(503, "revocation_unavailable", "kv_unavailable");

  // 9. single-use jti.
  const marker = jtiKey(body.jti);
  try {
    if ((await kvGetFresh(kv, marker)) !== null) return fail(409, "replayed", "jti_replayed");
    await kvPutWithTtl(kv, marker, { at: now }, JTI_MARKER_TTL_SECONDS);
  } catch (e) {
    ctx.log.error("oidc admin revoke rejected", { outcome: "rejected", status: 503, reason: "jti_marker_failed", error: errorClass(e) });
    return errorResponse(503, { error: "kv_write_failed" }, { headers: { "x-auth-request-id": id } });
  }

  // 10. the record.
  const ttl = { sessionTtlSeconds: s.sessionTtlSeconds, nowMs: nowMsValue };
  let result;
  try {
    if (body.scope === "session") {
      await revokeSession(kv, body.sid, ttl);
      result = { revoked: "session" };
    } else {
      // The signed request time, not now: a replay that slips past the jti
      // marker (eventual consistency) then rewrites the same epoch and changes
      // nothing (W3.R R3-3). revokeSubject clamps it to now and never moves
      // the stored epoch backwards.
      const revokedAt = await revokeSubject(kv, body.sub, { ...ttl, revokedAt: body.iat });
      result = { revoked: "user", revoked_at: revokedAt };
    }
  } catch (e) {
    try { await kv.delete(marker); } catch { /* best effort: a retry then needs a new jti */ }
    ctx.log.error("oidc admin revoke rejected", { outcome: "rejected", status: 503, reason: "kv_write_failed", error: errorClass(e) });
    return errorResponse(503, { error: "kv_write_failed" }, { headers: { "x-auth-request-id": id } });
  }

  const fields = { outcome: "revoked", scope: body.scope, jti: body.jti };
  if (body.reason !== undefined) fields.reason = body.reason;
  ctx.log.info("oidc admin revoke", fields);
  return errorResponse(200, { ...result, propagation_seconds: PROPAGATION_SECONDS }, { headers: { "x-auth-request-id": id } });
}

function errorClass(e) {
  return (e && typeof e.name === "string" && e.name) || "Error";
}
