// ID token verification: RS256 signature against the provider's JWKS, plus
// iss / aud / azp / sub / exp / nbf / iat / nonce and c_hash / at_hash.
// Runs once per login (never per request), so the JWKS fetch stays well inside
// the fetch budget.
//
// JWKS fetches: purpose "jwks" (cache {ttl: 3600}, KV-cached), and on a kid
// miss exactly ONE forced refetch, purpose "jwks-refresh", default cache mode
// pass and no KV read, so a key rotation is seen immediately.

import { base64UrlDecode, base64UrlEncode, decodeJsonSegment, timingSafeEqual, utf8 } from "../../../src/sdk/encoding.js";
import { CACHE_TTL_SECONDS, cachedJson, jwksKey } from "./discovery.js";

const CLOCK_SKEW_SECONDS = 60;

/**
 * Fixed reason codes for ID-token verification failures (F16). The token and
 * the JWKS are attacker-influenced, so failures are logged ONLY as one of
 * these codes, never as an error message (messages here are fixed text too).
 */
export const ID_TOKEN_REASONS = Object.freeze([
  "malformed", "unsupported_alg", "unsupported_typ", "kid_unknown", "jwks_unavailable", "bad_signature",
  "iss_mismatch", "aud_mismatch", "azp_mismatch", "sub_missing", "expired", "not_yet_valid", "iat_invalid",
  "nonce_mismatch", "c_hash_mismatch", "at_hash_mismatch", "verify_failed",
]);
const REASONS = new Set(ID_TOKEN_REASONS);

/** An ID-token verification failure carrying a fixed `reason` code. */
export class IdTokenError extends Error {
  constructor(reason, message) {
    super(message);
    this.name = "IdTokenError";
    this.reason = REASONS.has(reason) ? reason : "verify_failed";
  }
}

/**
 * The log-safe reason code for any verification failure: the IdTokenError's
 * code, else "verify_failed" (e.g. a crypto or decode error with a raw message).
 * @param {unknown} err
 * @returns {string}
 */
export function idTokenFailureReason(err) {
  return err instanceof IdTokenError ? err.reason : "verify_failed";
}

const fail = (reason, message) => { throw new IdTokenError(reason, message); };

/** Decode a JWT segment; any decode/parse failure is "malformed" (never a raw parser message). */
function decodeSegment(segment) {
  let v;
  try { v = decodeJsonSegment(segment); } catch { fail("malformed", "malformed JWT"); }
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail("malformed", "malformed JWT");
  return v;
}

/**
 * Fetch (or reuse from KV) the provider JWKS.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} jwksUri
 * @param {{force?: boolean}} [opts]
 */
export async function getJwks(ctx, jwksUri, { force = false } = {}) {
  return cachedJson(ctx, jwksKey(jwksUri), "jwks", async () => {
    const res = force
      ? await ctx.fetch(jwksUri, {}, { purpose: "jwks-refresh" })
      : await ctx.fetch(jwksUri, {}, { purpose: "jwks", cache: { ttl: CACHE_TTL_SECONDS } });
    if (!res.ok) throw new IdTokenError("jwks_unavailable", `jwks fetch failed: ${res.status}`);
    return res.json();
  }, { force });
}

/**
 * Verify an ID token. Throws on any failure (the callback turns that into a 400).
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} idToken
 * @param {{issuer: string, clientId: string, jwksUri: string}} expect
 * @param {string} expectedNonce
 * @param {{code?: string, accessToken?: string}} [hashes]  for c_hash / at_hash
 * @returns {Promise<Object>} the verified claims
 */
export async function verifyIdToken(ctx, idToken, { issuer, clientId, jwksUri }, expectedNonce, hashes = {}) {
  if (typeof idToken !== "string") fail("malformed", "malformed JWT");
  const parts = idToken.split(".");
  if (parts.length !== 3) fail("malformed", "malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = decodeSegment(headerB64);
  const claims = decodeSegment(payloadB64);

  if (header.alg !== "RS256") fail("unsupported_alg", "unsupported alg"); // N2
  if (header.typ !== undefined && header.typ !== "JWT") fail("unsupported_typ", "unsupported typ");

  // --- signature, with a single JWKS refetch on kid miss (N7) ---
  const key = await importSigningKey(ctx, jwksUri, header.kid);
  let sig;
  try { sig = base64UrlDecode(sigB64); } catch { fail("malformed", "malformed JWT"); }
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, sig, utf8(`${headerB64}.${payloadB64}`));
  if (!valid) fail("bad_signature", "invalid token signature"); // N1

  // --- claims ---
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.iss !== "string") fail("iss_mismatch", "iss required");
  if (claims.iss.replace(/\/$/, "") !== issuer) fail("iss_mismatch", "iss mismatch"); // N3
  if (!audienceMatches(claims.aud, clientId)) fail("aud_mismatch", "aud mismatch"); // N4
  if (claims.azp !== undefined && claims.azp !== clientId) fail("azp_mismatch", "azp mismatch");
  if (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== clientId) {
    fail("azp_mismatch", "azp required for multi-valued aud"); // N4b
  }
  if (typeof claims.sub !== "string" || claims.sub.length === 0) fail("sub_missing", "sub required");
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_SECONDS < now) fail("expired", "token expired"); // N5
  if (typeof claims.nbf === "number" && claims.nbf - CLOCK_SKEW_SECONDS > now) fail("not_yet_valid", "token not yet valid");
  if (typeof claims.iat !== "number") fail("iat_invalid", "iat required");
  if (claims.iat - CLOCK_SKEW_SECONDS > now) fail("iat_invalid", "token iat in the future");
  if (expectedNonce && claims.nonce !== expectedNonce) fail("nonce_mismatch", "nonce mismatch"); // N6

  // --- c_hash / at_hash when the corresponding artifact is present (N11) ---
  if (hashes.code && claims.c_hash) {
    if (!await timingSafeEqual(claims.c_hash, await leftHalfHash(hashes.code))) fail("c_hash_mismatch", "c_hash mismatch");
  }
  if (hashes.accessToken && claims.at_hash) {
    if (!await timingSafeEqual(claims.at_hash, await leftHalfHash(hashes.accessToken))) fail("at_hash_mismatch", "at_hash mismatch");
  }
  return claims;
}

async function importSigningKey(ctx, jwksUri, kid) {
  // A key matches the kid and is usable for RS256 verification; `use` (sig) and
  // `alg` (RS256) are honoured when the JWKS advertises them.
  const isSigningKey = (k) => k && k.kid === kid
    && k.kty === "RSA"
    && (k.use === undefined || k.use === "sig")
    && (k.alg === undefined || k.alg === "RS256");
  const keysOf = (jwks) => (jwks && Array.isArray(jwks.keys) ? jwks.keys : []);

  let jwk = keysOf(await getJwks(ctx, jwksUri)).find(isSigningKey);
  if (!jwk) jwk = keysOf(await getJwks(ctx, jwksUri, { force: true })).find(isSigningKey); // kid miss: refetch once
  if (!jwk) fail("kid_unknown", "no JWKS key for kid"); // the kid itself is attacker-controlled: never echoed
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

function audienceMatches(aud, clientId) {
  return Array.isArray(aud) ? aud.includes(clientId) : aud === clientId;
}

/** OIDC hash claim: base64url(left-128-bits(SHA-256(ascii(value)))). */
async function leftHalfHash(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(value)));
  return base64UrlEncode(digest.slice(0, digest.length / 2));
}
