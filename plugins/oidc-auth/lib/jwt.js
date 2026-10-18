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
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
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
  if (typeof idToken !== "string") throw new Error("malformed JWT");
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = decodeJsonSegment(headerB64);
  const claims = decodeJsonSegment(payloadB64);

  if (header.alg !== "RS256") throw new Error(`unsupported alg: ${header.alg}`); // N2
  if (header.typ !== undefined && header.typ !== "JWT") throw new Error(`unsupported typ: ${header.typ}`);

  // --- signature, with a single JWKS refetch on kid miss (N7) ---
  const key = await importSigningKey(ctx, jwksUri, header.kid);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, base64UrlDecode(sigB64), utf8(`${headerB64}.${payloadB64}`));
  if (!valid) throw new Error("invalid token signature"); // N1

  // --- claims ---
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.iss !== "string") throw new Error("iss required");
  if (claims.iss.replace(/\/$/, "") !== issuer) throw new Error("iss mismatch"); // N3
  if (!audienceMatches(claims.aud, clientId)) throw new Error("aud mismatch"); // N4
  if (claims.azp !== undefined && claims.azp !== clientId) throw new Error("azp mismatch");
  if (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== clientId) {
    throw new Error("azp required for multi-valued aud"); // N4b
  }
  if (typeof claims.sub !== "string" || claims.sub.length === 0) throw new Error("sub required");
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_SECONDS < now) throw new Error("token expired"); // N5
  if (typeof claims.nbf === "number" && claims.nbf - CLOCK_SKEW_SECONDS > now) throw new Error("token not yet valid");
  if (typeof claims.iat !== "number") throw new Error("iat required");
  if (claims.iat - CLOCK_SKEW_SECONDS > now) throw new Error("token iat in the future");
  if (expectedNonce && claims.nonce !== expectedNonce) throw new Error("nonce mismatch"); // N6

  // --- c_hash / at_hash when the corresponding artifact is present (N11) ---
  if (hashes.code && claims.c_hash) {
    if (!await timingSafeEqual(claims.c_hash, await leftHalfHash(hashes.code))) throw new Error("c_hash mismatch");
  }
  if (hashes.accessToken && claims.at_hash) {
    if (!await timingSafeEqual(claims.at_hash, await leftHalfHash(hashes.accessToken))) throw new Error("at_hash mismatch");
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
  if (!jwk) throw new Error(`no JWKS key for kid ${kid}`);
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
