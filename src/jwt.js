import { KVStore } from "fastly:kv-store";
import { base64UrlDecode, decodeJsonSegment } from "./encoding.js";

// Validates the ID token returned by the OpenID Provider during the auth-code
// exchange: RS256 signature against the provider's JWKS, plus the standard
// iss/aud/exp/nonce claim checks. This runs once per login — not per request —
// so the JWKS fetch stays well within AEM's 32-backend-request budget. The
// discovery doc and JWKS are cached in a KV store between executions.

const CACHE_TTL_SECONDS = 3600;

/**
 * Fetch + cache the OIDC discovery document (/.well-known/openid-configuration).
 * @param {import("./config.js").Config} config
 */
export async function getDiscovery(config) {
  return cachedJson(`discovery:${config.issuer}`, async () => {
    const res = await fetch(`${config.issuer}/.well-known/openid-configuration`, {
      backend: config.backends.idp,
    });
    if (!res.ok) throw new Error(`discovery fetch failed: ${res.status}`);
    return res.json();
  });
}

/** Fetch + cache the provider JWKS. */
async function getJwks(config, jwksUri) {
  return cachedJson(`jwks:${jwksUri}`, async () => {
    const res = await fetch(jwksUri, { backend: config.backends.idp });
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
    return res.json();
  });
}

/**
 * Verify an ID token and return its validated claims.
 * @throws if the token is malformed, mis-signed, expired, or fails a claim check.
 * @returns {Promise<Object>} the token claims
 */
export async function verifyIdToken(idToken, config, expectedNonce) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts;

  const header = decodeJsonSegment(headerB64);
  const claims = decodeJsonSegment(payloadB64);

  if (header.alg !== "RS256") throw new Error(`unsupported alg: ${header.alg}`);

  // --- signature ---
  const discovery = await getDiscovery(config);
  const jwks = await getJwks(config, discovery.jwks_uri);
  const jwk = jwks.keys.find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) throw new Error(`no JWKS key for kid ${header.kid}`);

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64UrlDecode(sigB64),
    signingInput,
  );
  if (!valid) throw new Error("invalid token signature");

  // --- claims ---
  const now = Math.floor(Date.now() / 1000);
  const skew = 60;
  if (claims.iss !== config.issuer) throw new Error("iss mismatch");
  if (!audienceMatches(claims.aud, config.clientId)) throw new Error("aud mismatch");
  if (typeof claims.exp === "number" && claims.exp + skew < now) throw new Error("token expired");
  if (typeof claims.nbf === "number" && claims.nbf - skew > now) throw new Error("token not yet valid");
  if (expectedNonce && claims.nonce !== expectedNonce) throw new Error("nonce mismatch");

  return claims;
}

function audienceMatches(aud, clientId) {
  return Array.isArray(aud) ? aud.includes(clientId) : aud === clientId;
}

// --- KV-backed JSON cache -----------------------------------------------------

async function cachedJson(key, fetcher) {
  let store;
  try {
    store = new KVStore("oidc_cache");
  } catch {
    store = null; // KV not bound (e.g. minimal local run) — fall through to live fetch
  }

  if (store) {
    const hit = await store.get(key);
    if (hit) {
      try {
        const wrapped = JSON.parse(await hit.text());
        if (wrapped.expires > Date.now()) return wrapped.value;
      } catch {
        /* ignore corrupt cache entry */
      }
    }
  }

  const value = await fetcher();
  if (store) {
    const wrapped = JSON.stringify({ value, expires: Date.now() + CACHE_TTL_SECONDS * 1000 });
    await store.put(key, wrapped);
  }
  return value;
}
