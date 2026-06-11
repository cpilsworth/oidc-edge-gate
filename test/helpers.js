// Test utilities shared by the mock OP and the edge-gate tests.
// All crypto uses Web Crypto (globalThis.crypto on Node 18+) so it runs
// identically to the Fastly Compute runtime. Ported from the worker suite;
// the only change is seeding into the KV stub instead of `cloudflare:test`'s env.
import { getKvMap } from "./stubs/state.js";

const enc = new TextEncoder();

export function b64url(bytes) {
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlJson(obj) {
  return b64url(enc.encode(JSON.stringify(obj)));
}

/** Generate an RSA-256 signing keypair and export the public half as a JWK with a kid. */
export async function makeRsaKey(kid = "test-key-1") {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { privateKey: pair.privateKey, publicJwk: jwk, kid };
}

/** Sign a JWT (RS256) from header+claims using a private key. */
export async function signJwt(header, claims, privateKey) {
  const h = b64urlJson(header);
  const p = b64urlJson(claims);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    enc.encode(`${h}.${p}`),
  );
  return `${h}.${p}.${b64url(sig)}`;
}

/** at_hash / c_hash: base64url(left-128-bits(SHA-256(ascii(token)))). */
export async function tokenHash(token) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(token)));
  return b64url(digest.slice(0, digest.length / 2));
}

/**
 * Seed the discovery doc + JWKS into the KV stub exactly as jwt.js caches them
 * (a `{value, expires}` wrapper). Writes into the "oidc_cache" namespace that
 * config.js opens via `new KVStore("oidc_cache")`.
 */
export function seedDiscovery(issuer, discovery, jwks, namespace = "oidc_cache") {
  const kv = getKvMap(namespace);
  const ttl = Date.now() + 3600_000;
  kv.set(`discovery:${issuer}`, JSON.stringify({ value: discovery, expires: ttl }));
  kv.set(`jwks:${discovery.jwks_uri}`, JSON.stringify({ value: jwks, expires: ttl }));
}

/** Build a Request with an optional cookie header. */
export function reqFor(path, { cookie, method = "GET", headers = {} } = {}) {
  const h = new Headers(headers);
  if (cookie) h.set("cookie", cookie);
  return new Request(`https://www.example.com${path}`, { method, headers: h });
}

/** Pull a named cookie value out of a Response's Set-Cookie header(s). */
export function getSetCookie(res, name) {
  const all = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie")];
  for (const line of all.filter(Boolean)) {
    const m = line.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
    if (m) return decodeURIComponent(m[1]);
  }
  return null;
}
