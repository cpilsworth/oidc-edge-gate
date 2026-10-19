// OIDC discovery (/.well-known/openid-configuration) and the shared
// KV-backed JSON cache used for discovery and JWKS.
//
// Layers, outermost first:
//   1. ctx.state memo: one discovery document per request, so a callback
//      fetches it at most once (the plugin's maxFetches budget counts on that).
//   2. ctx.kv cache (1 h, `{value, expires}` wrapper). Best-effort: a KV read or
//      write error is logged (without the key) and the request carries on with
//      a live fetch / uncached value. Absent KV means "always live".
//   3. ctx.fetch with cache {ttl: 3600}: the Fastly function cache under the KV
//      layer, so caching still helps on sandbox where KV is null.
// The document is validated on EVERY return, cache hits included: a poisoned
// cache or a misconfigured backend is what the validation guards against.

import { kvGetFresh, kvPutWithTtl } from "./kv.js";

export const CACHE_TTL_SECONDS = 3600;
const MEMO_KEY = "discovery";

/** KV keys (inside the plugin's KV namespace). */
export const discoveryKey = (issuer) => `oidc:discovery:${issuer}`;
export const jwksKey = (jwksUri) => `oidc:jwks:${jwksUri}`;

/**
 * Fetch (or reuse) and validate the issuer's discovery document.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} issuer  without a trailing slash (ctx.config.issuer)
 * @returns {Promise<Object>}
 */
export async function getDiscovery(ctx, issuer) {
  const memo = ctx.state.get(MEMO_KEY);
  if (memo && memo.issuer === issuer) return memo.doc;
  const doc = await cachedJson(ctx, discoveryKey(issuer), "discovery", async () => {
    // No `backend` option: an absolute URL uses a dynamic backend (the kernel
    // strips any backend option anyway; see CLAUDE.md).
    const res = await ctx.fetch(`${issuer}/.well-known/openid-configuration`, {}, {
      purpose: "discovery", cache: { ttl: CACHE_TTL_SECONDS },
    });
    if (!res.ok) throw new Error(`discovery fetch failed: ${res.status}`);
    return res.json();
  });
  validateDiscovery(doc, issuer);
  ctx.state.set(MEMO_KEY, { issuer, doc });
  return doc;
}

/**
 * Per OIDC Discovery: the document's issuer must match config, and the
 * endpoints the gate redirects to or fetches must be secure URLs (http only on
 * loopback, for a local IdP). Which ORIGINS may be fetched is a separate,
 * kernel-enforced check (the plugin's egress list).
 */
export function validateDiscovery(doc, issuer) {
  if (doc === null || typeof doc !== "object") throw new Error("discovery document is not an object");
  if (typeof doc.issuer !== "string" || doc.issuer.replace(/\/$/, "") !== issuer) {
    throw new Error("discovery issuer mismatch");
  }
  for (const ep of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    if (!isSecureUrl(doc[ep])) throw new Error(`discovery ${ep} is not a secure URL`);
  }
  // Optional; when present it drives the token endpoint auth negotiation
  // (lib/token.js negotiateTokenAuthMethod), so its shape must be exact.
  const methods = doc.token_endpoint_auth_methods_supported;
  if (methods !== undefined && (!Array.isArray(methods) || methods.some((m) => typeof m !== "string"))) {
    throw new Error("discovery token_endpoint_auth_methods_supported is not an array of strings");
  }
}

function isSecureUrl(value) {
  if (typeof value !== "string") return false;
  let u;
  try {
    u = new URL(value);
  } catch {
    return false;
  }
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" && ["localhost", "127.0.0.1", "::1", "[::1]"].includes(u.hostname);
}

/**
 * Best-effort KV-backed JSON cache. `force` skips the KV read (the JWKS
 * kid-rotation refetch); the fresh value is still written back.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} key
 * @param {"discovery"|"jwks"} kind  for log lines (the key is never logged)
 * @param {() => Promise<unknown>} fetcher
 * @param {{force?: boolean}} [opts]
 */
export async function cachedJson(ctx, key, kind, fetcher, { force = false } = {}) {
  if (!force) {
    let cached = null;
    try {
      cached = await kvGetFresh(ctx.kv, key);
    } catch {
      ctx.log.warn(`oidc ${kind} cache read failed; fetching live`);
    }
    if (cached !== null && cached !== undefined) return cached;
  }
  const value = await fetcher();
  try {
    await kvPutWithTtl(ctx.kv, key, value, CACHE_TTL_SECONDS);
  } catch {
    ctx.log.warn(`oidc ${kind} cache write failed; continuing uncached`);
  }
  return value;
}
