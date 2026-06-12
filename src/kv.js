// KV helpers with a self-describing expiry wrapper.
//
// The Fastly KV backend may or may not honour native TTL eviction, so values are
// stored as `{value, expires}` and `expires` is checked on read. Keeping that in
// one place gives a single definition of "expired" shared by the discovery/JWKS
// cache (jwt.js) and the single-use state-replay marker (oidc.js).

/**
 * Read a wrapped value, returning it only if present and unexpired; otherwise
 * null (also for a corrupt entry, or when `kv` is null because KV is unbound).
 * @param {?object} kv
 * @param {string} key
 */
export async function kvGetFresh(kv, key) {
  if (!kv) return null;
  const hit = await kv.get(key);
  if (!hit) return null;
  try {
    const wrapped = JSON.parse(await hit.text());
    if (wrapped.expires > Date.now()) return wrapped.value;
  } catch {
    /* ignore corrupt cache entry */
  }
  return null;
}

/**
 * Write `value` wrapped with an absolute expiry `ttlSeconds` in the future.
 * No-op when `kv` is null.
 * @param {?object} kv
 * @param {string} key
 * @param {*} value
 * @param {number} ttlSeconds
 */
export async function kvPutWithTtl(kv, key, value, ttlSeconds) {
  if (!kv) return;
  const wrapped = JSON.stringify({ value, expires: Date.now() + ttlSeconds * 1000 });
  await kv.put(key, wrapped);
}
