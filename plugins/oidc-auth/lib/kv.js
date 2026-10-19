// KV helpers with a self-describing expiry wrapper, over the plugin's
// namespaced ctx.kv (string values; the kernel prefixes keys "plugin:oidc-auth:").
//
// The Fastly KV backend may or may not honour native TTL eviction, so values
// are stored as JSON `{value, expires}` and `expires` is checked on read. One
// definition of "expired" serves the discovery/JWKS cache (./discovery.js) and
// the single-use state-replay marker (./state.js).

/**
 * Read a wrapped value; null when `kv` is null, the key is absent, the entry
 * expired, or the entry is corrupt. KV errors propagate (callers decide).
 * @param {import("../../../src/sdk/index.js").KvView|null} kv
 * @param {string} key
 */
export async function kvGetFresh(kv, key) {
  if (!kv) return null;
  const raw = await kv.get(key);
  if (raw === null || raw === undefined) return null;
  try {
    const wrapped = JSON.parse(raw);
    if (wrapped && wrapped.expires > Date.now()) return wrapped.value;
  } catch {
    /* corrupt entry: treat as absent */
  }
  return null;
}

/**
 * Write `value` wrapped with an absolute expiry `ttlSeconds` from now, also
 * passing the native ttl so the backend can evict it. No-op when `kv` is null.
 * KV errors propagate.
 * @param {import("../../../src/sdk/index.js").KvView|null} kv
 * @param {string} key
 * @param {unknown} value  JSON-serializable
 * @param {number} ttlSeconds  positive integer
 */
export async function kvPutWithTtl(kv, key, value, ttlSeconds) {
  if (!kv) return;
  await kv.put(key, JSON.stringify({ value, expires: Date.now() + ttlSeconds * 1000 }), { ttl: ttlSeconds });
}
