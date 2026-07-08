import { ConfigStore } from "fastly:config-store";
import { SecretStore } from "fastly:secret-store";
import { KVStore } from "fastly:kv-store";
import { compilePolicy } from "./policy.js";
import { EMBEDDED_CONFIGS, EMBEDDED_SECRETS } from "./embedded-config.js";

/**
 * Loads the gate configuration from the AEM-provided ConfigStore + SecretStore.
 *
 * Non-secret values come from ConfigStore("config_default") (populated by the
 * `configs:` block in edgeFunctions.yaml). Secrets come from
 * SecretStore("secret_default") (the `secrets:` block, resolved from Cloud
 * Manager). Locally, both are backed by the [local_server] section of
 * fastly.toml.
 *
 * The KV cache handle is opened here and threaded through `config.cache` so the
 * rest of the codebase never imports `fastly:kv-store` directly — that keeps the
 * pure OIDC/JWT/session modules platform-agnostic and unit-testable under plain
 * node-vitest (see worker-gate-parity-plan.md §2.4 / §5).
 *
 * @returns {Promise<Config>}
 */
export async function loadConfig() {
  // Sandbox Cloud Manager programs do NOT provision the service stores, so
  // constructing a ConfigStore/SecretStore throws. Open them defensively and
  // fall back to build-time embedded values (src/embedded-config.js) so the gate
  // runs store-free. On provisioned (non-sandbox) environments the stores exist
  // and take precedence.
  const cfgStore = openStore(ConfigStore, "config_default");
  const cfg = (key) => (cfgStore ? cfgStore.get(key) : null) ?? EMBEDDED_CONFIGS[key] ?? null;

  const routes = JSON.parse(cfg("routes") || '{"callback":"/.auth/callback","logout":"/.auth/logout"}');
  const backends = JSON.parse(cfg("backends") || '{"origin":"origin","idp":"idp"}');
  const policy = compilePolicy(JSON.parse(cfg("policy") || '{"rules":[],"default_tier":"protected"}'));

  const secretsMap = await loadSecrets();
  const clientSecret = secretsMap.client_secret;
  const sessionKey = secretsMap.session_hmac_key;
  if (!clientSecret) throw new Error("Missing secret: client_secret");
  if (!sessionKey) throw new Error("Missing secret: session_hmac_key");

  // Fail closed on invalid invariants at load rather than minting unverifiable
  // sessions later. A weak HMAC key undermines every signed cookie; a malformed
  // TTL mints sessions with exp:NaN that never validate (a silent login loop).
  if (utf8ByteLength(sessionKey) < 32) {
    throw new Error("session_hmac_key must be at least 32 bytes");
  }
  const sessionTtlSeconds = parseInt(cfg("session_ttl_seconds") || "3600", 10);
  if (!Number.isInteger(sessionTtlSeconds) || sessionTtlSeconds <= 0) {
    throw new Error("session_ttl_seconds must be a positive integer");
  }

  return {
    issuer: trimSlash(cfg("issuer")),
    clientId: cfg("client_id"),
    clientSecret,
    redirectUri: cfg("redirect_uri"),
    scopes: cfg("scopes") || "openid profile email",
    sessionTtlSeconds,
    sessionKey,
    routes,
    backends,
    policy, // { rules:[{path, tier, audience?}], default_tier }
    originHostname: cfg("origin_hostname"),
    forwardedHost: cfg("forwarded_host"),
    pushInvalidation: cfg("push_invalidation") === "enabled",
    groupsClaim: cfg("groups_claim") || "groups",
    cache: openCache(),
  };
}

/** Construct a Fastly store, returning null if it is not provisioned (sandbox). */
function openStore(Ctor, name) {
  try {
    return new Ctor(name);
  } catch {
    return null;
  }
}

/**
 * Resolve the gate secrets. Sources, in order:
 *   1. SecretStore key "secrets" — the CLOUD format, all secrets as one JSON blob.
 *   2. SecretStore individual keys — the LOCAL-dev format (fastly.toml).
 *   3. Embedded fallback (src/embedded-config.js) — sandbox, no store provisioned.
 * @returns {Promise<{client_secret?:string, session_hmac_key?:string}>}
 */
async function loadSecrets() {
  const store = openStore(SecretStore, "secret_default");
  if (!store) return { ...EMBEDDED_SECRETS };

  try {
    const bundle = await store.get("secrets");
    if (bundle) return JSON.parse(bundle.plaintext());
  } catch {
    // Not present or not JSON — fall through to per-key lookup.
  }

  const out = {};
  for (const key of ["client_secret", "session_hmac_key"]) {
    const entry = await store.get(key);
    if (entry) out[key] = entry.plaintext();
  }
  return out;
}

/**
 * Open the KV cache used for (a) the discovery doc + JWKS cache and (b) the
 * single-use state-replay marker. Provisioned by `kvs: true` in
 * edgeFunctions.yaml, which the platform always names `kv_default` (the name is
 * fixed and shared across functions — hence the `oidc:` key prefixes). Returns
 * null when KV is unbound (e.g. a minimal local run) so callers fall through to
 * live fetches.
 */
function openCache() {
  try {
    return new KVStore("kv_default");
  } catch {
    return null;
  }
}

function trimSlash(s) {
  return (s || "").replace(/\/$/, "");
}

function utf8ByteLength(s) {
  return new TextEncoder().encode(s || "").length;
}

/**
 * @typedef {Object} Config
 * @property {string} issuer
 * @property {string} clientId
 * @property {string} clientSecret
 * @property {string} redirectUri
 * @property {string} scopes
 * @property {number} sessionTtlSeconds
 * @property {string} sessionKey
 * @property {{callback:string, logout:string}} routes
 * @property {{origin:string, idp:string}} backends
 * @property {{rules:Array<{path:string,tier:string,audience?:string[]}>, default_tier:string}} policy
 * @property {string} originHostname  EDS delivery host the gate forwards to
 * @property {string} forwardedHost   public prod domain sent as X-Forwarded-Host
 * @property {boolean} pushInvalidation
 * @property {string} groupsClaim     id_token claim carrying group membership
 * @property {?object} cache          KV handle (fastly:kv-store) or null
 */
