import { ConfigStore } from "fastly:config-store";
import { SecretStore } from "fastly:secret-store";
import { KVStore } from "fastly:kv-store";

/**
 * Loads the gate configuration from the AEM-provided ConfigStore + SecretStore.
 *
 * Non-secret values come from ConfigStore("oidc_config") (populated by the
 * `configs:` block in edgeFunctions.yaml). Secrets come from
 * SecretStore("oidc_secrets") (the `secrets:` block, resolved from Cloud
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
  const cfg = new ConfigStore("oidc_config");
  const secrets = new SecretStore("oidc_secrets");

  const routes = JSON.parse(cfg.get("routes") || '{"callback":"/.auth/callback","logout":"/.auth/logout"}');
  const backends = JSON.parse(cfg.get("backends") || '{"origin":"origin","idp":"idp"}');
  const policy = JSON.parse(cfg.get("policy") || '{"rules":[],"default_tier":"protected"}');

  const [clientSecret, sessionKey] = await Promise.all([
    readSecret(secrets, "client_secret"),
    readSecret(secrets, "session_hmac_key"),
  ]);

  return {
    issuer: trimSlash(cfg.get("issuer")),
    clientId: cfg.get("client_id"),
    clientSecret,
    redirectUri: cfg.get("redirect_uri"),
    scopes: cfg.get("scopes") || "openid profile email",
    sessionTtlSeconds: parseInt(cfg.get("session_ttl_seconds") || "3600", 10),
    sessionKey,
    routes,
    backends,
    policy, // { rules:[{path, tier, audience?}], default_tier }
    originHostname: cfg.get("origin_hostname"),
    forwardedHost: cfg.get("forwarded_host"),
    pushInvalidation: cfg.get("push_invalidation") === "enabled",
    groupsClaim: cfg.get("groups_claim") || "groups",
    cache: openCache(),
  };
}

/**
 * Open the KV cache used for (a) the discovery doc + JWKS cache and (b) the
 * single-use state-replay marker. Returns null when KV is unbound (e.g. a
 * minimal local run) so callers fall through to live fetches.
 */
function openCache() {
  try {
    return new KVStore("oidc_cache");
  } catch {
    return null;
  }
}

async function readSecret(store, key) {
  const entry = await store.get(key);
  if (!entry) throw new Error(`Missing secret: ${key}`);
  return entry.plaintext();
}

function trimSlash(s) {
  return (s || "").replace(/\/$/, "");
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
