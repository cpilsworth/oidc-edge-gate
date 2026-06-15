import { ConfigStore } from "fastly:config-store";
import { SecretStore } from "fastly:secret-store";
import { KVStore } from "fastly:kv-store";
import { compilePolicy } from "./policy.js";

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
  const cfg = new ConfigStore("config_default");
  const secrets = new SecretStore("secret_default");

  const routes = JSON.parse(cfg.get("routes") || '{"callback":"/.auth/callback","logout":"/.auth/logout"}');
  const backends = JSON.parse(cfg.get("backends") || '{"origin":"origin","idp":"idp"}');
  const policy = compilePolicy(JSON.parse(cfg.get("policy") || '{"rules":[],"default_tier":"protected"}'));

  const [clientSecret, sessionKey] = await Promise.all([
    readSecret(secrets, "client_secret"),
    readSecret(secrets, "session_hmac_key"),
  ]);

  // Fail closed on invalid invariants at load rather than minting unverifiable
  // sessions later. A weak HMAC key undermines every signed cookie; a malformed
  // TTL mints sessions with exp:NaN that never validate (a silent login loop).
  if (utf8ByteLength(sessionKey) < 32) {
    throw new Error("session_hmac_key must be at least 32 bytes");
  }
  const sessionTtlSeconds = parseInt(cfg.get("session_ttl_seconds") || "3600", 10);
  if (!Number.isFinite(sessionTtlSeconds) || sessionTtlSeconds <= 0) {
    throw new Error("session_ttl_seconds must be a positive integer");
  }

  return {
    issuer: trimSlash(cfg.get("issuer")),
    clientId: cfg.get("client_id"),
    clientSecret,
    redirectUri: cfg.get("redirect_uri"),
    scopes: cfg.get("scopes") || "openid profile email",
    sessionTtlSeconds,
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

async function readSecret(store, key) {
  const entry = await store.get(key);
  if (!entry) throw new Error(`Missing secret: ${key}`);
  return entry.plaintext();
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
