import { ConfigStore } from "fastly:config-store";
import { SecretStore } from "fastly:secret-store";

/**
 * Loads the gate configuration from the AEM-provided ConfigStore + SecretStore.
 *
 * Non-secret values come from ConfigStore("oidc_config") (populated by the
 * `configs:` block in edgeFunctions.yaml). Secrets come from
 * SecretStore("oidc_secrets") (the `secrets:` block, resolved from Cloud
 * Manager). Locally, both are backed by the [local_server] section of
 * fastly.toml.
 *
 * @returns {Promise<Config>}
 */
export async function loadConfig() {
  const cfg = new ConfigStore("oidc_config");
  const secrets = new SecretStore("oidc_secrets");

  const routes = JSON.parse(cfg.get("routes") || '{"callback":"/.auth/callback","logout":"/.auth/logout"}');
  const backends = JSON.parse(cfg.get("backends") || '{"origin":"origin","idp":"idp"}');
  const policy = JSON.parse(cfg.get("policy") || "null");

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
    policy, // { require_claim, allow_values } | null
  };
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
 * @property {?{require_claim:string, allow_values:string[]}} policy
 */
