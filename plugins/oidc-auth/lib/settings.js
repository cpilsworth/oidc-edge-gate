// Per-request settings: the gate's scalar config (ctx.config), this plugin
// instance's options and its provider profile. Secrets are NOT copied here;
// they are read through ctx.secret() at the point of use (requireSecret).

import { getProvider } from "../providers/index.js";
import { normalizeOptions } from "./options.js";
import { negotiateTokenAuthMethod } from "./token.js";

/**
 * @typedef {Object} OidcSettings
 * @property {string} issuer             without a trailing slash
 * @property {string} clientId
 * @property {string} redirectUri
 * @property {string} scopes
 * @property {number} sessionTtlSeconds
 * @property {string} groupsClaim
 * @property {string|null} forwardedHost
 * @property {string} callbackPath
 * @property {string} logoutPath
 * @property {import("../providers/define.js").ProviderProfile} provider
 *           the frozen provider profile; e.g. `s.provider.groupsSource` ("claim" | "user-info")
 *           and `s.provider.endSession` ("discovery" | "none")
 * @property {"client_secret_post"|"client_secret_basic"|null} tokenEndpointAuthMethodPin
 *           the `token_endpoint_auth_method` option (null = negotiate)
 * @property {(discovery: Object) => ("client_secret_post"|"client_secret_basic")} tokenEndpointAuthMethod
 *           negotiate the token endpoint auth method for this discovery document
 *           (lib/token.js negotiateTokenAuthMethod); on no acceptable method it
 *           logs the reason (method names only) and throws (→ generic 500)
 */

/**
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {Object} options  validated (or raw) plugin options
 * @returns {OidcSettings}
 */
export function settingsFor(ctx, options) {
  const o = normalizeOptions(options);
  const c = ctx.config;
  const provider = getProvider(o.provider);
  const pin = o.token_endpoint_auth_method ?? null;
  return {
    issuer: c.issuer,
    clientId: c.clientId,
    redirectUri: c.redirectUri,
    scopes: c.scopes,
    sessionTtlSeconds: c.sessionTtlSeconds,
    groupsClaim: c.groupsClaim,
    forwardedHost: c.forwardedHost ?? null,
    callbackPath: o.callback_path,
    logoutPath: o.logout_path,
    provider,
    tokenEndpointAuthMethodPin: pin,
    tokenEndpointAuthMethod(discovery) {
      try {
        return negotiateTokenAuthMethod(provider, discovery, pin);
      } catch (e) {
        ctx.log.error("oidc token endpoint auth method negotiation failed", { provider: provider.name, detail: e.message });
        throw e;
      }
    },
  };
}

/**
 * Read a declared secret or throw (a 500 internal_error; the config loader
 * normally rejects a missing secret long before a request gets here).
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {"client_secret"|"session_hmac_key"} key
 * @returns {string}
 */
export function requireSecret(ctx, key) {
  const v = ctx.secret(key);
  if (typeof v !== "string" || v.length === 0) throw new Error(`oidc-auth: secret ${key} is not configured`);
  return v;
}
