// Per-request settings: the gate's scalar config (ctx.config), this plugin
// instance's options and its provider profile. Secrets are NOT copied here;
// they are read through ctx.secret() at the point of use (requireSecret).

import { getProvider } from "../providers/index.js";
import { normalizeOptions } from "./options.js";

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
 */

/**
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {Object} options  validated (or raw) plugin options
 * @returns {OidcSettings}
 */
export function settingsFor(ctx, options) {
  const o = normalizeOptions(options);
  const c = ctx.config;
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
    provider: getProvider(o.provider),
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
