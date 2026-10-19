// Plugin options: validation, defaults and the egress allow-list.
//
//   callback_path  exact /.auth/ path of the OIDC callback route (default /.auth/callback)
//   logout_path    exact /.auth/ path of the logout route        (default /.auth/logout)
//   provider       provider profile name, see ../providers/       (default "generic")
//   extra_egress   additional https origins the plugin may fetch (default [])
//   issuer         the gate's issuer; used ONLY to build the egress allow-list
//
// src/index.js injects callback_path/logout_path (from the gate's `routes`
// config key) and issuer (from the `issuer` config key) as base options, since
// egress(options) cannot see ctx.config. The issuer the plugin actually talks
// to is always ctx.config.issuer; if a policy pointed the `issuer` option
// somewhere else, every IdP fetch would fail closed with egress_denied.

import { PluginConfigError, validateEgress } from "../../../src/sdk/index.js";
import { DEFAULT_PROVIDER, PROVIDERS } from "../providers/index.js";

export const DEFAULT_CALLBACK_PATH = "/.auth/callback";
export const DEFAULT_LOGOUT_PATH = "/.auth/logout";
export const OPTION_KEYS = Object.freeze(["callback_path", "logout_path", "provider", "extra_egress", "issuer"]);

/**
 * Apply defaults and validate. Idempotent: normalizing normalized options
 * returns an equal object.
 * @param {Object} [options]
 * @returns {{callback_path: string, logout_path: string, provider: string, extra_egress: string[], issuer: string|null}}
 */
export function normalizeOptions(options = {}) {
  for (const k of Object.keys(options)) {
    if (!OPTION_KEYS.includes(k)) throw new PluginConfigError(`unknown option ${JSON.stringify(k)}`);
  }
  const out = {
    callback_path: options.callback_path ?? DEFAULT_CALLBACK_PATH,
    logout_path: options.logout_path ?? DEFAULT_LOGOUT_PATH,
    provider: options.provider ?? DEFAULT_PROVIDER,
    extra_egress: normalizeExtraEgress(options.extra_egress),
    issuer: normalizeIssuer(options.issuer),
  };
  for (const k of ["callback_path", "logout_path"]) {
    if (typeof out[k] !== "string" || !out[k].startsWith("/.auth/")) {
      throw new PluginConfigError(`${k} must be a path under /.auth/`);
    }
  }
  if (out.callback_path === out.logout_path) throw new PluginConfigError("callback_path and logout_path must differ");
  if (typeof out.provider !== "string" || !Object.prototype.hasOwnProperty.call(PROVIDERS, out.provider)) {
    throw new PluginConfigError(`provider must be one of ${Object.keys(PROVIDERS).join(", ")}`);
  }
  return out;
}

function normalizeExtraEgress(raw) {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw) || raw.some((e) => typeof e !== "string")) {
    throw new PluginConfigError("extra_egress must be an array of https origins");
  }
  validateEgress(raw, (msg) => { throw new PluginConfigError(`extra_egress: ${msg}`); });
  return [...new Set(raw.map((e) => new URL(e).origin))];
}

function normalizeIssuer(raw) {
  if (raw === undefined || raw === null || raw === "") return null;
  if (typeof raw !== "string") throw new PluginConfigError("issuer must be a string");
  return raw;
}

/**
 * The plugin's egress allow-list: the issuer's origin plus `extra_egress`.
 * An issuer that is not a URL contributes nothing (every IdP fetch then fails
 * closed with egress_denied instead of failing the whole config load).
 * @param {Object} options
 * @returns {string[]}
 */
export function egressFor(options) {
  const o = normalizeOptions(options);
  const list = [];
  if (o.issuer) {
    try {
      list.push(new URL(o.issuer).origin);
    } catch {
      /* not a URL: no issuer egress */
    }
  }
  for (const e of o.extra_egress) if (!list.includes(e)) list.push(e);
  return list;
}
