// Gate configuration loader (W1.3; was src/config.js), built on the platform
// profile detection in ./platform (W1.5). Spec: docs/architecture/plugins.md §11.
//
//   provisioned  ConfigStore("config_default") opens: config comes from the
//                store, else the BUILT-IN default below. There is no fallback
//                to the embedded (sandbox) values; secrets come only from the
//                SecretStore (the `secrets` JSON bundle, else per-key).
//   sandbox      the stores are not provisioned: config and secrets come from
//                src/embedded-config.js (CI injects the real client secret).
//
// The loader returns plain data. It does NOT compile the policy (that needs the
// plugin registry; see src/index.js) and it never exposes secrets through
// `config`: plugins read secrets only through ctx.secret(key), scoped to the
// keys their manifest declares.
//
// Runs on the Fastly Compute runtime: no Node-only APIs. Nothing here logs or
// embeds secret values; errors name the offending key only.

import { ConfigStore } from "fastly:config-store";
import { SecretStore } from "fastly:secret-store";
import { KVStore } from "fastly:kv-store";
import { EMBEDDED_CONFIGS, EMBEDDED_SECRETS } from "../embedded-config.js";
import { EXPECTED_PLATFORM_PROFILE } from "../build-profile.js";
import { detectPlatform } from "./platform/index.js";

/** Secret keys tried one by one on provisioned when there is no `secrets` bundle. */
export const SECRET_KEYS = Object.freeze(["client_secret", "session_hmac_key", "recaptcha_secret"]);

/**
 * Config keys with no safe default (F13). Missing or empty on EITHER profile is
 * a load error (fail closed: every request gets the generic 500), rather than a
 * gate that boots and then misroutes, mis-redirects or forwards to "null".
 */
export const REQUIRED_CONFIG_KEYS = Object.freeze(["issuer", "client_id", "redirect_uri", "origin_hostname", "forwarded_host"]);

/** Gate-owned route defaults (the `routes` config key). */
export const DEFAULT_ROUTES = Object.freeze({ callback: "/.auth/callback", logout: "/.auth/logout" });

/**
 * Built-in defaults, used when a key is absent from the profile's source. On
 * provisioned these are the ONLY fallback (no embedded leak, §11).
 * `recaptcha_min_score` defaults to "0.5" (Google's recommended starting
 * threshold) so a partially seeded store can never silently switch the v3
 * score check off. An explicitly empty value still means "no threshold".
 */
export const BUILT_IN_DEFAULTS = Object.freeze({
  routes: JSON.stringify(DEFAULT_ROUTES),
  policy: '{"rules":[],"default_tier":"protected"}',
  scopes: "openid profile email",
  session_ttl_seconds: "3600",
  groups_claim: "groups",
  recaptcha_min_score: "0.5",
});

/**
 * @typedef {Object} GateConfig  Frozen scalar config exposed to plugins as ctx.config. No secrets.
 * @property {string} issuer               without a trailing slash
 * @property {string|null} clientId
 * @property {string|null} redirectUri
 * @property {string} scopes
 * @property {number} sessionTtlSeconds
 * @property {Readonly<{callback: string, logout: string}>} routes
 * @property {string|null} originHostname  EDS delivery host the gate forwards to
 * @property {string|null} forwardedHost   public host sent as X-Forwarded-Host
 * @property {boolean} pushInvalidation
 * @property {string} groupsClaim          id_token claim carrying group membership
 * @property {number|null} recaptchaMinScore  v3 minimum score (0..1), or null for no threshold
 */

/**
 * @typedef {Object} LoadedGateConfig
 * @property {import("../sdk/index.js").Platform} platform
 * @property {Readonly<GateConfig>} config
 * @property {(key: string) => string|undefined} secret   lookup over the loaded secrets
 * @property {object|null} kv                             raw KV store handle, or null
 * @property {Object} rawPolicy                           the parsed `policy` JSON (a fresh object per load)
 * @property {string[]} warnings                          platform warnings (no secrets)
 */

/**
 * Load the gate configuration for the detected platform profile. Throws (fail
 * closed) on any invalid invariant; the caller turns that into a 500.
 *
 * @param {{stores?: {ConfigStore: Function, SecretStore: Function, KVStore: Function},
 *          embeddedConfigs?: Object, embeddedSecrets?: Object,
 *          expectedProfile?: "provisioned"|"sandbox"|null}} [opts]  injectable for tests;
 *          expectedProfile defaults to the build pin EXPECTED_PLATFORM_PROFILE
 * @returns {Promise<LoadedGateConfig>}
 */
export async function loadGateConfig(opts = {}) {
  const detection = detectPlatform(opts.stores || { ConfigStore, SecretStore, KVStore }, {
    embeddedConfigs: opts.embeddedConfigs || EMBEDDED_CONFIGS,
    embeddedSecrets: opts.embeddedSecrets || EMBEDDED_SECRETS,
    secretKeys: [...SECRET_KEYS],
    // F5: a pinned build fails closed instead of downgrading profiles.
    expectedProfile: opts.expectedProfile !== undefined ? opts.expectedProfile : EXPECTED_PLATFORM_PROFILE,
  });
  const cfg = (key) => {
    const v = detection.cfg(key);
    // As before, an empty value also takes the built-in default, except for
    // recaptcha_min_score, where an explicit "" means "no score threshold".
    const unset = v === null || v === undefined || (v === "" && key !== "recaptcha_min_score");
    if (!unset) return v;
    return Object.hasOwn(BUILT_IN_DEFAULTS, key) ? BUILT_IN_DEFAULTS[key] : (v ?? null);
  };

  for (const key of REQUIRED_CONFIG_KEYS) {
    const v = cfg(key);
    if (typeof v !== "string" || v.trim() === "") throw new Error(`Missing config: ${key}`);
  }

  const routes = parseRoutes(cfg("routes"));
  const rawPolicy = parseJson(cfg("policy"), "policy");
  if (rawPolicy === null || typeof rawPolicy !== "object" || Array.isArray(rawPolicy)) {
    throw new Error("policy must be a JSON object");
  }

  const secrets = await detection.loadSecrets();
  if (!secrets.client_secret) throw new Error("Missing secret: client_secret");
  if (!secrets.session_hmac_key) throw new Error("Missing secret: session_hmac_key");
  // recaptcha_secret is optional at load: most deployments have no reCAPTCHA
  // rule. A rule that needs it fails closed at request time (the plugin).

  // A weak HMAC key undermines every signed cookie.
  if (utf8ByteLength(secrets.session_hmac_key) < 32) {
    throw new Error("session_hmac_key must be at least 32 bytes");
  }
  // A malformed TTL would mint sessions with exp:NaN that never validate (a silent login loop).
  const sessionTtlSeconds = parseInt(cfg("session_ttl_seconds"), 10);
  if (!Number.isInteger(sessionTtlSeconds) || sessionTtlSeconds <= 0) {
    throw new Error("session_ttl_seconds must be a positive integer");
  }
  // Strict parse (Number, not parseFloat, so "0.5abc" is rejected) and range
  // check: a typo must fail closed at load, not silently weaken the check.
  const minRaw = cfg("recaptcha_min_score");
  const recaptchaMinScore = minRaw != null && String(minRaw).trim() !== "" ? Number(minRaw) : null;
  if (recaptchaMinScore != null && !(Number.isFinite(recaptchaMinScore) && recaptchaMinScore >= 0 && recaptchaMinScore <= 1)) {
    throw new Error("recaptcha_min_score must be a number between 0.0 and 1.0");
  }

  const config = Object.freeze({
    issuer: trimSlash(cfg("issuer")),
    clientId: cfg("client_id"),
    redirectUri: cfg("redirect_uri"),
    scopes: cfg("scopes"),
    sessionTtlSeconds,
    routes,
    originHostname: cfg("origin_hostname"),
    forwardedHost: cfg("forwarded_host"),
    pushInvalidation: cfg("push_invalidation") === "enabled",
    groupsClaim: cfg("groups_claim"),
    recaptchaMinScore,
  });

  const frozenSecrets = Object.freeze({ ...secrets });
  const secret = (key) => (Object.hasOwn(frozenSecrets, key) && typeof frozenSecrets[key] === "string" ? frozenSecrets[key] : undefined);

  return {
    platform: detection.platform,
    config,
    secret,
    kv: detection.stores.kv ?? null,
    rawPolicy,
    warnings: [...detection.warnings],
  };
}

function parseRoutes(text) {
  const parsed = parseJson(text, "routes");
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("routes must be a JSON object");
  const routes = { ...DEFAULT_ROUTES, ...parsed }; // a partial value keeps the other default
  for (const k of ["callback", "logout"]) {
    if (typeof routes[k] !== "string" || !routes[k].startsWith("/")) throw new Error(`routes.${k} must be a path starting with "/"`);
  }
  return Object.freeze({ callback: routes.callback, logout: routes.logout });
}

/** JSON.parse without echoing the input (parser messages can quote it). */
function parseJson(text, key) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${key} is not valid JSON`);
  }
}

function trimSlash(s) {
  return (s || "").replace(/\/$/, "");
}

function utf8ByteLength(s) {
  return new TextEncoder().encode(s || "").length;
}
