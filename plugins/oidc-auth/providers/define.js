// The provider-profile seam. A profile is a small frozen object with exactly
// these keys; defineProvider() checks its shape when the module loads, so a
// malformed profile fails the build/test run, never a request.
//
//   name                     "generic" | "auth0" | … (the `provider` plugin option)
//   tokenEndpointAuthMethod  "client_secret_post" | "client_secret_basic"
//   authorizeParams          extra static /authorize query params (core params excluded)
//   logoutParams({clientId, postLogoutRedirectUri}) -> {param: value} for end_session_endpoint
//
// Adding a provider (e.g. W2's janrain): write providers/<name>.js with
// defineProvider({...}), add it to PROVIDERS in ./index.js, add tests.

export const TOKEN_ENDPOINT_AUTH_METHODS = Object.freeze(["client_secret_post", "client_secret_basic"]);

/** /authorize parameters the shared login code owns; a profile may not set them. */
export const CORE_AUTHORIZE_PARAMS = Object.freeze([
  "response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method",
]);

const KEYS = new Set(["name", "tokenEndpointAuthMethod", "authorizeParams", "logoutParams"]);

/**
 * @typedef {Object} ProviderProfile
 * @property {string} name
 * @property {"client_secret_post"|"client_secret_basic"} tokenEndpointAuthMethod
 * @property {Readonly<Object<string, string>>} authorizeParams
 * @property {(p: {clientId: string, postLogoutRedirectUri: string}) => Object<string, string>} logoutParams
 */

/**
 * Validate and freeze a provider profile.
 * @param {ProviderProfile} profile
 * @returns {Readonly<ProviderProfile>}
 */
export function defineProvider(profile) {
  const fail = (msg) => { throw new TypeError(`oidc-auth provider ${JSON.stringify(profile && profile.name)}: ${msg}`); };
  if (!profile || typeof profile !== "object") fail("profile must be an object");
  for (const k of Object.keys(profile)) if (!KEYS.has(k)) fail(`unknown key ${JSON.stringify(k)}`);
  if (typeof profile.name !== "string" || !/^[a-z][a-z0-9-]*$/.test(profile.name)) fail("name must be lowercase");
  if (!TOKEN_ENDPOINT_AUTH_METHODS.includes(profile.tokenEndpointAuthMethod)) {
    fail(`tokenEndpointAuthMethod must be one of ${TOKEN_ENDPOINT_AUTH_METHODS.join(", ")}`);
  }
  const params = profile.authorizeParams ?? {};
  if (params === null || typeof params !== "object" || Array.isArray(params)) fail("authorizeParams must be an object");
  for (const [k, v] of Object.entries(params)) {
    if (CORE_AUTHORIZE_PARAMS.includes(k)) fail(`authorizeParams may not set the core parameter ${JSON.stringify(k)}`);
    if (typeof v !== "string") fail(`authorizeParams.${k} must be a string`);
  }
  if (typeof profile.logoutParams !== "function") fail("logoutParams must be a function");
  return Object.freeze({ ...profile, authorizeParams: Object.freeze({ ...params }) });
}
