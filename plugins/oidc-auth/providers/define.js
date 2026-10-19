// The provider-profile seam (docs/architecture/plugins.md §14.1). A profile is
// a small frozen object with exactly these keys; defineProvider() checks its
// shape when the module loads, so a malformed profile fails the build/test
// run, never a request.
//
//   name                      "generic" | "auth0" | "janrain" (the `provider` plugin option)
//   tokenEndpointAuthMethods  ordered, non-empty, duplicate-free preference list drawn from
//                             "client_secret_post" | "client_secret_basic". The method used is
//                             negotiated against discovery (lib/token.js negotiateTokenAuthMethod).
//   authorizeParams           extra static /authorize query params (core params excluded)
//   groupsSource              "claim"     groups from the `groups_claim` ID-token claim
//                             "user-info" groups only from login subscribers (the user-info
//                                         plugin); the draft starts with no groups
//   endSession                "discovery" 303 to the discovery end_session_endpoint when present
//                             "none"      always 303 to "/" after the local logout
//   logoutParams({clientId, postLogoutRedirectUri, state}) -> {param: string} for end_session_endpoint
//                             `state` is a fresh random value per logout; profiles that don't
//                             need it ignore it.
//
// Adding a provider: write providers/<name>.js with defineProvider({...}), add
// it to PROVIDERS in ./index.js, add tests.

export const TOKEN_ENDPOINT_AUTH_METHODS = Object.freeze(["client_secret_post", "client_secret_basic"]);
export const GROUPS_SOURCES = Object.freeze(["claim", "user-info"]);
export const END_SESSION_MODES = Object.freeze(["discovery", "none"]);

/** /authorize parameters the shared login code owns; a profile may not set them. */
export const CORE_AUTHORIZE_PARAMS = Object.freeze([
  "response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method",
]);

const KEYS = Object.freeze([
  "name", "tokenEndpointAuthMethods", "authorizeParams", "groupsSource", "endSession", "logoutParams",
]);

/**
 * @typedef {"client_secret_post"|"client_secret_basic"} TokenEndpointAuthMethod
 * @typedef {Object} ProviderProfile
 * @property {string} name
 * @property {ReadonlyArray<TokenEndpointAuthMethod>} tokenEndpointAuthMethods
 * @property {Readonly<Object<string, string>>} authorizeParams
 * @property {"claim"|"user-info"} groupsSource
 * @property {"discovery"|"none"} endSession
 * @property {(p: {clientId: string, postLogoutRedirectUri: string, state: string}) => Object<string, string>} logoutParams
 */

/**
 * Validate and freeze a provider profile. Every key is required; unknown keys
 * and wrong types throw.
 * @param {ProviderProfile} profile
 * @returns {Readonly<ProviderProfile>}
 */
export function defineProvider(profile) {
  const fail = (msg) => { throw new TypeError(`oidc-auth provider ${JSON.stringify(profile && profile.name)}: ${msg}`); };
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) fail("profile must be an object");
  for (const k of Object.keys(profile)) if (!KEYS.includes(k)) fail(`unknown key ${JSON.stringify(k)}`);
  for (const k of KEYS) if (!(k in profile)) fail(`missing key ${JSON.stringify(k)}`);
  if (typeof profile.name !== "string" || !/^[a-z][a-z0-9-]*$/.test(profile.name)) fail("name must be lowercase");

  const methods = profile.tokenEndpointAuthMethods;
  if (!Array.isArray(methods) || methods.length === 0) fail("tokenEndpointAuthMethods must be a non-empty array");
  for (const m of methods) {
    if (!TOKEN_ENDPOINT_AUTH_METHODS.includes(m)) {
      fail(`tokenEndpointAuthMethods entries must be one of ${TOKEN_ENDPOINT_AUTH_METHODS.join(", ")}`);
    }
  }
  if (new Set(methods).size !== methods.length) fail("tokenEndpointAuthMethods must not repeat a method");

  const params = profile.authorizeParams;
  if (params === null || typeof params !== "object" || Array.isArray(params)) fail("authorizeParams must be an object");
  for (const [k, v] of Object.entries(params)) {
    if (CORE_AUTHORIZE_PARAMS.includes(k)) fail(`authorizeParams may not set the core parameter ${JSON.stringify(k)}`);
    if (typeof v !== "string") fail(`authorizeParams.${k} must be a string`);
  }

  if (!GROUPS_SOURCES.includes(profile.groupsSource)) fail(`groupsSource must be one of ${GROUPS_SOURCES.join(", ")}`);
  if (!END_SESSION_MODES.includes(profile.endSession)) fail(`endSession must be one of ${END_SESSION_MODES.join(", ")}`);

  if (typeof profile.logoutParams !== "function") fail("logoutParams must be a function");
  // Probe once with sample inputs: the result must be a plain {param: string} map.
  const sample = profile.logoutParams({ clientId: "client", postLogoutRedirectUri: "https://site.invalid/", state: "state" });
  if (sample === null || typeof sample !== "object" || Array.isArray(sample)
      || Object.values(sample).some((v) => typeof v !== "string")) {
    fail("logoutParams must return an object of string values");
  }

  return Object.freeze({
    ...profile,
    tokenEndpointAuthMethods: Object.freeze([...methods]),
    authorizeParams: Object.freeze({ ...params }),
  });
}
