// Generic OpenID Connect provider profile: plain OIDC Core + Discovery +
// RP-Initiated Logout. This is the default (`provider: "generic"`) and is what
// the gate has always sent, so the current Auth0 sandbox config runs on it
// unchanged.
//
// A profile holds ONLY what differs between identity providers. Everything
// else (discovery, PKCE, state/nonce, ID token verification, the session) is
// shared code in ../lib/. See ./define.js for the profile shape.

import { defineProvider } from "./define.js";

export default defineProvider({
  name: "generic",

  // How the client authenticates at the token endpoint (RFC 6749 §2.3.1), in
  // order of preference; the first one discovery's
  // token_endpoint_auth_methods_supported lists wins (the first entry when
  // discovery omits the list). Post first keeps today's behaviour:
  //   "client_secret_post"  client_id + client_secret in the form body
  //   "client_secret_basic" Authorization: Basic base64(urlencode(id):urlencode(secret))
  tokenEndpointAuthMethods: ["client_secret_post", "client_secret_basic"],

  // Extra static query parameters for the /authorize redirect. The core
  // parameters (response_type, client_id, redirect_uri, scope, state, nonce,
  // code_challenge, code_challenge_method) cannot be overridden here.
  authorizeParams: {},

  // Groups come from the ID token claim named by the `groups_claim` config.
  groupsSource: "claim",

  // RP-initiated logout through the discovery document's end_session_endpoint.
  endSession: "discovery",

  /**
   * Query parameters for the IdP's end_session_endpoint (RP-initiated logout).
   * `state` is not sent (today's behaviour).
   * @param {{clientId: string, postLogoutRedirectUri: string, state: string}} p
   * @returns {Object<string, string>}
   */
  logoutParams({ clientId, postLogoutRedirectUri }) {
    return { client_id: clientId, post_logout_redirect_uri: postLogoutRedirectUri };
  },
});
