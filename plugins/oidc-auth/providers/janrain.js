// Janrain / Akamai Identity Cloud (Hosted Login) provider profile.
//
// Ground truth: docs/providers/janrain.md (desk research only; NOTHING there is
// verified-live yet: no tenant exists). Row numbers below refer to its §2
// capability matrix; [Sn] are its sources. The service is end-of-life and is
// decommissioned 2027-12-31 [S1], so this profile stays a thin configuration
// over the generic OIDC path with no Janrain-only machinery.
//
// Documented (Akamai TechDocs), not yet verified against a tenant:
//   - Token endpoint auth (row 7): discovery advertises both client_secret_basic
//     and client_secret_post [S2], but the confidential-client guide says Basic
//     "is required" [S9], with client_id also in the body. So Basic is preferred
//     and post is the fallback; the `token_endpoint_auth_method` option can pin
//     either once the tenant is checked (open question 5).
//   - response_mode (row 5): `query` is the documented default for
//     response_type=code [S7]; it is sent explicitly so a tenant default can
//     never turn the callback into a cross-site form_post (the SameSite=Lax
//     login-state cookie would not be sent with it).
//   - ID token claims (rows 18-19): Hosted Login scopes populate ONLY userinfo,
//     never the ID token [S5]; claims reach the ID token through the OIDC
//     `claims` parameter [S6] (claims_parameter_supported: true [S2]). The gate
//     reads email/name from the ID token, so they are requested there. If the
//     login policy uses push claims, the IdP ignores this parameter [S18].
//   - Groups (§4): no groups in Janrain tokens; they come from the separate
//     user-info backend at login (plugins/user-info), so groupsSource is
//     "user-info" and `groups_claim` is unused.
//   - Logout (row 22): end_session_endpoint from discovery, called in the
//     browser, with client_id, post_logout_redirect_uri (must be listed in the
//     client's postLogoutRedirectURIs) and state, all "functionally required"
//     [S11]. Local (this-device) logout; no logout_hint / id_token_hint.
//
// Assumptions (unverified; see janrain.md §5 open questions):
//   - Confidential client + PKCE together are accepted at /token (row 6, Q3);
//     the shared login code always sends S256 PKCE.
//   - `name` has no mapped profile attribute and is not in claims_supported
//     (row 18); requesting an unsupported claim is not an error (OIDC Core
//     §5.5), so it is asked for and may simply be absent.
//   - The token endpoint accepts client_id in the body alongside Basic auth
//     (as in the [S9] example); lib/token.js keeps client_id in the body.
//   - The client secret is never put on the /authorize request (row 8), even
//     though two pages suggest it.

import { defineProvider } from "./define.js";

/**
 * The OIDC `claims` request parameter (OIDC Core §5.5): ask for these claims
 * in the ID token (null = "voluntary, default behaviour"). Kept small: only
 * what the gate maps into the identity (email, name) plus their companions.
 */
export const JANRAIN_ID_TOKEN_CLAIMS = Object.freeze({
  id_token: { email: null, email_verified: null, name: null, given_name: null, family_name: null },
});

export default defineProvider({
  name: "janrain",

  // Basic first: the confidential-client guide requires it (row 7, [S9]).
  tokenEndpointAuthMethods: ["client_secret_basic", "client_secret_post"],

  authorizeParams: {
    response_mode: "query",
    claims: JSON.stringify(JANRAIN_ID_TOKEN_CLAIMS),
  },

  groupsSource: "user-info",

  endSession: "discovery",

  /**
   * @param {{clientId: string, postLogoutRedirectUri: string, state: string}} p
   * @returns {Object<string, string>}
   */
  logoutParams({ clientId, postLogoutRedirectUri, state }) {
    return { client_id: clientId, post_logout_redirect_uri: postLogoutRedirectUri, state };
  },
});
