// Auth0 provider profile.
//
// Auth0 is a standards-compliant OP for everything the gate uses, so this
// profile is the generic one under its own name. It exists so Auth0-specific
// differences have an obvious home, and so a policy can say what it runs on.
// Notes for the current tenant (see CLAUDE.md):
//   - Token endpoint: client_secret_post (the application's "Token Endpoint
//     Authentication Method" is "Post"), as today.
//   - Logout: the discovery document's end_session_endpoint (/oidc/logout,
//     "RP-Initiated Logout End Session Endpoint Discovery" enabled) takes
//     client_id + post_logout_redirect_uri, exactly like the generic profile.
//     The legacy /v2/logout?returnTo= endpoint is NOT used.
//   - Groups: Auth0 strips non-namespaced custom claims, so the groups claim is
//     namespaced (`groups_claim` config); that is config, not profile.

import generic from "./generic.js";
import { defineProvider } from "./define.js";

export default defineProvider({
  ...generic,
  name: "auth0",
});
