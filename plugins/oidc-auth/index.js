// oidc-auth: the gate's OpenID Connect relying party, as an authenticator
// plugin (docs/architecture/plugins.md). Auth-code flow with PKCE (S256),
// state + nonce, RS256 ID token verification, and the gate's own HMAC-signed
// session cookie.
//
//   authenticate  verify the __Host-edge_session cookie (v2, keyring) →
//                 createIdentity({method: "oidc-session", sessionId: sid})
//   challenge     interactive (protected tier): 302 to the IdP; otherwise null (kernel → 401 Bearer)
//   routes        <callback_path> (default /.auth/callback): finish the login
//                 <logout_path>   (default /.auth/logout):   POST-only logout
//
// Platform access goes only through ctx: ctx.fetch (purposes discovery, jwks,
// token, jwks-refresh), ctx.cookies (the two declared cookies), ctx.kv (discovery
// /JWKS cache + single-use state marker), ctx.secret, ctx.config, ctx.lifecycle.
// README.md documents options, KV behaviour per platform profile and security notes.

import { definePlugin } from "../../src/sdk/index.js";
import { handleCallback } from "./lib/callback.js";
import { startLogin } from "./lib/login.js";
import { handleLogout } from "./lib/logout.js";
import { egressFor, normalizeOptions } from "./lib/options.js";
import { SESSION_COOKIE, readSession, sessionToIdentity } from "./lib/session.js";
import { requireSecret, settingsFor } from "./lib/settings.js";
import { LOGIN_COOKIE } from "./lib/state.js";

export { DEFAULT_CALLBACK_PATH, DEFAULT_LOGOUT_PATH } from "./lib/options.js";

/**
 * Worst case per request is the callback: discovery + token + jwks + one
 * jwks-refresh after a kid miss. Discovery is memoized per request, so it is
 * fetched at most once.
 */
export const MAX_FETCHES = 4;

export default definePlugin({
  name: "oidc-auth",
  kind: "authenticator",
  description: "OpenID Connect relying party (auth code + PKCE) with an HMAC-signed gate session.",
  cookies: [SESSION_COOKIE, LOGIN_COOKIE],
  // session_hmac_key: active (signs + verifies the session and login-state
  // cookies); session_hmac_key_previous: optional, verify-only (key rotation).
  secrets: ["client_secret", "session_hmac_key", "session_hmac_key_previous"],
  maxFetches: MAX_FETCHES,
  egress: (options) => egressFor(options),

  validate(options) {
    return normalizeOptions(options);
  },

  routes(options) {
    const o = normalizeOptions(options);
    return {
      [o.callback_path]: (ctx, opts) => handleCallback(ctx, settingsFor(ctx, opts)),
      [o.logout_path]: (ctx, opts) => handleLogout(ctx, settingsFor(ctx, opts)),
    };
  },

  async authenticate(ctx) {
    if (!ctx.cookies.get(SESSION_COOKIE)) return null;
    // readSession verifies with the keyring: the active key plus the optional
    // verify-only session_hmac_key_previous (lib/signed-cookie.js).
    // exp - iat is bounded by session_ttl_seconds (+ skew; W2.R R10).
    const session = await readSession(ctx, requireSecret(ctx, "session_hmac_key"), ctx.config.sessionTtlSeconds);
    return session ? sessionToIdentity(session) : null;
  },

  async challenge(ctx, options, { interactive }) {
    // Secured tier (API/XHR) can't follow a redirect: return null and the
    // kernel answers 401 with WWW-Authenticate: Bearer.
    if (!interactive) return null;
    return startLogin(ctx, settingsFor(ctx, options));
  },
});
