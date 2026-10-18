// oidc-auth: TEMPORARY authenticator adapter (W1.3). Replaced in W1.4.
//
// Wraps the legacy OIDC relying-party modules that still live in src/
// (src/oidc.js, src/session.js, src/jwt.js, src/pkce.js, src/kv.js) behind the
// plugin contract, so the kernel can run today's behaviour unchanged:
//
//   authenticate  -> readSession() on the signed __Host-edge_session cookie
//                    -> createIdentity({method: "oidc-session", ...})
//   challenge     -> interactive (protected tier): startLogin() 302 to the IdP;
//                    otherwise null, so the kernel answers 401 Bearer (secured)
//   routes        -> <callback_path> (default /.auth/callback): handleCallback,
//                    emitting the login lifecycle event before the session is minted
//                    <logout_path> (default /.auth/logout): POST-only handleLogout,
//                    emitting the logout lifecycle event
//
// Route paths come from the plugin's options. src/kernel/config.js does not
// know about plugins; src/index.js injects the configured `routes` config key
// as `plugins["oidc-auth"]` base options ({callback_path, logout_path}) when
// oidc-auth is the policy's authenticator, unless the policy sets them itself.
//
// Known temporary gaps (see README.md): the legacy modules call the global
// fetch (not ctx.fetch), read the raw Cookie header (not ctx.cookies) and
// write Set-Cookie lines themselves. W1.4 removes all of that.

import { createIdentity, createIdentityDraft, definePlugin, PluginConfigError } from "../../src/sdk/index.js";
import { OidcClient } from "../../src/oidc.js";
import { readSession, SESSION_COOKIE, STATE_COOKIE } from "../../src/session.js";

export const DEFAULT_CALLBACK_PATH = "/.auth/callback";
export const DEFAULT_LOGOUT_PATH = "/.auth/logout";
const OPTION_KEYS = new Set(["callback_path", "logout_path"]);

/**
 * Bridge the plugin's namespaced ctx.kv (string values) to the legacy KV
 * contract (src/kv.js expects `get(key)` to resolve to an entry with an async
 * `text()`, and `put(key, value, {ttl})`). Null stays null: the legacy code
 * then skips caching and the single-use state marker, exactly as on sandbox.
 * @param {import("../../src/sdk/index.js").KvView|null} kv
 */
export function legacyKv(kv) {
  if (!kv) return null;
  return {
    async get(key) {
      const value = await kv.get(key);
      return value === null || value === undefined ? null : { text: async () => value };
    },
    async put(key, value, opts) {
      await kv.put(key, value, opts && opts.ttl !== undefined ? { ttl: opts.ttl } : undefined);
    },
    async delete(key) {
      await kv.delete(key);
    },
  };
}

/**
 * Assemble the legacy OidcConfig (src/oidc.js) for one request.
 * @param {import("../../src/sdk/index.js").Context} ctx
 * @param {{callback_path: string, logout_path: string}} options
 * @returns {import("../../src/oidc.js").OidcConfig}
 */
export function legacyConfig(ctx, options) {
  const c = ctx.config;
  return {
    issuer: c.issuer,
    clientId: c.clientId,
    clientSecret: ctx.secret("client_secret"),
    redirectUri: c.redirectUri,
    scopes: c.scopes,
    sessionTtlSeconds: c.sessionTtlSeconds,
    sessionKey: ctx.secret("session_hmac_key"),
    routes: { callback: options.callback_path, logout: options.logout_path },
    forwardedHost: c.forwardedHost,
    groupsClaim: c.groupsClaim,
    cache: legacyKv(ctx.kv),
  };
}

/** Legacy session object -> SDK Identity. */
export function sessionToIdentity(session) {
  const str = (v) => (typeof v === "string" ? v : undefined);
  return createIdentity({
    sub: session.sub,
    email: str(session.email),
    name: str(session.name),
    groups: session.groups,
    method: "oidc-session",
    issuedAt: session.iat,
    expiresAt: session.exp,
  });
}

function normalizeOptions(options) {
  const out = {
    callback_path: options.callback_path ?? DEFAULT_CALLBACK_PATH,
    logout_path: options.logout_path ?? DEFAULT_LOGOUT_PATH,
  };
  for (const k of OPTION_KEYS) {
    if (typeof out[k] !== "string" || !out[k].startsWith("/.auth/")) {
      throw new PluginConfigError(`${k} must be a path under /.auth/`);
    }
  }
  if (out.callback_path === out.logout_path) throw new PluginConfigError("callback_path and logout_path must differ");
  return out;
}

export default definePlugin({
  name: "oidc-auth",
  kind: "authenticator",
  description: "TEMPORARY adapter over the legacy OIDC relying party (src/oidc.js); replaced in W1.4.",
  cookies: [SESSION_COOKIE, STATE_COOKIE],
  secrets: ["client_secret", "session_hmac_key"],

  validate(options) {
    for (const k of Object.keys(options)) {
      if (!OPTION_KEYS.has(k)) throw new PluginConfigError(`unknown option ${JSON.stringify(k)}`);
    }
    return normalizeOptions(options);
  },

  routes(options) {
    const o = normalizeOptions(options);
    return {
      [o.callback_path]: async (ctx, opts) => {
        const client = new OidcClient(legacyConfig(ctx, normalizeOptions(opts)));
        return client.handleCallback(ctx.request, ctx.url, {
          // Login lifecycle: plugins' onLogin hooks see the verified identity
          // before the session exists; a throw aborts the login (fail closed).
          onVerified: async (claims) => {
            const draft = createIdentityDraft({
              sub: claims.sub,
              email: typeof claims.email === "string" ? claims.email : undefined,
              name: typeof claims.name === "string" ? claims.name : undefined,
              groups: claims[ctx.config.groupsClaim],
              claims,
            });
            const before = draft.groups;
            await ctx.lifecycle.emitLogin(draft);
            return draft.groups.filter((g) => !before.includes(g));
          },
        });
      },
      [o.logout_path]: async (ctx, opts) => {
        const config = legacyConfig(ctx, normalizeOptions(opts));
        const client = new OidcClient(config);
        return client.handleLogout(ctx.request, ctx.url, {
          onLogout: async () => {
            const session = await readSession(ctx.request, config);
            await ctx.lifecycle.emitLogout(session ? sessionToIdentity(session) : null);
          },
        });
      },
    };
  },

  async authenticate(ctx, options) {
    const session = await readSession(ctx.request, legacyConfig(ctx, normalizeOptions(options)));
    return session ? sessionToIdentity(session) : null;
  },

  async challenge(ctx, options, { interactive }) {
    // Secured tier (API/XHR): no redirect; the kernel answers 401 Bearer.
    if (!interactive) return null;
    const client = new OidcClient(legacyConfig(ctx, normalizeOptions(options)));
    return client.startLogin(ctx.request, ctx.url);
  },
});
