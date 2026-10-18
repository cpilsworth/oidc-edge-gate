// Shared fixtures for the oidc-auth plugin tests (not a test file itself).
// Every hook runs on createTestContext() (src/sdk/testing.js), which mirrors
// the kernel's per-plugin checks: declared cookies/secrets, egress allow-list
// and maxFetches. IdP traffic goes to the shared mock OP (test/mock-op.js).

import { createTestContext } from "../../../src/sdk/testing.js";
import { createMockOp } from "../../../test/mock-op.js";
import oidcAuth from "../index.js";

export const ISSUER = "https://op.test";
export const SITE = "https://www.example.com";
export const CLIENT_ID = "test-client";
export const HMAC_KEY = "plugin-test-hmac-key-at-least-32-bytes!!";
export const SECRETS = Object.freeze({ client_secret: "test-client-secret", session_hmac_key: HMAC_KEY });
export const CONFIG = Object.freeze({
  issuer: ISSUER,
  clientId: CLIENT_ID,
  redirectUri: `${SITE}/.auth/callback`,
  scopes: "openid profile email groups",
  sessionTtlSeconds: 3600,
  routes: { callback: "/.auth/callback", logout: "/.auth/logout" },
  originHostname: "main--x--y.aem.live",
  forwardedHost: "www.example.com",
  pushInvalidation: true,
  groupsClaim: "groups",
  recaptchaMinScore: 0.5,
});
/** Options as src/index.js injects them (routes + issuer), validated. */
export const OPTIONS = oidcAuth.validate({ callback_path: "/.auth/callback", logout_path: "/.auth/logout", issuer: ISSUER });

export { oidcAuth };

export function newOp(opts = {}) {
  return createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, ...opts });
}

/** A ctx.fetch responder that routes to the mock OP. */
export function opFetch(op) {
  return (input, init) => op.handle(new Request(input, init));
}

/**
 * A Context for one hook call.
 * @param {string} url  absolute, or a path on SITE
 */
export function makeCtx(url, {
  op, fetch, cookie, method = "GET", headers = {}, body, kv, platform, lifecycle,
  options = OPTIONS, config = CONFIG, secrets = SECRETS,
} = {}) {
  const h = new Headers(headers);
  if (cookie) h.set("cookie", cookie);
  const abs = /^https?:\/\//.test(url) ? url : `${SITE}${url}`;
  return createTestContext({
    plugin: oidcAuth,
    request: new Request(abs, { method, headers: h, body }),
    options,
    config,
    secrets,
    kv,
    platform,
    lifecycle,
    fetch: fetch || (op ? opFetch(op) : undefined),
  });
}

/** "name=value" for a cookie the plugin set through ctx.cookies (null if not set). */
export function setCookiePair(ctx, name) {
  const w = [...ctx.recorded.cookies].reverse().find((c) => c.name === name);
  if (!w || w.cleared) return null;
  return `${name}=${encodeURIComponent(w.value)}`;
}

/** The value of a cookie the plugin set (null if not set or cleared). */
export function setCookieValue(ctx, name) {
  const w = [...ctx.recorded.cookies].reverse().find((c) => c.name === name);
  return w && !w.cleared ? w.value : null;
}

export const routeFor = (path, options = OPTIONS) => oidcAuth.routes(options)[path];
export const callbackRoute = (options = OPTIONS) => routeFor(options.callback_path, options);
export const logoutRoute = (options = OPTIONS) => routeFor(options.logout_path, options);

/** Start a login (interactive challenge) for the given request path. */
export async function startLogin(op, path = "/protected/x?q=1", ctxOpts = {}) {
  const ctx = makeCtx(path, { op, ...ctxOpts });
  const res = await oidcAuth.challenge(ctx, ctxOpts.options || OPTIONS, { interactive: true });
  const params = new URL(res.headers.get("location")).searchParams;
  return { ctx, res, params, loginCookie: setCookiePair(ctx, "__Host-edge_login") };
}

let codeSeq = 0;

/**
 * Register a code at the OP for a started login and run the callback route.
 * @returns {Promise<{ctx, res, code}>}
 */
export async function runCallback(op, start, {
  claims = {}, groups, broken, wrongPkce = false, state, errorParam, dropCode = false,
  code = `code-${++codeSeq}`, register = true, ctxOpts = {},
} = {}) {
  if (register) {
    op.issueCode(code, {
      claims: { nonce: start.params.get("nonce"), ...(groups ? { groups } : {}), ...claims },
      accessToken: "atk",
      codeChallenge: wrongPkce ? "a-challenge-the-verifier-cannot-match" : start.params.get("code_challenge"),
    });
    if (broken) op.setBrokenForCode(code, broken);
  }
  const u = new URL(`${SITE}/.auth/callback`);
  u.searchParams.set("state", state ?? start.params.get("state"));
  if (errorParam) u.searchParams.set("error", errorParam);
  else if (!dropCode) u.searchParams.set("code", code);
  const ctx = makeCtx(u.href, { op, cookie: start.loginCookie, ...ctxOpts });
  const res = await callbackRoute(ctxOpts.options || OPTIONS)(ctx, ctxOpts.options || OPTIONS);
  return { ctx, res, code };
}
