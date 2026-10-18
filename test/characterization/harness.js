// Characterization harness (W0.1).
//
// PURPOSE: freeze the gate's externally visible behaviour before the kernel +
// plugin refactor. Everything here drives the gate ONLY through the public
// entry point `handleRequest` (src/index.js) and observes it ONLY through:
//   - the Response it returns (status, headers, body), and
//   - the outbound requests it makes via global `fetch` (recorded here).
//
// DO NOT import internal modules (src/session.js, src/policy.js, src/oidc.js,
// src/cookies.js, ...) from this directory: they are about to move. Session
// cookies are obtained through the real public login flow (start login ->
// /.auth/callback against the in-test mock OP -> take the Set-Cookie), so no
// signing key or cookie format knowledge is needed. The self-check test in
// import-boundary.test.js enforces this.

import { vi } from "vitest";
import { handleRequest } from "../../src/index.js";
import { createMockOp } from "../mock-op.js";

export const SESSION_COOKIE = "__Host-edge_session";
export const LOGIN_COOKIE = "__Host-edge_login";
export const SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
export const GATE_HOST = "www.example.com";

/**
 * Build a gate Request. Paths are resolved against https://www.example.com
 * unless an absolute URL is given.
 */
export function gateRequest(pathOrUrl, { method = "GET", headers = {}, cookie, body } = {}) {
  const url = /^https?:\/\//.test(pathOrUrl) ? pathOrUrl : `https://${GATE_HOST}${pathOrUrl}`;
  const h = new Headers(headers);
  if (cookie) h.set("cookie", cookie);
  return new Request(url, { method, headers: h, body });
}

/** Run one request through the gate's public entry point. */
export function run(pathOrUrl, opts) {
  return handleRequest({ request: gateRequest(pathOrUrl, opts) });
}

/** Parse every Set-Cookie line into { name, value, attrs:Set<lowercased attr>, raw }. */
export function setCookies(res) {
  const lines = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie")].filter(Boolean);
  return lines.map((raw) => {
    const [pair, ...attrs] = raw.split(";").map((s) => s.trim());
    const idx = pair.indexOf("=");
    return {
      name: idx === -1 ? pair : pair.slice(0, idx),
      value: idx === -1 ? "" : pair.slice(idx + 1),
      attrs: new Set(attrs.map((a) => a.toLowerCase())),
      raw,
    };
  });
}

/** The `name=value` pair of a named Set-Cookie, ready to send back as a Cookie header. */
export function cookiePair(res, name) {
  const c = setCookies(res).find((x) => x.name === name);
  return c ? `${c.name}=${c.value}` : null;
}

/** Response hygiene shared by every gate response. */
export function expectNoStore(expect, res) {
  expect(res.headers.get("cache-control")).toBe("private, no-store");
  expect(res.headers.get("surrogate-control")).toBe("private");
  expect(res.headers.get("age")).toBeNull();
}

/**
 * Install a recording, host-routed fetch mock.
 *
 * Routing: the OP issuer host goes to the mock OP; every other host goes to a
 * per-test overridable responder in `routes` (keyed by host, or by full URL for
 * siteverify). An unrouted host throws, so an unexpected outbound call fails
 * the test loudly instead of reaching the network.
 */
export function createFetchRecorder({ op, issuerHost, originHost, upstreamHosts = [] }) {
  const calls = [];
  const defaults = () => {
    const r = {
      [originHost]: () => new Response("origin-body", { status: 200, headers: { "content-type": "text/html" } }),
      [SITEVERIFY_URL]: () => Response.json({
        success: true, score: 0.9, hostname: GATE_HOST, challenge_ts: "2024-01-01T00:00:00Z",
      }),
    };
    for (const h of upstreamHosts) {
      r[h] = () => new Response(`upstream-body:${h}`, { status: 200, headers: { "content-type": "application/json" } });
    }
    return r;
  };
  let routes = defaults();

  async function fetchMock(input, init) {
    const req = new Request(input, init);
    const bodyBytes = req.body ? new Uint8Array(await req.clone().arrayBuffer()) : null;
    const url = new URL(req.url);
    const call = {
      url: req.url,
      host: url.host,
      pathname: url.pathname,
      search: url.search,
      method: req.method,
      headers: new Headers(req.headers),
      bodyBytes,
      get bodyText() { return bodyBytes ? new TextDecoder().decode(bodyBytes) : null; },
    };
    calls.push(call);
    const urlNoQuery = `${url.origin}${url.pathname}`;
    if (routes[urlNoQuery]) return routes[urlNoQuery](req, call);
    if (url.host === issuerHost) return op.handle(req);
    if (routes[url.host]) return routes[url.host](req, call);
    throw new Error(`characterization harness: unexpected outbound fetch to ${req.url}`);
  }

  return {
    calls,
    fetch: fetchMock,
    /** Override the responder for a host (or full siteverify URL) for this test. */
    route(key, handler) { routes[key] = handler; },
    reset() { calls.length = 0; routes = defaults(); },
    to(host) { return calls.filter((c) => c.host === host); },
  };
}

/**
 * Set up a full characterization environment: mock OP + fetch recorder +
 * login helper with memoized sessions. Call from beforeAll; wire
 * `install`/`uninstall` into beforeEach/afterEach.
 */
export async function createEnv({ issuer, clientId, originHost, groupsClaim, upstreamHosts = [] }) {
  const op = await createMockOp({ issuer, clientId, originHostname: originHost });
  const issuerHost = new URL(issuer).host;
  const rec = createFetchRecorder({ op, issuerHost, originHost, upstreamHosts });
  const realFetch = globalThis.fetch;
  const sessionCache = new Map();
  let codeSeq = 0;
  let spies = [];

  function install() {
    rec.reset();
    globalThis.fetch = rec.fetch;
    // The gate logs diagnostics on every rejection; keep test output readable.
    spies = [vi.spyOn(console, "error").mockImplementation(() => {}),
      vi.spyOn(console, "warn").mockImplementation(() => {})];
  }
  function uninstall() {
    globalThis.fetch = realFetch;
    for (const s of spies) s.mockRestore();
    spies = [];
  }

  /**
   * Start a login exactly as a browser would (anonymous GET of a protected
   * path). Returns the 302 response plus the parsed authorize params and the
   * login-state cookie pair.
   */
  async function startLogin(returnPath = "/protected/x", opts = {}) {
    const res = await run(returnPath, opts);
    const location = res.headers.get("location");
    const params = location ? new URL(location).searchParams : new URLSearchParams();
    return { res, location, params, loginCookie: cookiePair(res, LOGIN_COOKIE) };
  }

  /**
   * Full public login flow. `groups` is placed under the configured groups
   * claim; `claims` overrides/extends the id_token claims. The OP-side code is
   * registered with the real PKCE challenge, so the gate's verifier is checked.
   */
  async function login({ groups = [], claims = {}, returnPath = "/protected/x" } = {}) {
    const start = await startLogin(returnPath);
    const state = start.params.get("state");
    const nonce = start.params.get("nonce");
    const code = `code-${++codeSeq}`;
    op.issueCode(code, {
      claims: { nonce, ...(groupsClaim ? { [groupsClaim]: groups } : {}), ...claims },
      codeChallenge: start.params.get("code_challenge"),
    });
    const callback = await run(`/.auth/callback?code=${code}&state=${encodeURIComponent(state)}`, {
      cookie: start.loginCookie,
    });
    return { start, code, state, callback, sessionCookie: cookiePair(callback, SESSION_COOKIE) };
  }

  /** Memoized `__Host-edge_session=...` cookie pair for a group set; recorder calls are discarded. */
  async function session(groups = [], claims = {}) {
    const key = JSON.stringify([groups, claims]);
    if (!sessionCache.has(key)) {
      const before = rec.calls.length;
      const { sessionCookie } = await login({ groups, claims });
      rec.calls.splice(before);
      if (!sessionCookie) throw new Error("characterization harness: login flow did not mint a session");
      sessionCache.set(key, sessionCookie);
    }
    return sessionCache.get(key);
  }

  return { op, rec, install, uninstall, startLogin, login, session };
}
