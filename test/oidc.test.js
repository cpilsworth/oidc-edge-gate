import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { KVStore } from "fastly:kv-store";
import { OidcClient } from "../src/oidc.js";
import { readStateCookie, SESSION_COOKIE } from "../src/session.js";
import { createMockOp } from "./mock-op.js";
import { seedDiscovery, reqFor, getSetCookie } from "./helpers.js";
import { resetStubs } from "./stubs/state.js";

let op, config, oidc;
const realFetch = globalThis.fetch;

beforeEach(async () => {
  resetStubs();
  op = await createMockOp();
  config = {
    issuer: op.discovery.issuer, clientId: "test-client", clientSecret: "test-client-secret",
    redirectUri: "https://www.example.com/.auth/callback",
    scopes: "openid profile email groups", sessionTtlSeconds: 3600,
    sessionKey: "test-hmac-key-at-least-32-bytes-long!!",
    groupsClaim: "groups",
    cache: new KVStore("oidc_cache"),
    backends: { origin: "origin", idp: "idp" },
  };
  seedDiscovery(config.issuer, op.discovery, op.jwks);
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
  oidc = new OidcClient(config);
});

afterEach(() => { globalThis.fetch = realFetch; });

/** Run startLogin from `startPath`, then drive a callback with whatever we choose. */
async function startThenCallback({ startPath = "/members/x", tamperState = false, brokenToken,
                                   errorParam, dropCode = false, wrongPkce = false } = {}) {
  const start = await oidc.startLogin(reqFor(startPath), new URL(`https://www.example.com${startPath}`));
  const loginCookie = getSetCookie(start, "__edge_login");
  const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__edge_login=${loginCookie}` }), config);
  const authUrl = new URL(start.headers.get("location"));
  const code = "code-1";
  // Register the code at the OP. With wrongPkce, register a challenge the real verifier
  // can't satisfy, so the OP's /token returns invalid_grant (N10).
  op.issueCode(code, {
    claims: { nonce: saved.nonce }, accessToken: "atk",
    codeChallenge: wrongPkce ? "a-challenge-the-verifier-cannot-match" : authUrl.searchParams.get("code_challenge"),
  });
  if (brokenToken) op.setBrokenForCode(code, brokenToken);
  const cbUrl = new URL("https://www.example.com/.auth/callback");
  cbUrl.searchParams.set("state", tamperState ? "WRONG" : saved.state);
  if (errorParam) cbUrl.searchParams.set("error", errorParam);
  else if (!dropCode) cbUrl.searchParams.set("code", code);
  const cbReq = reqFor(cbUrl.pathname + cbUrl.search, { cookie: `__edge_login=${loginCookie}` });
  return { start, saved, loginCookie, res: await oidc.handleCallback(cbReq, cbUrl) };
}

describe("startLogin (P1 building block)", () => {
  it("302s to authorize with state+nonce+PKCE and sets the login cookie", async () => {
    const res = await oidc.startLogin(reqFor("/members/x"), new URL("https://www.example.com/members/x"));
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("location"));
    expect(loc.searchParams.get("response_type")).toBe("code");
    expect(loc.searchParams.get("state")).toBeTruthy();
    expect(loc.searchParams.get("nonce")).toBeTruthy();
    expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
    expect(getSetCookie(res, "__edge_login")).toBeTruthy();
  });
});

describe("handleCallback", () => {
  it("P2 valid callback mints a session and 302s back to returnTo", async () => {
    const { res } = await startThenCallback();
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/members/x");
    expect(getSetCookie(res, SESSION_COOKIE)).toBeTruthy();
  });
  it("N8 state mismatch → 400, no session", async () => {
    const { res } = await startThenCallback({ tamperState: true });
    expect(res.status).toBe(400);
    expect(getSetCookie(res, SESSION_COOKIE)).toBeNull();
  });
  it("N12 OP error callback → handled, no session, no 500", async () => {
    const { res } = await startThenCallback({ errorParam: "access_denied" });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect(getSetCookie(res, SESSION_COOKIE)).toBeNull();
  });
  it("missing code → 400", async () => {
    const { res } = await startThenCallback({ dropCode: true });
    expect(res.status).toBe(400);
  });
  it("N10 wrong PKCE verifier → OP rejects, RP surfaces 401, no session", async () => {
    const { res } = await startThenCallback({ wrongPkce: true });
    expect(res.status).toBe(401);
    expect(getSetCookie(res, SESSION_COOKIE)).toBeNull();
  });
  it("N13 protocol-relative returnTo is sanitized to '/' (no open redirect)", async () => {
    // Login from a path that yields a protocol-relative returnTo ("//evil.com").
    const { res } = await startThenCallback({ startPath: "//evil.com" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/"); // NOT //evil.com
  });
  it("N9 replayed callback (consumed state) → 400, no second session", async () => {
    // Build one callback, submit it twice with the same login cookie + state + code.
    const start = await oidc.startLogin(reqFor("/members/x"), new URL("https://www.example.com/members/x"));
    const loginCookie = getSetCookie(start, "__edge_login");
    const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__edge_login=${loginCookie}` }), config);
    const authUrl = new URL(start.headers.get("location"));
    op.issueCode("code-1", { claims: { nonce: saved.nonce }, accessToken: "atk",
      codeChallenge: authUrl.searchParams.get("code_challenge") });
    const cbUrl = new URL("https://www.example.com/.auth/callback");
    cbUrl.searchParams.set("state", saved.state);
    cbUrl.searchParams.set("code", "code-1");
    const mk = () => reqFor(cbUrl.pathname + cbUrl.search, { cookie: `__edge_login=${loginCookie}` });
    const first = await oidc.handleCallback(mk(), cbUrl);
    expect(first.status).toBe(302);
    expect(getSetCookie(first, SESSION_COOKIE)).toBeTruthy();
    const second = await oidc.handleCallback(mk(), cbUrl);
    expect(second.status).toBe(400);
    expect(getSetCookie(second, SESSION_COOKIE)).toBeNull();
  });

  it("N9 concurrent duplicate callbacks mint at most one session", async () => {
    const start = await oidc.startLogin(reqFor("/members/x"), new URL("https://www.example.com/members/x"));
    const loginCookie = getSetCookie(start, "__edge_login");
    const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__edge_login=${loginCookie}` }), config);
    const authUrl = new URL(start.headers.get("location"));
    op.issueCode("code-1", { claims: { nonce: saved.nonce }, accessToken: "atk",
      codeChallenge: authUrl.searchParams.get("code_challenge") });
    const cbUrl = new URL("https://www.example.com/.auth/callback");
    cbUrl.searchParams.set("state", saved.state);
    cbUrl.searchParams.set("code", "code-1");
    const mk = () => reqFor(cbUrl.pathname + cbUrl.search, { cookie: `__edge_login=${loginCookie}` });

    const results = await Promise.all([
      oidc.handleCallback(mk(), cbUrl),
      oidc.handleCallback(mk(), cbUrl),
    ]);

    const sessionCount = results.filter((res) => getSetCookie(res, SESSION_COOKIE)).length;
    expect(sessionCount).toBeLessThanOrEqual(1);
  });
});

describe("handleLogout (P6)", () => {
  it("clears the session and redirects to end_session_endpoint", async () => {
    const res = await oidc.handleLogout(reqFor("/.auth/logout"), new URL("https://www.example.com/.auth/logout"));
    expect(res.status).toBe(302);
    expect(getSetCookie(res, SESSION_COOKIE)).toBe("");
    expect(res.headers.get("location")).toContain(op.discovery.end_session_endpoint);
  });
});
