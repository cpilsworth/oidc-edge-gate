// oidc-auth through the real kernel (src/index.js → pipeline), on a
// provisioned (store-backed) platform. Covers what plugin unit tests on
// createTestContext cannot show end to end:
//   - a discovered endpoint outside the plugin's egress list → the kernel's
//     500 {"error":"egress_denied"}, and the request is never sent;
//   - provisioned + KV unbound → the callback fails closed with
//     503 {"error":"kv_unavailable"} (ADR §11; the approved W1.4 behaviour change);
//   - the Fastly cache mode of each IdP fetch (override 3600 for discovery and
//     JWKS, pass for the token exchange and the forced JWKS refetch) and the
//     fetch purposes in the kernel's fetch log.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

const kvMode = vi.hoisted(() => ({ unbound: false }));
vi.mock("fastly:kv-store", async () => {
  const real = await vi.importActual("./stubs/kv-store.js");
  return {
    KVStore: class extends real.KVStore {
      constructor(name) {
        if (kvMode.unbound) throw new Error(`No KVStore named '${name}' exists`);
        super(name);
      }
    },
  };
});

import { handleRequest, withAuthRouteOptions } from "../src/index.js";
import { createMockOp } from "./mock-op.js";
import { makeRsaKey, reqFor, signJwt } from "./helpers.js";
import { getKvMap, resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const ISSUER = "https://op.test";
const ORIGIN = "main--oidc--plugin.aem.live";
const HMAC_KEY = "oidc-gate-test-hmac-key-at-least-32-bytes!!";
const realFetch = globalThis.fetch;

let op;
let calls;
let fetchLog;
let discoveryDoc;
let responder;

const run = (path, opts) => handleRequest({ request: reqFor(path, opts) });
const cookiePair = (res, name) => {
  const line = res.headers.getSetCookie().find((l) => l.startsWith(`${name}=`));
  return line ? line.split(";")[0] : null;
};

beforeEach(async () => {
  kvMode.unbound = false;
  resetStubs();
  op = await createMockOp({ issuer: ISSUER, originHostname: ORIGIN });
  discoveryDoc = { ...op.discovery };
  seedConfig({
    issuer: ISSUER,
    client_id: "test-client",
    redirect_uri: "https://www.example.com/.auth/callback",
    origin_hostname: ORIGIN,
    forwarded_host: "www.example.com",
    groups_claim: "groups",
    policy: JSON.stringify({ rules: [{ path: "/", tier: "public" }], default_tier: "protected" }),
  });
  seedSecrets({ client_secret: "s", session_hmac_key: HMAC_KEY });
  calls = [];
  responder = (r) => op.handle(r);
  globalThis.fetch = async (input, init) => {
    const r = new Request(input, init);
    const u = new URL(r.url);
    calls.push({ host: u.host, path: u.pathname, cacheOverride: init && init.cacheOverride });
    if (u.host === "op.test" && u.pathname === "/.well-known/openid-configuration") return Response.json(discoveryDoc);
    return responder(r);
  };
  fetchLog = [];
  vi.spyOn(console, "log").mockImplementation((line) => {
    try {
      const e = JSON.parse(line);
      if (e.event === "fetch" && e.plugin === "oidc-auth") fetchLog.push(e.purpose);
    } catch { /* not a JSON log line */ }
  });
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => { globalThis.fetch = realFetch; vi.restoreAllMocks(); });

async function startLogin(path = "/protected/x") {
  const res = await run(path);
  expect(res.status).toBe(302);
  const params = new URL(res.headers.get("location")).searchParams;
  return { params, loginCookie: cookiePair(res, "__Host-edge_login") };
}

function callback(start, code) {
  return run(`/.auth/callback?code=${code}&state=${encodeURIComponent(start.params.get("state"))}`, { cookie: start.loginCookie });
}

describe("egress (kernel-enforced)", () => {
  it("a discovered token endpoint on another origin → 500 egress_denied; the request is never sent", async () => {
    discoveryDoc = { ...discoveryDoc, token_endpoint: "https://evil.test/token" };
    const start = await startLogin();
    op.issueCode("c1", { claims: { nonce: start.params.get("nonce") }, codeChallenge: start.params.get("code_challenge") });
    const res = await callback(start, "c1");
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "egress_denied" });
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(calls.filter((c) => c.host === "evil.test")).toEqual([]);
  });

  it("a discovered jwks_uri on another origin → 500 egress_denied (not a 400 auth error)", async () => {
    discoveryDoc = { ...discoveryDoc, jwks_uri: "https://keys.evil.test/jwks" };
    const start = await startLogin();
    op.issueCode("c2", { claims: { nonce: start.params.get("nonce") }, codeChallenge: start.params.get("code_challenge") });
    const res = await callback(start, "c2");
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "egress_denied" });
    expect(calls.filter((c) => c.host === "keys.evil.test")).toEqual([]);
  });
});

describe("provisioned platform, KV unbound", () => {
  it("login start still works; the callback fails closed with 503 kv_unavailable, before any token exchange", async () => {
    kvMode.unbound = true;
    const start = await startLogin();
    op.issueCode("c3", { claims: { nonce: start.params.get("nonce") }, codeChallenge: start.params.get("code_challenge") });
    calls.length = 0;
    const res = await callback(start, "c3");
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "kv_unavailable" });
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("with KV bound, the same flow logs in", async () => {
    const start = await startLogin();
    op.issueCode("c4", { claims: { nonce: start.params.get("nonce") }, codeChallenge: start.params.get("code_challenge") });
    const res = await callback(start, "c4");
    expect(res.status).toBe(302);
    expect(cookiePair(res, "__Host-edge_session")).toBeTruthy();
  });
});

describe("IdP fetches: purposes and Fastly cache modes", () => {
  it("worst-case callback: discovery (override 3600), token (pass), jwks (override 3600), jwks-refresh (pass)", async () => {
    const start = await startLogin();
    // Empty the KV cache so the callback fetches discovery and JWKS live.
    getKvMap("kv_default").clear();
    const rotated = await makeRsaKey("key-B");
    let jwksCalls = 0;
    responder = async (r) => {
      const u = new URL(r.url);
      if (u.pathname === "/jwks") return Response.json({ keys: ++jwksCalls === 1 ? [op.key.publicJwk] : [op.key.publicJwk, rotated.publicJwk] });
      if (u.pathname === "/token") {
        const now = Math.floor(Date.now() / 1000);
        const idToken = await signJwt({ alg: "RS256", kid: "key-B", typ: "JWT" },
          { iss: ISSUER, aud: "test-client", sub: "user-123", iat: now, exp: now + 60, nonce: start.params.get("nonce") }, rotated.privateKey);
        return Response.json({ id_token: idToken });
      }
      return op.handle(r);
    };
    calls.length = 0;
    fetchLog.length = 0;
    const res = await callback(start, "any");
    expect(res.status).toBe(302);
    expect(fetchLog).toEqual(["discovery", "token", "jwks", "jwks-refresh"]);
    expect(calls.map((c) => [c.path, c.cacheOverride.mode, c.cacheOverride.ttl])).toEqual([
      ["/.well-known/openid-configuration", "override", 3600],
      ["/token", "pass", undefined],
      ["/jwks", "override", 3600],
      ["/jwks", "pass", undefined],
    ]);
  });
});

describe("src/index.js injects the issuer option (egress needs it)", () => {
  const routes = { callback: "/.auth/callback", logout: "/.auth/logout" };

  it("legacy and explicit oidc-auth policies get the gate's issuer; the config value wins over the policy", () => {
    expect(withAuthRouteOptions({ rules: [] }, routes, { issuer: ISSUER }).plugins["oidc-auth"])
      .toEqual({ callback_path: "/.auth/callback", logout_path: "/.auth/logout", issuer: ISSUER });
    const v2 = { version: 2, authentication: { use: "oidc-auth" }, plugins: { "oidc-auth": { issuer: "https://evil.test", logout_path: "/.auth/bye" } } };
    expect(withAuthRouteOptions(v2, routes, { issuer: ISSUER }).plugins["oidc-auth"])
      .toEqual({ callback_path: "/.auth/callback", logout_path: "/.auth/bye", issuer: ISSUER });
  });

  it("no issuer configured → nothing injected (the plugin then has no IdP egress)", () => {
    expect(withAuthRouteOptions({ rules: [] }, routes, { issuer: "" }).plugins["oidc-auth"]).not.toHaveProperty("issuer");
    expect(withAuthRouteOptions({ rules: [] }, routes).plugins["oidc-auth"]).not.toHaveProperty("issuer");
  });

  it("a policy that does not use oidc-auth is untouched", () => {
    const other = { version: 2, default_tier: "public" };
    expect(withAuthRouteOptions(other, routes, { issuer: ISSUER })).toBe(other);
  });
});
