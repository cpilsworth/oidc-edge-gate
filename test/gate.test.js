import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { KVStore } from "fastly:kv-store";
import { handleRequest } from "../src/index.js";
import { mintSessionCookie } from "../src/session.js";
import { createMockOp } from "./mock-op.js";
import { seedDiscovery, reqFor, getSetCookie } from "./helpers.js";
import { resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const ISSUER = "https://op.test";
const ORIGIN_HOST = "main--mysite--myorg.aem.live";
const HMAC_KEY = "test-hmac-key-at-least-32-bytes-long!!";

// Policy mirrors local.config.json: public assets/blog, protected tier, an
// audience-gated medical sub-tree, and a secured API tier; default protected.
const POLICY = {
  rules: [
    { path: "/", tier: "public" },
    { path: "/blog/*", tier: "public" },
    { path: "/styles/*", tier: "public" },
    { path: "/scripts/*", tier: "public" },
    { path: "/blocks/*", tier: "public" },
    { path: "/icons/*", tier: "public" },
    { path: "/protected/*", tier: "protected" },
    { path: "/protected/medical/*", tier: "protected", audience: ["medical"] },
    { path: "/api/*", tier: "secured" },
  ],
  default_tier: "protected",
};

// The minted-cookie config matches what loadConfig will reconstruct.
const cookieConfig = { sessionKey: HMAC_KEY, sessionTtlSeconds: 3600, groupsClaim: "groups" };
const realFetch = globalThis.fetch;
let op;

async function sessionCookieHeader(groups) {
  const sc = await mintSessionCookie({ sub: "user-123", groups }, cookieConfig);
  const value = sc.match(/__edge_session=([^;]*)/)[1];
  return `__edge_session=${value}`;
}

function run(path, opts) {
  return handleRequest({ request: reqFor(path, opts) });
}

beforeEach(async () => {
  resetStubs();
  op = await createMockOp({ issuer: ISSUER, clientId: "test-client", originHostname: ORIGIN_HOST });
  seedConfig({
    issuer: ISSUER,
    client_id: "test-client",
    redirect_uri: "https://www.example.com/.auth/callback",
    scopes: "openid profile email groups",
    session_ttl_seconds: "3600",
    groups_claim: "groups",
    routes: JSON.stringify({ callback: "/.auth/callback", logout: "/.auth/logout" }),
    backends: JSON.stringify({ origin: "origin", idp: "idp" }),
    origin_hostname: ORIGIN_HOST,
    forwarded_host: "www.example.com",
    push_invalidation: "enabled",
    policy: JSON.stringify(POLICY),
  });
  seedSecrets({ client_secret: "test-client-secret", session_hmac_key: HMAC_KEY });
  // Seed discovery/JWKS so any login/callback path avoids a live IdP fetch.
  seedDiscovery(ISSUER, op.discovery, op.jwks);
  // Route every outbound fetch (origin + IdP) to the mock OP.
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
});

afterEach(() => { globalThis.fetch = realFetch; });

describe("gate end-to-end", () => {
  it("P4 public path forwards without auth", async () => {
    const res = await run("/blog/post");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
  });

  it("P1 protected path with no session → 302 to IdP", async () => {
    const res = await run("/protected/x");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/authorize");
  });

  it("N14 secured path with no session → 401 JSON, no redirect", async () => {
    const res = await run("/api/orders");
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(res.headers.get("location")).toBeNull();
  });

  it("P5/P7 secured path with authorized session → forward", async () => {
    const cookie = await sessionCookieHeader(["site-readers"]);
    const res = await run("/api/orders", { headers: { cookie } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
  });

  it("P7 protected path with valid session → forward to origin", async () => {
    const cookie = await sessionCookieHeader(["site-readers"]);
    const res = await run("/protected/x", { headers: { cookie } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("N15 authenticated but wrong audience → JSON 403, no-store (edge has no error page)", async () => {
    const cookie = await sessionCookieHeader(["other-group"]);
    const res = await run("/protected/medical/x", {
      headers: { cookie, "sec-fetch-mode": "navigate" },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("N15b wrong-audience sub-resource fetch also gets JSON 403", async () => {
    const cookie = await sessionCookieHeader(["other-group"]);
    for (const path of ["/protected/medical/media_abc.jpg", "/protected/medical/footer"]) {
      const res = await run(path, { headers: { cookie, "sec-fetch-mode": "cors" } });
      expect(res.status, path).toBe(403);
      expect(res.headers.get("content-type"), path).toContain("application/json");
    }
  });

  it("N16 public assets load without auth even when user lacks role for protected page", async () => {
    const cookie = await sessionCookieHeader(["other-group"]);
    for (const path of ["/styles/main.css", "/scripts/app.js", "/blocks/header.js", "/icons/logo.svg"]) {
      const res = await run(path, { headers: { cookie } });
      expect(res.status, path).toBe(200);
    }
  });

  it("malformed session cookies fail closed without 500", async () => {
    const protectedRes = await run("/protected/x", { headers: { cookie: "__edge_session=%" } });
    expect(protectedRes.status).toBe(302);
    expect(protectedRes.status).toBeLessThan(500);

    const securedRes = await run("/api/orders", { headers: { cookie: "__edge_session=not-valid!!!" } });
    expect(securedRes.status).toBe(401);
    expect(securedRes.status).toBeLessThan(500);
  });

  it("full login round-trip: callback mints a session and 302s home", async () => {
    // Drive a protected request to get the login redirect + state cookie.
    const startRes = await run("/protected/x");
    const loginCookie = getSetCookie(startRes, "__edge_login");
    const authUrl = new URL(startRes.headers.get("location"));
    const state = authUrl.searchParams.get("state");
    // We need the nonce + verifier from the signed cookie; replay it through the
    // callback. Register a code whose challenge matches what startLogin sent.
    op.issueCode("code-1", { codeChallenge: authUrl.searchParams.get("code_challenge"), accessToken: "atk" });
    // The mock OP mints an id_token with the nonce we hand it; but startLogin's
    // nonce is sealed in the cookie. Read it back the way handleCallback does.
    const { readStateCookie } = await import("../src/session.js");
    const saved = await readStateCookie(
      reqFor("/.auth/callback", { cookie: `__edge_login=${loginCookie}` }),
      { sessionKey: HMAC_KEY });
    op.codes.get("code-1").claims = { nonce: saved.nonce };

    const cbRes = await run(`/.auth/callback?state=${state}&code=code-1`, {
      headers: { cookie: `__edge_login=${loginCookie}` },
    });
    expect(cbRes.status).toBe(302);
    expect(cbRes.headers.get("location")).toBe("/protected/x");
    expect(getSetCookie(cbRes, "__edge_session")).toBeTruthy();
  });
});
