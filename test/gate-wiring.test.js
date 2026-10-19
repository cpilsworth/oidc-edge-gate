// src/index.js composition root (W1.3): config loader → registry → policy
// compiler → pipeline. Behaviour of the gate itself is pinned by
// test/characterization/**; this file covers the wiring: the `routes` config
// key reaching the oidc-auth plugin, fail-closed loads that are never cached,
// v2 policies, and once-per-instance warning logs.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createMockOp } from "./mock-op.js";
import { reqFor } from "./helpers.js";

const ISSUER = "https://op.test";
const ORIGIN = "main--wiring--test.aem.live";
const HMAC_KEY = "wiring-test-hmac-key-at-least-32-bytes!!";
const POLICY = { rules: [{ path: "/", tier: "public" }, { path: "/api/*", tier: "secured" }], default_tier: "protected" };

const realFetch = globalThis.fetch;
let op;
let handleRequest;
let withAuthRouteOptions;
let errors;
let warns;
let resetStubs;
let seedConfig;
let seedSecrets;

function seed(overrides = {}, secrets = { client_secret: "s", session_hmac_key: HMAC_KEY }) {
  seedConfig({
    issuer: ISSUER,
    client_id: "test-client",
    redirect_uri: "https://www.example.com/.auth/callback",
    origin_hostname: ORIGIN,
    forwarded_host: "www.example.com",
    push_invalidation: "enabled",
    policy: JSON.stringify(POLICY),
    ...overrides,
  });
  seedSecrets(secrets);
}

const run = (path, opts) => handleRequest({ request: reqFor(path, opts) });

beforeEach(async () => {
  // A fresh src/index.js instance (memo + once-per-instance logs) per test. The
  // stub state module is re-imported too, so seeding reaches the same instance
  // the fresh fastly:* stubs read from.
  vi.resetModules();
  ({ handleRequest, withAuthRouteOptions } = await import("../src/index.js"));
  ({ resetStubs, seedConfig, seedSecrets } = await import("./stubs/state.js"));
  resetStubs();
  op = await createMockOp({ issuer: ISSUER, originHostname: ORIGIN });
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
  errors = vi.spyOn(console, "error").mockImplementation(() => {});
  warns = vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => { globalThis.fetch = realFetch; vi.restoreAllMocks(); });

describe("routes config key → oidc-auth route options", () => {
  it("default routes: /.auth/logout is the plugin's route (GET → 405)", async () => {
    seed();
    const res = await run("/.auth/logout");
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
  });

  it("custom routes move the plugin's routes; the old paths fall to the policy", async () => {
    seed({ routes: JSON.stringify({ callback: "/.auth/cb", logout: "/.auth/bye" }) });
    expect((await run("/.auth/bye")).status).toBe(405);
    const old = await run("/.auth/logout");
    expect(old.status).toBe(302); // default tier protected → login
    const local = await handleRequest({ request: new Request("http://localhost:7676/some/page") });
    expect(new URL(local.headers.get("location")).searchParams.get("redirect_uri")).toBe("http://localhost:7676/.auth/cb");
  });

  it("options set in the policy win over the routes config key", async () => {
    seed({
      routes: JSON.stringify({ callback: "/.auth/cb", logout: "/.auth/bye" }),
      policy: JSON.stringify({ ...POLICY, plugins: { "oidc-auth": { logout_path: "/.auth/signout" } } }),
    });
    expect((await run("/.auth/signout")).status).toBe(405);
    expect((await run("/.auth/bye")).status).toBe(302);
  });

  it("a route path outside /.auth/ fails the load closed: 500 internal_error with a request id", async () => {
    seed({ routes: JSON.stringify({ callback: "/login", logout: "/.auth/logout" }) });
    const res = await run("/");
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "internal_error" });
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
  });

  it("withAuthRouteOptions only injects for oidc-auth (explicit, or the legacy default)", () => {
    const routes = { callback: "/.auth/cb", logout: "/.auth/bye" };
    expect(withAuthRouteOptions({ rules: [] }, routes).plugins["oidc-auth"]).toEqual({ callback_path: "/.auth/cb", logout_path: "/.auth/bye" });
    expect(withAuthRouteOptions({ version: 2, authentication: { use: "oidc-auth" } }, routes).plugins["oidc-auth"].callback_path).toBe("/.auth/cb");
    const v2NoAuth = { version: 2, default_tier: "public" };
    expect(withAuthRouteOptions(v2NoAuth, routes)).toBe(v2NoAuth);
    const other = { authentication: { use: "something-else" } };
    expect(withAuthRouteOptions(other, routes)).toBe(other);
    const raw = { rules: [] };
    withAuthRouteOptions(raw, routes);
    expect(raw).toEqual({ rules: [] }); // not mutated
  });
});

describe("load failures are fail-closed and never cached", () => {
  it("a missing secret → 500, and the next request after provisioning it succeeds", async () => {
    seed({}, { session_hmac_key: HMAC_KEY });
    const bad = await run("/");
    expect(bad.status).toBe(500);
    expect(await bad.json()).toEqual({ error: "internal_error" });
    expect(errors).toHaveBeenCalled();
    expect(errors.mock.calls.flat().join(" ")).not.toContain(HMAC_KEY);

    seedSecrets({ client_secret: "now-present" });
    expect((await run("/")).status).toBe(200);
  });

  it("an invalid policy → 500; fixing it recovers without a restart", async () => {
    seed({ policy: JSON.stringify({ rules: [{ path: "/x", tier: "nope" }] }) });
    expect((await run("/")).status).toBe(500);
    seed({ policy: JSON.stringify(POLICY) });
    expect((await run("/")).status).toBe(200);
  });

  it("a declared platform_profile that does not match → 500", async () => {
    seed({ platform_profile: "sandbox" });
    expect((await run("/")).status).toBe(500);
  });
});

describe("policy compile memo and warnings", () => {
  it("compile warnings (legacy upgrade) are logged once per instance, not per request", async () => {
    seed();
    await run("/");
    await run("/");
    await run("/api/x");
    const legacyWarnings = warns.mock.calls.filter((c) => String(c[0]).includes("legacy policy"));
    expect(legacyWarnings).toHaveLength(1);
  });

  it("a changed policy is recompiled (memo keyed by its inputs)", async () => {
    seed();
    expect((await run("/api/x")).status).toBe(401);
    seed({ policy: JSON.stringify({ ...POLICY, rules: [...POLICY.rules, { path: "/api/open", tier: "public" }] }) });
    expect((await run("/api/open")).status).toBe(200);
  });
});

describe("v2 policies", () => {
  it("explicit authentication + recaptcha middleware with min_score options", async () => {
    seed({
      policy: JSON.stringify({
        version: 2,
        default_tier: "protected",
        authentication: { use: "oidc-auth" },
        rules: [
          { path: "/", tier: "public" },
          { path: "/form/*", tier: "public", middleware: [{ use: "recaptcha", options: { min_score: 0.8 } }] },
        ],
      }),
    }, { client_secret: "s", session_hmac_key: HMAC_KEY, recaptcha_secret: "r" });
    globalThis.fetch = async (input, init) => {
      const r = new Request(input, init);
      if (new URL(r.url).hostname === "www.google.com") return Response.json({ success: true, score: 0.7 });
      return op.handle(r);
    };
    const post = (body) => run("/form/x", { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded" } });
    const res = await post("g-recaptcha-response=t");
    expect(res.status).toBe(400); // 0.7 < the rule's 0.8 (the gate default 0.5 would pass)
    expect(await res.json()).toEqual({ error: "recaptcha_failed" });
    expect((await run("/form/x")).status).toBe(200); // GET is not checked (plugin default when)
    expect((await run("/somewhere")).status).toBe(302);
  });

  it("an all-public v2 policy without an authenticator runs (no oidc-auth routes active)", async () => {
    seed({ policy: JSON.stringify({ version: 2, default_tier: "public", rules: [] }) });
    expect((await run("/anything")).status).toBe(200);
    // /.auth/logout is not claimed by anyone, so it is just a public path here.
    expect((await run("/.auth/logout")).status).toBe(200);
  });
});
