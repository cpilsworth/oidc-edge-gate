// W0.1 characterization suite — STORE-BACKED configuration (provisioned env).
//
// Secondary to embedded-gate.test.js. Exercises the paths the embedded
// sandbox config cannot reach: values from ConfigStore/SecretStore, a KV
// cache (discovery caching + the single-use state marker), the `secured`
// tier, policy `default_headers`, and a reCAPTCHA rule on a PROTECTED route
// (which is what pins today's reCAPTCHA-before-auth ordering).
//
// Uses the in-memory fastly:* stubs (aliased in vitest.config.js) and drives
// only `handleRequest`.
import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { createEnv, run, setCookies, expectNoStore, SITEVERIFY_URL, LOGIN_COOKIE } from "./harness.js";
import { resetStubs, seedConfig, seedSecrets } from "../stubs/state.js";

const ISSUER = "https://op.test";
const CLIENT_ID = "test-client";
const ORIGIN = "main--store--backed.aem.live";
const UPSTREAM = "api.upstream.test";
const JSON_CT = "application/json; charset=utf-8";
const FORM_CT = "application/x-www-form-urlencoded";

const POLICY = {
  rules: [
    { path: "/", tier: "public" },
    { path: "/errors/*", tier: "public" },
    { path: "/protected/*", tier: "protected" },
    { path: "/protected/medical/*", tier: "protected", audience: ["medical"] },
    { path: "/api/*", tier: "secured" },
    { path: "/ext/*", tier: "public", upstream: `https://${UPSTREAM}` },
    { path: "/members/form/*", tier: "protected", recaptcha: true },
  ],
  default_headers: { "x-origin-proof": "store-default-header" },
  default_tier: "protected",
};

function seedAll({ recaptcha = true } = {}) {
  seedConfig({
    issuer: ISSUER,
    client_id: CLIENT_ID,
    redirect_uri: "https://www.example.com/.auth/callback",
    scopes: "openid profile email",
    session_ttl_seconds: "3600",
    groups_claim: "groups",
    routes: JSON.stringify({ callback: "/.auth/callback", logout: "/.auth/logout" }),
    backends: JSON.stringify({ origin: "origin", idp: "idp" }),
    origin_hostname: ORIGIN,
    forwarded_host: "www.example.com",
    push_invalidation: "enabled",
    policy: JSON.stringify(POLICY),
  });
  seedSecrets({
    client_secret: "store-client-secret",
    session_hmac_key: "store-test-hmac-key-at-least-32-bytes!!",
    ...(recaptcha ? { recaptcha_secret: "store-recaptcha-secret" } : {}),
  });
}

let env;
let rec;

beforeAll(async () => {
  env = await createEnv({ issuer: ISSUER, clientId: CLIENT_ID, originHost: ORIGIN, groupsClaim: "groups", upstreamHosts: [UPSTREAM] });
  rec = env.rec;
});
beforeEach(() => { resetStubs(); seedAll(); env.install(); });
afterEach(() => env.uninstall());

describe("store-backed configuration", () => {
  it("store values take precedence over the embedded fallback (origin host, forwarded host)", async () => {
    await run("/");
    const [call] = rec.to(ORIGIN);
    expect(call.url).toBe(`https://${ORIGIN}/`);
    expect(call.headers.get("x-forwarded-host")).toBe("www.example.com");
  });

  it("secured tier, anonymous → 401 JSON unauthorized with WWW-Authenticate: Bearer, no redirect", async () => {
    const res = await run("/api/orders");
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toBe(JSON_CT);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
    expect(res.headers.get("location")).toBeNull();
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    expect(setCookies(res)).toEqual([]);
    expectNoStore(expect, res);
    expect(rec.calls).toHaveLength(0);
  });

  it("secured tier with a valid session → forwarded with identity headers", async () => {
    const cookie = await env.session(["site-readers"]);
    const res = await run("/api/orders", { cookie });
    expect(res.status).toBe(200);
    const [call] = rec.to(ORIGIN);
    expect(call.headers.get("x-auth-subject")).toBe("user-123");
    expect(call.headers.get("x-auth-groups")).toBe("site-readers");
  });

  it("policy default_headers go to the EDS origin and the /errors/403 fetch, but not to an upstream override", async () => {
    await run("/");
    expect(rec.to(ORIGIN)[0].headers.get("x-origin-proof")).toBe("store-default-header");

    rec.reset();
    const cookie = await env.session([]);
    const res = await run("/protected/medical/x", { cookie });
    expect(res.status).toBe(403);
    expect(rec.to(ORIGIN)[0].pathname).toBe("/errors/403");
    expect(rec.to(ORIGIN)[0].headers.get("x-origin-proof")).toBe("store-default-header");

    rec.reset();
    await run("/ext/thing");
    const [up] = rec.to(UPSTREAM);
    expect(up.headers.get("x-origin-proof")).toBeNull();
  });

  it("KV present: discovery is fetched once then served from the KV cache", async () => {
    await run("/protected/a");
    await run("/protected/b");
    const disc = rec.calls.filter((c) => c.url === `${ISSUER}/.well-known/openid-configuration`);
    expect(disc).toHaveLength(1);
  });

  it("KV present: replaying a consumed callback is rejected by the gate's single-use state marker → 400", async () => {
    const { start, code, state, callback } = await env.login();
    expect(callback.status).toBe(302);
    rec.reset();
    const replay = await run(`/.auth/callback?code=${code}&state=${encodeURIComponent(state)}`, { cookie: start.loginCookie });
    expect(replay.status).toBe(400);
    // Rejected before any token exchange.
    expect(rec.calls.filter((c) => c.url === `${ISSUER}/token`)).toHaveLength(0);
  });

  it("recaptcha rule with no recaptcha_secret provisioned → POST fails closed with 500 internal_error", async () => {
    resetStubs();
    seedAll({ recaptcha: false });
    const cookie = await env.session([]);
    const res = await run("/members/form/x", { method: "POST", cookie, body: "g-recaptcha-response=t", headers: { "content-type": FORM_CT } });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "internal_error" });
    expect(rec.to(ORIGIN)).toHaveLength(0);
  });

  // Documents the CURRENT ordering: on a rule that is BOTH protected and
  // `recaptcha: true`, the reCAPTCHA check runs BEFORE any session handling.
  //   - an anonymous POST without a token gets 400 recaptcha_failed, not a
  //     302 to login;
  //   - an anonymous POST with a valid token costs a siteverify call and only
  //     THEN gets the 302 to login.
  // EXPECTED TO CHANGE deliberately (decision D6): forms stay public by
  // default, and on protected routes reCAPTCHA will run AFTER authentication.
  // When that lands, update this test on purpose — do not "fix" it silently.
  it("recaptcha-runs-before-auth", async () => {
    const noToken = await run("/members/form/x", { method: "POST", body: "name=Ada", headers: { "content-type": FORM_CT } });
    expect(noToken.status).toBe(400);
    expect(await noToken.json()).toEqual({ error: "recaptcha_failed" });
    expect(noToken.headers.get("location")).toBeNull();

    rec.reset();
    const withToken = await run("/members/form/x", { method: "POST", body: "g-recaptcha-response=t", headers: { "content-type": FORM_CT } });
    expect(withToken.status).toBe(302);
    expect(setCookies(withToken).map((c) => c.name)).toEqual([LOGIN_COOKIE]);
    const order = rec.calls.map((c) => (c.url === SITEVERIFY_URL ? "siteverify" : c.pathname));
    expect(order[0]).toBe("siteverify");
    expect(order).toContain("/.well-known/openid-configuration");
    expect(rec.to(ORIGIN)).toHaveLength(0);
  });

  it("protected recaptcha route with a session and a valid token → forwarded with identity AND x-recaptcha-* headers", async () => {
    const cookie = await env.session(["site-readers"]);
    const res = await run("/members/form/x", { method: "POST", cookie, body: "g-recaptcha-response=t&a=1", headers: { "content-type": FORM_CT } });
    expect(res.status).toBe(200);
    const [call] = rec.to(ORIGIN);
    expect(call.bodyText).toBe("g-recaptcha-response=t&a=1");
    expect(call.headers.get("x-auth-subject")).toBe("user-123");
    expect(call.headers.get("x-recaptcha-score")).toBe("0.9");
    expect(call.headers.get("cookie")).toBeNull();
  });

  it("protected recaptcha route with a session but no token → 400 recaptcha_failed (session does not exempt)", async () => {
    const cookie = await env.session(["site-readers"]);
    const res = await run("/members/form/x", { method: "POST", cookie, body: "a=1", headers: { "content-type": FORM_CT } });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "recaptcha_failed" });
  });
});
