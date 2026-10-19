// user-info through the real kernel (src/index.js → pipeline) on a
// provisioned (store-backed) platform, with the default mock OP and an inline
// fake user-info backend:
//   - groups from the backend at login grant an audience page;
//   - /api/me (handler "user-info", secured) returns the allowlisted profile,
//     anonymous → 401; the profile is cached in KV;
//   - expose "headers" forwards sanitized x-user-* headers to the EDS origin,
//     and inbound x-user-* headers are stripped;
//   - a backend failure at login: "fail" → no session; "degrade" → a session
//     without groups, lifetime capped.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { handleRequest } from "../src/index.js";
import { createMockOp } from "./mock-op.js";
import { createMockUserInfo } from "./mock-user-info.js";
import { reqFor } from "./helpers.js";
import { getKvMap, resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const ISSUER = "https://op.test";
const ORIGIN = "main--userinfo--plugin.aem.live";
const HMAC_KEY = "user-info-gate-test-hmac-key-at-least-32-bytes!!";
const SVC_USER = "svc-user-info";
const SVC_PASS = "svc-PASSWORD-do-not-log";
const BASIC = `Basic ${btoa(`${SVC_USER}:${SVC_PASS}`)}`;
const SUB = "auth0|u/1?x#y";
const SESSION_TTL = 3600;
const realFetch = globalThis.fetch;

let op;
let backendSeen;
let originSeen;
let upstreamSeen;
let backendRespond;
let logLines;

const run = (path, opts) => handleRequest({ request: reqFor(path, opts) });
const cookieLine = (res, name) => res.headers.getSetCookie().find((l) => l.startsWith(`${name}=`)) || null;
const cookiePair = (res, name) => { const l = cookieLine(res, name); return l ? l.split(";")[0] : null; };
const maxAge = (line) => { const m = /;\s*Max-Age=(\d+)/i.exec(line || ""); return m ? Number(m[1]) : null; };

function seed(userInfoOptions = {}, { rules = [], middleware } = {}) {
  seedConfig({
    issuer: ISSUER,
    client_id: "test-client",
    redirect_uri: "https://www.example.com/.auth/callback",
    origin_hostname: ORIGIN,
    forwarded_host: "www.example.com",
    groups_claim: "groups",
    session_ttl_seconds: String(SESSION_TTL),
    policy: JSON.stringify({
      version: 2,
      default_tier: "protected",
      authentication: { use: "oidc-auth" },
      plugins: {
        "user-info": {
          endpoint: "https://users.test/v1/users/{sub}",
          groups_path: "data.groups",
          profile_fields: ["given_name", "department"],
          expose: "headers",
          ...userInfoOptions,
        },
      },
      ...(middleware ? { middleware } : {}),
      rules: [
        { path: "/", tier: "public" },
        { path: "/api/me", tier: "secured", handler: "user-info" },
        { path: "/protected/medical/*", tier: "protected", audience: ["medical"], middleware: [{ use: "user-info" }] },
        ...rules,
      ],
    }),
  });
}

beforeEach(async () => {
  resetStubs();
  op = await createMockOp({ issuer: ISSUER, originHostname: ORIGIN });
  seed();
  // Provisioned secrets come from the JSON bundle (the per-key fallback only
  // knows the gate's own keys; see the W4.1 report).
  seedSecrets({
    secrets: JSON.stringify({ client_secret: "s", session_hmac_key: HMAC_KEY, user_info_username: SVC_USER, user_info_password: SVC_PASS }),
  });
  backendSeen = [];
  originSeen = [];
  upstreamSeen = [];
  backendRespond = () => Response.json({
    data: { groups: ["medical", "a,admin"] },
    given_name: "Ann\r\nX-Injected: 1", department: "Cardiología", ssn: "123-45-6789",
  });
  globalThis.fetch = async (input, init) => {
    const r = new Request(input, init);
    const u = new URL(r.url);
    if (u.host === "users.test") {
      backendSeen.push({ path: u.pathname, authorization: r.headers.get("authorization"), cacheOverride: init && init.cacheOverride });
      return backendRespond(r);
    }
    if (u.host === "partner.test") {
      upstreamSeen.push({ path: u.pathname, headers: Object.fromEntries(r.headers) });
      return new Response("partner-body", { status: 200 });
    }
    if (u.host === ORIGIN) {
      originSeen.push({ path: u.pathname, headers: Object.fromEntries(r.headers) });
      return new Response("origin-body", { status: 200, headers: { "content-type": "text/html" } });
    }
    return op.handle(r);
  };
  logLines = [];
  const capture = (line, ...rest) => { logLines.push([line, ...rest].map(String).join(" ")); };
  vi.spyOn(console, "log").mockImplementation(capture);
  vi.spyOn(console, "warn").mockImplementation(capture);
  vi.spyOn(console, "error").mockImplementation(capture);
});
afterEach(() => { globalThis.fetch = realFetch; vi.restoreAllMocks(); });

async function login(path = "/protected/medical/") {
  const res = await run(path);
  expect(res.status).toBe(302);
  const params = new URL(res.headers.get("location")).searchParams;
  const loginCookie = cookiePair(res, "__Host-edge_login");
  op.issueCode("code-1", { claims: { nonce: params.get("nonce"), sub: SUB }, codeChallenge: params.get("code_challenge") });
  return run(`/.auth/callback?code=code-1&state=${encodeURIComponent(params.get("state"))}`, { cookie: loginCookie });
}

function expectCleanLogs() {
  const text = logLines.join("\n");
  for (const needle of [SVC_PASS, BASIC, btoa(`${SVC_USER}:${SVC_PASS}`), "123-45-6789", encodeURIComponent(SUB)]) {
    expect(text, `logs leak ${needle}`).not.toContain(needle);
  }
}

describe("user-info end to end (provisioned)", () => {
  it("login: onLogin adds the backend's groups; the session grants the audience page; x-user-* reach the origin", async () => {
    const cb = await login();
    expect(cb.status).toBe(302);
    const session = cookiePair(cb, "__Host-edge_session");
    expect(session).toBeTruthy();
    // The backend was called once, with the encoded sub and Basic credentials, cache "pass".
    expect(backendSeen).toHaveLength(1);
    expect(backendSeen[0].path).toBe(`/v1/users/${encodeURIComponent(SUB)}`);
    expect(backendSeen[0].authorization).toBe(BASIC);
    expect(backendSeen[0].cacheOverride.mode).toBe("pass");

    // Spoofed inbound x-user-* headers never reach the origin.
    const page = await run("/protected/medical/", { cookie: session, headers: { "x-user-given-name": "Mallory", "x-user-ssn": "1", x_user_department: "spoof" } });
    expect(page.status).toBe(200);
    expect(await page.text()).toBe("origin-body");
    const fwd = originSeen.at(-1).headers;
    expect(fwd["x-auth-subject"]).toBe(SUB);
    expect(fwd["x-auth-groups"].split(",")).toEqual(["site-readers", "medical"]); // "a,admin" dropped
    expect(fwd["x-user-given-name"]).toBe("AnnX-Injected: 1");
    expect(fwd["x-user-department"]).toBe("Cardiolog%C3%ADa");
    expect(Object.keys(fwd).filter((h) => h.startsWith("x-user") || h.startsWith("x_user")).sort()).toEqual(["x-user-department", "x-user-given-name"]);
    expect(fwd["x-injected"]).toBeUndefined();
    // Same endpoint for groups and profile: the login warmed the KV cache, so no second backend call.
    expect(backendSeen).toHaveLength(1);
    expect([...getKvMap("kv_default").keys()].filter((k) => k.startsWith("plugin:user-info:profile:"))).toHaveLength(1);
    expectCleanLogs();
  });

  it("/api/me returns the identity and the allowlisted profile; anonymous → 401", async () => {
    const session = cookiePair(await login(), "__Host-edge_session");
    const me = await run("/api/me", { cookie: session });
    expect(me.status).toBe(200);
    expect(me.headers.get("cache-control")).toBe("private, no-store");
    expect(await me.json()).toEqual({
      sub: SUB, email: "u@example.com", name: null, groups: ["site-readers", "medical"],
      profile: { given_name: "Ann\r\nX-Injected: 1", department: "Cardiología" },
    });
    expect(originSeen.filter((o) => o.path === "/api/me")).toEqual([]); // handled by the plugin, never forwarded

    const anon = await run("/api/me");
    expect(anon.status).toBe(401);
    expect(await anon.json()).toEqual({ error: "unauthorized" });
    expectCleanLogs();
  });

  it("profile cache: a miss fetches once and stores in KV; the next request is a hit", async () => {
    const session = cookiePair(await login(), "__Host-edge_session");
    const kv = getKvMap("kv_default");
    for (const k of [...kv.keys()]) if (k.startsWith("plugin:user-info:")) kv.delete(k);
    backendSeen.length = 0;
    expect((await run("/api/me", { cookie: session })).status).toBe(200);
    expect(backendSeen).toHaveLength(1);
    expect((await run("/api/me", { cookie: session })).status).toBe(200);
    expect(backendSeen).toHaveLength(1);
  });

  it("a profile backend failure (cache empty) → 503 user_info_unavailable", async () => {
    const session = cookiePair(await login(), "__Host-edge_session");
    const kv = getKvMap("kv_default");
    for (const k of [...kv.keys()]) if (k.startsWith("plugin:user-info:")) kv.delete(k);
    backendRespond = () => new Response("down", { status: 502 });
    const me = await run("/api/me", { cookie: session });
    expect(me.status).toBe(503);
    expect(await me.json()).toEqual({ error: "user_info_unavailable" });
    const page = await run("/protected/medical/", { cookie: session });
    expect(page.status).toBe(503);
    expect(originSeen.filter((o) => o.path === "/protected/medical/")).toEqual([]);
    expectCleanLogs();
  });

  it("W2.R R13: logout deletes the subject's cached profile from KV", async () => {
    const session = cookiePair(await login(), "__Host-edge_session");
    const kv = getKvMap("kv_default");
    const profileKeys = () => [...kv.keys()].filter((k) => k.startsWith("plugin:user-info:profile:"));
    expect(profileKeys()).toHaveLength(1);
    const res = await run("/.auth/logout", { method: "POST", cookie: session, headers: { origin: "https://www.example.com" } });
    expect(res.status).toBe(303);
    expect(profileKeys()).toEqual([]);
  });

  it("groups without the audience → 403 on the audience page", async () => {
    backendRespond = () => Response.json({ data: { groups: ["market-access"] } });
    const session = cookiePair(await login(), "__Host-edge_session");
    expect(session).toBeTruthy();
    const page = await run("/protected/medical/", { cookie: session });
    expect(page.status).toBe(403);
  });
});

describe("backend failure at login", () => {
  for (const [label, respond] of [
    ["HTTP 500", () => new Response("boom", { status: 500 })],
    ["network error", () => { throw new TypeError("fetch failed"); }],
    ["bad JSON", () => new Response("<html>", { status: 200 })],
    ["groups path missing", () => Response.json({ groups: ["medical"] })],
  ]) {
    it(`on_login_error "fail" (${label}) → no session (W2.3 maps this to 503)`, async () => {
      backendRespond = respond;
      const cb = await login();
      expect(cb.status).not.toBe(302);
      expect(cb.status).toBeGreaterThanOrEqual(500);
      expect(cookieLine(cb, "__Host-edge_session")).toBeNull();
      expectCleanLogs();
    });
  }

  it("W2.R R14: the 503 auth error page clears the login-state cookie (no session)", async () => {
    backendRespond = () => new Response("boom", { status: 500 });
    const cb = await login();
    expect(cb.status).toBe(503);
    expect(cb.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(cookieLine(cb, "__Host-edge_session")).toBeNull();
    const cleared = cookieLine(cb, "__Host-edge_login");
    expect(cleared).toMatch(/^__Host-edge_login=;/);
    expect(maxAge(cleared)).toBe(0);
  });

  it("on_login_error \"degrade\" → a session without the backend's groups (audience page 403)", async () => {
    resetStubs();
    seed({ on_login_error: "degrade", degrade_ttl_seconds: 120 });
    seedSecrets({
      secrets: JSON.stringify({ client_secret: "s", session_hmac_key: HMAC_KEY, user_info_username: SVC_USER, user_info_password: SVC_PASS }),
    });
    backendRespond = () => new Response("boom", { status: 500 });
    const cb = await login();
    expect(cb.status).toBe(302);
    const session = cookiePair(cb, "__Host-edge_session");
    expect(session).toBeTruthy();
    expect((await run("/protected/x", { cookie: session })).status).toBe(200); // still logged in
    backendRespond = () => Response.json({ given_name: "Ann", department: "R&D" });
    expect((await run("/protected/medical/", { cookie: session })).status).toBe(403); // no "medical" group
    expect(logLines.some((l) => l.includes("degraded session"))).toBe(true);
    expectCleanLogs();
  });

  it("on_login_error \"degrade\" → the session cookie's Max-Age reflects degrade_ttl_seconds", async () => {
    resetStubs();
    seed({ on_login_error: "degrade", degrade_ttl_seconds: 120 });
    seedSecrets({
      secrets: JSON.stringify({ client_secret: "s", session_hmac_key: HMAC_KEY, user_info_username: SVC_USER, user_info_password: SVC_PASS }),
    });
    backendRespond = () => new Response("boom", { status: 500 });
    const cb = await login();
    expect(cb.status).toBe(302);
    const age = maxAge(cookieLine(cb, "__Host-edge_session"));
    expect(age).not.toBeNull();
    // identity.expiresAt carries the cap (draft.limitLifetime); session v2
    // derives both exp and Max-Age from it.
    expect(age).toBeGreaterThan(0);
    expect(age).toBeLessThanOrEqual(120);
    expect(age).toBeLessThan(SESSION_TTL);
  });
});

describe("with W2.2's mock user-info backend (separate profile endpoint)", () => {
  let ui;
  const useMock = (userInfoOptions = {}) => {
    ui = createMockUserInfo({
      origin: "https://userinfo.test", username: SVC_USER, password: SVC_PASS, groupsPath: "data.groups",
      users: { [SUB]: { groups: ["medical"], profile: { given_name: "Ann", department: "R&D", ssn: "123-45-6789" } } },
    });
    resetStubs();
    seed({ endpoint: ui.endpoint, profile_endpoint: ui.profileEndpoint, ...userInfoOptions });
    seedSecrets({
      secrets: JSON.stringify({ client_secret: "s", session_hmac_key: HMAC_KEY, user_info_username: SVC_USER, user_info_password: SVC_PASS }),
    });
    backendRespond = null;
    const inner = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const target = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (new URL(target).origin === ui.origin) return ui.handle(new Request(input, init));
      return inner(input, init);
    };
  };

  it("groups at login, then the profile from profile_endpoint (authenticated, never the ssn)", async () => {
    useMock();
    const session = cookiePair(await login(), "__Host-edge_session");
    expect(session).toBeTruthy();
    expect(ui.requests.map((r) => [r.kind, r.authValid, r.sub])).toEqual([["groups", true, SUB]]);
    const page = await run("/protected/medical/", { cookie: session });
    expect(page.status).toBe(200);
    expect(originSeen.at(-1).headers["x-user-given-name"]).toBe("Ann");
    expect(ui.requests.map((r) => r.kind)).toEqual(["groups", "profile"]);
    const me = await (await run("/api/me", { cookie: session })).json();
    expect(me.groups).toEqual(["site-readers", "medical"]);
    expect(me.profile).toEqual({ given_name: "Ann", department: "R&D" });
    expect(ui.requests).toHaveLength(2); // the profile was cached in KV
    expectCleanLogs();
  });

  for (const mode of ["status-500", "malformed-json", "missing-groups", "groups-not-array", "network-error"]) {
    it(`failure mode ${mode} with "fail" → no session`, async () => {
      useMock();
      ui.fail(mode);
      const cb = await login();
      expect(ui.requests).toHaveLength(1); // the backend was reached and answered with the failure
      expect(ui.requests[0].failure).toBe(mode);
      expect(cb.status).not.toBe(302);
      expect(cookieLine(cb, "__Host-edge_session")).toBeNull();
    });
  }

  for (const mode of ["groups-non-string", "groups-comma"]) {
    it(`failure mode ${mode} → normalized groups, no unsafe value in the session`, async () => {
      useMock();
      ui.fail(mode);
      const session = cookiePair(await login(), "__Host-edge_session");
      expect(session).toBeTruthy();
      const me = await (await run("/api/me", { cookie: session })).json();
      expect(me.groups).toEqual(mode === "groups-comma" ? ["site-readers", "readers"] : ["site-readers", "medical"]);
    });
  }
});

const reseed = (userInfoOptions, extra) => {
  resetStubs();
  seed(userInfoOptions, extra);
  seedSecrets({
    secrets: JSON.stringify({ client_secret: "s", session_hmac_key: HMAC_KEY, user_info_username: SVC_USER, user_info_password: SVC_PASS }),
  });
};
const xUser = (headers) => Object.keys(headers).filter((h) => h.startsWith("x-user-")).sort();

describe("W2.R R2: x-user-* (identityHeaders) and third-party upstreams", () => {
  const partnerRules = [
    { path: "/partner/*", tier: "protected", upstream: "https://partner.test", middleware: [{ use: "user-info" }] },
    { path: "/partner-id/*", tier: "protected", upstream: "https://partner.test", forward_identity: true, middleware: [{ use: "user-info" }] },
  ];

  it("an upstream rule without forward_identity gets no x-user-* (and no x-auth-*)", async () => {
    reseed({}, { rules: partnerRules });
    const session = cookiePair(await login(), "__Host-edge_session");
    const res = await run("/partner/x", { cookie: session });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("partner-body");
    const fwd = upstreamSeen.at(-1).headers;
    expect(xUser(fwd)).toEqual([]);
    expect(fwd["x-auth-subject"]).toBeUndefined();
  });

  it("with forward_identity: true the upstream gets them, like x-auth-*", async () => {
    reseed({}, { rules: partnerRules });
    const session = cookiePair(await login(), "__Host-edge_session");
    expect((await run("/partner-id/x", { cookie: session })).status).toBe(200);
    const fwd = upstreamSeen.at(-1).headers;
    expect(xUser(fwd)).toEqual(["x-user-department", "x-user-given-name"]);
    expect(fwd["x-auth-subject"]).toBe(SUB);
  });

  it("the EDS origin always gets them", async () => {
    reseed({}, { rules: partnerRules });
    const session = cookiePair(await login(), "__Host-edge_session");
    expect((await run("/protected/medical/", { cookie: session })).status).toBe(200);
    expect(xUser(originSeen.at(-1).headers)).toEqual(["x-user-department", "x-user-given-name"]);
  });
});

describe("W2.R R5: a global ref and a rule ref with different profile options on one request", () => {
  it("each fetches once (two fetches at most), no 503; one KV key per sub", async () => {
    reseed({}, {
      middleware: [{ use: "user-info" }],
      rules: [{ path: "/protected/two/*", tier: "protected", middleware: [{ use: "user-info", options: { profile_fields: ["given_name"] } }] }],
    });
    const session = cookiePair(await login(), "__Host-edge_session");
    const kv = getKvMap("kv_default");
    for (const k of [...kv.keys()]) if (k.startsWith("plugin:user-info:")) kv.delete(k);
    backendSeen.length = 0;
    const res = await run("/protected/two/", { cookie: session });
    expect(res.status).toBe(200);
    expect(backendSeen.length).toBeGreaterThan(0);
    expect(backendSeen.length).toBeLessThanOrEqual(2);
    const fwd = originSeen.at(-1).headers;
    expect(xUser(fwd)).toEqual(["x-user-department", "x-user-given-name"]);
    expect([...kv.keys()].filter((k) => k.startsWith("plugin:user-info:profile:"))).toHaveLength(1);
    // The next request still fits the budget: a fingerprint mismatch is a miss that overwrites.
    backendSeen.length = 0;
    expect((await run("/protected/two/", { cookie: session })).status).toBe(200);
    expect(backendSeen.length).toBeLessThanOrEqual(2);
  });
});
