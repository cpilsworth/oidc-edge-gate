// The Janrain configuration end to end (W2.3, docs/architecture/plugins.md
// §14.4): src/index.js → kernel pipeline → oidc-auth (provider "janrain") +
// user-info, against W2.2's Janrain-mode mock OP and mock user-info backend,
// routed by origin with routeFetch alongside a stub EDS origin.
//
// Every scenario runs under BOTH platform profiles:
//   provisioned  the in-memory Config/Secret/KV stubs, seeded per test;
//   sandbox      every store constructor throws; config and secrets come from
//                a mocked src/embedded-config.js holding this file's fake values.
// No real secret is read: the embedded config module is replaced wholesale.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

const env = vi.hoisted(() => ({ sandbox: false, kvUnbound: false }));
const embedded = vi.hoisted(() => ({ configs: {}, secrets: {} }));

const unprovisioned = (kind, name) => new Error(`No ${kind} named '${name}' exists`);
vi.mock("fastly:config-store", async () => {
  const real = await vi.importActual("./stubs/config-store.js");
  return {
    ConfigStore: class extends real.ConfigStore {
      constructor(name) { if (env.sandbox) throw unprovisioned("ConfigStore", name); super(name); }
    },
  };
});
vi.mock("fastly:secret-store", async () => {
  const real = await vi.importActual("./stubs/secret-store.js");
  return {
    SecretStore: class extends real.SecretStore {
      constructor(name) { if (env.sandbox) throw unprovisioned("SecretStore", name); super(name); }
    },
  };
});
vi.mock("fastly:kv-store", async () => {
  const real = await vi.importActual("./stubs/kv-store.js");
  return {
    KVStore: class extends real.KVStore {
      constructor(name) { if (env.sandbox || env.kvUnbound) throw unprovisioned("KVStore", name); super(name); }
    },
  };
});
vi.mock("../src/embedded-config.js", () => ({ EMBEDDED_CONFIGS: embedded.configs, EMBEDDED_SECRETS: embedded.secrets }));

import { handleRequest } from "../src/index.js";
import { createMockOp } from "./mock-op.js";
import { createMockUserInfo, routeFetch } from "./mock-user-info.js";
import { reqFor } from "./helpers.js";
import { getKvMap, resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const SITE = "https://www.example.com";
const ORIGIN = "main--janrain--gate.aem.live";
const CLIENT_ID = "janrain-gate-client";
const CLIENT_SECRET = "janrain-gate-FAKE-client-secret";
const HMAC_KEY = "janrain-gate-FAKE-hmac-key-at-least-32-bytes!!";
const NEXT_HMAC_KEY = "janrain-gate-FAKE-next-hmac-key-at-least-32-bytes";
const SVC_USER = "svc-janrain-gate";
const SVC_PASS = "svc-FAKE-password-do-not-log";
const SESSION_TTL = 3600;
const MEDICAL_SUB = "3c388dd9-0000-4000-8000-000000000001";
const OTHER_SUB = "3c388dd9-0000-4000-8000-000000000002";
const SESSION = "__Host-edge_session";
const LOGIN = "__Host-edge_login";
const realFetch = globalThis.fetch;

let profile;
let op;
let ui;
let fetchFn;
let jwksLag; // when set, the next JWKS fetch serves this (stale) document once
let logLines;

const run = (path, opts) => handleRequest({ request: reqFor(path, opts) });
const cookieLine = (res, name) => res.headers.getSetCookie().find((l) => l.startsWith(`${name}=`)) || null;
const cookiePair = (res, name) => { const l = cookieLine(res, name); return l ? l.split(";")[0] : null; };
const maxAge = (line) => { const m = /;\s*Max-Age=(\d+)/i.exec(line || ""); return m ? Number(m[1]) : null; };
/** The session cookie's payload JSON (base64url of the part before the "."); signature not checked. */
const payloadOf = (pair) => JSON.parse(Buffer.from(decodeURIComponent(pair.split("=")[1]).split(".")[0], "base64url").toString("utf8"));

function policy(userInfo = {}) {
  return {
    version: 2,
    default_tier: "protected",
    authentication: { use: "oidc-auth", options: { provider: "janrain" } },
    plugins: userInfo === null ? {} : {
      "user-info": {
        endpoint: ui.endpoint,
        profile_endpoint: ui.profileEndpoint,
        groups_path: "data.groups",
        profile_fields: ["given_name", "department"],
        ...userInfo,
      },
    },
    rules: [
      { path: "/", tier: "public" },
      { path: "/errors/*", tier: "public" },
      ...(userInfo === null ? [] : [{ path: "/api/me", tier: "secured", handler: "user-info" }]),
      { path: "/protected/medical/*", tier: "protected", audience: ["medical"] },
    ],
  };
}

/** Configure the gate for the current profile (stores, or the mocked embedded config). */
function configure({ userInfo = {}, secrets = {} } = {}) {
  const config = {
    issuer: op.issuer,
    client_id: CLIENT_ID,
    redirect_uri: `${SITE}/.auth/callback`,
    scopes: "openid email profile",
    session_ttl_seconds: String(SESSION_TTL),
    // Names the ID token's groups claim on purpose: with groupsSource
    // "user-info" it must still be ignored.
    groups_claim: "groups",
    routes: JSON.stringify({ callback: "/.auth/callback", logout: "/.auth/logout" }),
    origin_hostname: ORIGIN,
    forwarded_host: "www.example.com",
    platform_profile: profile,
    policy: JSON.stringify(policy(userInfo)),
  };
  const secretValues = {
    client_secret: CLIENT_SECRET, session_hmac_key: HMAC_KEY,
    user_info_username: SVC_USER, user_info_password: SVC_PASS, ...secrets,
  };
  for (const k of Object.keys(secretValues)) if (secretValues[k] === undefined) delete secretValues[k];
  if (profile === "sandbox") {
    for (const bag of [embedded.configs, embedded.secrets]) for (const k of Object.keys(bag)) delete bag[k];
    Object.assign(embedded.configs, config);
    Object.assign(embedded.secrets, secretValues);
  } else {
    resetStubs();
    seedConfig(config);
    seedSecrets({ secrets: JSON.stringify(secretValues) });
  }
}

async function setup({ opts = {}, users } = {}) {
  op = await createMockOp({
    mode: "janrain", clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, originHostname: ORIGIN, groupsInIdToken: true, ...opts,
  });
  ui = createMockUserInfo({
    origin: "https://userinfo.test", username: SVC_USER, password: SVC_PASS, groupsPath: "data.groups",
    users: users ?? {
      [MEDICAL_SUB]: { groups: ["medical"], profile: { given_name: "Uma", department: "Cardiology", ssn: "123-45-6789" } },
      [OTHER_SUB]: { groups: ["market-access"], profile: { given_name: "Otto", department: "Access" } },
    },
  });
  const opRoute = async (r) => {
    if (jwksLag && new URL(r.url).href === op.discovery.jwks_uri) {
      const doc = jwksLag;
      jwksLag = null;
      return Response.json(doc);
    }
    return op.handle(r);
  };
  const origin = async () => new Response("origin-body", { status: 200, headers: { "content-type": "text/html" } });
  fetchFn = routeFetch({ [new URL(op.issuer).origin]: opRoute, [ui.origin]: ui, [ORIGIN]: origin });
  globalThis.fetch = fetchFn;
  configure();
}

/** The browser's whole login: gate → /authorize (mock OP) → gate callback. */
async function login({ path = "/protected/medical/", sub = MEDICAL_SUB } = {}) {
  op.setUser({ ...op.user, sub });
  const start = await run(path);
  expect(start.status).toBe(302);
  const authorize = new URL(start.headers.get("location"));
  const loginCookie = cookiePair(start, LOGIN);
  const idp = await op.handle(new Request(authorize)); // the browser leg; not a gate fetch
  expect(idp.status).toBe(302);
  const back = new URL(idp.headers.get("location"));
  expect(back.origin).toBe(SITE);
  const before = fetchFn.calls.length;
  const callback = await run(back.pathname + back.search, { cookie: loginCookie });
  return { start, authorize, callback, session: cookiePair(callback, SESSION), callbackFetches: fetchFn.calls.slice(before) };
}

beforeEach(() => {
  env.kvUnbound = false;
  jwksLag = null;
  resetStubs();
  logLines = [];
  const capture = (...args) => { logLines.push(args.map(String).join(" ")); };
  vi.spyOn(console, "log").mockImplementation(capture);
  vi.spyOn(console, "warn").mockImplementation(capture);
  vi.spyOn(console, "error").mockImplementation(capture);
});
afterEach(() => { globalThis.fetch = realFetch; env.sandbox = false; vi.restoreAllMocks(); });

for (const p of ["provisioned", "sandbox"]) {
  describe(`Janrain + user-info end to end [${p}]`, () => {
    beforeEach(async () => {
      profile = p;
      env.sandbox = p === "sandbox";
      await setup();
    });

    it("1. the authorize redirect carries response_mode=query, S256 PKCE and the claims parameter", async () => {
      const { authorize } = await login();
      expect(`${authorize.origin}${authorize.pathname}`).toBe(op.discovery.authorization_endpoint);
      const q = authorize.searchParams;
      expect(q.get("response_type")).toBe("code");
      expect(q.get("response_mode")).toBe("query");
      expect(q.get("code_challenge_method")).toBe("S256");
      expect(q.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(JSON.parse(q.get("claims")).id_token).toMatchObject({ email: null, email_verified: null, name: null });
      expect(q.has("client_secret")).toBe(false);
      expect(op.lastAuthorize()).toMatchObject({ error: null, response_mode: "query", code_challenge_method: "S256" });
    });

    it("2. the token request uses client_secret_basic, with no client_secret in the body", async () => {
      const { callback } = await login();
      expect(callback.status).toBe(302);
      expect(op.lastToken()).toMatchObject({
        authMethod: "client_secret_basic", clientId: CLIENT_ID, hasClientSecretInBody: false,
        hasAuthorizationHeader: true, hasCodeVerifier: true, status: 200,
      });
      expect(op.lastToken().body.client_id).toBe(CLIENT_ID);
    });

    it("3. the ID token's groups are ignored; the session groups are the user-info groups", async () => {
      const { callback, session } = await login();
      expect(callback.status).toBe(302);
      expect(callback.headers.get("location")).toBe("/protected/medical/");
      expect(op.user.groups).toEqual(["site-readers"]); // in the ID token (groupsInIdToken: true)
      expect(payloadOf(session).groups).toEqual(["medical"]);
      const page = await run("/protected/medical/", { cookie: session });
      expect(page.status).toBe(200);
      expect(ui.requests.map((r) => [r.kind, r.authValid, r.sub])).toEqual([["groups", true, MEDICAL_SUB]]);
    });

    it("4. the audience page: 200 for a user with medical, 403 for a user without", async () => {
      const medical = await login();
      expect((await run("/protected/medical/", { cookie: medical.session })).status).toBe(200);
      expect((await run("/protected/medical", { cookie: medical.session })).status).toBe(200); // bare section path
      const other = await login({ sub: OTHER_SUB });
      expect(payloadOf(other.session).groups).toEqual(["market-access"]);
      expect((await run("/protected/medical/", { cookie: other.session })).status).toBe(403);
      expect((await run("/protected/other", { cookie: other.session })).status).toBe(200); // still logged in
    });

    it("5. /api/me returns the allowlisted profile; anonymous → 401", async () => {
      const { session } = await login();
      const me = await run("/api/me", { cookie: session });
      expect(me.status).toBe(200);
      expect(await me.json()).toEqual({
        sub: MEDICAL_SUB, email: "u@example.com", name: null, groups: ["medical"],
        profile: { given_name: "Uma", department: "Cardiology" },
      });
      const anon = await run("/api/me");
      expect(anon.status).toBe(401);
      expect(await anon.json()).toEqual({ error: "unauthorized" });
    });

    it("6a. a user-info outage at login → 503, no session", async () => {
      ui.fail("status-500");
      const { callback } = await login();
      expect(callback.status).toBe(503);
      expect(callback.headers.get("content-type")).toBe("text/plain; charset=utf-8");
      expect(await callback.text()).toMatch(/^503 — authentication error \(request-id: /);
      expect(cookieLine(callback, SESSION)).toBeNull();
      ui.fail("network-error");
      const again = await login();
      expect(again.callback.status).toBe(503);
      expect(cookieLine(again.callback, SESSION)).toBeNull();
    });

    it("6b. on_login_error degrade → a short session with no groups", async () => {
      configure({ userInfo: { on_login_error: "degrade", degrade_ttl_seconds: 120 } });
      ui.fail("status-500");
      const { callback, session } = await login();
      expect(callback.status).toBe(302);
      const payload = payloadOf(session);
      expect(payload.groups).toEqual([]);
      expect(payload.exp - payload.iat).toBe(120);
      expect(maxAge(cookieLine(callback, SESSION))).toBe(120);
      expect((await run("/protected/other", { cookie: session })).status).toBe(200);
      expect((await run("/protected/medical/", { cookie: session })).status).toBe(403);
    });

    it("7. POST logout → 303 to end_session with client_id, post_logout_redirect_uri and a random state; cookies cleared. GET → 405", async () => {
      const { session } = await login();
      const states = [];
      for (let i = 0; i < 2; i++) {
        const res = await run("/.auth/logout", { method: "POST", cookie: session, headers: { origin: SITE } });
        expect(res.status).toBe(303);
        const to = new URL(res.headers.get("location"));
        expect(`${to.origin}${to.pathname}`).toBe(op.discovery.end_session_endpoint);
        expect(to.searchParams.get("client_id")).toBe(CLIENT_ID);
        expect(to.searchParams.get("post_logout_redirect_uri")).toBe(`${SITE}/`);
        expect(to.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{22,}$/);
        states.push(to.searchParams.get("state"));
        for (const name of [SESSION, LOGIN]) expect(maxAge(cookieLine(res, name))).toBe(0);
        // The mock OP's end_session accepts it and sends the browser back.
        const idp = await op.handle(new Request(to));
        expect(idp.status).toBe(302);
        expect(op.lastEndSession()).toMatchObject({ status: 302, client_id: CLIENT_ID });
      }
      expect(states[0]).not.toBe(states[1]);
      const get = await run("/.auth/logout", { cookie: session });
      expect(get.status).toBe(405);
      expect(get.headers.get("allow")).toBe("POST");
      expect(cookieLine(get, SESSION)).toBeNull();
    });

    it("8. the session cookie is v2 (v, typ, kid, sid) and carries no profile data", async () => {
      const { session, callback } = await login();
      expect(cookieLine(callback, SESSION)).toMatch(/; HttpOnly/i);
      const payload = payloadOf(session);
      expect(payload).toMatchObject({ v: 2, typ: "session", sub: MEDICAL_SUB, email: "u@example.com" });
      expect(payload.kid).toMatch(/^[A-Za-z0-9_-]{8}$/);
      expect(payload.sid).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(Object.keys(payload)).toEqual(["v", "typ", "kid", "sid", "sub", "email", "groups", "iat", "exp"]);
      const text = JSON.stringify(payload);
      for (const needle of ["Uma", "Cardiology", "123-45-6789", "given_name", "department", "family_name"]) expect(text).not.toContain(needle);
      // Every login gets a fresh sid.
      const second = await login();
      expect(payloadOf(second.session).sid).not.toBe(payload.sid);
    });

    it("9. signing-key rotation via session_hmac_key_previous keeps an existing session valid", async () => {
      const { session } = await login();
      configure({ secrets: { session_hmac_key: NEXT_HMAC_KEY, session_hmac_key_previous: HMAC_KEY } });
      expect((await run("/protected/medical/", { cookie: session })).status).toBe(200);
      // A new login is signed with the new key (a different kid).
      const fresh = await login();
      expect(payloadOf(fresh.session).kid).not.toBe(payloadOf(session).kid);
      // Once the previous key is removed, the old session no longer verifies.
      configure({ secrets: { session_hmac_key: NEXT_HMAC_KEY } });
      const stale = await run("/protected/medical/", { cookie: session });
      expect(stale.status).toBe(302);
      expect(stale.headers.get("location")).toMatch(/^https:\/\/v1\.api\.us\.janrain\.com\//);
      expect((await run("/protected/medical/", { cookie: fresh.session })).status).toBe(200);
    });

    it("10. a JWKS key rotation at the IdP still allows login", async () => {
      expect((await login()).callback.status).toBe(302); // warms the JWKS cache where there is KV
      const oldKid = op.key.kid;
      await op.rotateKey({ keepOld: false });
      expect(op.key.kid).not.toBe(oldKid);
      const { callback, session } = await login();
      expect(callback.status).toBe(302);
      expect((await run("/protected/medical/", { cookie: session })).status).toBe(200);
    });

    if (p === "provisioned") {
      it("11. no KV on a provisioned platform → the callback answers 503 kv_unavailable", async () => {
        env.kvUnbound = true;
        const { start, callback } = await login();
        expect(start.status).toBe(302); // login start still works
        expect(callback.status).toBe(503);
        expect(await callback.json()).toEqual({ error: "kv_unavailable" });
        expect(cookieLine(callback, SESSION)).toBeNull();
        expect(op.requests.token).toEqual([]);
        expect(ui.requests).toEqual([]);
      });
    } else {
      it("11. sandbox: the login works without KV", async () => {
        const { callback, session } = await login();
        expect(callback.status).toBe(302);
        expect((await run("/protected/medical/", { cookie: session })).status).toBe(200);
        expect(getKvMap("kv_default").size).toBe(0);
      });
    }

    it("13. user-info not enabled: the login still works with no groups, audience pages 403, and a reason code is logged", async () => {
      configure({ userInfo: null });
      const { callback, session } = await login();
      expect(callback.status).toBe(302);
      expect(payloadOf(session).groups).toEqual([]); // the ID token's groups are still ignored
      expect((await run("/protected/medical/", { cookie: session })).status).toBe(403);
      expect((await run("/protected/other", { cookie: session })).status).toBe(200);
      expect(ui.requests).toEqual([]);
      expect(logLines.some((l) => l.includes("no_groups_from_user_info"))).toBe(true);
    });

    it("14. logs never carry credentials, tokens or profile data", async () => {
      const { session } = await login();
      await run("/api/me", { cookie: session });
      ui.fail("status-500");
      await login();
      const text = logLines.join("\n");
      expect(text.length).toBeGreaterThan(0);
      for (const needle of [SVC_PASS, CLIENT_SECRET, HMAC_KEY, btoa(`${SVC_USER}:${SVC_PASS}`), "123-45-6789", "Cardiology", decodeURIComponent(session.split("=")[1])]) {
        expect(text.includes(needle), "a log line leaks a secret or profile value").toBe(false);
      }
    });

    it("12. fetch budget: the callback makes at most 5 backend fetches", async () => {
      // Cold caches (sandbox has no KV at all): discovery, token, jwks, user-info.
      resetStubs();
      configure();
      const cold = await login();
      expect(cold.callback.status).toBe(302);
      const kinds = (calls) => calls.map((c) => {
        const u = new URL(c.url);
        if (u.origin === ui.origin) return "user-info";
        if (u.href === op.discovery.jwks_uri) return "jwks";
        if (u.href === op.discovery.token_endpoint) return "token";
        if (u.pathname.endsWith("/.well-known/openid-configuration")) return "discovery";
        return u.host;
      });
      // Provisioned: the login start already cached discovery in KV.
      const discovery = p === "sandbox" ? ["discovery"] : [];
      expect(kinds(cold.callbackFetches)).toEqual([...discovery, "token", "jwks", "user-info"]);

      // Worst case: a kid miss on a stale JWKS forces one refetch.
      resetStubs();
      configure();
      const stale = op.jwks;
      await op.rotateKey({ keepOld: false });
      jwksLag = stale;
      const worst = await login();
      expect(worst.callback.status).toBe(302);
      expect(kinds(worst.callbackFetches)).toEqual([...discovery, "token", "jwks", "jwks", "user-info"]);
      expect(worst.callbackFetches.length).toBeLessThanOrEqual(5);
      expect(worst.callbackFetches.every((c) => c.routed)).toBe(true);
    });
  });
}
