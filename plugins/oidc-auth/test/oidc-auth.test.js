// oidc-auth TEMPORARY adapter (W1.3): the plugin contract over the legacy
// src/oidc.js + src/session.js. Driven through src/sdk/testing.js; the legacy
// modules still call the global fetch, so it is pointed at the mock OP.
// W1.4 replaces the adapter and these tests.
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from "vitest";
import { isIdentity, createIdentity } from "../../../src/sdk/index.js";
import { createTestContext } from "../../../src/sdk/testing.js";
// W1.4 removes this: test-only imports of the shared mock OP and legacy session helpers.
import { createMockOp } from "../../../test/mock-op.js";
import { mintSessionCookie } from "../../../src/session.js";
import oidcAuth, { legacyKv, DEFAULT_CALLBACK_PATH, DEFAULT_LOGOUT_PATH } from "../index.js";

const ISSUER = "https://op.test";
const HMAC_KEY = "adapter-test-hmac-key-at-least-32-bytes!!";
const SECRETS = { client_secret: "test-client-secret", session_hmac_key: HMAC_KEY };
const CONFIG = {
  issuer: ISSUER,
  clientId: "test-client",
  redirectUri: "https://www.example.com/.auth/callback",
  scopes: "openid profile email",
  sessionTtlSeconds: 3600,
  routes: { callback: DEFAULT_CALLBACK_PATH, logout: DEFAULT_LOGOUT_PATH },
  originHostname: "main--x--y.aem.live",
  forwardedHost: "www.example.com",
  pushInvalidation: true,
  groupsClaim: "groups",
  recaptchaMinScore: 0.5,
};
const OPTIONS = oidcAuth.validate({});

const realFetch = globalThis.fetch;
let op;

beforeAll(async () => { op = await createMockOp({ issuer: ISSUER }); });
beforeEach(() => {
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => { globalThis.fetch = realFetch; vi.restoreAllMocks(); });

function ctxFor(url, { cookie, method = "GET", headers = {}, lifecycle, kv } = {}) {
  const h = new Headers(headers);
  if (cookie) h.set("cookie", cookie);
  return createTestContext({
    plugin: oidcAuth,
    request: new Request(url, { method, headers: h }),
    options: OPTIONS,
    config: CONFIG,
    secrets: SECRETS,
    lifecycle,
    kv,
  });
}

const cookiePair = (res, name) => {
  const line = res.headers.getSetCookie().find((l) => l.startsWith(`${name}=`));
  return line ? line.split(";")[0] : null;
};

async function sessionCookie(groups = ["g1"]) {
  const line = await mintSessionCookie({ sub: "user-123", email: "u@example.com", name: "U", groups }, { sessionKey: HMAC_KEY, sessionTtlSeconds: 3600, groupsClaim: "groups" });
  return line.split(";")[0];
}

/** Start a login and drive the callback through the plugin's own route. */
async function loginThroughRoute({ groups = ["g1"], lifecycle } = {}) {
  const start = await oidcAuth.challenge(ctxFor("https://www.example.com/protected/x?q=1"), OPTIONS, { interactive: true });
  const params = new URL(start.headers.get("location")).searchParams;
  const code = `code-${Math.random().toString(36).slice(2)}`;
  op.issueCode(code, { claims: { nonce: params.get("nonce"), groups }, codeChallenge: params.get("code_challenge") });
  const routes = oidcAuth.routes(OPTIONS);
  const ctx = ctxFor(`https://www.example.com/.auth/callback?code=${code}&state=${encodeURIComponent(params.get("state"))}`, {
    cookie: cookiePair(start, "__Host-edge_login"), lifecycle,
  });
  const res = await routes[DEFAULT_CALLBACK_PATH](ctx, OPTIONS);
  return { res, ctx };
}

describe("oidc-auth manifest", () => {
  it("is an authenticator that owns the gate cookies and reads its two secrets", () => {
    expect(oidcAuth.kind).toBe("authenticator");
    expect(oidcAuth.cookies).toEqual(["__Host-edge_session", "__Host-edge_login"]);
    expect(oidcAuth.secrets).toEqual(["client_secret", "session_hmac_key"]);
  });

  it("validate: route paths default to /.auth/callback and /.auth/logout", () => {
    expect(oidcAuth.validate({})).toEqual({ callback_path: "/.auth/callback", logout_path: "/.auth/logout" });
    expect(oidcAuth.validate({ callback_path: "/.auth/cb", logout_path: "/.auth/bye" })).toEqual({ callback_path: "/.auth/cb", logout_path: "/.auth/bye" });
  });

  it("validate: rejects unknown options, paths outside /.auth/ and identical paths", () => {
    expect(() => oidcAuth.validate({ callback: "/.auth/x" })).toThrow(/unknown option/);
    expect(() => oidcAuth.validate({ callback_path: "/login" })).toThrow(/under \/\.auth\//);
    expect(() => oidcAuth.validate({ callback_path: "/.auth/x", logout_path: "/.auth/x" })).toThrow(/must differ/);
  });

  it("routes(options) claims exactly the configured callback and logout paths", () => {
    expect(Object.keys(oidcAuth.routes(OPTIONS)).sort()).toEqual(["/.auth/callback", "/.auth/logout"]);
    expect(Object.keys(oidcAuth.routes({ callback_path: "/.auth/cb", logout_path: "/.auth/bye" })).sort()).toEqual(["/.auth/bye", "/.auth/cb"]);
  });
});

describe("authenticate", () => {
  it("a valid session cookie yields a frozen SDK Identity (method oidc-session)", async () => {
    const identity = await oidcAuth.authenticate(ctxFor("https://www.example.com/protected/x", { cookie: await sessionCookie(["a", "b"]) }), OPTIONS);
    expect(isIdentity(identity)).toBe(true);
    expect(identity).toMatchObject({ sub: "user-123", email: "u@example.com", name: "U", groups: ["a", "b"], method: "oidc-session" });
    expect(identity.expiresAt - identity.issuedAt).toBe(3600);
  });

  it("no, garbage or tampered cookie → null (the kernel then challenges)", async () => {
    for (const cookie of [undefined, "__Host-edge_session=garbage", `${(await sessionCookie()).slice(0, -2)}xx`]) {
      expect(await oidcAuth.authenticate(ctxFor("https://www.example.com/protected/x", { cookie }), OPTIONS)).toBeNull();
    }
  });
});

describe("challenge", () => {
  it("interactive (protected): 302 to the IdP with the login-state cookie", async () => {
    const res = await oidcAuth.challenge(ctxFor("https://www.example.com/protected/x"), OPTIONS, { interactive: true });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toMatch(/^https:\/\/op\.test\/authorize\?/);
    expect(cookiePair(res, "__Host-edge_login")).toBeTruthy();
  });

  it("non-interactive (secured): null, so the kernel answers 401 Bearer", async () => {
    let called = false;
    globalThis.fetch = async () => { called = true; return new Response("{}"); };
    expect(await oidcAuth.challenge(ctxFor("https://www.example.com/api/x"), OPTIONS, { interactive: false })).toBeNull();
    expect(called).toBe(false);
  });
});

describe("callback route + login lifecycle", () => {
  it("emits login with the verified draft BEFORE minting; groups added by subscribers land in the session", async () => {
    const seen = [];
    const { res, ctx } = await loginThroughRoute({
      groups: ["idp-group"],
      lifecycle: {
        emitLogin: async (draft) => {
          seen.push({ sub: draft.sub, email: draft.email, groups: [...draft.groups], hasClaims: typeof draft.claims === "object" });
          draft.addGroups(["from-hook"]);
        },
      },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/protected/x?q=1");
    expect(ctx.recorded.lifecycle.map((e) => e.event)).toEqual(["login"]);
    expect(seen).toEqual([{ sub: "user-123", email: "u@example.com", groups: ["idp-group"], hasClaims: true }]);

    const session = cookiePair(res, "__Host-edge_session");
    const identity = await oidcAuth.authenticate(ctxFor("https://www.example.com/protected/x", { cookie: session }), OPTIONS);
    expect(identity.groups).toEqual(["idp-group", "from-hook"]);
  });

  it("without subscriber changes the session carries exactly the IdP groups", async () => {
    const { res } = await loginThroughRoute({ groups: ["x", "y"] });
    const identity = await oidcAuth.authenticate(ctxFor("https://www.example.com/", { cookie: cookiePair(res, "__Host-edge_session") }), OPTIONS);
    expect(identity.groups).toEqual(["x", "y"]);
  });

  it("a failing login subscriber aborts the login (fail closed): 500, no session minted", async () => {
    const { res } = await loginThroughRoute({ lifecycle: { emitLogin: async () => { throw new Error("user-info backend down"); } } });
    expect(res.status).toBe(500);
    expect(cookiePair(res, "__Host-edge_session")).toBeNull();
    expect(await res.text()).toMatch(/^500 — authentication error/);
  });
});

describe("logout route + logout lifecycle", () => {
  const SITE = "https://www.example.com";

  it("same-site POST: emits logout with the current identity, then 303 with both cookies cleared", async () => {
    const ctx = ctxFor(`${SITE}/.auth/logout`, { method: "POST", headers: { origin: SITE }, cookie: await sessionCookie(["g"]) });
    const res = await oidcAuth.routes(OPTIONS)[DEFAULT_LOGOUT_PATH](ctx, OPTIONS);
    expect(res.status).toBe(303);
    expect(res.headers.getSetCookie().map((l) => l.split("=")[0])).toEqual(["__Host-edge_session", "__Host-edge_login"]);
    expect(ctx.recorded.lifecycle).toHaveLength(1);
    const { event, value } = ctx.recorded.lifecycle[0];
    expect(event).toBe("logout");
    expect(isIdentity(value)).toBe(true);
    expect(value.sub).toBe("user-123");
  });

  it("anonymous same-site POST emits logout with null", async () => {
    const ctx = ctxFor(`${SITE}/.auth/logout`, { method: "POST", headers: { origin: SITE } });
    await oidcAuth.routes(OPTIONS)[DEFAULT_LOGOUT_PATH](ctx, OPTIONS);
    expect(ctx.recorded.lifecycle).toEqual([{ event: "logout", value: null }]);
  });

  it("GET → 405 and cross-site POST → 403, neither emits logout", async () => {
    const get = ctxFor(`${SITE}/.auth/logout`, { cookie: await sessionCookie() });
    expect((await oidcAuth.routes(OPTIONS)[DEFAULT_LOGOUT_PATH](get, OPTIONS)).status).toBe(405);
    const evil = ctxFor(`${SITE}/.auth/logout`, { method: "POST", headers: { origin: "https://evil.example" } });
    expect((await oidcAuth.routes(OPTIONS)[DEFAULT_LOGOUT_PATH](evil, OPTIONS)).status).toBe(403);
    expect([...get.recorded.lifecycle, ...evil.recorded.lifecycle]).toEqual([]);
  });

  it("a failing logout subscriber does not block the logout", async () => {
    const ctx = ctxFor(`${SITE}/.auth/logout`, { method: "POST", headers: { origin: SITE }, lifecycle: { emitLogout: async () => { throw new Error("boom"); } } });
    expect((await oidcAuth.routes(OPTIONS)[DEFAULT_LOGOUT_PATH](ctx, OPTIONS)).status).toBe(303);
  });
});

describe("KV bridge (ctx.kv strings → legacy {text()} entries)", () => {
  it("null stays null", () => {
    expect(legacyKv(null)).toBeNull();
  });

  it("get wraps strings, put forwards the ttl, delete passes through", async () => {
    const ctx = ctxFor("https://www.example.com/", { kv: { a: "1" } });
    const kv = legacyKv(ctx.kv);
    expect(await (await kv.get("a")).text()).toBe("1");
    expect(await kv.get("missing")).toBeNull();
    await kv.put("b", "2", { ttl: 600 });
    expect(ctx.recorded.kv.get("b")).toBe("2");
    await kv.delete("b");
    expect(ctx.recorded.kv.has("b")).toBe(false);
  });

  it("with KV present, discovery is cached through ctx.kv (one IdP fetch for two logins)", async () => {
    let discoveryFetches = 0;
    globalThis.fetch = (input, init) => {
      const r = new Request(input, init);
      if (new URL(r.url).pathname === "/.well-known/openid-configuration") discoveryFetches += 1;
      return op.handle(r);
    };
    const kv = new Map();
    for (let i = 0; i < 2; i += 1) {
      const ctx = createTestContext({ plugin: oidcAuth, request: new Request("https://www.example.com/p"), options: OPTIONS, config: CONFIG, secrets: SECRETS, kv });
      await oidcAuth.challenge(ctx, OPTIONS, { interactive: true });
      for (const [k, v] of ctx.recorded.kv) kv.set(k, v);
    }
    expect(discoveryFetches).toBe(1);
    expect([...kv.keys()]).toEqual([`oidc:discovery:${ISSUER}`]);
  });
});

it("sanity: createIdentity lookalikes are not identities (adapter returns minted ones only)", () => {
  expect(isIdentity({ sub: "x" })).toBe(false);
  expect(isIdentity(createIdentity({ sub: "x", method: "m", issuedAt: 1, expiresAt: 2 }))).toBe(true);
});
