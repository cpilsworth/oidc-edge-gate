// "Evil plugin" tests: one block per kernel invariant (docs/architecture/plugins.md §12).
// Built only on fake plugins (definePlugin) and fake deps (classify, CompiledPolicy).
import { describe, it, expect, vi } from "vitest";
import { definePlugin, createIdentity } from "../../src/sdk/index.js";
import { createRegistry, resolveRoutes } from "../../src/kernel/registry.js";
import { createPipeline } from "../../src/kernel/pipeline.js";

const noop = async () => {};
const mw = (name, extra = {}) => definePlugin({ name, kind: "middleware", phases: ["beforeForward"], beforeForward: noop, ...extra });
const ident = (sub = "u1", groups = []) => createIdentity({ sub, groups, method: "test", issuedAt: 1, expiresAt: 2 });

function sessAuth(extra = {}) {
  return definePlugin({
    name: "sess", kind: "authenticator", cookies: ["__Host-sess"],
    authenticate: async (ctx) => {
      const v = ctx.cookies.get("__Host-sess");
      return v ? ident(v, ["member"]) : null;
    },
    ...extra,
  });
}

const ref = (use, { options = Object.freeze({}), when = () => true, onError = "fail" } = {}) =>
  Object.freeze({ use, options, when, onError, source: "rule" });

const cls = (tier, extra = {}) => Object.freeze({
  rule: null, tier, auth: tier === "public" ? "none" : "required", audience: undefined, upstream: undefined,
  headers: undefined, secretHeaders: undefined, forwardIdentity: false, handler: "origin", middleware: [], ...extra,
});

function kernel({ plugins, authentication = { use: "sess", options: {} }, middleware = [], fallback = cls("protected"), forward, ...rest }) {
  const registry = createRegistry(plugins);
  const policy = {
    version: 2, defaultTier: "protected", authentication,
    enabled: new Map(plugins.map((p) => [p.name, {}])), middleware, rules: [], warnings: [],
  };
  const forwarded = [];
  const deps = {
    policy, registry,
    classify: () => ({ ...fallback, middleware: [...middleware, ...fallback.middleware] }),
    platform: { profile: "sandbox", has: () => false }, secret: () => undefined, kv: null, config: {},
    normalizePath: (p) => p,
    forward: forward || vi.fn(async (input) => { forwarded.push(input); return new Response("origin"); }),
    errorPage: vi.fn(async (status, input, body) => new Response(JSON.stringify(body), { status })),
    logSink: () => {},
    ...rest,
  };
  return { pipeline: createPipeline(deps), deps, forwarded };
}

const get = (path, headers = {}) => new Request(`https://gate.example${path}`, { headers });

describe("invariant 1: a non-public request is never forwarded or handled without an identity", () => {
  it("a middleware that returns nothing cannot let an anonymous request through", async () => {
    const lax = mw("lax", { phases: ["request"], beforeForward: undefined, request: async () => undefined });
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), lax], middleware: [ref("lax")] });
    const res = await pipeline.handle(get("/p"));
    expect(res.status).toBe(401);
    expect(deps.forward).not.toHaveBeenCalled();
  });

  // F18: the request phase runs before authentication.
  it.each(["protected", "secured"])("a request-phase plugin cannot serve a 2xx before authentication on a %s tier (500)", async (tier) => {
    const logs = [];
    const early = mw("early", { phases: ["request"], beforeForward: undefined, request: async () => new Response("members-only content", { status: 200 }) });
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), early], middleware: [ref("early")], fallback: cls(tier), logSink: (event, fields) => logs.push({ event, ...fields }) });
    const res = await pipeline.handle(get("/p"));
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "internal_error" });
    expect(deps.forward).not.toHaveBeenCalled();
    expect(logs.some((l) => /invariant violation: request-phase short-circuit/.test(l.event) && l.plugin === "early" && l.status === 200)).toBe(true);
  });

  it("a request-phase 3xx/4xx/5xx short-circuit on a protected tier is still allowed (e.g. rate limiting)", async () => {
    for (const status of [302, 429, 503]) {
      const early = mw("early", { phases: ["request"], beforeForward: undefined, request: async () => new Response(null, { status, headers: status === 302 ? { location: "/elsewhere" } : {} }) });
      const { pipeline, deps } = kernel({ plugins: [sessAuth(), early], middleware: [ref("early")], fallback: cls("protected") });
      expect((await pipeline.handle(get("/p"))).status).toBe(status);
      expect(deps.forward).not.toHaveBeenCalled();
    }
  });

  it("a request-phase 2xx short-circuit on a public tier is still allowed", async () => {
    const early = mw("early", { phases: ["request"], beforeForward: undefined, request: async () => new Response("ok", { status: 200 }) });
    const { pipeline } = kernel({ plugins: [sessAuth(), early], middleware: [ref("early")], fallback: cls("public") });
    expect((await pipeline.handle(get("/p"))).status).toBe(200);
  });

  it("a classification claiming tier protected with auth none is a 500, never a forward", async () => {
    const h = mw("hand", { handle: vi.fn(async () => new Response("handled")) });
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), h], fallback: cls("protected", { auth: "none", handler: "hand" }) });
    const res = await pipeline.handle(get("/p"));
    expect(res.status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
    expect(h.handle).not.toHaveBeenCalled();
  });

  it("a plugin rule handler on a secured rule is never invoked anonymously", async () => {
    const handle = vi.fn(async () => new Response("secret"));
    const h = mw("hand", { handle });
    const { pipeline } = kernel({ plugins: [sessAuth(), h], fallback: cls("secured", { handler: "hand" }) });
    expect((await pipeline.handle(get("/api"))).status).toBe(401);
    expect(handle).not.toHaveBeenCalled();
  });

  it("a plugin cannot redirect the forward to a different (unclassified) path via replaceRequest", async () => {
    const swap = mw("swap", {
      phases: ["request"], beforeForward: undefined,
      request: async (ctx) => { ctx.replaceRequest(new Request("https://gate.example/protected/secret")); },
    });
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), swap], middleware: [ref("swap")], fallback: cls("public") });
    const res = await pipeline.handle(get("/public"));
    expect(res.status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
  });
});

describe("invariant 2: only authenticators produce identities, only as frozen createIdentity() values", () => {
  it("a middleware returning an object shaped like an identity has no effect", async () => {
    const forger = mw("forger", {
      phases: ["request", "beforeForward"],
      request: async () => ident("admin", ["admin"]),
      beforeForward: async () => ({ sub: "admin", groups: ["admin"] }),
    });
    const { pipeline, deps, forwarded } = kernel({ plugins: [sessAuth(), forger], middleware: [ref("forger")] });
    expect((await pipeline.handle(get("/p"))).status).toBe(401);
    expect(deps.forward).not.toHaveBeenCalled();
    await pipeline.handle(get("/p", { cookie: "__Host-sess=u1" }));
    expect(forwarded[0].identity.sub).toBe("u1");
  });

  it("an authenticator returning a non-frozen plain object gives 500", async () => {
    const a = sessAuth({ authenticate: async () => ({ sub: "admin", groups: ["admin"], method: "x", issuedAt: 1, expiresAt: 2, attrs: {} }) });
    const { pipeline, deps } = kernel({ plugins: [a] });
    const res = await pipeline.handle(get("/p"));
    expect(res.status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("an authenticator returning a shallow-frozen object with mutable groups gives 500 (even on an optional rule)", async () => {
    const a = sessAuth({ authenticate: async () => Object.freeze({ sub: "a", groups: ["admin"], method: "x", issuedAt: 1, expiresAt: 2, attrs: Object.freeze({}) }) });
    const { pipeline, deps } = kernel({ plugins: [a], fallback: cls("public", { auth: "optional" }) });
    expect((await pipeline.handle(get("/x"))).status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("hooks cannot replace or mutate the identity", async () => {
    const tamper = mw("tamper", {
      beforeForward: async (ctx) => {
        try { ctx.identity.groups.push("admin"); } catch { /* frozen */ }
        try { ctx.identity.sub = "admin"; } catch { /* frozen */ }
        try { ctx.identity = ident("admin"); } catch { /* read-only */ }
      },
    });
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth(), tamper], middleware: [ref("tamper")], fallback: cls("protected", { audience: ["member"] }) });
    await pipeline.handle(get("/p", { cookie: "__Host-sess=u1" }));
    expect(forwarded[0].identity).toMatchObject({ sub: "u1", groups: ["member"] });
  });
});

describe("invariant 3: only the kernel writes x-auth-*; reserved prefixes stripped; plugins write only their own prefixes", () => {
  it("a plugin setting x-auth-subject via forwardHeaders is rejected (500, nothing forwarded)", async () => {
    const evil = mw("evil", { trustedHeaderPrefixes: ["x-evil-"], beforeForward: async (ctx) => ctx.forwardHeaders.set("x-auth-subject", "admin") });
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), evil], middleware: [ref("evil")], fallback: cls("public") });
    expect((await pipeline.handle(get("/x"))).status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("a plugin writing another plugin's header prefix is rejected", async () => {
    const victim = mw("victim", { trustedHeaderPrefixes: ["x-victim-"] });
    const evil = mw("evil", { trustedHeaderPrefixes: ["x-evil-"], beforeForward: async (ctx) => ctx.forwardHeaders.set("x-victim-score", "1") });
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), victim, evil], middleware: [ref("evil")], fallback: cls("public") });
    expect((await pipeline.handle(get("/x"))).status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("client-supplied reserved headers are stripped before plugins and forward see the request, even for inactive plugins", async () => {
    const seen = [];
    const peek = mw("peek", { phases: ["request"], beforeForward: undefined, request: async (ctx) => { seen.push([...ctx.request.headers.keys()]); } });
    const inactive = mw("inactive", { trustedHeaderPrefixes: ["x-inactive-"] });
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth(), peek, inactive], middleware: [ref("peek")], fallback: cls("public") });
    await pipeline.handle(get("/x", { "x-auth-subject": "admin", "X-Auth-Groups": "admin", "x-inactive-ok": "1", "x-other": "kept" }));
    expect(seen[0]).toEqual(["x-other"]);
    expect([...forwarded[0].request.headers.keys()]).toEqual(["x-other"]);
  });

  it("F10: client-supplied underscore lookalikes (x_auth_groups) are stripped before plugins and forward", async () => {
    const seen = [];
    const peek = mw("peek", { phases: ["request"], beforeForward: undefined, request: async (ctx) => { seen.push([...ctx.request.headers.keys()]); } });
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth(), peek], middleware: [ref("peek")], fallback: cls("public") });
    await pipeline.handle(get("/x", { x_auth_groups: "admin", "X_Auth_Subject": "admin", x_push_invalidation: "enabled", "x-push-invalidation": "enabled", "x-other": "kept" }));
    expect(seen[0]).toEqual(["x-other"]);
    expect([...forwarded[0].request.headers.keys()]).toEqual(["x-other"]);
  });

  it("a plugin cannot smuggle x-auth-* in through replaceRequest", async () => {
    const smuggle = mw("smuggle", {
      phases: ["request"], beforeForward: undefined,
      request: async (ctx) => ctx.replaceRequest(new Request(ctx.request.url, { headers: { "x-auth-subject": "admin" } })),
    });
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth(), smuggle], middleware: [ref("smuggle")], fallback: cls("public") });
    await pipeline.handle(get("/x"));
    expect(forwarded[0].request.headers.has("x-auth-subject")).toBe(false);
  });

  it("a plugin cannot set x-auth-* on the response via responseHeaders", async () => {
    const evil = mw("evil", { beforeForward: async (ctx) => { ctx.responseHeaders.set("x-auth-subject", "admin"); } });
    const { pipeline } = kernel({ plugins: [sessAuth(), evil], middleware: [ref("evil")], fallback: cls("public") });
    expect((await pipeline.handle(get("/x"))).headers.has("x-auth-subject")).toBe(false);
  });
});

describe("invariant 4: plugin cookies never reach/come from the origin; only the declaring plugin writes them", () => {
  it("a plugin writing another plugin's cookie is rejected", async () => {
    const evil = mw("evil", { cookies: ["mine"], beforeForward: async (ctx) => ctx.cookies.set("__Host-sess", "admin") });
    const { pipeline } = kernel({ plugins: [sessAuth(), evil], middleware: [ref("evil")], fallback: cls("public") });
    const res = await pipeline.handle(get("/x"));
    expect(res.status).toBe(500);
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  it("a plugin reading another plugin's cookie is rejected", async () => {
    const evil = mw("evil", { beforeForward: async (ctx) => { ctx.cookies.get("__Host-sess"); } });
    const { pipeline } = kernel({ plugins: [sessAuth(), evil], middleware: [ref("evil")], fallback: cls("public") });
    expect((await pipeline.handle(get("/x", { cookie: "__Host-sess=u1" }))).status).toBe(500);
  });

  it("the origin setting a gate cookie is stripped", async () => {
    const forward = async () => {
      const h = new Headers();
      h.append("set-cookie", "__Host-sess=forged; Path=/");
      h.append("set-cookie", "site=1; Path=/");
      return new Response("origin", { headers: h });
    };
    const { pipeline } = kernel({ plugins: [sessAuth()], fallback: cls("public"), forward });
    expect((await pipeline.handle(get("/x"))).headers.getSetCookie()).toEqual(["site=1; Path=/"]);
  });

  it("a short-circuit response cannot set another plugin's cookie via a raw Set-Cookie", async () => {
    const evil = mw("evil", { beforeForward: async () => new Response("x", { headers: { "set-cookie": "__Host-sess=admin; Path=/" } }) });
    const { pipeline } = kernel({ plugins: [sessAuth(), evil], middleware: [ref("evil")], fallback: cls("public") });
    expect((await pipeline.handle(get("/x"))).headers.getSetCookie()).toEqual([]);
  });

  // F11: plugins read cookies only via ctx.cookies; the raw header is never visible.
  it("an evil plugin cannot read another plugin's cookie from the raw Cookie header (ctx.request or forward)", async () => {
    const stolen = [];
    const evil = mw("evil", {
      phases: ["request", "beforeForward"],
      request: async (ctx) => { stolen.push(ctx.request.headers.get("cookie")); },
      beforeForward: async (ctx) => {
        stolen.push(ctx.request.headers.get("cookie"));
        // and it cannot put one back via replaceRequest
        ctx.replaceRequest(new Request(ctx.request.url, { headers: { cookie: "__Host-sess=forged" } }));
      },
    });
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth(), evil], middleware: [ref("evil")], fallback: cls("protected") });
    const res = await pipeline.handle(get("/x", { cookie: "__Host-sess=u1; other=1" }));
    expect(res.status).toBe(200); // the authenticator still read its cookie via ctx.cookies
    expect(stolen).toEqual([null, null]);
    expect(forwarded[0].identity.sub).toBe("u1");
    expect(forwarded[0].request.headers.has("cookie")).toBe(false);
  });

  it("ForwardInput lists owned cookies so forward drops them", async () => {
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth(), mw("other", { cookies: ["o"] })], fallback: cls("public") });
    await pipeline.handle(get("/x"));
    expect(forwarded[0].ownedCookies).toEqual(["__Host-sess", "o"]);
  });
});

describe("invariant 5: /.auth/* routes only for enabled declaring plugins; collisions fail loading", () => {
  it("two plugins claiming /.auth/x is an error", () => {
    const a = mw("alpha", { routes: { "/.auth/x": async () => new Response("a") } });
    const b = mw("beta", { routes: (o) => ({ "/.auth/x": async () => new Response("b") }) });
    expect(() => resolveRoutes(createRegistry([a, b]), new Map([["alpha", {}], ["beta", {}]]))).toThrow(/already claimed/);
    expect(() => kernel({ plugins: [a, b], authentication: null })).toThrow(/already claimed/);
  });

  it("a routes(options) function cannot claim a path outside /.auth/", () => {
    const evil = mw("evil", { routes: () => ({ "/protected/secret": async () => new Response("x") }) });
    expect(() => kernel({ plugins: [evil], authentication: null })).toThrow(/\/\.auth\//);
  });

  it("a disabled plugin's route is not served", async () => {
    const route = vi.fn(async () => new Response("hijack"));
    const a = mw("alpha", { routes: { "/.auth/x": route } });
    const registry = createRegistry([sessAuth(), a]);
    const policy = { authentication: { use: "sess", options: {} }, enabled: new Map([["sess", {}]]), middleware: [] };
    const pipeline = createPipeline({
      policy, registry, classify: () => cls("protected"), normalizePath: (p) => p,
      forward: async () => new Response("origin"), errorPage: async () => new Response("", { status: 403 }), logSink: () => {},
    });
    expect((await pipeline.handle(get("/.auth/x"))).status).toBe(401);
    expect(route).not.toHaveBeenCalled();
  });
});

describe("invariant 6: anything needing an identity has exactly one authenticator", () => {
  it("a required-auth rule with a null authenticator config is a 500, never forwarded", async () => {
    const { pipeline, deps } = kernel({ plugins: [sessAuth()], authentication: null });
    const res = await pipeline.handle(get("/p", { cookie: "__Host-sess=u1" }));
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "internal_error" });
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("an optional-auth rule with no authenticator is a 500", async () => {
    const { pipeline, deps } = kernel({ plugins: [sessAuth()], authentication: null, fallback: cls("public", { auth: "optional" }) });
    expect((await pipeline.handle(get("/x"))).status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("a middleware configured as the authenticator is a 500", async () => {
    const fake = mw("fake");
    const { pipeline, deps } = kernel({ plugins: [fake], authentication: { use: "fake", options: {} } });
    expect((await pipeline.handle(get("/p"))).status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("an unregistered authenticator is a 500", async () => {
    const { pipeline, deps } = kernel({ plugins: [sessAuth()], authentication: { use: "ghost", options: {} } });
    expect((await pipeline.handle(get("/p"))).status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
  });
});

describe("invariant 7: the finalizer and the fetch budget apply to every response and every fetch", () => {
  const fetchImpl = async () => new Response("ok");

  it("a plugin exceeding maxFetches gives 503, even with on_error: skip", async () => {
    const greedy = mw("greedy", {
      egress: ["https://api.example.com"], maxFetches: 1, allowSkipOnError: true,
      beforeForward: async (ctx) => { await ctx.fetch("https://api.example.com/1"); await ctx.fetch("https://api.example.com/2"); },
    });
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), greedy], middleware: [ref("greedy", { onError: "skip" })], fallback: cls("public"), fetchImpl });
    const res = await pipeline.handle(get("/x"));
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "budget_exceeded" });
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("a plugin that catches and swallows the budget error still gets 503", async () => {
    const sneaky = mw("sneaky", {
      egress: ["https://api.example.com"], maxFetches: 1,
      beforeForward: async (ctx) => {
        for (let i = 0; i < 5; i++) { try { await ctx.fetch("https://api.example.com/x"); } catch { /* swallow */ } }
      },
    });
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), sneaky], middleware: [ref("sneaky")], fallback: cls("public"), fetchImpl });
    expect((await pipeline.handle(get("/x"))).status).toBe(503);
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("an egress violation gives 500 egress_denied, even with on_error: skip and a swallowed throw", async () => {
    const leaky = mw("leaky", {
      egress: ["https://api.example.com"], maxFetches: 2, allowSkipOnError: true,
      beforeForward: async (ctx) => { try { await ctx.fetch("https://attacker.example/steal"); } catch { /* swallow */ } },
    });
    const spy = vi.fn(fetchImpl);
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), leaky], middleware: [ref("leaky", { onError: "skip" })], fallback: cls("public"), fetchImpl: spy });
    const res = await pipeline.handle(get("/x"));
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "egress_denied" });
    expect(spy).not.toHaveBeenCalled();
    expect(deps.forward).not.toHaveBeenCalled();
  });

  // F6: egress is checked on the canonical Request that is actually fetched.
  it("an evil plugin cannot bypass egress with an object whose url is allowed but whose toString() is not", async () => {
    const trick = { url: "https://api.example.com/ok", toString: () => "https://attacker.example/steal" };
    const evil = mw("evil", { egress: ["https://api.example.com"], maxFetches: 1, beforeForward: async (ctx) => { await ctx.fetch(trick); } });
    const spy = vi.fn(fetchImpl);
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), evil], middleware: [ref("evil")], fallback: cls("public"), fetchImpl: spy });
    const res = await pipeline.handle(get("/x"));
    // Denied, or (never) fetched anything but the allowed origin.
    for (const [input] of spy.mock.calls) expect(new URL(typeof input === "string" ? input : input.url).origin).toBe("https://api.example.com");
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "egress_denied" });
    expect(spy).not.toHaveBeenCalled();
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("the global budget is shared by plugins and the kernel's forward", async () => {
    const user = mw("user", { egress: ["https://api.example.com"], maxFetches: 2, beforeForward: async (ctx) => { await ctx.fetch("https://api.example.com/a"); } });
    const forward = async (input) => input.fetch("https://origin.example/p");
    const { pipeline } = kernel({ plugins: [sessAuth(), user], middleware: [ref("user")], fallback: cls("public"), fetchImpl, forward, fetchBudget: 1 });
    const res = await pipeline.handle(get("/x"));
    expect(res.status).toBe(503);
  });

  it("an onLogin subscriber fetch is budgeted too", async () => {
    const { createIdentityDraft } = await import("../../src/sdk/index.js");
    const a = definePlugin({
      name: "sess", kind: "authenticator", authenticate: async () => null,
      routes: { "/.auth/cb": async (ctx) => { await ctx.lifecycle.emitLogin(createIdentityDraft({ sub: "u" })); return new Response("ok"); } },
    });
    const sub = mw("sub", { onLogin: async (ctx) => { await ctx.fetch("https://api.example.com/"); } }); // maxFetches 0, no egress
    const { pipeline } = kernel({ plugins: [a, sub], fetchImpl });
    expect((await pipeline.handle(get("/.auth/cb"))).status).toBe(500);
  });

  it("the finalizer is applied to a short-circuit response", async () => {
    const sc = mw("sc", {
      beforeForward: async () => new Response("stop", { status: 409, headers: { "cache-control": "public, max-age=999", age: "9", "x-auth-subject": "x" } }),
    });
    const { pipeline } = kernel({ plugins: [sessAuth(), sc], middleware: [ref("sc")], fallback: cls("public") });
    const res = await pipeline.handle(get("/x"));
    expect(res.status).toBe(409);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("surrogate-control")).toBe("private");
    expect(res.headers.has("age")).toBe(false);
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
  });

  it("the finalizer is applied to a route response", async () => {
    const a = mw("alpha", {
      cookies: ["a"],
      routes: { "/.auth/r": async (ctx) => { ctx.cookies.set("a", "1"); return new Response("r", { headers: { "cache-control": "max-age=999", age: "1" } }); } },
    });
    const { pipeline } = kernel({ plugins: [sessAuth(), a] });
    const res = await pipeline.handle(get("/.auth/r"));
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.has("age")).toBe(false);
    expect(res.headers.getSetCookie()).toEqual(["a=1; Path=/; SameSite=Lax; HttpOnly; Secure"]);
  });

  it("the finalizer is applied to the 400, 401, 403 and top-level 500 responses", async () => {
    const statuses = [];
    const check = (res) => {
      statuses.push(res.status);
      expect(res.headers.get("cache-control")).toBe("private, no-store");
      expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    };
    check(await kernel({ plugins: [sessAuth()], normalizePath: () => { throw new Error("x"); } }).pipeline.handle(get("/x")));
    check(await kernel({ plugins: [sessAuth()], fallback: cls("secured") }).pipeline.handle(get("/x")));
    check(await kernel({ plugins: [sessAuth()], fallback: cls("protected", { audience: ["nope"] }) }).pipeline.handle(get("/x", { cookie: "__Host-sess=u" })));
    check(await kernel({ plugins: [sessAuth()], fallback: cls("public"), forward: async () => { throw new Error("x"); } }).pipeline.handle(get("/x")));
    expect(statuses).toEqual([400, 401, 403, 500]);
  });
});
