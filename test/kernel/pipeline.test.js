import { describe, it, expect, vi } from "vitest";
import { definePlugin, createIdentity, createIdentityDraft, PluginError } from "../../src/sdk/index.js";
import { createRegistry } from "../../src/kernel/registry.js";
import { createPipeline, predicateInput, acceptIdentity } from "../../src/kernel/pipeline.js";

// --- fakes ------------------------------------------------------------------------
// Fake plugins (definePlugin), a fake classify() and a fake CompiledPolicy. No
// dependency on src/kernel/policy.js (W1.2).

const noop = async () => {};
const mw = (name, extra = {}) => definePlugin({ name, kind: "middleware", phases: ["beforeForward"], beforeForward: noop, ...extra });

/** Session authenticator: cookie `sess=<sub>|<g1,g2>`; challenge 302s when interactive. */
function sessAuth(extra = {}) {
  return definePlugin({
    name: "sess",
    kind: "authenticator",
    cookies: ["sess"],
    authenticate: async (ctx) => {
      const v = ctx.cookies.get("sess");
      if (!v) return null;
      const [sub, groups = ""] = v.split("|");
      return createIdentity({ sub, email: `${sub}@example.com`, groups: groups ? groups.split(",") : [], method: "test", issuedAt: 1, expiresAt: 2 });
    },
    challenge: async (ctx, options, how) => (how.interactive ? new Response(null, { status: 302, headers: { location: "https://idp.example/login" } }) : null),
    ...extra,
  });
}

const ref = (use, { options = Object.freeze({}), when = () => true, onError = "fail", source = "rule" } = {}) =>
  Object.freeze({ use, options, when, onError, source });

function cls(tier = "public", extra = {}) {
  return Object.freeze({
    rule: null,
    tier,
    auth: tier === "public" ? "none" : "required",
    audience: undefined,
    upstream: undefined,
    headers: undefined,
    secretHeaders: undefined,
    forwardIdentity: false,
    handler: "origin",
    middleware: [],
    ...extra,
  });
}

function kernel({
  plugins = [], authentication = { use: "sess", options: Object.freeze({}) }, enabled, middleware = [],
  routes: classes = {}, fallback = cls("protected"), forward, errorPage, normalizePath = (p) => p, ...rest
} = {}) {
  const registry = createRegistry(plugins);
  const en = enabled ?? new Map(plugins.map((p) => [p.name, Object.freeze({})]));
  const policy = Object.freeze({
    version: 2, defaultTier: "protected", authentication, enabled: en, middleware, rules: [], defaultHeaders: undefined, warnings: [],
  });
  const logs = [];
  const classify = vi.fn((path) => {
    const c = classes[path] ?? fallback;
    return { ...c, middleware: [...middleware, ...(c.middleware || [])] };
  });
  const forwarded = [];
  const deps = {
    policy,
    registry,
    classify,
    platform: Object.freeze({ profile: "sandbox", has: () => false }),
    secret: (k) => ({ hdr_key: "S3CRET" })[k],
    kv: null,
    config: { originHostname: "origin.example" },
    normalizePath,
    forward: forward || vi.fn(async (input) => {
      forwarded.push(input);
      return new Response("origin body", { status: 200, headers: { "cache-control": "public, max-age=60", age: "5" } });
    }),
    errorPage: errorPage || vi.fn(async (status, input, fallbackBody) => new Response(JSON.stringify(fallbackBody), { status })),
    logSink: (event, fields) => logs.push({ event, ...fields }),
    ...rest,
  };
  const pipeline = createPipeline(deps);
  return { pipeline, deps, logs, forwarded, classify, registry };
}

const get = (path, headers = {}, init = {}) => new Request(`https://gate.example${path}`, { headers, ...init });
const json = async (res) => JSON.parse(await res.text());

// --- tests ------------------------------------------------------------------------

describe("createPipeline", () => {
  it("requires its core deps", () => {
    expect(() => createPipeline({})).toThrow(/deps\.policy/);
  });

  it("fails at load when two enabled plugins claim one route", () => {
    const a = mw("alpha", { routes: { "/.auth/x": async () => new Response("a") } });
    const b = mw("beta", { routes: { "/.auth/x": async () => new Response("b") } });
    expect(() => kernel({ plugins: [a, b], authentication: null })).toThrow(/already claimed/);
  });
});

describe("§4 normalize", () => {
  it("a normalizePath throw gives 400 bad_request with a request id, before anything else", async () => {
    const { pipeline, classify, deps } = kernel({ plugins: [sessAuth()], normalizePath: () => { throw new Error("smuggled"); } });
    const res = await pipeline.handle(get("/a%2fb"));
    expect(res.status).toBe(400);
    expect(await json(res)).toEqual({ error: "bad_request" });
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(classify).not.toHaveBeenCalled();
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("a changed path rebuilds the request so the same path is classified and forwarded", async () => {
    const { pipeline, classify, forwarded } = kernel({
      plugins: [sessAuth()], routes: { "/b/": cls("public") }, normalizePath: () => "/b/",
    });
    const res = await pipeline.handle(get("/a/../b/?q=1", {}, { method: "GET" }));
    expect(res.status).toBe(200);
    expect(classify).toHaveBeenCalledWith("/b/", expect.any(Object));
    expect(new URL(forwarded[0].request.url).pathname).toBe("/b/");
    expect(forwarded[0].url.search).toBe("?q=1");
  });

  it("a changed path keeps a POST body", async () => {
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth()], routes: { "/f": cls("public") }, normalizePath: () => "/f" });
    await pipeline.handle(new Request("https://gate.example/x/../f", { method: "POST", body: "a=1" }));
    expect(forwarded[0].request.method).toBe("POST");
    expect(await forwarded[0].request.text()).toBe("a=1");
  });
});

describe("§4 routes", () => {
  it("an exact route of an enabled plugin runs with tier public and no identity, then finalize", async () => {
    let seen;
    const handler = vi.fn(async (ctx, options) => {
      seen = { tier: ctx.tier, identity: ctx.identity, authenticated: ctx.authenticated, options, rule: ctx.rule };
      return new Response("routed", { headers: { "cache-control": "max-age=999" } });
    });
    const a = mw("alpha", { routes: { "/.auth/ping": handler } });
    const opts = Object.freeze({ o: 1 });
    const { pipeline, classify, deps } = kernel({
      plugins: [sessAuth(), a], enabled: new Map([["sess", {}], ["alpha", opts]]),
    });
    const res = await pipeline.handle(get("/.auth/ping", { cookie: "sess=u1|admin" }));
    expect(await res.text()).toBe("routed");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(seen).toMatchObject({ tier: "public", identity: null, authenticated: false, options: opts });
    expect(seen.rule).toMatchObject({ path: "/.auth/ping", tier: "public", route: true });
    expect(classify).not.toHaveBeenCalled();
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("routes of plugins that are not enabled are not served", async () => {
    const a = mw("alpha", { routes: { "/.auth/ping": async () => new Response("routed") } });
    const { pipeline, classify } = kernel({
      plugins: [sessAuth(), a], enabled: new Map([["sess", {}]]), routes: { "/.auth/ping": cls("public") },
    });
    const res = await pipeline.handle(get("/.auth/ping"));
    expect(await res.text()).toBe("origin body");
    expect(classify).toHaveBeenCalled();
  });

  it("matching is exact (no trailing-slash or prefix match)", async () => {
    const handler = vi.fn(async () => new Response("routed"));
    const a = mw("alpha", { routes: { "/.auth/ping": handler } });
    const { pipeline } = kernel({ plugins: [sessAuth(), a], fallback: cls("public") });
    await pipeline.handle(get("/.auth/ping/"));
    await pipeline.handle(get("/.auth/ping/x"));
    expect(handler).not.toHaveBeenCalled();
  });

  it("a route that does not return a Response is a 500", async () => {
    const a = mw("alpha", { routes: { "/.auth/ping": async () => ({ status: 200 }) } });
    const res = await kernel({ plugins: [sessAuth(), a] }).pipeline.handle(get("/.auth/ping"));
    expect(res.status).toBe(500);
    expect(await json(res)).toEqual({ error: "internal_error" });
  });

  it("a route throwing PluginError gives its status and code", async () => {
    const a = mw("alpha", { routes: { "/.auth/ping": async () => { throw new PluginError(405, "method_not_allowed", "GET not allowed"); } } });
    const res = await kernel({ plugins: [sessAuth(), a] }).pipeline.handle(get("/.auth/ping"));
    expect(res.status).toBe(405);
    expect(await json(res)).toEqual({ error: "method_not_allowed" });
  });
});

describe("§4 classify", () => {
  it("calls deps.classify(path, policy)", async () => {
    const { pipeline, classify, deps } = kernel({ plugins: [sessAuth()], fallback: cls("public") });
    await pipeline.handle(get("/x"));
    expect(classify).toHaveBeenCalledWith("/x", deps.policy);
  });

  it("an invalid classification is a 500", async () => {
    const { pipeline, deps } = kernel({ plugins: [sessAuth()], fallback: { tier: "nope", auth: "none" } });
    const res = await pipeline.handle(get("/x"));
    expect(res.status).toBe(500);
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("ctx.rule is a frozen copy of the rule, or a default-tier pseudo-rule", async () => {
    const rules = [];
    const p = mw("alpha", { beforeForward: async (ctx) => { rules.push(ctx.rule); } });
    const rule = { path: "/r/*", tier: "public", spec: 3 };
    const { pipeline } = kernel({
      plugins: [sessAuth(), p], middleware: [ref("alpha")],
      routes: { "/r/x": cls("public", { rule }) }, fallback: cls("public"),
    });
    await pipeline.handle(get("/r/x"));
    await pipeline.handle(get("/other"));
    expect(rules[0]).toEqual(rule);
    expect(rules[0]).not.toBe(rule);
    expect(Object.isFrozen(rules[0])).toBe(true);
    expect(rules[1]).toMatchObject({ path: null, tier: "public", default: true });
  });
});

describe("§4 request phase", () => {
  it("runs global refs then rule refs, with authenticated:false even when a session exists", async () => {
    const order = [];
    const inputs = [];
    const mk = (name) => mw(name, { phases: ["request"], beforeForward: undefined, request: async () => { order.push(name); } });
    const g = mk("glob");
    const r = mk("rul");
    const { pipeline } = kernel({
      plugins: [sessAuth(), g, r],
      middleware: [ref("glob", { source: "global", when: (i) => { inputs.push(i); return true; } })],
      routes: { "/p": cls("protected", { middleware: [ref("rul")] }) },
    });
    const res = await pipeline.handle(get("/p", { cookie: "sess=u1|admin" }));
    expect(res.status).toBe(200);
    expect(order).toEqual(["glob", "rul"]);
    expect(inputs[0]).toMatchObject({ authenticated: false, groups: [] });
  });

  it("a Response short-circuits: no authentication, no forward, no afterForward, but finalize", async () => {
    const authenticate = vi.fn(async () => null);
    const after = vi.fn();
    const blocker = mw("block", { phases: ["request"], beforeForward: undefined, request: async () => new Response("blocked", { status: 429 }) });
    const tail = mw("tail", { phases: ["afterForward"], beforeForward: undefined, afterForward: after });
    const { pipeline, deps } = kernel({
      plugins: [sessAuth({ authenticate }), blocker, tail], middleware: [ref("block"), ref("tail")],
    });
    const res = await pipeline.handle(get("/p"));
    expect(res.status).toBe(429);
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(authenticate).not.toHaveBeenCalled();
    expect(deps.forward).not.toHaveBeenCalled();
    expect(after).not.toHaveBeenCalled();
  });

  it("when() false skips the hook", async () => {
    const hook = vi.fn();
    const p = mw("alpha", { phases: ["request"], beforeForward: undefined, request: hook });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha", { when: (i) => i.method === "POST" })], fallback: cls("public") });
    await pipeline.handle(get("/x"));
    expect(hook).not.toHaveBeenCalled();
    await pipeline.handle(get("/x", {}, { method: "POST", body: "x" }));
    expect(hook).toHaveBeenCalledOnce();
  });

  it("a ref whose plugin does not declare the phase is not run in it", async () => {
    const before = vi.fn();
    const p = mw("alpha", { beforeForward: before });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha")], fallback: cls("public") });
    await pipeline.handle(get("/x"));
    expect(before).toHaveBeenCalledOnce(); // beforeForward only, never as request
  });

  it("a replaced request (buffered body) is what later phases and forward see", async () => {
    const p = mw("buf", {
      phases: ["request"], beforeForward: undefined,
      request: async (ctx) => {
        const body = await ctx.request.arrayBuffer();
        ctx.replaceRequest(new Request(ctx.request.url, { method: ctx.request.method, headers: ctx.request.headers, body }));
      },
    });
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth(), p], middleware: [ref("buf")], fallback: cls("public") });
    await pipeline.handle(new Request("https://gate.example/form", { method: "POST", body: "a=1&b=2" }));
    expect(await forwarded[0].request.text()).toBe("a=1&b=2");
  });
});

describe("§4 authenticate", () => {
  it("auth none never calls the authenticator", async () => {
    const authenticate = vi.fn(async () => null);
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth({ authenticate })], fallback: cls("public") });
    await pipeline.handle(get("/x", { cookie: "sess=u1" }));
    expect(authenticate).not.toHaveBeenCalled();
    expect(forwarded[0].identity).toBeNull();
  });

  it("auth required: the authenticator gets its options and the identity is forwarded", async () => {
    const opts = Object.freeze({ cookie: "sess" });
    let seenOpts;
    const base = sessAuth();
    const a = sessAuth({ authenticate: async (ctx, o) => { seenOpts = o; return base.authenticate(ctx, o); } });
    const { pipeline, forwarded } = kernel({ plugins: [a], authentication: { use: "sess", options: opts } });
    const res = await pipeline.handle(get("/p", { cookie: "sess=u1|g1,g2" }));
    expect(res.status).toBe(200);
    expect(seenOpts).toBe(opts);
    expect(forwarded[0].identity).toMatchObject({ sub: "u1", groups: ["g1", "g2"] });
    expect(Object.isFrozen(forwarded[0].identity)).toBe(true);
  });

  it("auth optional: an identity is used when present", async () => {
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth()], fallback: cls("public", { auth: "optional" }) });
    await pipeline.handle(get("/x", { cookie: "sess=u1" }));
    expect(forwarded[0].identity.sub).toBe("u1");
  });

  it("auth optional: errors are logged and the request continues anonymously", async () => {
    const a = sessAuth({ authenticate: async () => { throw new Error("jwks down"); } });
    const { pipeline, forwarded, logs } = kernel({ plugins: [a], fallback: cls("public", { auth: "optional" }) });
    const res = await pipeline.handle(get("/x", { cookie: "sess=u1" }));
    expect(res.status).toBe(200);
    expect(forwarded[0].identity).toBeNull();
    expect(logs.some((l) => l.level === "warn" && /optional authentication failed/.test(l.event))).toBe(true);
  });

  it("auth optional: anonymous is not challenged", async () => {
    const challenge = vi.fn();
    const { pipeline } = kernel({ plugins: [sessAuth({ challenge })], fallback: cls("public", { auth: "optional" }) });
    expect((await pipeline.handle(get("/x"))).status).toBe(200);
    expect(challenge).not.toHaveBeenCalled();
  });

  it("auth required: a PluginError propagates as its status/code (message never sent)", async () => {
    const a = sessAuth({ authenticate: async () => { throw new PluginError(503, "idp_unavailable", "secret detail"); } });
    const { pipeline, deps } = kernel({ plugins: [a] });
    const res = await pipeline.handle(get("/p", { cookie: "sess=u1" }));
    expect(res.status).toBe(503);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({ error: "idp_unavailable" });
    expect(body).not.toContain("secret detail");
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("auth required: any other error is a 500 internal_error", async () => {
    const a = sessAuth({ authenticate: async () => { throw new Error("boom"); } });
    const res = await kernel({ plugins: [a] }).pipeline.handle(get("/p"));
    expect(res.status).toBe(500);
    expect(await json(res)).toEqual({ error: "internal_error" });
  });
});

describe("§4 enforce", () => {
  it("protected without identity: challenge({interactive:true}) Response is returned (finalized)", async () => {
    const how = [];
    const base = sessAuth();
    const a = sessAuth({ challenge: async (ctx, o, h) => { how.push(h); return base.challenge(ctx, o, h); } });
    const res = await kernel({ plugins: [a] }).pipeline.handle(get("/p"));
    expect(how).toEqual([{ interactive: true }]);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("https://idp.example/login");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("secured without identity: challenge({interactive:false}) null gives 401 + WWW-Authenticate: Bearer", async () => {
    const how = [];
    const base = sessAuth();
    const a = sessAuth({ challenge: async (ctx, o, h) => { how.push(h); return base.challenge(ctx, o, h); } });
    const { pipeline, deps } = kernel({ plugins: [a], fallback: cls("secured") });
    const res = await pipeline.handle(get("/api/x"));
    expect(how).toEqual([{ interactive: false }]);
    expect(res.status).toBe(401);
    expect(await json(res)).toEqual({ error: "unauthorized" });
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("an authenticator without challenge() gives 401", async () => {
    const a = definePlugin({ name: "sess", kind: "authenticator", authenticate: async () => null });
    const res = await kernel({ plugins: [a] }).pipeline.handle(get("/p"));
    expect(res.status).toBe(401);
  });

  it("a challenge that throws is a 500", async () => {
    const a = sessAuth({ challenge: async () => { throw new Error("x"); } });
    expect((await kernel({ plugins: [a] }).pipeline.handle(get("/p"))).status).toBe(500);
  });
});

describe("§4 authorize", () => {
  it("an audience miss calls deps.errorPage(403, ForwardInput, {error:'forbidden'}) and never forwards", async () => {
    const { pipeline, deps } = kernel({ plugins: [sessAuth()], fallback: cls("protected", { audience: ["medical"] }) });
    const res = await pipeline.handle(get("/p", { cookie: "sess=u1|sales" }));
    expect(res.status).toBe(403);
    expect(deps.errorPage).toHaveBeenCalledWith(403, expect.objectContaining({ identity: expect.objectContaining({ sub: "u1" }) }), { error: "forbidden" });
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("an audience hit forwards", async () => {
    const { pipeline, deps } = kernel({ plugins: [sessAuth()], fallback: cls("protected", { audience: ["medical", "x"] }) });
    expect((await pipeline.handle(get("/p", { cookie: "sess=u1|medical" }))).status).toBe(200);
    expect(deps.forward).toHaveBeenCalledOnce();
  });

  it("an empty audience allows any identity", async () => {
    const { pipeline } = kernel({ plugins: [sessAuth()], fallback: cls("protected", { audience: [] }) });
    expect((await pipeline.handle(get("/p", { cookie: "sess=u1" }))).status).toBe(200);
  });

  it("an audience on an optional rule rejects anonymous users", async () => {
    const { pipeline } = kernel({ plugins: [sessAuth()], fallback: cls("public", { auth: "optional", audience: ["g"] }) });
    expect((await pipeline.handle(get("/x"))).status).toBe(403);
  });
});

describe("§4 beforeForward", () => {
  it("sees the identity in when() and ctx; a Response short-circuits", async () => {
    const inputs = [];
    const p = mw("alpha", { beforeForward: async (ctx) => (ctx.identity.groups.includes("blocked") ? new Response("no", { status: 418 }) : undefined) });
    const { pipeline, deps } = kernel({
      plugins: [sessAuth(), p], middleware: [ref("alpha", { when: (i) => { inputs.push(i); return true; } })],
    });
    expect((await pipeline.handle(get("/p", { cookie: "sess=u1|ok" }))).status).toBe(200);
    expect((await pipeline.handle(get("/p", { cookie: "sess=u2|blocked" }))).status).toBe(418);
    expect(inputs[0]).toMatchObject({ authenticated: true, groups: ["ok"] });
    expect(deps.forward).toHaveBeenCalledOnce();
  });

  it("groups_any-style predicates can skip a ref", async () => {
    const hook = vi.fn();
    const p = mw("alpha", { beforeForward: hook });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha", { when: (i) => i.groups.includes("vip") })] });
    await pipeline.handle(get("/p", { cookie: "sess=u1|basic" }));
    expect(hook).not.toHaveBeenCalled();
  });
});

describe("§4 handler", () => {
  it("origin: deps.forward gets a full ForwardInput", async () => {
    const p = mw("alpha", { trustedHeaderPrefixes: ["x-alpha-"], beforeForward: async (ctx) => ctx.forwardHeaders.set("x-alpha-score", "0.9") });
    const q = mw("beta", { trustedHeaderPrefixes: ["x-beta-"], cookies: ["bc"], phases: ["request"], beforeForward: undefined, request: async (ctx) => ctx.forwardHeaders.set("x-beta-ok", "1") });
    const c = cls("protected", { upstream: "https://up.example" });
    const { pipeline, forwarded } = kernel({ plugins: [sessAuth(), p, q], middleware: [ref("alpha"), ref("beta")], fallback: c });
    // F12: trace ids must be 8-64 chars of [A-Za-z0-9._-] (was "trace-1").
    await pipeline.handle(get("/p", { cookie: "sess=u1|g", "fastly-trace-id": "trace-0001" }));
    const input = forwarded[0];
    expect(input.request).toBeInstanceOf(Request);
    expect(input.url).toBeInstanceOf(URL);
    expect(input.classification).toMatchObject({ tier: "protected", upstream: "https://up.example" });
    expect(input.identity.sub).toBe("u1");
    expect(Object.fromEntries(input.pluginHeaders)).toEqual({ "x-alpha-score": "0.9", "x-beta-ok": "1" });
    expect(input.stripPrefixes).toEqual(["x-auth-", "x-alpha-", "x-beta-"]);
    expect(input.ownedCookies).toEqual(["sess", "bc"]);
    expect(input.secret("hdr_key")).toBe("S3CRET");
    expect(input.requestId).toBe("trace-0001");
    expect(typeof input.fetch).toBe("function");
  });

  it("ForwardInput.fetch is the budgeted kernel fetch", async () => {
    const fetchImpl = vi.fn(async () => new Response("from origin"));
    const forward = async (input) => input.fetch("https://origin.example/p");
    const { pipeline } = kernel({ plugins: [sessAuth()], fallback: cls("public"), forward, fetchImpl, fetchBudget: 1 });
    const res = await pipeline.handle(get("/p"));
    expect(await res.text()).toBe("from origin");
    expect(fetchImpl.mock.calls[0][1].cacheOverride.mode).toBe("pass");
  });

  it("a kernel fetch over budget inside forward gives 503 budget_exceeded", async () => {
    const forward = async (input) => { await input.fetch("https://o.example/1"); return input.fetch("https://o.example/2"); };
    const { pipeline } = kernel({ plugins: [sessAuth()], fallback: cls("public"), forward, fetchImpl: async () => new Response("x"), fetchBudget: 1 });
    const res = await pipeline.handle(get("/p"));
    expect(res.status).toBe(503);
    expect(await json(res)).toEqual({ error: "budget_exceeded" });
  });

  it("a plugin handler runs handle(ctx, enabled base options) instead of forward", async () => {
    const opts = Object.freeze({ greeting: "hi" });
    const h = mw("hello", { handle: async (ctx, o) => new Response(`${o.greeting} ${ctx.identity.sub}`) });
    const { pipeline, deps } = kernel({
      plugins: [sessAuth(), h], enabled: new Map([["sess", {}], ["hello", opts]]), fallback: cls("protected", { handler: "hello" }),
    });
    const res = await pipeline.handle(get("/p", { cookie: "sess=u1" }));
    expect(await res.text()).toBe("hi u1");
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("a plugin handler returning a non-Response is a 500", async () => {
    const h = mw("hello", { handle: async () => "nope" });
    const { pipeline } = kernel({ plugins: [sessAuth(), h], fallback: cls("public", { handler: "hello" }) });
    expect((await pipeline.handle(get("/p"))).status).toBe(500);
  });

  it("an unknown handler plugin is a 500", async () => {
    const { pipeline } = kernel({ plugins: [sessAuth()], fallback: cls("public", { handler: "ghost" }) });
    expect((await pipeline.handle(get("/p"))).status).toBe(500);
  });
});

describe("§4 afterForward", () => {
  it("runs on handler responses and may replace them", async () => {
    const p = mw("alpha", {
      phases: ["afterForward"], beforeForward: undefined,
      afterForward: async (ctx, o, res) => new Response(`${await res.text()} + after`, { status: res.status }),
    });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha")], fallback: cls("public") });
    expect(await (await pipeline.handle(get("/x"))).text()).toBe("origin body + after");
  });

  it("a void return keeps the handler response", async () => {
    const p = mw("alpha", { phases: ["afterForward"], beforeForward: undefined, afterForward: async () => undefined });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha")], fallback: cls("public") });
    expect(await (await pipeline.handle(get("/x"))).text()).toBe("origin body");
  });

  it("does not run on route, challenge or error responses", async () => {
    const after = vi.fn();
    const p = mw("alpha", { phases: ["afterForward"], beforeForward: undefined, afterForward: after, routes: { "/.auth/r": async () => new Response("r") } });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha")], fallback: cls("protected", { audience: ["x"] }) });
    await pipeline.handle(get("/.auth/r"));
    await pipeline.handle(get("/p"));
    await pipeline.handle(get("/p", { cookie: "sess=u1|y" }));
    expect(after).not.toHaveBeenCalled();
  });
});

describe("§4 finalize", () => {
  it("applies to forwarded responses: no-store, age removed", async () => {
    const res = await kernel({ plugins: [sessAuth()], fallback: cls("public") }).pipeline.handle(get("/x"));
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("surrogate-control")).toBe("private");
    expect(res.headers.has("age")).toBe(false);
  });

  it("applies plugin cookie writes and response headers to every response, including errors", async () => {
    const p = mw("alpha", {
      cookies: ["pref"], phases: ["request"], beforeForward: undefined,
      request: async (ctx) => { ctx.cookies.set("pref", "1"); ctx.responseHeaders.set("x-frame-options", "DENY"); },
    });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha")], fallback: cls("secured") });
    const res = await pipeline.handle(get("/api"));
    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie()).toEqual(["pref=1; Path=/; SameSite=Lax; HttpOnly; Secure"]);
    expect(res.headers.get("x-frame-options")).toBe("DENY");
  });
});

describe("§5 errors", () => {
  const thrower = (err, extra = {}) => mw("alpha", { beforeForward: async () => { throw err; }, ...extra });

  it("PluginError gives status {error: code}; the message is only logged", async () => {
    const { pipeline, logs } = kernel({ plugins: [sessAuth(), thrower(new PluginError(400, "recaptcha_failed", "score 0.1 too low"))], middleware: [ref("alpha")], fallback: cls("public") });
    const res = await pipeline.handle(get("/x"));
    expect(res.status).toBe(400);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({ error: "recaptcha_failed" });
    expect(body).not.toContain("score");
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    expect(JSON.stringify(logs)).toContain("score 0.1 too low");
  });

  it("any other throw with on_error fail is a generic 500", async () => {
    const { pipeline, deps } = kernel({ plugins: [sessAuth(), thrower(new Error("db password is hunter2"))], middleware: [ref("alpha")], fallback: cls("public") });
    const res = await pipeline.handle(get("/x"));
    expect(res.status).toBe(500);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({ error: "internal_error" });
    expect(body).not.toContain("hunter2");
    expect(deps.forward).not.toHaveBeenCalled();
  });

  it("on_error skip (allowSkipOnError) logs and continues", async () => {
    const p = thrower(new Error("flaky"), { allowSkipOnError: true });
    const { pipeline, deps, logs } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha", { onError: "skip" })], fallback: cls("public") });
    expect((await pipeline.handle(get("/x"))).status).toBe(200);
    expect(deps.forward).toHaveBeenCalledOnce();
    expect(logs.some((l) => /skipped/.test(l.event) && l.plugin === "alpha")).toBe(true);
  });

  it("on_error skip is ignored when the plugin does not allow it", async () => {
    const { pipeline } = kernel({ plugins: [sessAuth(), thrower(new Error("x"))], middleware: [ref("alpha", { onError: "skip" })], fallback: cls("public") });
    expect((await pipeline.handle(get("/x"))).status).toBe(500);
  });

  it("on_error skip does not swallow a PluginError", async () => {
    const p = thrower(new PluginError(429, "rate_limited"), { allowSkipOnError: true });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha", { onError: "skip" })], fallback: cls("public") });
    expect((await pipeline.handle(get("/x"))).status).toBe(429);
  });

  it("afterForward error with skip keeps the handler response", async () => {
    const p = mw("alpha", { phases: ["afterForward"], beforeForward: undefined, allowSkipOnError: true, afterForward: async () => { throw new Error("x"); } });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha", { onError: "skip" })], fallback: cls("public") });
    expect(await (await pipeline.handle(get("/x"))).text()).toBe("origin body");
  });

  it("afterForward error with fail is a 500", async () => {
    const p = mw("alpha", { phases: ["afterForward"], beforeForward: undefined, afterForward: async () => { throw new Error("x"); } });
    const { pipeline } = kernel({ plugins: [sessAuth(), p], middleware: [ref("alpha")], fallback: cls("public") });
    expect((await pipeline.handle(get("/x"))).status).toBe(500);
  });

  it("an unexpected kernel error is the top-level 500 with x-auth-request-id (fastly-trace-id preferred)", async () => {
    const { pipeline } = kernel({ plugins: [sessAuth()], forward: async () => { throw new Error("backend exploded"); }, fallback: cls("public") });
    const res = await pipeline.handle(get("/x", { "fastly-trace-id": "trace-77" }));
    expect(res.status).toBe(500);
    expect(await json(res)).toEqual({ error: "internal_error" });
    expect(res.headers.get("x-auth-request-id")).toBe("trace-77");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("a classify() throw is the top-level 500", async () => {
    const { pipeline, classify } = kernel({ plugins: [sessAuth()] });
    classify.mockImplementation(() => { throw new Error("bad policy"); });
    expect((await pipeline.handle(get("/x"))).status).toBe(500);
  });
});

describe("PredicateInput", () => {
  const req = (headers, method = "GET") => new Request("https://g.example/", { method, headers, ...(method === "POST" ? { body: "x" } : {}) });

  it("contentType is the lowercase media type without parameters", () => {
    expect(predicateInput(req({ "content-type": "Multipart/Form-Data; boundary=x" }, "POST"), null).contentType).toBe("multipart/form-data");
    expect(predicateInput(req({}), null).contentType).toBe("");
  });

  it("accept is json / html / other", () => {
    expect(predicateInput(req({ accept: "application/json" }), null).accept).toBe("json");
    expect(predicateInput(req({ accept: "text/html,application/json;q=0.9" }), null).accept).toBe("html");
    expect(predicateInput(req({ accept: "TEXT/HTML" }), null).accept).toBe("html");
    expect(predicateInput(req({ accept: "*/*" }), null).accept).toBe("other");
    expect(predicateInput(req({}), null).accept).toBe("other");
  });

  it("method is uppercase; groups/authenticated come from the identity", () => {
    const id = createIdentity({ sub: "u", method: "m", issuedAt: 1, expiresAt: 2, groups: ["a"] });
    const anon = predicateInput(req({}), null);
    expect(anon).toMatchObject({ method: "GET", authenticated: false, groups: [] });
    expect(predicateInput(req({}, "POST"), id)).toMatchObject({ method: "POST", authenticated: true, groups: ["a"] });
    expect(Object.isFrozen(anon)).toBe(true);
  });
});

describe("acceptIdentity", () => {
  it("accepts null/undefined as anonymous and canonicalizes a createIdentity() value", () => {
    expect(acceptIdentity(null)).toBeNull();
    expect(acceptIdentity(undefined)).toBeNull();
    const id = createIdentity({ sub: "u", method: "m", issuedAt: 1, expiresAt: 2, groups: ["a", "a"], attrs: { k: 1 } });
    const out = acceptIdentity(id);
    expect(out).toEqual(id);
    expect(Object.isFrozen(out.groups)).toBe(true);
  });

  it("rejects anything not minted by createIdentity(), including perfect frozen lookalikes", () => {
    const fields = { sub: "u", method: "m", issuedAt: 1, expiresAt: 2, groups: [], attrs: {} };
    expect(() => acceptIdentity({ ...fields })).toThrow(/non-Identity/);
    expect(() => acceptIdentity(Object.freeze({ ...fields }))).toThrow(/non-Identity/);
    // A deeply frozen object with exactly the right keys is still a forgery.
    const lookalike = Object.freeze({ ...fields, email: undefined, name: undefined, sessionId: undefined,
      groups: Object.freeze(["admin"]), attrs: Object.freeze({}) });
    expect(() => acceptIdentity(lookalike)).toThrow(/non-Identity/);
    expect(() => acceptIdentity(Object.freeze({ ...fields, groups: Object.freeze([]), attrs: Object.freeze({}), admin: true }))).toThrow(/non-Identity/);
    expect(() => acceptIdentity("u1")).toThrow(/non-Identity/);
    // The genuine article passes through unchanged.
    const real = createIdentity(fields);
    expect(acceptIdentity(real)).toBe(real);
  });
});

describe("lifecycle through the pipeline", () => {
  function loginAuth(onLoginFail) {
    return definePlugin({
      name: "sess", kind: "authenticator", cookies: ["sess"],
      authenticate: async () => null,
      routes: {
        "/.auth/callback": async (ctx) => {
          const draft = createIdentityDraft({ sub: "u1", groups: ["base"] });
          try {
            await ctx.lifecycle.emitLogin(draft);
          } catch {
            return onLoginFail();
          }
          const id = draft.toIdentity({ method: "test", issuedAt: 1, expiresAt: 2 });
          ctx.cookies.set("sess", `${id.sub}|${id.groups.join(",")}`);
          return new Response(null, { status: 302, headers: { location: "/" } });
        },
      },
    });
  }

  it("emitLogin from a route runs enabled onLogin hooks, which add groups", async () => {
    const info = mw("user-info", { onLogin: async (ctx, draft) => draft.addGroups(["medical"]) });
    const { pipeline } = kernel({ plugins: [loginAuth(() => new Response("fail", { status: 502 })), info] });
    const res = await pipeline.handle(get("/.auth/callback"));
    expect(res.status).toBe(302);
    expect(res.headers.getSetCookie()).toEqual(["sess=u1%7Cbase%2Cmedical; Path=/; SameSite=Lax; HttpOnly; Secure"]);
  });

  it("a failing onLogin aborts the login; the authenticator decides the response", async () => {
    const info = mw("user-info", { onLogin: async () => { throw new Error("backend down"); } });
    const { pipeline } = kernel({ plugins: [loginAuth(() => new Response("login failed", { status: 502 })), info] });
    const res = await pipeline.handle(get("/.auth/callback"));
    expect(res.status).toBe(502);
    expect(res.headers.getSetCookie()).toEqual([]);
  });
});
