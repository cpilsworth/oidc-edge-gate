import { describe, it, expect, vi } from "vitest";
import { definePlugin, createIdentity, createIdentityDraft } from "../../src/sdk/index.js";
import { createRegistry } from "../../src/kernel/registry.js";
import { createFetchBudget } from "../../src/kernel/fetch.js";
import {
  createRequestScope, makeLogger, stripReservedHeaders, defaultLogSink, errorSummary,
} from "../../src/kernel/context.js";

const noop = async () => {};
const mw = (name, extra = {}) => definePlugin({ name, kind: "middleware", phases: ["beforeForward"], beforeForward: noop, ...extra });
const auth = (name, extra = {}) => definePlugin({ name, kind: "authenticator", authenticate: async () => null, ...extra });

function fakeKv() {
  const map = new Map();
  return {
    map,
    get: vi.fn(async (k) => (map.has(k) ? { text: async () => map.get(k) } : null)),
    put: vi.fn(async (k, v) => { map.set(k, v); }),
    delete: vi.fn(async (k) => { map.delete(k); }),
  };
}

function scopeFor(plugins, {
  url = "https://gate.example/page", headers = {}, enabled = new Map(), kv = null, secret, logs = [], fetchImpl,
} = {}) {
  const registry = createRegistry(plugins);
  const logSink = (event, fields) => logs.push({ event, ...fields });
  const request = new Request(url, { headers });
  const budget = createFetchBudget({ fetchImpl: fetchImpl || (async () => new Response("ok")), logSink });
  const scope = createRequestScope({
    request, url: new URL(url), path: new URL(url).pathname, requestId: "rid-9",
    inboundCookieHeader: request.headers.get("cookie"), registry, enabled,
    platform: Object.freeze({ profile: "sandbox", has: () => false }), config: Object.freeze({ a: 1 }),
    secret, kv, budget, logSink,
  });
  return { scope, registry, logs, budget };
}

describe("Context shape", () => {
  it("exposes the SDK Context fields and is frozen", () => {
    const p = mw("alpha");
    const { scope } = scopeFor([p]);
    scope.tier = "protected";
    scope.rule = Object.freeze({ path: "/page" });
    const opts = Object.freeze({ o: 1 });
    const ctx = scope.contextFor(p, opts);
    expect(Object.isFrozen(ctx)).toBe(true);
    expect(ctx.request).toBeInstanceOf(Request);
    expect(ctx.url).toBeInstanceOf(URL);
    expect(ctx.url.href).toBe("https://gate.example/page");
    expect(ctx.path).toBe("/page");
    expect(ctx.requestId).toBe("rid-9");
    expect(ctx.tier).toBe("protected");
    expect(ctx.rule).toEqual({ path: "/page" });
    expect(ctx.identity).toBeNull();
    expect(ctx.authenticated).toBe(false);
    expect(ctx.platform.profile).toBe("sandbox");
    expect(ctx.options).toBe(opts);
    expect(ctx.config).toEqual({ a: 1 });
    expect(typeof ctx.fetch).toBe("function");
    expect(ctx.kv).toBeNull();
    expect(typeof ctx.secret).toBe("function");
    expect(ctx.responseHeaders).toBeInstanceOf(Headers);
    expect(ctx.state).toBeInstanceOf(Map);
    expect(typeof ctx.log.info).toBe("function");
    expect(ctx.lifecycle).toBeUndefined();
  });

  it("ctx.url is a copy: mutating it does not move the kernel's URL", () => {
    const p = mw("alpha");
    const { scope } = scopeFor([p]);
    scope.contextFor(p, {}).url.pathname = "/elsewhere";
    expect(scope.contextFor(p, {}).url.pathname).toBe("/page");
  });

  it("identity is read live from the scope and cannot be assigned", () => {
    const p = mw("alpha");
    const { scope } = scopeFor([p]);
    const ctx = scope.contextFor(p, {});
    const id = createIdentity({ sub: "u", method: "m", issuedAt: 1, expiresAt: 2, groups: ["g"] });
    scope.identity = id;
    expect(ctx.identity).toBe(id);
    expect(ctx.authenticated).toBe(true);
    expect(() => { "use strict"; ctx.identity = null; }).toThrow(TypeError);
    expect(Object.isFrozen(ctx.identity)).toBe(true);
    expect(() => { ctx.identity.groups.push("admin"); }).toThrow(TypeError);
  });
});

describe("ctx.state", () => {
  it("is private per plugin and shared across that plugin's hooks in a request", () => {
    const a = mw("alpha");
    const b = mw("beta");
    const { scope } = scopeFor([a, b]);
    scope.contextFor(a, {}).state.set("k", 1);
    expect(scope.contextFor(a, { other: 1 }).state.get("k")).toBe(1);
    expect(scope.contextFor(b, {}).state.has("k")).toBe(false);
  });

  it("is fresh for a new request", () => {
    const a = mw("alpha");
    scopeFor([a]).scope.contextFor(a, {}).state.set("k", 1);
    expect(scopeFor([a]).scope.contextFor(a, {}).state.has("k")).toBe(false);
  });
});

describe("ctx.forwardHeaders", () => {
  it("accepts names under the plugin's own prefixes (case-insensitive) into pluginHeaders", () => {
    const p = mw("alpha", { trustedHeaderPrefixes: ["x-alpha-"] });
    const { scope } = scopeFor([p]);
    const ctx = scope.contextFor(p, {});
    ctx.forwardHeaders.set("X-Alpha-Score", "0.9");
    ctx.forwardHeaders.set("x-alpha-gone", "1");
    ctx.forwardHeaders.delete("x-alpha-gone");
    expect(scope.pluginHeaders.get("x-alpha-score")).toBe("0.9");
    expect(scope.pluginHeaders.has("x-alpha-gone")).toBe(false);
  });

  it("rejects x-auth-*, other plugins' prefixes, unprefixed names and the bare prefix", () => {
    const a = mw("alpha", { trustedHeaderPrefixes: ["x-alpha-"] });
    const b = mw("beta", { trustedHeaderPrefixes: ["x-beta-"] });
    const { scope } = scopeFor([a, b]);
    const ctx = scope.contextFor(a, {});
    for (const name of ["x-auth-subject", "X-Auth-Groups", "x-beta-score", "authorization", "x-alpha-", 42]) {
      expect(() => ctx.forwardHeaders.set(name, "v")).toThrow(Error);
    }
    expect(() => ctx.forwardHeaders.delete("x-beta-score")).toThrow(Error);
    expect([...scope.pluginHeaders.keys()]).toEqual([]);
  });
});

describe("ctx.cookies", () => {
  it("get reads declared cookies from the inbound Cookie header", () => {
    const p = auth("sess", { cookies: ["__Host-s", "st"] });
    const { scope } = scopeFor([p], { headers: { cookie: "__Host-s=abc%20d; other=1; st=x" } });
    const ctx = scope.contextFor(p, {});
    expect(ctx.cookies.get("__Host-s")).toBe("abc d");
    expect(ctx.cookies.get("st")).toBe("x");
  });

  it("get of a declared but absent cookie is undefined", () => {
    const p = auth("sess", { cookies: ["__Host-s"] });
    expect(scopeFor([p]).scope.contextFor(p, {}).cookies.get("__Host-s")).toBeUndefined();
  });

  it("undeclared names (including another plugin's cookie) are rejected for get/set/clear", () => {
    const a = mw("alpha", { cookies: ["a"] });
    const s = auth("sess", { cookies: ["__Host-s"] });
    const { scope } = scopeFor([a, s], { headers: { cookie: "__Host-s=secret; other=1" } });
    const ctx = scope.contextFor(a, {});
    expect(() => ctx.cookies.get("__Host-s")).toThrow(/did not declare/);
    expect(() => ctx.cookies.get("other")).toThrow(/did not declare/);
    expect(() => ctx.cookies.set("__Host-s", "forged")).toThrow(/did not declare/);
    expect(() => ctx.cookies.clear("__Host-s")).toThrow(/did not declare/);
    expect(scope.cookieWriteLines()).toEqual([]);
  });

  it("set/clear record secure-default Set-Cookie lines; last write per name wins", () => {
    const p = auth("sess", { cookies: ["__Host-s", "st"] });
    const { scope } = scopeFor([p]);
    const ctx = scope.contextFor(p, {});
    ctx.cookies.set("__Host-s", "v1");
    ctx.cookies.set("__Host-s", "v 2", { maxAge: 3600, sameSite: "Strict" });
    ctx.cookies.clear("st");
    const lines = scope.cookieWriteLines();
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("__Host-s=v%202; Path=/; Max-Age=3600; SameSite=Strict; HttpOnly; Secure");
    expect(lines[1]).toBe("st=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly; Secure");
    expect(lines[0]).not.toMatch(/Domain=/);
  });

  it("validates set attributes", () => {
    const p = auth("sess", { cookies: ["c"] });
    const ctx = scopeFor([p]).scope.contextFor(p, {});
    expect(() => ctx.cookies.set("c", 1)).toThrow(TypeError);
    expect(() => ctx.cookies.set("c", "v", { sameSite: "lax" })).toThrow(TypeError);
    expect(() => ctx.cookies.set("c", "v", { maxAge: 1.5 })).toThrow(TypeError);
  });
});

describe("ctx.kv", () => {
  it("is null without a KV store", () => {
    const p = mw("alpha");
    expect(scopeFor([p]).scope.contextFor(p, {}).kv).toBeNull();
  });

  it("namespaces keys under plugin:<name>:", async () => {
    const kv = fakeKv();
    const a = mw("alpha");
    const b = mw("beta");
    const { scope } = scopeFor([a, b], { kv });
    const ka = scope.contextFor(a, {}).kv;
    await ka.put("k", "v");
    await ka.put("t", "w", { ttl: 60 });
    expect(kv.map.get("plugin:alpha:k")).toBe("v");
    expect(kv.put).toHaveBeenLastCalledWith("plugin:alpha:t", "w", { ttl: 60 });
    expect(await ka.get("k")).toBe("v");
    expect(await scope.contextFor(b, {}).kv.get("k")).toBeNull();
    await ka.delete("k");
    expect(kv.map.has("plugin:alpha:k")).toBe(false);
  });

  it("validates keys, values and ttl", async () => {
    const p = mw("alpha");
    const ctx = scopeFor([p], { kv: fakeKv() }).scope.contextFor(p, {});
    await expect(ctx.kv.get("")).rejects.toThrow(TypeError);
    await expect(ctx.kv.put("k", 1)).rejects.toThrow(TypeError);
    await expect(ctx.kv.put("k", "v", { ttl: -1 })).rejects.toThrow(TypeError);
  });
});

describe("ctx.secret", () => {
  it("returns declared secrets and refuses (with a warning) undeclared ones", () => {
    const p = mw("alpha", { secrets: ["alpha_key"] });
    const logs = [];
    const secret = (k) => ({ alpha_key: "A", other_key: "O" })[k];
    const ctx = scopeFor([p], { secret, logs }).scope.contextFor(p, {});
    expect(ctx.secret("alpha_key")).toBe("A");
    expect(ctx.secret("other_key")).toBeUndefined();
    const warn = logs.find((l) => l.level === "warn");
    expect(warn).toMatchObject({ plugin: "alpha", requestId: "rid-9", key: "other_key" });
    expect(JSON.stringify(logs)).not.toContain("\"O\"");
  });

  it("returns undefined when no secret lookup is configured", () => {
    const p = mw("alpha", { secrets: ["alpha_key"] });
    expect(scopeFor([p]).scope.contextFor(p, {}).secret("alpha_key")).toBeUndefined();
  });
});

describe("ctx.log", () => {
  it("carries the request id and plugin name, which callers cannot override", () => {
    const p = mw("alpha");
    const logs = [];
    scopeFor([p], { logs }).scope.contextFor(p, {}).log.info("hello", { requestId: "spoof", plugin: "spoof", n: 1 });
    expect(logs[0]).toEqual({ event: "hello", n: 1, level: "info", requestId: "rid-9", plugin: "alpha" });
  });

  it("makeLogger/defaultLogSink write one JSON line by level", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const l = makeLogger(defaultLogSink, { requestId: "r" });
      l.info("i"); l.warn("w"); l.error("e");
      expect(JSON.parse(log.mock.calls[0][0])).toEqual({ event: "i", level: "info", requestId: "r" });
      expect(warn).toHaveBeenCalledOnce();
      expect(error).toHaveBeenCalledOnce();
    } finally {
      log.mockRestore(); warn.mockRestore(); error.mockRestore();
    }
  });

  it("errorSummary keeps name and message only", () => {
    expect(errorSummary(new TypeError("boom"))).toBe("TypeError: boom");
    expect(errorSummary("x")).toBe("x");
  });
});

describe("ctx.fetch", () => {
  it("is budgeted and egress-checked per plugin", async () => {
    const p = mw("alpha", { egress: ["https://api.example.com"], maxFetches: 1 });
    const { scope, budget } = scopeFor([p]);
    const ctx = scope.contextFor(p, {});
    await ctx.fetch("https://api.example.com/x");
    await expect(ctx.fetch("https://api.example.com/y")).rejects.toMatchObject({ code: "budget_exceeded" });
    await expect(scope.contextFor(p, {}).fetch("https://evil.example/")).rejects.toMatchObject({ code: "egress_denied" });
    expect(budget.used()).toBe(1);
  });
});

describe("ctx.replaceRequest", () => {
  it("replaces the request seen by later hooks", async () => {
    const p = mw("alpha");
    const { scope } = scopeFor([p], { url: "https://gate.example/form" });
    const ctx = scope.contextFor(p, {});
    ctx.replaceRequest(new Request("https://gate.example/form", { headers: { "x-n": "2" } }));
    expect(scope.contextFor(p, {}).request.headers.get("x-n")).toBe("2");
    expect(ctx.request.headers.get("x-n")).toBe("2");
  });

  it("re-strips reserved headers from the replacement", () => {
    const p = mw("alpha", { trustedHeaderPrefixes: ["x-alpha-"] });
    const { scope } = scopeFor([p], { url: "https://gate.example/form" });
    scope.contextFor(p, {}).replaceRequest(new Request("https://gate.example/form", {
      headers: { "x-auth-subject": "admin", "x-alpha-score": "1", keep: "y" },
    }));
    expect(scope.request.headers.has("x-auth-subject")).toBe(false);
    expect(scope.request.headers.has("x-alpha-score")).toBe(false);
    expect(scope.request.headers.get("keep")).toBe("y");
  });

  it("refuses a different URL or method, or a non-Request", () => {
    const p = mw("alpha");
    const { scope } = scopeFor([p], { url: "https://gate.example/public" });
    const ctx = scope.contextFor(p, {});
    expect(() => ctx.replaceRequest(new Request("https://gate.example/protected/x"))).toThrow(/URL/);
    expect(() => ctx.replaceRequest(new Request("https://gate.example/public", { method: "POST" }))).toThrow(/method/);
    expect(() => ctx.replaceRequest({ url: "https://gate.example/public" })).toThrow(TypeError);
  });
});

describe("stripReservedHeaders", () => {
  it("returns the same request when nothing is reserved", () => {
    const r = new Request("https://g.example/", { headers: { a: "1" } });
    expect(stripReservedHeaders(r, ["x-auth-"])).toBe(r);
  });

  it("removes every header under a reserved prefix, keeping method and body", async () => {
    const r = new Request("https://g.example/", { method: "POST", body: "b=1", headers: { "X-Auth-Subject": "s", "x-p-a": "1", ok: "1" } });
    const out = stripReservedHeaders(r, ["x-auth-", "x-p-"]);
    expect([...out.headers.keys()].sort()).toEqual(["content-type", "ok"]);
    expect(out.method).toBe("POST");
    expect(await out.text()).toBe("b=1");
  });
});

describe("ctx.lifecycle", () => {
  it("is present for authenticators only", () => {
    const a = auth("sess");
    const m = mw("alpha");
    const { scope } = scopeFor([a, m]);
    expect(typeof scope.contextFor(a, {}).lifecycle.emitLogin).toBe("function");
    expect(scope.contextFor(m, {}).lifecycle).toBeUndefined();
  });

  it("emitLogin runs onLogin of every ENABLED plugin except the emitter, in registry order", async () => {
    const order = [];
    const sess = auth("sess", { onLogin: async () => order.push("sess") });
    const one = mw("one", { onLogin: async (ctx, draft, opts) => { order.push(`one:${opts.v}:${ctx.options.v}`); draft.addGroups(["g1"]); } });
    const off = mw("off", { onLogin: async () => order.push("off") });
    const two = mw("two", { onLogin: async (ctx, draft) => { order.push("two"); draft.setAttr("tier", "gold"); } });
    const enabled = new Map([["two", {}], ["sess", {}], ["one", { v: 7 }]]);
    const { scope } = scopeFor([sess, one, off, two], { enabled });
    const draft = createIdentityDraft({ sub: "u" });
    await scope.contextFor(sess, {}).lifecycle.emitLogin(draft);
    expect(order).toEqual(["one:7:7", "two"]);
    expect(draft.groups).toEqual(["g1"]);
    expect(draft.attrs).toEqual({ tier: "gold" });
  });

  it("emitLogin propagates a subscriber error (fail closed) and stops", async () => {
    const after = vi.fn();
    const sess = auth("sess");
    const bad = mw("bad", { onLogin: async () => { throw new Error("backend down"); } });
    const later = mw("later", { onLogin: after });
    const { scope } = scopeFor([sess, bad, later], { enabled: new Map([["sess", {}], ["bad", {}], ["later", {}]]) });
    await expect(scope.contextFor(sess, {}).lifecycle.emitLogin(createIdentityDraft({ sub: "u" }))).rejects.toThrow("backend down");
    expect(after).not.toHaveBeenCalled();
  });

  it("emitLogin rejects a non-draft", async () => {
    const sess = auth("sess");
    const { scope } = scopeFor([sess]);
    await expect(scope.contextFor(sess, {}).lifecycle.emitLogin({ sub: "u" })).rejects.toThrow(TypeError);
  });

  it("emitLogin cannot be re-entered from a lifecycle hook", async () => {
    const sess = auth("sess");
    const other = auth("other", { onLogin: async (ctx, draft) => ctx.lifecycle.emitLogin(draft) });
    const { scope } = scopeFor([sess, other], { enabled: new Map([["sess", {}], ["other", {}]]) });
    await expect(scope.contextFor(sess, {}).lifecycle.emitLogin(createIdentityDraft({ sub: "u" }))).rejects.toThrow(/lifecycle hook/);
  });

  it("emitLogout runs every enabled onLogout, logging and swallowing errors", async () => {
    const seen = [];
    const sess = auth("sess");
    const bad = mw("bad", { onLogout: async () => { throw new Error("nope"); } });
    const good = mw("good", { onLogout: async (ctx, identity) => seen.push(identity && identity.sub) });
    const logs = [];
    const { scope } = scopeFor([sess, bad, good], { enabled: new Map([["sess", {}], ["bad", {}], ["good", {}]]), logs });
    const id = createIdentity({ sub: "u1", method: "m", issuedAt: 1, expiresAt: 2 });
    await expect(scope.contextFor(sess, {}).lifecycle.emitLogout(id)).resolves.toBeUndefined();
    expect(seen).toEqual(["u1"]);
    expect(logs.find((l) => l.level === "error")).toMatchObject({ plugin: "bad", requestId: "rid-9" });
  });
});
