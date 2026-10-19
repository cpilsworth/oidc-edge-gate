import { describe, it, expect } from "vitest";
import { definePlugin, PluginDefinitionError } from "../../src/sdk/index.js";
import { createRegistry, resolveRoutes, resolveEgress } from "../../src/kernel/registry.js";

const noop = async () => {};
const mw = (name, extra = {}) => definePlugin({ name, kind: "middleware", phases: ["beforeForward"], beforeForward: noop, ...extra });
const auth = (name, extra = {}) => definePlugin({ name, kind: "authenticator", authenticate: async () => null, ...extra });

describe("createRegistry", () => {
  it("exposes plugins in registration order", () => {
    const a = mw("alpha");
    const b = auth("beta-auth");
    const reg = createRegistry([a, b]);
    expect(reg.list().map((p) => p.name)).toEqual(["alpha", "beta-auth"]);
    expect(reg.get("alpha")).toBe(a);
    expect(reg.has("beta-auth")).toBe(true);
    expect(reg.has("nope")).toBe(false);
    expect(reg.get("nope")).toBeUndefined();
    expect(Object.isFrozen(reg)).toBe(true);
  });

  it("list() returns a copy", () => {
    const reg = createRegistry([mw("alpha")]);
    reg.list().pop();
    expect(reg.list()).toHaveLength(1);
  });

  it("reservedHeaderPrefixes starts with x-auth- and adds every plugin prefix", () => {
    const reg = createRegistry([
      mw("alpha", { trustedHeaderPrefixes: ["x-alpha-"] }),
      mw("beta", { trustedHeaderPrefixes: ["x-beta-", "x-bee-"] }),
    ]);
    expect(reg.reservedHeaderPrefixes()).toEqual(["x-auth-", "x-alpha-", "x-beta-", "x-bee-"]);
  });

  it("ownedCookies lists every declared cookie and cookieOwner maps it back", () => {
    const reg = createRegistry([mw("alpha", { cookies: ["__Host-a"] }), auth("sess", { cookies: ["__Host-s", "st"] })]);
    expect(reg.ownedCookies()).toEqual(["__Host-a", "__Host-s", "st"]);
    expect(reg.cookieOwner("st")).toBe("sess");
    expect(reg.cookieOwner("other")).toBeUndefined();
  });

  it("an empty registry still reserves x-auth-", () => {
    const reg = createRegistry([]);
    expect(reg.reservedHeaderPrefixes()).toEqual(["x-auth-"]);
    expect(reg.ownedCookies()).toEqual([]);
  });

  it("rejects a non-array", () => {
    expect(() => createRegistry(null)).toThrow(PluginDefinitionError);
  });

  it("rejects an object that is not a definePlugin() result", () => {
    const raw = { name: "raw", kind: "middleware", phases: [], beforeForward: noop };
    expect(() => createRegistry([raw])).toThrow(PluginDefinitionError);
    expect(() => createRegistry([Object.freeze(raw)])).toThrow(/definePlugin/);
    expect(() => createRegistry([null])).toThrow(PluginDefinitionError);
    expect(() => createRegistry(["alpha"])).toThrow(PluginDefinitionError);
  });

  it("rejects duplicate plugin names", () => {
    expect(() => createRegistry([mw("alpha"), auth("alpha")])).toThrow(/twice/);
  });

  it("rejects two plugins declaring the same cookie", () => {
    expect(() => createRegistry([mw("alpha", { cookies: ["c"] }), mw("beta", { cookies: ["c"] })]))
      .toThrow(/already declared by plugin "alpha"/);
  });

  it("rejects two plugins declaring the same header prefix", () => {
    expect(() => createRegistry([mw("alpha", { trustedHeaderPrefixes: ["x-p-"] }), mw("beta", { trustedHeaderPrefixes: ["x-p-"] })]))
      .toThrow(PluginDefinitionError);
  });

  it("rejects overlapping header prefixes in either direction", () => {
    expect(() => createRegistry([mw("alpha", { trustedHeaderPrefixes: ["x-p-"] }), mw("beta", { trustedHeaderPrefixes: ["x-p-q-"] })]))
      .toThrow(/collides/);
    expect(() => createRegistry([mw("alpha", { trustedHeaderPrefixes: ["x-p-q-"] }), mw("beta", { trustedHeaderPrefixes: ["x-p-"] })]))
      .toThrow(/collides/);
  });

  it("rejects two plugins declaring the same secret key (W2.R R11)", () => {
    expect(() => createRegistry([mw("alpha", { secrets: ["shared_key"] }), mw("beta", { secrets: ["other", "shared_key"] })]))
      .toThrow(PluginDefinitionError);
    expect(() => createRegistry([mw("alpha", { secrets: ["shared_key"] }), auth("beta-auth", { secrets: ["shared_key"] })]))
      .toThrow(/secret "shared_key" is already declared by plugin "alpha"/);
    expect(() => createRegistry([mw("alpha", { secrets: ["a_key"] }), mw("beta", { secrets: ["b_key"] })])).not.toThrow();
  });

  it("the registered plugins declare disjoint secrets", async () => {
    const { default: plugins } = await import("../../plugins/index.js");
    expect(() => createRegistry(plugins)).not.toThrow();
  });

  it("identityHeaderPrefixes lists the prefixes of identityHeaders: true plugins only (W2.R R2)", () => {
    const reg = createRegistry([
      mw("alpha", { trustedHeaderPrefixes: ["x-alpha-"], identityHeaders: true }),
      mw("beta", { trustedHeaderPrefixes: ["x-beta-"] }),
    ]);
    expect(reg.identityHeaderPrefixes()).toEqual(["x-alpha-"]);
    expect(createRegistry([]).identityHeaderPrefixes()).toEqual([]);
  });

  it("accepts distinct prefixes that merely share leading characters", () => {
    expect(() => createRegistry([mw("alpha", { trustedHeaderPrefixes: ["x-pa-"] }), mw("beta", { trustedHeaderPrefixes: ["x-pb-"] })]))
      .not.toThrow();
  });
});

describe("resolveRoutes", () => {
  const h1 = async () => new Response("1");
  const h2 = async () => new Response("2");

  it("returns routes of enabled plugins only, with their base options", () => {
    const a = mw("alpha", { routes: { "/.auth/a": h1 } });
    const b = mw("beta", { routes: { "/.auth/b": h2 } });
    const reg = createRegistry([a, b]);
    const opts = Object.freeze({ x: 1 });
    const routes = resolveRoutes(reg, new Map([["alpha", opts]]));
    expect([...routes.keys()]).toEqual(["/.auth/a"]);
    expect(routes.get("/.auth/a")).toEqual({ plugin: a, handler: h1, options: opts });
  });

  it("calls routes(options) and uses the result", () => {
    const p = auth("sess", { routes: (o) => ({ [o.callback]: h1 }) });
    const routes = resolveRoutes(createRegistry([p]), new Map([["sess", { callback: "/.auth/cb" }]]));
    expect(routes.get("/.auth/cb").handler).toBe(h1);
  });

  it("re-validates a routes(options) result", () => {
    const p = auth("sess", { routes: () => ({ "/not-auth": h1 }) });
    expect(() => resolveRoutes(createRegistry([p]), new Map([["sess", {}]]))).toThrow(PluginDefinitionError);
    const q = auth("sess2", { routes: () => ({ "/.auth/x": "nope" }) });
    expect(() => resolveRoutes(createRegistry([q]), new Map([["sess2", {}]]))).toThrow(/handler must be a function/);
    const r = auth("sess3", { routes: () => null });
    expect(() => resolveRoutes(createRegistry([r]), new Map([["sess3", {}]]))).toThrow(PluginDefinitionError);
  });

  it("rejects two plugins claiming one path", () => {
    const a = mw("alpha", { routes: { "/.auth/x": h1 } });
    const b = mw("beta", { routes: () => ({ "/.auth/x": h2 }) });
    const reg = createRegistry([a, b]);
    expect(() => resolveRoutes(reg, new Map([["alpha", {}], ["beta", {}]]))).toThrow(/already claimed by plugin "alpha"/);
    // Not a collision when only one of them is enabled.
    expect(() => resolveRoutes(reg, new Map([["beta", {}]]))).not.toThrow();
  });

  it("rejects an enabled name that is not registered", () => {
    expect(() => resolveRoutes(createRegistry([]), new Map([["ghost", {}]]))).toThrow(/not registered/);
  });

  it("accepts a plain object for enabled and tolerates none", () => {
    const a = mw("alpha", { routes: { "/.auth/a": h1 } });
    expect(resolveRoutes(createRegistry([a]), { alpha: {} }).size).toBe(1);
    expect(resolveRoutes(createRegistry([a]), undefined).size).toBe(0);
  });
});

describe("resolveEgress", () => {
  it("returns a Set of origins from a static list", () => {
    const p = mw("alpha", { egress: ["https://api.example.com", "https://b.example.com:8443/"] });
    expect(resolveEgress(p, {})).toEqual(new Set(["https://api.example.com", "https://b.example.com:8443"]));
  });

  it("calls egress(options) and re-validates", () => {
    const p = mw("alpha", { egress: (o) => [o.base] });
    expect(resolveEgress(p, { base: "https://x.example" })).toEqual(new Set(["https://x.example"]));
    expect(() => resolveEgress(p, { base: "http://x.example" })).toThrow(PluginDefinitionError);
    expect(() => resolveEgress(p, { base: "https://x.example/path" })).toThrow(PluginDefinitionError);
    const q = mw("beta", { egress: () => "https://x.example" });
    expect(() => resolveEgress(q, {})).toThrow(/array/);
  });

  it("defaults to an empty set", () => {
    expect(resolveEgress(mw("alpha"), {}).size).toBe(0);
  });
});
