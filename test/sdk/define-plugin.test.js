import { describe, it, expect } from "vitest";
import {
  definePlugin, PluginDefinitionError, PluginError, PluginConfigError,
  createIdentity, createIdentityDraft, isIdentity, normalizeGroups, validateEgress, validateRoutes, MAX_PLUGIN_FETCHES,
  isValidGroup, MAX_GROUP_LENGTH,
} from "../../src/sdk/index.js";

const noop = async () => {};
const mw = (extra = {}) => ({ name: "demo", kind: "middleware", phases: ["beforeForward"], beforeForward: noop, ...extra });
const auth = (extra = {}) => ({ name: "demo-auth", kind: "authenticator", authenticate: async () => null, ...extra });

describe("definePlugin — valid manifests", () => {
  it("returns a frozen manifest with normalized defaults", () => {
    const p = definePlugin(mw());
    expect(Object.isFrozen(p)).toBe(true);
    expect(p.maxFetches).toBe(0);
    expect(p.trustedHeaderPrefixes).toEqual([]);
    expect(p.cookies).toEqual([]);
    expect(p.secrets).toEqual([]);
    expect(p.allowSkipOnError).toBe(false);
    expect(p.identityHeaders).toBe(false);
    expect(Object.isFrozen(p.phases)).toBe(true);
  });

  it("accepts a full middleware manifest", () => {
    const p = definePlugin(mw({
      description: "x", phases: ["request", "beforeForward", "afterForward"], request: noop, afterForward: noop,
      trustedHeaderPrefixes: ["x-demo-"], cookies: ["__Host-demo"], routes: { "/.auth/demo/ping": noop },
      egress: ["https://api.example.com"], secrets: ["demo_key"], maxFetches: 2,
      defaults: { when: { methods: ["POST"] }, on_error: "skip" }, allowSkipOnError: true,
      validate: (o) => o, handle: noop, onLogin: noop, onLogout: noop,
    }));
    expect(p.phases).toEqual(["request", "beforeForward", "afterForward"]);
  });

  it("identityHeaders: optional boolean, default false (W2.R R2)", () => {
    expect(definePlugin(mw({ trustedHeaderPrefixes: ["x-demo-"], identityHeaders: true })).identityHeaders).toBe(true);
    expect(definePlugin(mw({ identityHeaders: false })).identityHeaders).toBe(false);
    expect(definePlugin(mw()).identityHeaders).toBe(false);
  });

  it("accepts an authenticator with challenge, routes as a function and egress as a function", () => {
    const p = definePlugin(auth({ challenge: noop, routes: () => ({}), egress: (o) => [o.issuer] }));
    expect(typeof p.routes).toBe("function");
    expect(typeof p.egress).toBe("function");
  });
});

describe("definePlugin — rejects malformed manifests (fail at load, not at request time)", () => {
  const cases = [
    ["non-object", null],
    ["bad name", mw({ name: "User_Info" })],
    ["unknown key (typo)", mw({ maxFetch: 1 })],
    ["unknown kind", mw({ kind: "filter" })],
    ["unknown phase", mw({ phases: ["after"] })],
    ["repeated phase", mw({ phases: ["beforeForward", "beforeForward"] })],
    ["declared phase without hook", mw({ phases: ["request"], beforeForward: undefined })],
    ["hook without declared phase", mw({ request: noop })],
    ["middleware defining authenticate", mw({ authenticate: noop })],
    ["authenticator without authenticate", { name: "a", kind: "authenticator" }],
    ["authenticator with phases", auth({ phases: ["request"], request: noop })],
    ["authenticator with a middleware hook", auth({ beforeForward: noop })],
    ["non-function hook", mw({ onLogin: "x" })],
    ["x-auth- prefix claimed", mw({ trustedHeaderPrefixes: ["x-auth-extra-"] })],
    ["uppercase header prefix", mw({ trustedHeaderPrefixes: ["X-Demo-"] })],
    ["prefix without trailing dash", mw({ trustedHeaderPrefixes: ["x-demo"] })],
    ["invalid cookie name", mw({ cookies: ["bad cookie"] })],
    ["route outside /.auth/", mw({ routes: { "/admin": noop } })],
    ["route with trailing slash", mw({ routes: { "/.auth/x/": noop } })],
    ["route with wildcard", mw({ routes: { "/.auth/*": noop } })],
    ["route handler not a function", mw({ routes: { "/.auth/x": "nope" } })],
    ["egress http (non-loopback)", mw({ egress: ["http://api.example.com"] })],
    ["egress with path", mw({ egress: ["https://api.example.com/v1"] })],
    ["egress with credentials", mw({ egress: ["https://u:p@api.example.com"] })],
    ["secrets not snake_case", mw({ secrets: ["Demo-Key"] })],
    ["maxFetches too high", mw({ maxFetches: MAX_PLUGIN_FETCHES + 1 })],
    ["maxFetches fractional", mw({ maxFetches: 1.5 })],
    ["unknown defaults key", mw({ defaults: { order: 1 } })],
    ["bad defaults.on_error", mw({ defaults: { on_error: "ignore" } })],
    ["skip default without allowSkipOnError", mw({ defaults: { on_error: "skip" } })],
    ["unknown predicate key", mw({ defaults: { when: { path: "/x" } } })],
    ["identityHeaders not a boolean (string)", mw({ identityHeaders: "yes" })],
    ["identityHeaders not a boolean (number)", mw({ identityHeaders: 1 })],
    ["identityHeaders null", mw({ identityHeaders: null })],
  ];
  it.each(cases)("%s", (_label, manifest) => {
    expect(() => definePlugin(manifest)).toThrow(PluginDefinitionError);
  });

  it("errors name the plugin", () => {
    expect(() => definePlugin(mw({ maxFetch: 1 }))).toThrow(/plugin "demo".*maxFetch/);
  });
});

describe("validateEgress / validateRoutes (also used by the registry for function forms)", () => {
  const fail = (m) => { throw new Error(m); };
  it("allows https origins and loopback http", () => {
    expect(() => validateEgress(["https://a.example", "https://a.example:8443", "http://localhost:7681", "http://127.0.0.1"], fail)).not.toThrow();
  });
  it("rejects garbage", () => {
    expect(() => validateEgress(["not a url"], fail)).toThrow();
    expect(() => validateEgress(["https://a.example?x=1"], fail)).toThrow();
  });
  it("routes must be exact lowercase /.auth/ paths with function handlers", () => {
    expect(() => validateRoutes({ "/.auth/callback": noop, "/.auth/admin/revoke": noop }, fail)).not.toThrow();
    expect(() => validateRoutes({ "/.auth/Callback": noop }, fail)).toThrow();
  });
});

describe("PluginError / PluginConfigError", () => {
  it("carries status and snake_case code", () => {
    const e = new PluginError(400, "recaptcha_failed", "token missing");
    expect(e).toBeInstanceOf(Error);
    expect(e.status).toBe(400);
    expect(e.code).toBe("recaptcha_failed");
    expect(e.message).toBe("token missing");
  });
  it("rejects non-error statuses and bad codes", () => {
    expect(() => new PluginError(302, "x")).toThrow(TypeError);
    expect(() => new PluginError(400, "Bad-Code")).toThrow(TypeError);
  });
  it("PluginConfigError is an Error", () => {
    expect(new PluginConfigError("bad")).toBeInstanceOf(Error);
  });
});

describe("createIdentity", () => {
  const base = { sub: "u1", method: "oidc-session", issuedAt: 100, expiresAt: 200 };
  it("builds a deeply frozen identity with normalized groups", () => {
    const id = createIdentity({ ...base, email: "a@b.c", groups: ["a", "a", "", 3, "b"], attrs: { tier: "gold", n: 1 } });
    expect(id.groups).toEqual(["a", "b"]);
    expect(Object.isFrozen(id)).toBe(true);
    expect(Object.isFrozen(id.groups)).toBe(true);
    expect(Object.isFrozen(id.attrs)).toBe(true);
    expect(() => { id.groups.push("admin"); }).toThrow();
  });
  it.each([
    ["missing sub", { ...base, sub: "" }],
    ["missing method", { ...base, method: undefined }],
    ["non-numeric times", { ...base, issuedAt: "100" }],
    ["non-string email", { ...base, email: 5 }],
    ["non-scalar attr", { ...base, attrs: { x: {} } }],
  ])("rejects %s", (_l, fields) => {
    expect(() => createIdentity(fields)).toThrow(TypeError);
  });
});

describe("createIdentityDraft lifetime cap", () => {
  it("clamps expiresAt to issuedAt + the smallest cap", () => {
    const d = createIdentityDraft({ sub: "u" });
    expect(d.lifetimeCap).toBeNull();
    d.limitLifetime(600);
    d.limitLifetime(300);
    d.limitLifetime(900);
    expect(d.lifetimeCap).toBe(300);
    const id = d.toIdentity({ method: "m", issuedAt: 1000, expiresAt: 4600 });
    expect(id.expiresAt).toBe(1300);
  });
  it("never lengthens a session and rejects bad caps", () => {
    const d = createIdentityDraft({ sub: "u" });
    d.limitLifetime(99999);
    expect(d.toIdentity({ method: "m", issuedAt: 1000, expiresAt: 1060 }).expiresAt).toBe(1060);
    const e = createIdentityDraft({ sub: "u" });
    for (const bad of [0, -1, 1.5, "60", NaN]) expect(() => e.limitLifetime(bad)).toThrow(TypeError);
  });
  it("cannot be set after sealing", () => {
    const d = createIdentityDraft({ sub: "u" });
    d.toIdentity({ method: "m", issuedAt: 1, expiresAt: 2 });
    expect(() => d.limitLifetime(10)).toThrow(/sealed/);
  });
});

describe("isIdentity (unforgeable brand)", () => {
  it("is true only for createIdentity()/toIdentity() results", () => {
    const real = createIdentity({ sub: "u", method: "m", issuedAt: 1, expiresAt: 2 });
    expect(isIdentity(real)).toBe(true);
    expect(isIdentity(createIdentityDraft({ sub: "u" }).toIdentity({ method: "m", issuedAt: 1, expiresAt: 2 }))).toBe(true);
    const copy = Object.freeze({ ...real, groups: Object.freeze([...real.groups]), attrs: Object.freeze({}) });
    expect(isIdentity(copy)).toBe(false);
    expect(isIdentity(null)).toBe(false);
    expect(isIdentity("u")).toBe(false);
  });
});

describe("normalizeGroups", () => {
  it("handles string, array, and junk", () => {
    expect(normalizeGroups("medical")).toEqual(["medical"]);
    expect(normalizeGroups(["x", "x", null, "y"])).toEqual(["x", "y"]);
    expect(normalizeGroups(undefined)).toEqual([]);
    expect(normalizeGroups({ a: 1 })).toEqual([]);
    // F17: x-auth-groups is comma-joined, so a group with "," (or a control char) is ambiguous: dropped.
    expect(normalizeGroups(["ok", "a,admin", "evil\nx", "tab\tx", "nul\u0000", "del\u007f", "c1\u0085", "fine-group", "has space"]))
      .toEqual(["ok", "fine-group", "has space"]);
    expect(normalizeGroups("medical,admin")).toEqual([]);
  });

  it("W2.R R3: keeps only printable ASCII, no comma, no edge whitespace, length 1..128", () => {
    const long = "g".repeat(MAX_GROUP_LENGTH);
    expect(normalizeGroups([
      "medical", "market-access", "site-readers", "https://oidc.workers.dev/groups", "a", "a b", "x_y.z:1~!", long,
      " lead", "trail ", " ", "", `${long}g`, "Cardiología", "naïve", "emoji-\u{1F600}", "nbsp\u00a0x", "a,b", "c1\u0085",
    ])).toEqual(["medical", "market-access", "site-readers", "https://oidc.workers.dev/groups", "a", "a b", "x_y.z:1~!", long]);
    for (const g of ["medical", "market-access", "site-readers", long]) expect(isValidGroup(g), g).toBe(true);
    for (const g of [" a", "a ", "", `${long}g`, "é", "a,b", 1, null]) expect(isValidGroup(g), String(g)).toBe(false);
  });
});

describe("createIdentityDraft", () => {
  it("lets subscribers add groups/attrs but not change sub/email/name, then seals", () => {
    const d = createIdentityDraft({ sub: "u1", email: "a@b.c", groups: [], claims: { iss: "x" } });
    d.addGroups(["medical", "medical", "market-access"]);
    d.setAttr("customerId", "C42");
    expect(() => { d.sub = "admin"; }).toThrow();
    expect(() => { d.claims.iss = "y"; }).toThrow();
    expect(() => d.setAttr("bad key", 1)).toThrow(TypeError);
    expect(() => d.setAttr("obj", {})).toThrow(TypeError);
    const id = d.toIdentity({ method: "oidc-session", sessionId: "s1", issuedAt: 1, expiresAt: 2 });
    expect(id.groups).toEqual(["medical", "market-access"]);
    expect(id.attrs).toEqual({ customerId: "C42" });
    expect(id.sessionId).toBe("s1");
    expect(() => d.addGroups(["late"])).toThrow(/sealed/);
  });

  it("W2.R R6: addGroups de-duplicates against existing groups in linear time, order preserved", () => {
    const d = createIdentityDraft({ sub: "u1", groups: ["b", "a"] });
    d.addGroups(["a", "c", "b", "c", " bad", "d"]);
    expect(d.groups).toEqual(["b", "a", "c", "d"]);
    const big = Array.from({ length: 20000 }, (_, i) => `g${i}`);
    const t0 = Date.now();
    d.addGroups(big);
    d.addGroups(big);
    expect(Date.now() - t0).toBeLessThan(1000); // quadratic (Array.includes) would be ~4e8 comparisons
    expect(d.groups).toHaveLength(20004);
  });
});
