// W1.2: policy v2 compiler (src/kernel/policy.js). Ports every case from
// test/policy.test.js to the new API, then covers the v2 additions: load
// errors, legacy upgrades, plugin option merge/validate, predicates,
// middleware ordering, and an equivalence check against the legacy
// classifier on the REAL sandbox and provisioned policies. src/policy.js was
// deleted in W1.3; the equivalence check now runs against a frozen copy of
// its compile/classify logic (`legacy` below, test-only).
//
// The registry here is a small fake built from definePlugin manifests (it does
// not import W1.1's src/kernel/registry.js).
//
// SECURITY: the real policies carry a shared secret as a header VALUE under
// /form/*. This file only ever compares header NAMES.
import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { definePlugin, PluginConfigError, CORE_HEADER_PREFIX } from "../../src/sdk/index.js";
import {
  compilePolicy, classify, compilePredicate, audienceAllows, PolicyError,
} from "../../src/kernel/policy.js";
import { EMBEDDED_CONFIGS } from "../../src/embedded-config.js";
import { extractYamlConfigs, DEFAULT_YAML_PATH } from "../../scripts/check-config-parity.mjs";

// --- fake registry ------------------------------------------------------------------

function createFakeRegistry(manifests) {
  const byName = new Map();
  for (const m of manifests) {
    if (byName.has(m.name)) throw new Error(`duplicate plugin ${m.name}`);
    byName.set(m.name, m);
  }
  return {
    get: (name) => byName.get(name),
    has: (name) => byName.has(name),
    list: () => [...byName.values()],
    reservedHeaderPrefixes: () => [CORE_HEADER_PREFIX, ...[...byName.values()].flatMap((m) => m.trustedHeaderPrefixes)],
    ownedCookies: () => [...byName.values()].flatMap((m) => m.cookies),
  };
}

const noop = () => {};

function makePlugins({ recaptchaValidate } = {}) {
  return [
    definePlugin({
      name: "oidc-auth",
      kind: "authenticator",
      cookies: ["__Host-edge_session"],
      authenticate: async () => null,
      challenge: async () => null,
      validate: (o) => o,
    }),
    definePlugin({
      name: "basic-auth",
      kind: "authenticator",
      authenticate: async () => null,
    }),
    definePlugin({
      name: "recaptcha",
      kind: "middleware",
      phases: ["beforeForward"],
      trustedHeaderPrefixes: ["x-recaptcha-"],
      beforeForward: noop,
      validate: recaptchaValidate || ((o) => {
        if (o.min_score !== undefined && typeof o.min_score !== "number") throw new PluginConfigError("min_score must be a number");
        return { min_score: 0.5, ...o };
      }),
    }),
    definePlugin({
      name: "security-headers",
      kind: "middleware",
      phases: ["afterForward"],
      afterForward: noop,
      allowSkipOnError: true,
      defaults: { on_error: "skip" },
    }),
    definePlugin({
      name: "early",
      kind: "middleware",
      phases: ["request"],
      request: noop,
    }),
    definePlugin({
      name: "html-only",
      kind: "middleware",
      phases: ["beforeForward"],
      beforeForward: noop,
      defaults: { when: { accept: "html", methods: ["GET"] } },
    }),
    definePlugin({
      name: "user-info",
      kind: "middleware",
      trustedHeaderPrefixes: ["x-user-info-"],
      onLogin: async () => {},
    }),
    definePlugin({
      name: "api-proxy",
      kind: "middleware",
      handle: async () => new Response("ok"),
    }),
  ];
}

const registry = createFakeRegistry(makePlugins());
const compile = (raw, reg = registry, env) => compilePolicy(raw, reg, env);

/** The legacy test's shape: tier + audience only (plus present extras). */
const ta = (c) => ({ tier: c.tier, audience: c.audience });

// --- ported from test/policy.test.js -------------------------------------------------

const policy = compile({
  rules: [
    { path: "/", tier: "public" },
    { path: "/blog/*", tier: "public" },
    { path: "/media_*", tier: "public" },
    { path: "/*.plain.html", tier: "public" },
    { path: "/members/*", tier: "protected", audience: ["site-readers"] },
    { path: "/members/admin/*", tier: "protected", audience: ["admins"] },
    { path: "/api/*", tier: "secured", audience: ["site-readers"] },
  ],
  default_tier: "protected",
});

describe("classify (ported)", () => {
  it("exact root match is public", () => {
    expect(ta(classify("/", policy))).toEqual({ tier: "public", audience: undefined });
  });
  it("prefix globs match", () => {
    expect(classify("/blog/2026/post", policy).tier).toBe("public");
    expect(classify("/media_abc123.png", policy).tier).toBe("public");
    expect(classify("/foo.plain.html", policy).tier).toBe("public");
  });
  it("most-specific rule wins (longer literal prefix)", () => {
    expect(ta(classify("/members/x", policy))).toEqual({ tier: "protected", audience: ["site-readers"] });
    expect(ta(classify("/members/admin/y", policy))).toEqual({ tier: "protected", audience: ["admins"] });
  });
  it("a trailing /* also covers the section's bare path, so its audience applies there too", () => {
    expect(ta(classify("/members/admin", policy))).toEqual({ tier: "protected", audience: ["admins"] });
    expect(ta(classify("/members/admin/", policy))).toEqual({ tier: "protected", audience: ["admins"] });
    expect(ta(classify("/members", policy))).toEqual({ tier: "protected", audience: ["site-readers"] });
    expect(classify("/blog", policy).tier).toBe("public");
  });
  it("bare-path coverage stops at a segment boundary", () => {
    expect(ta(classify("/members/administrator", policy))).toEqual({ tier: "protected", audience: ["site-readers"] });
    expect(ta(classify("/blogpost", policy))).toEqual({ tier: "protected", audience: undefined });
    expect(classify("/blogpost", policy).rule).toBeNull();
  });
  it("wildcards not at the end of a /-segment keep the plain any-characters meaning", () => {
    expect(classify("/media_", policy).tier).toBe("public");
    expect(ta(classify("/media", policy))).toEqual({ tier: "protected", audience: undefined });
    expect(classify("/x/y.plain.html", policy).tier).toBe("public");
  });
  it("secured tier carries its audience", () => {
    expect(ta(classify("/api/orders", policy))).toEqual({ tier: "secured", audience: ["site-readers"] });
  });
  it("unmatched path falls to default_tier with no audience", () => {
    expect(ta(classify("/totally/new/route", policy))).toEqual({ tier: "protected", audience: undefined });
  });
  it("surfaces a rule's upstream override", () => {
    const p = compile({ rules: [{ path: "/api/*", tier: "secured", upstream: "https://swapi.dev" }], default_tier: "protected" });
    const c = classify("/api/people", p);
    expect({ tier: c.tier, audience: c.audience, upstream: c.upstream }).toEqual({
      tier: "secured", audience: undefined, upstream: "https://swapi.dev",
    });
  });
  it("keeps a trailing-slash upstream as configured", () => {
    const p = compile({ rules: [{ path: "/form/*", tier: "public", upstream: "https://httpbun.com/" }] });
    expect(classify("/form/x", p).upstream).toBe("https://httpbun.com/");
  });
  it("rules are sorted most-specific-first (exact patterns before globs)", () => {
    expect(policy.rules.map((r) => r.path)).toEqual([
      "/", "/members/admin/*", "/members/*", "/media_*", "/blog/*", "/api/*", "/*.plain.html",
    ]);
  });
});

describe("classify — recaptcha (ported: legacy flag -> middleware ref)", () => {
  it("no recaptcha flag configured -> no middleware", () => {
    const p = compile({ rules: [{ path: "/x", tier: "public" }], default_tier: "protected" });
    expect(classify("/x", p).middleware).toEqual([]);
  });
  // F7: the legacy flag now covers every state-changing method, not only POST.
  it("recaptcha: true surfaces a recaptcha ref (state-changing methods)", () => {
    const p = compile({ rules: [{ path: "/form/*", tier: "public", recaptcha: true }], default_tier: "protected" });
    const refs = classify("/form/submit", p).middleware;
    expect(refs.map((r) => r.use)).toEqual(["recaptcha"]);
    expect(refs[0].source).toBe("rule");
    expect(refs[0].onError).toBe("fail");
    expect(refs[0].when.predicate).toEqual({ methods: ["POST", "PUT", "PATCH", "DELETE"] });
    for (const m of ["POST", "PUT", "PATCH", "DELETE"]) expect(refs[0].when(input({ method: m }))).toBe(true);
    expect(refs[0].when(input({ method: "GET" }))).toBe(false);
    expect(refs[0].when(input({ method: "HEAD" }))).toBe(false);
    expect(p.enabled.has("recaptcha")).toBe(true);
  });
  it("unmatched path falling to default_tier has no recaptcha ref", () => {
    const p = compile({ rules: [], default_tier: "public" });
    expect(classify("/anything", p).middleware).toEqual([]);
  });
  it("rejects a non-boolean recaptcha value", () => {
    expect(() => compile({ rules: [{ path: "/x", tier: "public", recaptcha: "true" }] })).toThrow(/recaptcha must be a boolean/);
  });
  it("accepts recaptcha: false explicitly (no ref, warning)", () => {
    const p = compile({ rules: [{ path: "/x", tier: "public", recaptcha: false }] });
    expect(classify("/x", p).middleware).toEqual([]);
    expect(p.warnings.some((w) => /recaptcha: false/.test(w))).toBe(true);
  });
  it("recaptcha: true without a registered recaptcha plugin is a load error", () => {
    const reg = createFakeRegistry(makePlugins().filter((m) => m.name !== "recaptcha"));
    expect(() => compile({ rules: [{ path: "/f/*", tier: "public", recaptcha: true }] }, reg)).toThrow(/unknown plugin "recaptcha"/);
  });
});

describe("classify — policy-configured headers (ported)", () => {
  it("no headers configured -> undefined (not an empty object)", () => {
    const p = compile({ rules: [{ path: "/x", tier: "public" }], default_tier: "protected" });
    expect(classify("/x", p).headers).toBeUndefined();
  });
  it("surfaces a rule's own headers", () => {
    const p = compile({ rules: [{ path: "/form/*", tier: "public", headers: { "x-form-secret": "abc" } }], default_tier: "protected" });
    expect(classify("/form/submit", p).headers).toEqual({ "x-form-secret": "abc" });
  });
  it("does NOT merge default_headers into a rule's own headers", () => {
    const p = compile({
      rules: [
        { path: "/a", tier: "public" },
        { path: "/b", tier: "public", headers: { shared: "rule-b" } },
      ],
      default_headers: { shared: "default", "x-common": "yes" },
      default_tier: "protected",
    });
    expect(classify("/a", p).headers).toBeUndefined();
    expect(classify("/b", p).headers).toEqual({ shared: "rule-b" });
    expect(p.defaultHeaders).toEqual({ shared: "default", "x-common": "yes" });
  });
  it("unmatched path falling to default_tier has no rule-specific headers", () => {
    const p = compile({ rules: [], default_headers: { "x-common": "yes" }, default_tier: "public" });
    const c = classify("/anything", p);
    expect({ tier: c.tier, audience: c.audience, upstream: c.upstream, headers: c.headers }).toEqual({
      tier: "public", audience: undefined, upstream: undefined, headers: undefined,
    });
  });
});

describe("compilePolicy — header validation (ported + plugin prefixes)", () => {
  it("rejects a non-object headers value", () => {
    expect(() => compile({ rules: [{ path: "/x", tier: "public", headers: "nope" }] })).toThrow(/must be an object/);
  });
  it("rejects a non-string header value", () => {
    expect(() => compile({ rules: [{ path: "/x", tier: "public", headers: { a: 1 } }] })).toThrow(/must be a string/);
  });
  it("rejects a non-object default_headers value", () => {
    expect(() => compile({ rules: [], default_headers: ["nope"] })).toThrow(/must be an object/);
  });
  it("rejects an invalid header name", () => {
    expect(() => compile({ rules: [{ path: "/x", tier: "public", headers: { "bad name": "v" } }] })).toThrow(/not a valid header name/);
  });

  // x-recaptcha-* and x-user-info-* come from the fake registry's declared prefixes.
  for (const reserved of ["host", "Cookie", "set-cookie", "X-Forwarded-Host", "x-push-invalidation", "x-auth-subject", "x-recaptcha-score", "X-User-Info-Tier"]) {
    it(`rejects the gate-managed header "${reserved}" in a rule's headers`, () => {
      expect(() => compile({ rules: [{ path: "/x", tier: "public", headers: { [reserved]: "v" } }] })).toThrow(/gate-managed/);
    });
    it(`rejects the gate-managed header "${reserved}" in default_headers`, () => {
      expect(() => compile({ rules: [], default_headers: { [reserved]: "v" } })).toThrow(/gate-managed/);
    });
  }
  it("a prefix is reserved only when a registered plugin declares it", () => {
    const reg = createFakeRegistry(makePlugins().filter((m) => m.name !== "user-info"));
    expect(() => compile({ rules: [{ path: "/x", tier: "public", headers: { "x-user-info-tier": "v" } }] }, reg)).not.toThrow();
  });
});

describe("compilePolicy validation (ported)", () => {
  it("rejects an unknown rule tier at load", () => {
    expect(() => compile({ rules: [{ path: "/x", tier: "protetced" }], default_tier: "protected" })).toThrow(/unknown policy tier/);
  });
  it("rejects an unknown default_tier at load", () => {
    expect(() => compile({ rules: [], default_tier: "secret" })).toThrow(/unknown default_tier/);
  });
  it("defaults to protected when default_tier is omitted", () => {
    expect(compile({ rules: [] }).defaultTier).toBe("protected");
  });
  it("handles a missing rules array", () => {
    const p = compile({ default_tier: "public" });
    expect(p.rules).toEqual([]);
    expect(classify("/anything", p).tier).toBe("public");
  });
  it("handles a missing default_tier", () => {
    expect(compile({ rules: [{ path: "/", tier: "public" }] }).defaultTier).toBe("protected");
  });
  it("load errors are PolicyErrors", () => {
    expect(() => compile({ rules: [], default_tier: "secret" })).toThrow(PolicyError);
  });
});

describe("audienceAllows (ported from isAuthorized)", () => {
  it("no audience required → any identity passes", () => {
    expect(audienceAllows({ groups: [] }, undefined)).toBe(true);
    expect(audienceAllows({ groups: ["x"] }, [])).toBe(true);
    expect(audienceAllows(null, [])).toBe(true);
  });
  it("group intersection decides authorization", () => {
    expect(audienceAllows({ groups: ["site-readers"] }, ["site-readers"])).toBe(true);
    expect(audienceAllows({ groups: ["other"] }, ["site-readers"])).toBe(false);
    expect(audienceAllows({}, ["site-readers"])).toBe(false);
    expect(audienceAllows(null, ["site-readers"])).toBe(false);
  });
});

// --- version + structure ---------------------------------------------------------------

describe("compilePolicy — versions", () => {
  const v2 = (extra = {}) => ({ version: 2, authentication: { use: "oidc-auth" }, rules: [], ...extra });

  it("version 2 compiles without upgrade warnings", () => {
    const p = compile(v2());
    expect(p.version).toBe(2);
    expect(p.warnings).toEqual([]);
    expect(p.authentication).toEqual({ use: "oidc-auth", options: {} });
  });
  it("no version key is legacy (version 1)", () => {
    expect(compile({ rules: [] }).version).toBe(1);
  });
  it.each([1, 3, "2", null])("rejects version %j", (version) => {
    expect(() => compile({ version, rules: [] })).toThrow(/unsupported version/);
  });
  it("rejects a non-object policy", () => {
    expect(() => compile(null)).toThrow(/must be a JSON object/);
    expect(() => compile([])).toThrow(/must be a JSON object/);
  });
  it("rejects an unknown top-level key", () => {
    expect(() => compile(v2({ defaults_tier: "public" }))).toThrow(/unknown top-level key "defaults_tier"/);
  });
  it("rejects a non-array rules value", () => {
    expect(() => compile(v2({ rules: {} }))).toThrow(/rules must be an array/);
  });
  it("v2 does not default the authenticator (invariant 6)", () => {
    expect(() => compile({ version: 2, rules: [] })).toThrow(/no "authentication" plugin/);
  });
  it("the compiled policy is frozen", () => {
    const p = compile(v2({ rules: [{ path: "/a", tier: "public" }] }));
    expect(Object.isFrozen(p)).toBe(true);
    expect(Object.isFrozen(p.rules)).toBe(true);
    expect(Object.isFrozen(p.rules[0])).toBe(true);
  });
});

// --- rule-level load errors -------------------------------------------------------------

describe("compilePolicy — rule load errors", () => {
  const withRule = (rule) => ({ version: 2, authentication: { use: "oidc-auth" }, rules: [rule] });
  const bad = (rule, re) => expect(() => compile(withRule(rule))).toThrow(re);

  it("unknown rule key", () => bad({ path: "/x", tier: "public", tiers: "x" }, /unknown key "tiers"/));
  it("non-object rule", () => bad("nope", /must be an object/));
  it("missing path", () => bad({ tier: "public" }, /path must be a non-empty string/));
  it("empty path", () => bad({ path: "", tier: "public" }, /path must be a non-empty string/));
  it("path without a leading slash", () => bad({ path: "x/*", tier: "public" }, /starting with "\/"/));
  it("missing tier", () => bad({ path: "/x" }, /unknown policy tier/));
  it("unknown auth value", () => bad({ path: "/x", tier: "public", auth: "maybe" }, /auth must be/));
  it("auth required on a public rule", () => bad({ path: "/x", tier: "public", auth: "required" }, /not allowed on a public rule/));
  it("auth optional on a protected rule", () => bad({ path: "/x", tier: "protected", auth: "optional" }, /not allowed on a protected rule/));
  it("auth none on a secured rule", () => bad({ path: "/x", tier: "secured", auth: "none" }, /not allowed on a secured rule/));
  it("audience not an array", () => bad({ path: "/x", tier: "protected", audience: "medical" }, /audience must be an array/));
  it("audience with an empty string", () => bad({ path: "/x", tier: "protected", audience: [""] }, /audience must be an array of non-empty strings/));
  it("audience with a non-string", () => bad({ path: "/x", tier: "protected", audience: [1] }, /audience must be an array of non-empty strings/));
  it("audience on an auth: none rule", () => bad({ path: "/x", tier: "public", audience: ["a"] }, /audience requires an identity/));
  it("upstream not a URL", () => bad({ path: "/x", tier: "public", upstream: "swapi.dev" }, /not an absolute URL/));
  it("upstream not a string", () => bad({ path: "/x", tier: "public", upstream: 5 }, /upstream must be an absolute URL string/));
  it("upstream over http", () => bad({ path: "/x", tier: "public", upstream: "http://swapi.dev" }, /must be https/));
  it("upstream with another scheme", () => bad({ path: "/x", tier: "public", upstream: "ftp://swapi.dev" }, /must be https/));
  it("upstream with a query", () => bad({ path: "/x", tier: "public", upstream: "https://swapi.dev/?a=1" }, /query or fragment/));
  it("upstream with an empty query", () => bad({ path: "/x", tier: "public", upstream: "https://swapi.dev/?" }, /query or fragment/));
  it("upstream with a hash", () => bad({ path: "/x", tier: "public", upstream: "https://swapi.dev/#x" }, /query or fragment/));
  it("upstream with credentials", () => bad({ path: "/x", tier: "public", upstream: "https://u:p@swapi.dev" }, /credentials/));
  it("upstream on a plugin handler", () => bad({ path: "/x", tier: "public", handler: "api-proxy", upstream: "https://swapi.dev" }, /upstream applies only to handler "origin"/));
  it("secret_headers not an object", () => bad({ path: "/x", tier: "public", secret_headers: ["x"] }, /secret_headers must be an object/));
  it("secret_headers with a non-snake_case key", () => bad({ path: "/x", tier: "public", secret_headers: { "x-k": "Form-Key" } }, /snake_case secret key/));
  it("secret_headers with a reserved name", () => bad({ path: "/x", tier: "public", secret_headers: { "x-auth-k": "k" } }, /gate-managed/));
  it("secret_headers with a plugin-reserved name", () => bad({ path: "/x", tier: "public", secret_headers: { "x-recaptcha-k": "k" } }, /gate-managed/));
  // F4: secret_headers must never forward a gate or plugin secret.
  for (const key of ["client_secret", "session_hmac_key", "recaptcha_secret"]) {
    it(`secret_headers naming the gate secret ${key}`, () => bad({ path: "/x", tier: "public", secret_headers: { "x-k": key } }, /can never be forwarded/));
  }
  it("secret_headers naming a secret declared by any registered plugin (even one not enabled)", () => {
    const reg = createFakeRegistry([
      ...makePlugins(),
      definePlugin({ name: "vault-user", kind: "middleware", phases: ["beforeForward"], beforeForward: noop, secrets: ["vault_token"] }),
    ]);
    expect(() => compile({ rules: [{ path: "/x", tier: "public", secret_headers: { "x-k": "vault_token" } }] }, reg)).toThrow(PolicyError);
    expect(() => compile({ rules: [{ path: "/x", tier: "public", secret_headers: { "x-k": "vault_token" } }] }, reg)).toThrow(/"vault_token", which can never be forwarded/);
    // an undeclared, rule-only secret key is still fine
    expect(() => compile({ rules: [{ path: "/x", tier: "public", secret_headers: { "x-k": "form_key" } }] }, reg)).not.toThrow();
  });
  // F10: "_" lookalikes of gate-managed names are gate-managed too.
  it("headers with an underscore lookalike of a reserved prefix", () => bad({ path: "/x", tier: "public", headers: { x_auth_subject: "admin" } }, /gate-managed/));
  it("headers with an underscore lookalike of a plugin prefix", () => bad({ path: "/x", tier: "public", headers: { "x_recaptcha-score": "1" } }, /gate-managed/));
  it("headers with an underscore lookalike of x-push-invalidation", () => bad({ path: "/x", tier: "public", headers: { x_push_invalidation: "enabled" } }, /gate-managed/));
  it("secret_headers overlapping headers (case-insensitive)", () => bad({ path: "/x", tier: "public", headers: { "X-K": "v" }, secret_headers: { "x-k": "k" } }, /both headers and secret_headers/));
  it("forward_identity not a boolean", () => bad({ path: "/x", tier: "public", forward_identity: "yes" }, /forward_identity must be a boolean/));
  it("handler not a string", () => bad({ path: "/x", tier: "public", handler: 1 }, /handler must be/));
  it("unknown handler plugin", () => bad({ path: "/x", tier: "public", handler: "nope" }, /unknown handler plugin "nope"/));
  it("handler plugin without handle()", () => bad({ path: "/x", tier: "public", handler: "recaptcha" }, /has no handle\(\)/));
  it("rule middleware not an array", () => bad({ path: "/x", tier: "public", middleware: { use: "recaptcha" } }, /middleware must be an array/));
  it("both session and auth", () => bad({ path: "/x", tier: "public", session: "none", auth: "none" }, /set "auth" only/));

  it("allows http upstreams on localhost and 127.0.0.1", () => {
    for (const u of ["http://localhost:8080", "http://127.0.0.1/"]) {
      expect(classify("/x", compile(withRule({ path: "/x", tier: "public", upstream: u }))).upstream).toBe(u);
    }
  });
});

// --- auth, secret headers, handler -------------------------------------------------------

describe("compilePolicy — rule fields", () => {
  const base = { version: 2, authentication: { use: "oidc-auth" } };

  it("auth defaults by tier", () => {
    const p = compile({ ...base, rules: [
      { path: "/p", tier: "public" }, { path: "/r", tier: "protected" }, { path: "/s", tier: "secured" },
    ] });
    expect(classify("/p", p).auth).toBe("none");
    expect(classify("/r", p).auth).toBe("required");
    expect(classify("/s", p).auth).toBe("required");
  });
  it("auth optional is allowed on public rules", () => {
    const p = compile({ ...base, rules: [{ path: "/p", tier: "public", auth: "optional", audience: [] }] });
    expect(classify("/p", p).auth).toBe("optional");
  });
  it("secret_headers, forward_identity and a plugin handler surface on the classification", () => {
    const p = compile({ ...base, rules: [
      { path: "/u/*", tier: "secured", upstream: "https://api.example", headers: { "x-k": "v" }, secret_headers: { "x-api-key": "api_key" }, forward_identity: true },
      { path: "/h", tier: "public", handler: "api-proxy" },
    ] });
    const u = classify("/u/1", p);
    expect(u.secretHeaders).toEqual({ "x-api-key": "api_key" });
    expect(u.forwardIdentity).toBe(true);
    expect(u.handler).toBe("origin");
    const h = classify("/h", p);
    expect(h.handler).toBe("api-proxy");
    expect(h.forwardIdentity).toBe(false);
    expect(h.secretHeaders).toBeUndefined();
    expect(p.enabled.has("api-proxy")).toBe(true);
  });
  it("legacy session is upgraded to auth with a warning", () => {
    const p = compile({ rules: [{ path: "/p", tier: "public", session: "optional" }] });
    expect(classify("/p", p).auth).toBe("optional");
    expect(p.warnings).toContain('rule "/p": legacy "session" upgraded to "auth"');
  });
  it("legacy session is upgraded in a v2 policy too", () => {
    const p = compile({ ...base, rules: [{ path: "/p", tier: "secured", session: "required" }] });
    expect(classify("/p", p).auth).toBe("required");
    expect(p.warnings.length).toBe(1);
  });
  it("legacy session values are validated like auth", () => {
    expect(() => compile({ rules: [{ path: "/p", tier: "public", session: true }] })).toThrow(/auth must be/);
  });
});

// --- authentication + invariant 6 ------------------------------------------------------------

describe("compilePolicy — authentication", () => {
  it("legacy policies default to oidc-auth with a warning", () => {
    const p = compile({ rules: [] });
    expect(p.authentication).toEqual({ use: "oidc-auth", options: {} });
    expect(p.enabled.get("oidc-auth")).toEqual({});
    expect(p.warnings).toEqual(['legacy policy: no "authentication"; defaulted to {"use": "oidc-auth"}']);
  });
  it("legacy all-public policies without oidc-auth registered compile without an authenticator", () => {
    const reg = createFakeRegistry(makePlugins().filter((m) => m.name !== "oidc-auth"));
    const p = compile({ rules: [{ path: "/", tier: "public" }], default_tier: "public" }, reg);
    expect(p.authentication).toBeNull();
    expect(p.warnings).toEqual([]);
  });
  it("invariant 6: a non-public default tier needs an authenticator", () => {
    const reg = createFakeRegistry(makePlugins().filter((m) => m.name !== "oidc-auth"));
    expect(() => compile({ rules: [] }, reg)).toThrow(/no "authentication" plugin/);
  });
  it("invariant 6: a non-public rule needs an authenticator", () => {
    expect(() => compile({ version: 2, default_tier: "public", rules: [{ path: "/s", tier: "secured" }] })).toThrow(/no "authentication" plugin/);
  });
  it("invariant 6: an auth: optional rule needs an authenticator", () => {
    expect(() => compile({ version: 2, default_tier: "public", rules: [{ path: "/s", tier: "public", auth: "optional" }] })).toThrow(/no "authentication" plugin/);
  });
  it("an all-public v2 policy needs no authenticator", () => {
    const p = compile({ version: 2, default_tier: "public", rules: [{ path: "/s", tier: "public" }] });
    expect(p.authentication).toBeNull();
    expect(p.enabled.size).toBe(0);
  });
  it("an explicit authenticator is used as configured (legacy too)", () => {
    const p = compile({ authentication: { use: "basic-auth", options: { realm: "x" } }, rules: [] });
    expect(p.authentication).toEqual({ use: "basic-auth", options: { realm: "x" } });
    expect(p.warnings).toEqual([]);
  });
  it("rejects a non-authenticator in authentication", () => {
    expect(() => compile({ version: 2, authentication: { use: "recaptcha" }, rules: [] })).toThrow(/is not an authenticator/);
  });
  it("rejects an unknown authenticator", () => {
    expect(() => compile({ version: 2, authentication: { use: "nope" }, rules: [] })).toThrow(/authentication: unknown plugin "nope"/);
  });
  it("rejects an unknown key in authentication", () => {
    expect(() => compile({ version: 2, authentication: { use: "oidc-auth", when: {} }, rules: [] })).toThrow(/authentication: unknown key "when"/);
  });
  it("rejects a non-object authentication", () => {
    expect(() => compile({ version: 2, authentication: "oidc-auth", rules: [] })).toThrow(/authentication must be an object/);
    expect(() => compile({ version: 2, authentication: null, rules: [] })).toThrow(/authentication must be an object/);
  });
  it("rejects non-object authentication options", () => {
    expect(() => compile({ version: 2, authentication: { use: "oidc-auth", options: [] }, rules: [] })).toThrow(/authentication.options must be an object/);
  });
  it("merges plugins.<authenticator> base options under authentication.options", () => {
    const p = compile({ version: 2, plugins: { "oidc-auth": { a: 1, b: 1 } }, authentication: { use: "oidc-auth", options: { b: 2 } }, rules: [] });
    expect(p.authentication.options).toEqual({ a: 1, b: 2 });
    expect(p.enabled.get("oidc-auth")).toEqual({ a: 1, b: 2 });
  });
});

// --- plugins block + enabled map ---------------------------------------------------------------

describe("compilePolicy — plugins block and enabled map", () => {
  const base = { version: 2, authentication: { use: "oidc-auth" } };

  it("rejects an unknown plugin in the plugins block", () => {
    expect(() => compile({ ...base, plugins: { nope: {} }, rules: [] })).toThrow(/plugins: unknown plugin "nope"/);
  });
  it("rejects a non-object plugins block", () => {
    expect(() => compile({ ...base, plugins: ["user-info"], rules: [] })).toThrow(/plugins must be an object/);
  });
  it("rejects non-object base options", () => {
    expect(() => compile({ ...base, plugins: { "user-info": true }, rules: [] })).toThrow(/plugins.user-info must be an options object/);
  });
  it("validates base options (validate() errors fail the load)", () => {
    expect(() => compile({ ...base, plugins: { recaptcha: { min_score: "high" } }, rules: [] })).toThrow(/invalid options for plugin "recaptcha": min_score must be a number/);
  });
  it("enabled = authenticator + plugins block + middleware + handler plugins, with validated base options", () => {
    const p = compile({
      ...base,
      plugins: { "user-info": { endpoint: "x" }, recaptcha: { min_score: 0.7 } },
      middleware: [{ use: "security-headers" }],
      rules: [
        { path: "/f/*", tier: "public", middleware: [{ use: "html-only" }] },
        { path: "/h", tier: "public", handler: "api-proxy" },
      ],
    });
    expect([...p.enabled.keys()]).toEqual(["oidc-auth", "user-info", "recaptcha", "security-headers", "html-only", "api-proxy"]);
    expect(p.enabled.get("user-info")).toEqual({ endpoint: "x" });
    expect(p.enabled.get("recaptcha")).toEqual({ min_score: 0.7 });
    expect(p.enabled.get("security-headers")).toEqual({});
    expect(p.enabled.has("early")).toBe(false);
  });
});

// --- middleware refs -----------------------------------------------------------------------------

describe("compilePolicy — middleware refs", () => {
  const base = { version: 2, authentication: { use: "oidc-auth" } };
  const withGlobal = (ref, extra = {}) => ({ ...base, middleware: [ref], rules: [], ...extra });
  const bad = (ref, re) => expect(() => compile(withGlobal(ref))).toThrow(re);

  it("rejects a non-array global middleware", () => {
    expect(() => compile({ ...base, middleware: { use: "recaptcha" }, rules: [] })).toThrow(/middleware must be an array/);
  });
  it("rejects a non-object ref", () => bad("recaptcha", /must be an object/));
  it("rejects an unknown ref key", () => bad({ use: "recaptcha", option: {} }, /unknown key "option"/));
  it("rejects an unknown plugin", () => bad({ use: "nope" }, /unknown plugin "nope"/));
  it("rejects a missing use", () => bad({ options: {} }, /unknown plugin undefined/));
  it("rejects an authenticator used as middleware", () => bad({ use: "oidc-auth" }, /is not a middleware plugin/));
  it("rejects a phase-less plugin used as middleware", () => bad({ use: "user-info" }, /declares no middleware phase/));
  it("rejects when.authenticated: true on a request-only plugin", () => bad({ use: "early", when: { authenticated: true } }, /could never match/));
  it("allows when.authenticated: false on a request-only plugin", () => {
    expect(() => compile(withGlobal({ use: "early", when: { authenticated: false } }))).not.toThrow();
  });
  it("rejects an invalid on_error", () => bad({ use: "recaptcha", on_error: "ignore" }, /on_error must be "fail" or "skip"/));
  it("rejects on_error skip without allowSkipOnError", () => bad({ use: "recaptcha", on_error: "skip" }, /on_error "skip" is not allowed/));
  it("rejects non-object ref options", () => bad({ use: "recaptcha", options: 1 }, /options must be an object/));
  it("rejects an unknown predicate key", () => bad({ use: "recaptcha", when: { method: ["POST"] } }, /unknown predicate key "method"/));
  it("rejects invalid ref options via validate()", () => bad({ use: "recaptcha", options: { min_score: "x" } }, /invalid options for plugin "recaptcha"/));
  it("rejects a validate() that returns a non-object", () => {
    const reg = createFakeRegistry(makePlugins({ recaptchaValidate: () => 42 }));
    expect(() => compile(withGlobal({ use: "recaptcha" }), reg)).toThrow(/validate\(\) must return an options object/);
  });

  it("on_error defaults to plugin defaults, else fail; skip is allowed with allowSkipOnError", () => {
    const p = compile({ ...base, middleware: [
      { use: "security-headers" }, { use: "recaptcha" }, { use: "security-headers", on_error: "fail" },
    ], rules: [] });
    expect(p.middleware.map((r) => r.onError)).toEqual(["skip", "fail", "fail"]);
  });

  it("ref when REPLACES the plugin default when (no merge)", () => {
    const p = compile({ ...base, middleware: [{ use: "html-only" }, { use: "html-only", when: { methods: ["POST"] } }], rules: [] });
    expect(p.middleware[0].when.predicate).toEqual({ accept: "html", methods: ["GET"] });
    expect(p.middleware[1].when.predicate).toEqual({ methods: ["POST"] });
    expect(p.middleware[1].when(input({ method: "POST", accept: "json" }))).toBe(true);
  });

  it("no when anywhere compiles to always-true", () => {
    const p = compile(withGlobal({ use: "recaptcha" }));
    expect(p.middleware[0].when(input({}))).toBe(true);
    expect(p.middleware[0].source).toBe("global");
  });

  it("options = plugins.<use> base options shallow-merged with ref options, then validate()", () => {
    const p = compile({
      ...base,
      plugins: { recaptcha: { min_score: 0.7, nested: { a: 1 } } },
      middleware: [{ use: "recaptcha", options: { nested: { b: 2 } } }],
      rules: [{ path: "/f", tier: "public", middleware: [{ use: "recaptcha" }] }],
    });
    expect(p.middleware[0].options).toEqual({ min_score: 0.7, nested: { b: 2 } });
    expect(Object.isFrozen(p.middleware[0].options)).toBe(true);
    expect(classify("/f", p).middleware[1].options).toEqual({ min_score: 0.7, nested: { a: 1 } });
  });

  it("validate() runs once per distinct merged options and receives the platform", () => {
    const validate = vi.fn((o) => ({ ...o, normalized: true }));
    const reg = createFakeRegistry(makePlugins({ recaptchaValidate: validate }));
    const platform = { profile: "sandbox", has: () => false };
    const p = compilePolicy({
      ...base,
      plugins: { recaptcha: { min_score: 0.5 } },
      middleware: [{ use: "recaptcha" }],
      rules: [
        { path: "/a", tier: "public", middleware: [{ use: "recaptcha" }] },
        { path: "/b", tier: "public", middleware: [{ use: "recaptcha", options: { min_score: 0.5 } }] },
        { path: "/c", tier: "public", middleware: [{ use: "recaptcha", options: { min_score: 0.9 } }] },
        { path: "/d", tier: "public", recaptcha: true },
      ],
    }, reg, { platform });
    // {min_score:0.5} (base, global, /a, /b, /d) and {min_score:0.9} (/c)
    expect(validate).toHaveBeenCalledTimes(2);
    expect(validate.mock.calls[0][1]).toEqual({ platform });
    const refs = ["/a", "/b", "/d"].map((path) => classify(path, p).middleware.at(-1));
    expect(refs.every((r) => r.options === p.middleware[0].options)).toBe(true);
    expect(p.enabled.get("recaptcha")).toBe(p.middleware[0].options);
    expect(classify("/c", p).middleware.at(-1).options).toEqual({ min_score: 0.9, normalized: true });
  });

  it("validate() is passed a copy, so it can't mutate the policy's options", () => {
    const reg = createFakeRegistry(makePlugins({ recaptchaValidate: (o) => { o.injected = true; } }));
    const raw = { ...base, plugins: { recaptcha: { min_score: 0.5 } }, middleware: [{ use: "recaptcha" }], rules: [] };
    const p = compile(raw, reg);
    expect(raw.plugins.recaptcha).toEqual({ min_score: 0.5 });
    expect(p.middleware[0].options).toEqual({ min_score: 0.5 });
  });
});

// --- legacy upgrade in full -------------------------------------------------------------------------

describe("compilePolicy — legacy upgrade", () => {
  it("upgrades recaptcha, session and authentication with one warning each", () => {
    const p = compile({
      rules: [
        { path: "/form/*", tier: "public", recaptcha: true, middleware: [{ use: "html-only" }] },
        { path: "/opt", tier: "public", session: "optional" },
      ],
    });
    expect(p.version).toBe(1);
    expect(p.warnings).toHaveLength(3);
    expect(p.warnings.join("\n")).toMatch(/oidc-auth/);
    expect(p.warnings.join("\n")).toMatch(/"recaptcha: true" upgraded/);
    expect(p.warnings.join("\n")).toMatch(/"session" upgraded/);
    // the legacy recaptcha ref goes first among the rule's refs
    expect(classify("/form/x", p).middleware.map((r) => r.use)).toEqual(["recaptcha", "html-only"]);
  });
  it("the recaptcha upgrade keeps its state-changing methods even when the plugin has a default when", () => {
    const plugins = makePlugins().map((m) => (m.name === "recaptcha"
      ? definePlugin({ name: "recaptcha", kind: "middleware", phases: ["beforeForward"], trustedHeaderPrefixes: ["x-recaptcha-"], beforeForward: noop, defaults: { when: { methods: ["PUT"] } } })
      : m));
    const p = compile({ rules: [{ path: "/f", tier: "public", recaptcha: true }] }, createFakeRegistry(plugins));
    expect(classify("/f", p).middleware[0].when.predicate).toEqual({ methods: ["POST", "PUT", "PATCH", "DELETE"] });
  });
});

// --- predicates -------------------------------------------------------------------------------------

function input(over) {
  return { method: "GET", authenticated: false, groups: [], contentType: "", accept: "other", ...over };
}

describe("compilePredicate", () => {
  it("undefined and {} are always true", () => {
    expect(compilePredicate(undefined)(input({}))).toBe(true);
    expect(compilePredicate({})(input({ method: "DELETE" }))).toBe(true);
  });
  it("authenticated", () => {
    expect(compilePredicate({ authenticated: true })(input({ authenticated: true }))).toBe(true);
    expect(compilePredicate({ authenticated: true })(input({ authenticated: false }))).toBe(false);
    expect(compilePredicate({ authenticated: false })(input({ authenticated: false }))).toBe(true);
    expect(compilePredicate({ authenticated: false })(input({ authenticated: true }))).toBe(false);
  });
  it("methods", () => {
    const p = compilePredicate({ methods: ["POST", "PUT"] });
    expect(p(input({ method: "PUT" }))).toBe(true);
    expect(p(input({ method: "GET" }))).toBe(false);
  });
  it("groups_any", () => {
    const p = compilePredicate({ groups_any: ["medical", "admins"] });
    expect(p(input({ groups: ["x", "admins"] }))).toBe(true);
    expect(p(input({ groups: ["x"] }))).toBe(false);
    expect(p(input({ groups: [] }))).toBe(false);
  });
  it("content_types", () => {
    const p = compilePredicate({ content_types: ["application/x-www-form-urlencoded", "multipart/form-data"] });
    expect(p(input({ contentType: "multipart/form-data" }))).toBe(true);
    expect(p(input({ contentType: "application/json" }))).toBe(false);
    expect(p(input({ contentType: "" }))).toBe(false);
  });
  it("accept", () => {
    expect(compilePredicate({ accept: "html" })(input({ accept: "html" }))).toBe(true);
    expect(compilePredicate({ accept: "html" })(input({ accept: "json" }))).toBe(false);
    expect(compilePredicate({ accept: "json" })(input({ accept: "json" }))).toBe(true);
    expect(compilePredicate({ accept: "json" })(input({ accept: "other" }))).toBe(false);
  });
  it("every present key must match", () => {
    const p = compilePredicate({ methods: ["POST"], authenticated: true });
    expect(p(input({ method: "POST", authenticated: true }))).toBe(true);
    expect(p(input({ method: "POST", authenticated: false }))).toBe(false);
    expect(p(input({ method: "GET", authenticated: true }))).toBe(false);
  });
  it("exposes the normalized predicate and is frozen", () => {
    const p = compilePredicate({ methods: ["POST", "POST"] });
    expect(p.predicate).toEqual({ methods: ["POST"] });
    expect(Object.isFrozen(p)).toBe(true);
  });
  it.each([
    [[], /must be an object/],
    [null, /must be an object/],
    [{ verb: "GET" }, /unknown predicate key "verb"/],
    [{ authenticated: "yes" }, /authenticated must be a boolean/],
    [{ methods: "POST" }, /methods must be a non-empty array/],
    [{ methods: [] }, /methods must be a non-empty array/],
    [{ methods: ["post"] }, /uppercase HTTP method/],
    [{ methods: [1] }, /non-empty strings/],
    [{ groups_any: [""] }, /non-empty strings/],
    [{ groups_any: "medical" }, /groups_any must be a non-empty array/],
    [{ content_types: ["Application/JSON"] }, /lowercase media type/],
    [{ content_types: ["application/json; charset=utf-8"] }, /lowercase media type/],
    [{ content_types: ["json"] }, /lowercase media type/],
    [{ accept: "xml" }, /accept must be "html" or "json"/],
  ])("rejects %j", (when, re) => {
    expect(() => compilePredicate(when)).toThrow(re);
  });
});

// --- classify: ordering + default tier ---------------------------------------------------------------

describe("classify — middleware ordering and default tier", () => {
  const p = compile({
    version: 2,
    authentication: { use: "oidc-auth" },
    middleware: [{ use: "security-headers" }, { use: "early" }],
    rules: [
      { path: "/f/*", tier: "public", middleware: [{ use: "html-only" }, { use: "recaptcha" }] },
      { path: "/plain", tier: "public" },
    ],
  });

  it("global refs come first, then the rule's, each in policy order", () => {
    const c = classify("/f/x", p);
    expect(c.middleware.map((r) => `${r.source}:${r.use}`)).toEqual([
      "global:security-headers", "global:early", "rule:html-only", "rule:recaptcha",
    ]);
  });
  it("a rule without middleware gets the global refs only", () => {
    expect(classify("/plain", p).middleware.map((r) => r.use)).toEqual(["security-headers", "early"]);
  });
  it("the default-tier pseudo-classification", () => {
    const c = classify("/nowhere", p);
    expect(c).toEqual({
      rule: null, tier: "protected", auth: "required", audience: undefined, upstream: undefined,
      headers: undefined, secretHeaders: undefined, forwardIdentity: false, handler: "origin",
      middleware: p.middleware,
    });
  });
  it("a public default tier gets auth none", () => {
    const q = compile({ version: 2, default_tier: "public", rules: [] });
    expect(classify("/x", q).auth).toBe("none");
  });
  it("classifications are frozen and reused per rule", () => {
    const a = classify("/f/1", p);
    expect(Object.isFrozen(a)).toBe(true);
    expect(classify("/f/2", p)).toBe(a);
    expect(a.rule.path).toBe("/f/*");
  });
  it("works on a hand-built CompiledPolicy (not from compilePolicy)", () => {
    const hand = { defaultTier: "secured", middleware: [], rules: [] };
    expect(classify("/x", hand)).toMatchObject({ rule: null, tier: "secured", auth: "required", handler: "origin" });
  });
});

// --- EQUIVALENCE with the legacy classifier on the real policies ---------------------------------------

const EQUIVALENCE_PATHS = [
  // root, assets and EDS internals
  "/", "/index.html", "/scripts/aem.js", "/scripts", "/scripts/", "/styles/styles.css", "/blocks/hero/hero.js",
  "/icons/logo.svg", "/fonts/roboto.woff2", "/media_1a2b3c.png", "/media_", "/media", "/sitemap.xml",
  "/robots.txt", "/robots.txt/x", "/favicon.ico",
  // nav / footer fragments
  "/nav", "/footer", "/nav.plain.html", "/footer.plain.html", "/content/nav.plain.html",
  "/content/footer.plain.html", "/content/other.plain.html", "/nav/", "/navigation",
  // errors
  "/errors/403", "/errors/404", "/errors", "/errors/",
  // protected and audience sections
  "/protected", "/protected/", "/protected/page", "/protected/medical", "/protected/medical/",
  "/protected/medical/doc", "/protected/medicalx", "/protected/market-access", "/protected/market-access/",
  "/protected/market-access/x/y", "/protected/market", "/protectedx",
  // api
  "/api", "/api/", "/api/x", "/api/people/1", "/apiary",
  // form
  "/form", "/form/", "/form/x", "/form/x/y", "/forms",
  // well-known
  "/.well-known/x", "/.well-known/openid-configuration", "/.well-known",
  // unmatched / gate-ish / encoded-looking
  "/totally/new/route", "/about", "/.auth/callback", "/.auth/logout", "/protected%2Fmedical",
  "/protected/%2e%2e/medical", "/%2Fprotected", "/scripts%2F..%2Fprotected", "/media_%2F..",
];

const yamlConfigs = extractYamlConfigs(readFileSync(DEFAULT_YAML_PATH, "utf8"));
const REAL_POLICIES = [
  ["embedded (sandbox)", EMBEDDED_CONFIGS.policy],
  ["config/edgeFunctions.yaml (provisioned)", yamlConfigs.policy],
];

const headerNames = (h) => (h ? Object.keys(h).sort() : undefined);

// Frozen copy of the deleted legacy classifier (src/policy.js as of 9cbfe62),
// kept test-only as the equivalence oracle. Do not "fix" it: it documents the
// behaviour the v2 compiler must reproduce for legacy policies.
const legacy = (() => {
  const VALID_TIERS = new Set(["public", "protected", "secured"]);
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const specificity = (pattern) => {
    const star = pattern.indexOf("*");
    if (star === -1) return 1000 + pattern.length;
    return pattern.slice(0, star).length;
  };
  const globToRegExp = (pattern) => {
    if (pattern.endsWith("/*")) {
      const base = pattern.slice(0, -2);
      return new RegExp("^" + base.split("*").map(escapeRe).join(".*") + "(?:/.*)?$");
    }
    return new RegExp("^" + pattern.split("*").map(escapeRe).join(".*") + "$");
  };
  return {
    compilePolicy(policy) {
      const rules = (policy.rules || []).map((r) => {
        if (!VALID_TIERS.has(r.tier)) throw new Error(`unknown policy tier: ${JSON.stringify(r.tier)}`);
        return { ...r, re: globToRegExp(r.path), spec: specificity(r.path), headers: r.headers == null ? undefined : { ...r.headers } };
      }).sort((a, b) => b.spec - a.spec);
      const defaultTier = policy.default_tier || "protected";
      const defaultHeaders = policy.default_headers == null ? undefined : { ...policy.default_headers };
      return { ...policy, rules, default_tier: defaultTier, default_headers: defaultHeaders };
    },
    classify(pathname, policy) {
      const best = (policy.rules || []).find((r) => r.re.test(pathname));
      if (!best) return { tier: policy.default_tier, audience: undefined, upstream: undefined, headers: undefined, recaptcha: undefined };
      return { tier: best.tier, audience: best.audience, upstream: best.upstream, headers: best.headers, recaptcha: best.recaptcha };
    },
  };
})();

describe("equivalence with the legacy classifier (frozen copy) on the real policies", () => {
  it(`checks at least 40 representative paths (${EQUIVALENCE_PATHS.length})`, () => {
    expect(EQUIVALENCE_PATHS.length).toBeGreaterThanOrEqual(40);
    expect(new Set(EQUIVALENCE_PATHS).size).toBe(EQUIVALENCE_PATHS.length);
  });

  describe.each(REAL_POLICIES)("%s", (_label, json) => {
    const legacyPolicy = legacy.compilePolicy(JSON.parse(json));
    const v2 = compilePolicy(JSON.parse(json), registry);

    it("compiles as a legacy policy upgraded to oidc-auth", () => {
      expect(v2.version).toBe(1);
      expect(v2.authentication.use).toBe("oidc-auth");
      expect(v2.defaultTier).toBe(legacyPolicy.default_tier);
      expect(headerNames(v2.defaultHeaders)).toEqual(headerNames(legacyPolicy.default_headers));
    });

    it.each(EQUIVALENCE_PATHS)("%s", (path) => {
      const was = legacy.classify(path, legacyPolicy);
      const now = classify(path, v2);
      expect({
        tier: now.tier, audience: now.audience, upstream: now.upstream, headers: headerNames(now.headers),
        recaptcha: now.middleware.some((r) => r.use === "recaptcha"),
      }).toEqual({
        tier: was.tier, audience: was.audience, upstream: was.upstream, headers: headerNames(was.headers),
        recaptcha: was.recaptcha === true,
      });
      // auth mode follows the tier
      expect(now.auth).toBe(now.tier === "public" ? "none" : "required");
    });

    it("recaptcha: true rules surface as a state-changing-methods recaptcha middleware ref", () => {
      const raw = JSON.parse(json);
      const flagged = raw.rules.filter((r) => r.recaptcha === true);
      expect(flagged.length).toBeGreaterThan(0);
      for (const r of flagged) {
        const c = classify(r.path.replace(/\*$/, "submit"), v2);
        expect(c.rule.path).toBe(r.path);
        const refs = c.middleware.filter((m) => m.use === "recaptcha");
        expect(refs).toHaveLength(1);
        expect(refs[0].when.predicate).toEqual({ methods: ["POST", "PUT", "PATCH", "DELETE"] });
        expect(refs[0].onError).toBe("fail");
      }
      expect(v2.warnings.filter((w) => /"recaptcha: true" upgraded/.test(w))).toHaveLength(flagged.length);
    });
  });
});

describe("W1.R F3: wildcards match any character, including CR/LF", () => {
  it("a newline inside a section path still matches the section rule", () => {
    const p = compile({
      default_tier: "protected",
      rules: [
        { path: "/protected/*", tier: "protected" },
        { path: "/protected/medical/*", tier: "protected", audience: ["medical"] },
        { path: "/*.plain.html", tier: "public" },
      ],
    });
    expect(classify("/protected/medical/a\nb", p).audience).toEqual(["medical"]);
    expect(classify("/protected/medical/\r", p).audience).toEqual(["medical"]);
    expect(classify("/x\ny.plain.html", p).tier).toBe("public");
  });
});
