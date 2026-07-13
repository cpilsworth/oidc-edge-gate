import { describe, it, expect } from "vitest";
import { classify, compilePolicy, isAuthorized } from "../src/policy.js";

const policy = compilePolicy({
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

describe("classify", () => {
  it("exact root match is public", () => {
    expect(classify("/", policy)).toEqual({ tier: "public", audience: undefined });
  });
  it("prefix globs match", () => {
    expect(classify("/blog/2026/post", policy).tier).toBe("public");
    expect(classify("/media_abc123.png", policy).tier).toBe("public");
    expect(classify("/foo.plain.html", policy).tier).toBe("public");
  });
  it("most-specific rule wins (longer literal prefix)", () => {
    expect(classify("/members/x", policy)).toEqual({ tier: "protected", audience: ["site-readers"] });
    expect(classify("/members/admin/y", policy)).toEqual({ tier: "protected", audience: ["admins"] });
  });
  it("secured tier carries its audience", () => {
    expect(classify("/api/orders", policy)).toEqual({ tier: "secured", audience: ["site-readers"] });
  });
  it("unmatched path falls to default_tier with no audience", () => {
    expect(classify("/totally/new/route", policy)).toEqual({ tier: "protected", audience: undefined });
  });
  it("surfaces a rule's upstream override", () => {
    const p = compilePolicy({
      rules: [{ path: "/api/*", tier: "secured", upstream: "https://swapi.dev" }],
      default_tier: "protected",
    });
    expect(classify("/api/people", p)).toEqual({
      tier: "secured", audience: undefined, upstream: "https://swapi.dev",
    });
  });
});

describe("classify — recaptcha flag", () => {
  it("no recaptcha flag configured -> undefined", () => {
    const p = compilePolicy({ rules: [{ path: "/x", tier: "public" }], default_tier: "protected" });
    expect(classify("/x", p).recaptcha).toBeUndefined();
  });

  it("surfaces a rule's recaptcha: true", () => {
    const p = compilePolicy({
      rules: [{ path: "/form/*", tier: "public", recaptcha: true }],
      default_tier: "protected",
    });
    expect(classify("/form/submit", p).recaptcha).toBe(true);
  });

  it("unmatched path falling to default_tier has no recaptcha flag", () => {
    const p = compilePolicy({ rules: [], default_tier: "public" });
    expect(classify("/anything", p).recaptcha).toBeUndefined();
  });
});

describe("compilePolicy — recaptcha validation", () => {
  it("rejects a non-boolean recaptcha value", () => {
    expect(() => compilePolicy({ rules: [{ path: "/x", tier: "public", recaptcha: "true" }] }))
      .toThrow(/recaptcha must be a boolean/);
  });

  it("accepts recaptcha: false explicitly", () => {
    const p = compilePolicy({ rules: [{ path: "/x", tier: "public", recaptcha: false }] });
    expect(classify("/x", p).recaptcha).toBe(false);
  });
});

describe("classify — policy-configured headers", () => {
  it("no headers configured -> undefined (not an empty object)", () => {
    const p = compilePolicy({ rules: [{ path: "/x", tier: "public" }], default_tier: "protected" });
    expect(classify("/x", p).headers).toBeUndefined();
  });

  it("surfaces a rule's own headers", () => {
    const p = compilePolicy({
      rules: [{ path: "/form/*", tier: "public", headers: { "x-form-secret": "abc" } }],
      default_tier: "protected",
    });
    expect(classify("/form/submit", p).headers).toEqual({ "x-form-secret": "abc" });
  });

  it("does NOT merge default_headers into a rule's own headers — classify() only surfaces the rule's headers", () => {
    // default_headers is validated by compilePolicy but applied by
    // forwardToOrigin (EDS-origin only, see origin.js) — not merged here,
    // since classify() doesn't know whether a rule's `upstream` points at a
    // third party that default_headers must never reach.
    const p = compilePolicy({
      rules: [
        { path: "/a", tier: "public" },
        { path: "/b", tier: "public", headers: { shared: "rule-b" } },
      ],
      default_headers: { shared: "default", "x-common": "yes" },
      default_tier: "protected",
    });
    expect(classify("/a", p).headers).toBeUndefined();
    expect(classify("/b", p).headers).toEqual({ shared: "rule-b" });
    expect(p.default_headers).toEqual({ shared: "default", "x-common": "yes" });
  });

  it("unmatched path falling to default_tier has no rule-specific headers", () => {
    const p = compilePolicy({
      rules: [],
      default_headers: { "x-common": "yes" },
      default_tier: "public",
    });
    expect(classify("/anything", p)).toEqual({
      tier: "public", audience: undefined, upstream: undefined, headers: undefined,
    });
  });
});

describe("compilePolicy — header validation", () => {
  it("rejects a non-object headers value", () => {
    expect(() => compilePolicy({ rules: [{ path: "/x", tier: "public", headers: "nope" }] }))
      .toThrow(/must be an object/);
  });

  it("rejects a non-string header value", () => {
    expect(() => compilePolicy({ rules: [{ path: "/x", tier: "public", headers: { a: 1 } }] }))
      .toThrow(/must be a string/);
  });

  it("rejects a non-object default_headers value", () => {
    expect(() => compilePolicy({ rules: [], default_headers: ["nope"] }))
      .toThrow(/must be an object/);
  });

  for (const reserved of ["host", "Cookie", "set-cookie", "X-Forwarded-Host", "x-push-invalidation", "x-auth-subject", "x-recaptcha-score"]) {
    it(`rejects the gate-managed header "${reserved}" in a rule's headers`, () => {
      expect(() => compilePolicy({ rules: [{ path: "/x", tier: "public", headers: { [reserved]: "v" } }] }))
        .toThrow(/gate-managed/);
    });

    it(`rejects the gate-managed header "${reserved}" in default_headers`, () => {
      expect(() => compilePolicy({ rules: [], default_headers: { [reserved]: "v" } }))
        .toThrow(/gate-managed/);
    });
  }
});

describe("compilePolicy validation", () => {
  it("rejects an unknown rule tier at load", () => {
    expect(() => compilePolicy({ rules: [{ path: "/x", tier: "protetced" }], default_tier: "protected" }))
      .toThrow(/unknown policy tier/);
  });
  it("rejects an unknown default_tier at load", () => {
    expect(() => compilePolicy({ rules: [], default_tier: "secret" }))
      .toThrow(/unknown default_tier/);
  });
  it("defaults to protected when default_tier is omitted", () => {
    const p = compilePolicy({ rules: [] });
    expect(p.default_tier).toBe("protected");
  });
  it("handles a null-ish rules array via the || [] fallback", () => {
    const p = compilePolicy({ default_tier: "public" });
    expect(p.rules).toEqual([]);
    expect(classify("/anything", p).tier).toBe("public");
  });
  it("handles a null-ish default_tier via the || 'protected' fallback", () => {
    const p = compilePolicy({ rules: [{ path: "/", tier: "public" }] });
    expect(p.default_tier).toBe("protected");
  });
});

describe("isAuthorized", () => {
  it("no audience required → any authenticated session passes", () => {
    expect(isAuthorized({ groups: [] }, undefined)).toBe(true);
    expect(isAuthorized({ groups: ["x"] }, [])).toBe(true);
  });
  it("group intersection decides authorization", () => {
    expect(isAuthorized({ groups: ["site-readers"] }, ["site-readers"])).toBe(true);
    expect(isAuthorized({ groups: ["other"] }, ["site-readers"])).toBe(false);
    expect(isAuthorized({}, ["site-readers"])).toBe(false);
  });
});
