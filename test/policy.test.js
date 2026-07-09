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
