import { describe, it, expect } from "vitest";
import { classify, isAuthorized } from "../src/policy.js";

const policy = {
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
};

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
