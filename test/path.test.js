import { describe, it, expect } from "vitest";
import { normalizePathname } from "../src/kernel/path.js";

describe("normalizePathname", () => {
  it("leaves a clean path unchanged", () => {
    expect(normalizePathname("/protected/secret")).toBe("/protected/secret");
  });

  it("collapses repeated slashes so //protected can't dodge /protected/*", () => {
    expect(normalizePathname("//protected/secret")).toBe("/protected/secret");
    expect(normalizePathname("/a//b///c")).toBe("/a/b/c");
  });

  it("percent-decodes so /%70rotected resolves to /protected", () => {
    expect(normalizePathname("/%70rotected/secret")).toBe("/protected/secret");
  });

  it("rejects an encoded forward slash (no smuggled separators)", () => {
    expect(() => normalizePathname("/foo%2fbar")).toThrow();
    expect(() => normalizePathname("/foo%2Fbar")).toThrow();
  });

  it("rejects an encoded backslash", () => {
    expect(() => normalizePathname("/foo%5cbar")).toThrow();
    expect(() => normalizePathname("/foo%5Cbar")).toThrow();
  });

  it("rejects a malformed percent-escape", () => {
    expect(() => normalizePathname("/bad%zz")).toThrow();
    expect(() => normalizePathname("/dangling%")).toThrow();
  });

  it("preserves legitimately-encoded characters that aren't separators", () => {
    expect(normalizePathname("/ok%20space")).toBe("/ok space");
  });

  it("resolves . segments", () => {
    expect(normalizePathname("/a/./b")).toBe("/a/b");
    expect(normalizePathname("/./a")).toBe("/a");
  });

  it("resolves .. segments so /public/../protected can't dodge a rule", () => {
    expect(normalizePathname("/public/../protected/secret")).toBe("/protected/secret");
    expect(normalizePathname("/a/b/../../c")).toBe("/c");
  });

  it("preserves a trailing slash through .. resolution", () => {
    expect(normalizePathname("/foo/")).toBe("/foo/");
    expect(normalizePathname("/a/b/../")).toBe("/a/");
  });

  it("rejects a .. that would escape above the root", () => {
    expect(() => normalizePathname("/../etc/passwd")).toThrow();
    expect(() => normalizePathname("/a/../../etc")).toThrow();
  });

  it("treats root as / regardless of trailing slash collapse", () => {
    expect(normalizePathname("/")).toBe("/");
    expect(normalizePathname("/foo/../")).toBe("/");
  });
});

describe("normalizePathname rejects re-normalizable input (W1.R F1)", () => {
  it.each([
    ["/errors/%252e%252e/protected/medical/secret", /double-encoded/],
    ["/scripts/%252E%252E/protected/", /double-encoded/],
    ["/public/..%252fprotected", /double-encoded/],
    ["/protected/medical/%2541", /double-encoded/],
    ["/icons/.%09./protected/market-access/x", /control/],
    ["/errors/%2e%09%2e/x", /control/],
    ["/protected/me%09dical/x", /control/],
    ["/protected/medical/a%0Ab", /control/],
    ["/protected/medical%0D", /control/],
    ["/x%00", /control/],
    ["/x%7F", /control/],
  ])("%s -> throws", (raw, re) => {
    expect(() => normalizePathname(raw)).toThrow(re);
  });

  it.each([
    ["/docs/my%20file.pdf", "/docs/my file.pdf"],
    ["/caf%C3%A9/", "/café/"],
    ["/a%25", null], // a literal "%" that is not followed by two hex digits after decoding is allowed
  ])("legitimate encoded path %s still normalizes", (raw, expected) => {
    if (expected === null) {
      expect(normalizePathname(raw)).toBe("/a%");
    } else {
      expect(normalizePathname(raw)).toBe(expected);
    }
  });
});
