import { describe, it, expect } from "vitest";
import { normalizePathname } from "../src/path.js";

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
