// Self-check: the characterization suite must stay decoupled from internal
// modules so it survives the kernel + plugin refactor. Every import (static,
// dynamic, re-export or vi.mock target) in this directory that points into
// src/ must point at src/index.js and nothing else.
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const srcDir = join(repoRoot, "src");
const ALLOWED = join(srcDir, "index.js");

// Matches: import x from "spec" / import "spec" / export ... from "spec" /
// import("spec") / require("spec") / vi.mock("spec") / vi.doMock("spec").
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*|\bvi\.(?:do)?[mM]ock\s*\(\s*)(["'`])([^"'`]+)\1/g;

function listFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? listFiles(join(dir, e.name)) : /\.(m|c)?js$/.test(e.name) ? [join(dir, e.name)] : []);
}

describe("characterization suite import boundary", () => {
  const files = listFiles(here);

  it("finds the suite's own files", () => {
    const names = files.map((f) => relative(here, f));
    expect(names).toEqual(expect.arrayContaining(["harness.js", "embedded-gate.test.js", "store-backed.test.js", "import-boundary.test.js"]));
  });

  it("imports nothing from src/ except src/index.js", () => {
    const offenders = [];
    let sawIndex = false;
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const m of text.matchAll(SPECIFIER)) {
        const spec = m[2];
        if (!spec.startsWith(".") && !spec.startsWith("/")) continue; // bare / node: / fastly: specifiers
        const target = resolve(dirname(file), spec);
        if (target === ALLOWED) { sawIndex = true; continue; }
        if (target === srcDir || target.startsWith(srcDir + "/")) {
          offenders.push(`${relative(repoRoot, file)} -> ${spec}`);
        }
      }
    }
    expect(offenders).toEqual([]);
    expect(sawIndex).toBe(true); // the regex really does see imports
  });
});
