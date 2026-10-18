// Static import scan enforcing the plugin folder rules of
// docs/architecture/plugins.md §3:
//   1. A plugin imports only src/sdk/**, files inside its own folder, and
//      built-ins. Never fastly:*, src/kernel/**, other src/* modules, or
//      another plugin. (Runtime files: no bare specifiers at all, since there
//      are no plugin npm dependencies and no Node APIs on Fastly; test files
//      may also import vitest and node:* built-ins.)
//   2. The kernel (src/**) never imports from plugins/ except plugins/index.js.
//   3. Every folder in plugins/ except _template is registered in
//      plugins/index.js and has index.js, README.md and test/.
//
// TEMPORARY_ALLOWLIST lets the W1.3 oidc-auth adapter reach the legacy OIDC
// modules that still live in src/. W1.4 removes it.
import { describe, it, expect } from "vitest";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pluginsDir = join(repoRoot, "plugins");
const srcDir = join(repoRoot, "src");
const sdkDir = join(srcDir, "sdk");
const rel = (p) => relative(repoRoot, p).split(sep).join("/");

// W1.4 removes this: the temporary oidc-auth adapter wraps the legacy modules.
const TEMPORARY_ALLOWLIST = [
  {
    from: "plugins/oidc-auth/",
    to: ["src/oidc.js", "src/session.js", "src/jwt.js", "src/pkce.js", "src/kv.js"],
  },
  {
    from: "plugins/oidc-auth/test/",
    to: ["test/mock-op.js", "test/helpers.js"],
  },
];

// import x from "spec" / import "spec" / export ... from "spec" / import("spec") /
// require("spec") / vi.mock("spec") / vi.doMock("spec").
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*|\bvi\.(?:do)?[mM]ock\s*\(\s*)(["'`])([^"'`]+)\1/g;

function listJs(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.name === "node_modules") return [];
    const p = join(dir, e.name);
    return e.isDirectory() ? listJs(p) : /\.(m|c)?js$/.test(e.name) ? [p] : [];
  });
}

function specifiers(file) {
  return [...readFileSync(file, "utf8").matchAll(SPECIFIER)].map((m) => m[2]);
}

const isTestFile = (file) => rel(file).split("/").includes("test");
const pluginFolders = () => readdirSync(pluginsDir, { withFileTypes: true })
  .filter((e) => e.isDirectory() && e.name !== "_template")
  .map((e) => e.name);

/** Rule 1 for one plugin file. Returns a violation string or null. */
function checkPluginImport(file, spec) {
  const fromRel = rel(file);
  if (!spec.startsWith(".") && !spec.startsWith("/")) {
    if (isTestFile(file) && (spec === "vitest" || spec.startsWith("node:"))) return null;
    return `${fromRel} -> ${spec} (bare specifier: plugins have no dependencies; fastly:* is kernel-only)`;
  }
  const target = resolve(dirname(file), spec);
  const targetRel = rel(target);
  if (target === sdkDir || target.startsWith(sdkDir + sep)) return null;
  if (fromRel === "plugins/index.js") {
    return /^plugins\/[a-z0-9-]+\/index\.js$/.test(targetRel) ? null : `${fromRel} -> ${spec} (plugins/index.js may only import plugin entry points)`;
  }
  const own = join(pluginsDir, fromRel.split("/")[1]);
  if (target === own || target.startsWith(own + sep)) return null;
  for (const entry of TEMPORARY_ALLOWLIST) {
    if (fromRel.startsWith(entry.from) && entry.to.includes(targetRel)) return null;
  }
  return `${fromRel} -> ${spec}`;
}

describe("plugin boundaries (ADR §3)", () => {
  const pluginFiles = listJs(pluginsDir);

  it("finds plugin files to scan (the scanner sees imports)", () => {
    expect(pluginFiles.map(rel)).toEqual(expect.arrayContaining(["plugins/index.js", "plugins/recaptcha/index.js", "plugins/oidc-auth/index.js"]));
    expect(specifiers(join(pluginsDir, "index.js")).length).toBeGreaterThan(0);
  });

  it("rule 1: plugins import only src/sdk/**, their own folder and built-ins", () => {
    const offenders = [];
    for (const file of pluginFiles) {
      for (const spec of specifiers(file)) {
        const v = checkPluginImport(file, spec);
        if (v) offenders.push(v);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("rule 1 checker rejects the forbidden kinds of import", () => {
    const f = join(pluginsDir, "recaptcha", "index.js");
    const t = join(pluginsDir, "recaptcha", "test", "x.test.js");
    expect(checkPluginImport(f, "fastly:kv-store")).toMatch(/bare specifier/);
    expect(checkPluginImport(f, "node:fs")).toMatch(/bare specifier/);
    expect(checkPluginImport(f, "../../src/kernel/fetch.js")).toBeTruthy();
    expect(checkPluginImport(f, "../../src/oidc.js")).toBeTruthy(); // allowlisted for oidc-auth only
    expect(checkPluginImport(f, "../oidc-auth/index.js")).toBeTruthy();
    expect(checkPluginImport(f, "../../src/embedded-config.js")).toBeTruthy();
    expect(checkPluginImport(t, "../../../test/mock-op.js")).toBeTruthy();
    expect(checkPluginImport(t, "vitest")).toBeNull();
    expect(checkPluginImport(f, "../../src/sdk/index.js")).toBeNull();
    expect(checkPluginImport(f, "./lib/siteverify.js")).toBeNull();
  });

  it("rule 2: src/ never imports from plugins/ except plugins/index.js", () => {
    const offenders = [];
    let sawRegistry = false;
    for (const file of listJs(srcDir)) {
      for (const spec of specifiers(file)) {
        if (!spec.startsWith(".")) continue;
        const target = resolve(dirname(file), spec);
        if (!(target === pluginsDir || target.startsWith(pluginsDir + sep))) continue;
        if (rel(target) === "plugins/index.js") { sawRegistry = true; continue; }
        offenders.push(`${rel(file)} -> ${spec}`);
      }
    }
    expect(offenders).toEqual([]);
    expect(sawRegistry).toBe(true);
  });

  it("rule 3: every plugin folder (except _template) is registered and has index.js, README.md and test/", async () => {
    const folders = pluginFolders();
    expect(folders.length).toBeGreaterThan(0);
    const registered = specifiers(join(pluginsDir, "index.js"))
      .map((s) => rel(resolve(pluginsDir, s)))
      .filter((p) => /^plugins\/[a-z0-9-]+\/index\.js$/.test(p))
      .map((p) => p.split("/")[1]);
    const { default: list } = await import("../plugins/index.js");
    for (const name of folders) {
      const dir = join(pluginsDir, name);
      expect(existsSync(join(dir, "index.js")), `${name}/index.js`).toBe(true);
      expect(existsSync(join(dir, "README.md")), `${name}/README.md`).toBe(true);
      expect(existsSync(join(dir, "test")) && statSync(join(dir, "test")).isDirectory(), `${name}/test/`).toBe(true);
      expect(listJs(join(dir, "test")).some((f) => f.endsWith(".test.js")), `${name}/test/*.test.js`).toBe(true);
      expect(registered, `${name} imported by plugins/index.js`).toContain(name);
      expect(list.map((p) => p.name), `${name} in the exported plugin list`).toContain(name);
    }
  });

  it("the temporary allowlist is only for the oidc-auth adapter (W1.4 removes it)", () => {
    expect(TEMPORARY_ALLOWLIST.every((e) => e.from.startsWith("plugins/oidc-auth/"))).toBe(true);
  });
});
