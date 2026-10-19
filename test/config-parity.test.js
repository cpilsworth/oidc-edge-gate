import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import {
  ConfigParseError,
  DEFAULT_YAML_PATH,
  KNOWN_DIVERGENCES,
  compareConfigs,
  diffPolicies,
  diffScalars,
  extractYamlConfigs,
  formatReport,
  loadEmbeddedConfigs,
  loadYamlConfigs,
  main,
} from "../scripts/check-config-parity.mjs";

const yamlDoc = (body) => `kind: "EdgeFunctions"\ndata:\n  configs:\n${body}\n  secrets:\n    - key: s\n      value: \${{ NOT_PARSED }}\n`;

describe("extractYamlConfigs", () => {
  it("parses double-quoted values with trailing comments", () => {
    const out = extractYamlConfigs(
      yamlDoc(`    - key: a\n      value: "x # not a comment"   # real comment\n    - key: b\n      value: "say \\"hi\\""`),
    );
    expect(out).toEqual({ a: "x # not a comment", b: 'say "hi"' });
  });

  it("folds single-quoted multi-line JSON and unescapes ''", () => {
    const out = extractYamlConfigs(
      yamlDoc(
        [
          "    # comment line",
          "    - key: policy",
          "      value: '{",
          '        "rules":[',
          `          {"path":"/it''s","tier":"public"}`,
          "        ]",
          "      }'  # trailing",
        ].join("\n"),
      ),
    );
    expect(out.policy).toBe(`{ "rules":[ {"path":"/it's","tier":"public"} ] }`);
    expect(JSON.parse(out.policy).rules[0].path).toBe("/it's");
  });

  it("stops at the end of the configs block and never parses secrets", () => {
    const out = extractYamlConfigs(yamlDoc(`    - key: a\n      value: 'one'`));
    expect(Object.keys(out)).toEqual(["a"]);
  });

  it.each([
    ["plain scalar", `    - key: a\n      value: bare`],
    ["block scalar", `    - key: a\n      value: |\n        text`],
    ["unterminated quote", `    - key: a\n      value: 'open`],
    ["key without value", `    - key: a\n    - key: b\n      value: "x"`],
    ["unknown construct", `    - name: a`],
    ["junk after quote", `    - key: a\n      value: "x" y`],
  ])("fails loudly on %s", (_label, body) => {
    expect(() => extractYamlConfigs(yamlDoc(body))).toThrow(ConfigParseError);
  });

  it("fails when there is no configs block", () => {
    expect(() => extractYamlConfigs("data:\n  functions: []\n")).toThrow(ConfigParseError);
  });
});

describe("diffPolicies / diffScalars", () => {
  const base = {
    rules: [
      { path: "/", tier: "public" },
      { path: "/a/*", tier: "protected", audience: ["x", "y"] },
      { path: "/f/*", tier: "public", upstream: "https://u1", headers: { "X-One": "v1" }, recaptcha: true },
    ],
    default_tier: "protected",
  };

  it("reports nothing for equivalent policies (audience as a set, header values ignored)", () => {
    const other = structuredClone(base);
    other.rules[1].audience = ["y", "x"];
    other.rules[2].headers = { "x-one": "different-value" };
    expect(diffPolicies(JSON.stringify(base), other)).toEqual([]);
  });

  it("reports field diffs, one-sided rules, and defaults", () => {
    const other = {
      rules: [
        { path: "/a/*", tier: "secured", audience: ["x"] },
        { path: "/f/*", tier: "public", upstream: "https://u2", headers: { "x-two": "v" } },
        { path: "/new", tier: "public" },
      ],
      default_tier: "public",
      default_headers: { "x-d": "v" },
    };
    const ids = diffPolicies(base, other).map((d) => d.id).sort();
    expect(ids).toEqual(
      [
        "policy:default_headers",
        "policy:default_tier",
        "rule:/:missing-in-yaml",
        "rule:/a/*:audience",
        "rule:/a/*:tier",
        "rule:/f/*:headers",
        "rule:/f/*:recaptcha",
        "rule:/f/*:upstream",
        "rule:/new:missing-in-embedded",
      ].sort(),
    );
  });

  it("redacts secret-looking scalar values and reports missing keys", () => {
    const d = diffScalars({ api_token: "t1", host: "a", only_e: "1" }, { api_token: "t2", host: "b", only_y: "2" });
    expect(d.map((x) => x.id)).toEqual([
      "scalar:api_token",
      "scalar:host",
      "scalar:only_e:missing-in-yaml",
      "scalar:only_y:missing-in-embedded",
    ]);
    expect(d[0]).toMatchObject({ embedded: "<redacted>", yaml: "<redacted>" });
    expect(d[1]).toMatchObject({ embedded: "a", yaml: "b" });
  });

  it("classifies diffs against an allowlist and flags stale entries", () => {
    const r = compareConfigs(
      { host: "a", policy: JSON.stringify(base) },
      { host: "b", policy: JSON.stringify(base) },
      [
        { id: "scalar:host", expected: "env-specific", reason: "r" },
        { id: "rule:/gone:tier", expected: "to-reconcile", reason: "r" },
      ],
    );
    expect(r.summary).toMatchObject({ total: 1, known: 1, unexpected: 0, staleKnownIds: ["rule:/gone:tier"] });
  });
});

describe("real repo config parity", () => {
  async function run() {
    const [embedded, yaml] = await Promise.all([loadEmbeddedConfigs(), loadYamlConfigs()]);
    return compareConfigs(embedded, yaml);
  }

  it("actual differences equal KNOWN_DIVERGENCES exactly", async () => {
    const result = await run();
    const actual = [...result.scalars, ...result.rules].map((d) => d.id).sort();
    expect(actual).toEqual(KNOWN_DIVERGENCES.map((k) => k.id).sort());
    expect(result.summary.unexpected).toBe(0);
    for (const k of KNOWN_DIVERGENCES) {
      expect(["env-specific", "to-reconcile"]).toContain(k.expected);
      expect(k.reason.length).toBeGreaterThan(0);
    }
  });

  it("CLI exits 0 with text and --json output", async () => {
    const logs = [];
    expect(await main([], { log: (s) => logs.push(s) })).toBe(0);
    expect(await main(["--json"], { log: (s) => logs.push(s) })).toBe(0);
    expect(JSON.parse(logs[1]).summary.unexpected).toBe(0);
  });

  it("CLI exits 2 on a parse error", async () => {
    const logs = [];
    expect(await main([], { yamlPath: "/nonexistent/edgeFunctions.yaml", log: (s) => logs.push(s) })).toBe(2);
  });

  it("never emits header values from either policy", async () => {
    const [embedded, yaml] = await Promise.all([loadEmbeddedConfigs(), loadYamlConfigs()]);
    const values = [];
    for (const p of [JSON.parse(yaml.policy), JSON.parse(embedded.policy)]) {
      for (const h of [p.default_headers, ...p.rules.map((r) => r.headers)]) {
        if (h) values.push(...Object.values(h));
      }
    }
    expect(values.length).toBeGreaterThan(0);
    // Sanity: the raw YAML really contains them, so the absence check is meaningful.
    const rawYaml = await readFile(DEFAULT_YAML_PATH, "utf8");
    expect(values.some((v) => rawYaml.includes(v))).toBe(true);

    const result = compareConfigs(embedded, yaml);
    const outputs = [JSON.stringify(result), formatReport(result)];
    const logs = [];
    await main(["--json"], { log: (s) => logs.push(s) });
    await main([], { log: (s) => logs.push(s) });
    outputs.push(...logs);
    for (const out of outputs) {
      for (const value of values) {
        expect(out.includes(value)).toBe(false);
      }
    }
  });
});
