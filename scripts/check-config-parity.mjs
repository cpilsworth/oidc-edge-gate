#!/usr/bin/env node
// Config parity checker: sandbox config (src/embedded-config.js → EMBEDDED_CONFIGS)
// vs provisioned config (config/edgeFunctions.yaml → data.configs[]).
//
// Usage:  node scripts/check-config-parity.mjs [--json]
// Exit:   0 = no differences outside KNOWN_DIVERGENCES
//         1 = at least one unexpected difference
//         2 = parse / load error
//
// SECURITY: header VALUES are never compared or reported — only header NAMES.
// Scalar values are redacted for any key matching SECRET_KEY_RE. The YAML
// `secrets:` block is never parsed and EMBEDDED_SECRETS is never read.
//
// Supported YAML subset (anything else throws ConfigParseError):
//   - a `configs:` mapping key (block form, nothing after the colon); the block
//     ends at the first non-blank, non-comment line indented <= `configs:`.
//   - inside it, list items `- key: <plain-name>` (name = [A-Za-z0-9_.-]+),
//     each followed by exactly one `value:` line.
//   - values that are either:
//       * a double-quoted single-line string (escapes \" \\ \/ \n \t only),
//       * a single-quoted string, possibly spanning lines ('' = escaped quote;
//         line breaks fold to one space, blank lines to "\n", per YAML flow
//         scalar folding),
//     each optionally followed by whitespace + `# comment`.
//   - full-line `#` comments and blank lines anywhere in the block.
// Not supported: plain (unquoted) scalars, block scalars (| / >), flow
// sequences/maps, anchors/aliases, tags, extra keys in an item, quoted keys.

import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO_ROOT = new URL("../", import.meta.url);
export const DEFAULT_YAML_PATH = fileURLToPath(new URL("config/edgeFunctions.yaml", REPO_ROOT));
export const DEFAULT_EMBEDDED_PATH = fileURLToPath(new URL("src/embedded-config.js", REPO_ROOT));

/** Scalar keys whose values must never be printed. */
export const SECRET_KEY_RE = /secret|key|token|password/i;

/** Keys compared structurally rather than as scalars. */
const STRUCTURED_KEYS = new Set(["policy"]);

/**
 * Differences we know about and accept for now, matched by stable id.
 * `expected: "env-specific"` — legitimately differs per environment (sandbox
 * debug host vs the real public domain). `expected: "to-reconcile"` — policy
 * drift to be fixed in a later work package; remove the entry when fixed (the
 * parity test fails on stale entries).
 * @type {ReadonlyArray<{id: string, expected: "env-specific"|"to-reconcile", reason: string}>}
 */
export const KNOWN_DIVERGENCES = Object.freeze([
  {
    id: "scalar:redirect_uri",
    expected: "env-specific",
    reason: "Sandbox uses the debug edgefunction-* host; YAML uses the real public domain.",
  },
  {
    id: "scalar:forwarded_host",
    expected: "env-specific",
    reason: "Sandbox forwards the debug edgefunction-* host; YAML forwards the real public domain.",
  },
  {
    id: "scalar:platform_profile",
    expected: "env-specific",
    reason: "Declared platform profile: the embedded config only runs on sandbox, the YAML only on provisioned (src/kernel/platform).",
  },
  {
    id: "rule:/api/*:tier",
    expected: "to-reconcile",
    reason: "Sandbox runs /api/* as an open public swapi.dev proxy; YAML has it secured. Target: secured API-gateway pass-through.",
  },
  {
    id: "rule:/form/*:upstream",
    expected: "to-reconcile",
    reason: "Form backend differs (sandbox requestbin vs YAML httpbun). Target: public form backend with reCAPTCHA.",
  },
  {
    id: "rule:/form:missing-in-yaml",
    expected: "to-reconcile",
    reason: "Exact /form page rule exists only in the sandbox config; reconcile with the /form/* form-backend work.",
  },
  {
    id: "rule:/protected/market-access/*:missing-in-yaml",
    expected: "to-reconcile",
    reason: "market-access audience section was added to the sandbox config but not to the YAML.",
  },
]);

/** Thrown for anything the checker cannot parse; maps to exit code 2. */
export class ConfigParseError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigParseError";
  }
}

// ---------------------------------------------------------------- YAML subset

const indentOf = (line) => line.length - line.trimStart().length;
const isSkippable = (line) => line.trim() === "" || line.trim().startsWith("#");

/** Accepts nothing or a `# comment` after a closing quote. */
function assertTrailer(rest, lineNo) {
  if (rest.trim() !== "" && !/^\s+#/.test(rest)) {
    throw new ConfigParseError(`line ${lineNo}: unexpected content after quoted value`);
  }
}

function parseDoubleQuoted(line, start, lineNo) {
  let out = "";
  for (let i = start + 1; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      assertTrailer(line.slice(i + 1), lineNo);
      return out;
    }
    if (c === "\\") {
      const n = line[++i];
      const map = { '"': '"', "\\": "\\", "/": "/", n: "\n", t: "\t" };
      if (!(n in map)) throw new ConfigParseError(`line ${lineNo}: unsupported escape in double-quoted value`);
      out += map[n];
    } else {
      out += c;
    }
  }
  throw new ConfigParseError(`line ${lineNo}: unterminated double-quoted value (multi-line double quotes unsupported)`);
}

/** Returns { value, endIndex } where endIndex is the index of the last consumed line. */
function parseSingleQuoted(lines, idx, start) {
  const parts = []; // raw text per physical line, '' already unescaped
  let cur = "";
  let col = start + 1;
  for (let i = idx; i < lines.length; i++) {
    const line = lines[i];
    for (let j = col; j < line.length; j++) {
      if (line[j] === "'") {
        if (line[j + 1] === "'") {
          cur += "'";
          j++;
          continue;
        }
        parts.push(cur);
        assertTrailer(line.slice(j + 1), i + 1);
        return { value: foldLines(parts), endIndex: i };
      }
      cur += line[j];
    }
    parts.push(cur);
    cur = "";
    col = 0;
  }
  throw new ConfigParseError(`line ${idx + 1}: unterminated single-quoted value`);
}

/** YAML flow-scalar folding: one break → space, each blank line → "\n". */
function foldLines(parts) {
  if (parts.length === 1) return parts[0];
  let out = parts[0].trimEnd();
  let pendingBlank = 0;
  for (let k = 1; k < parts.length; k++) {
    const isLast = k === parts.length - 1;
    const seg = isLast ? parts[k].trimStart() : parts[k].trim();
    if (seg === "" && !isLast) {
      pendingBlank++;
      continue;
    }
    out += pendingBlank ? "\n".repeat(pendingBlank) : " ";
    pendingBlank = 0;
    out += seg;
  }
  return out;
}

/**
 * Extract `data.configs` key/value pairs from edgeFunctions.yaml text using the
 * documented YAML subset. Never looks past the end of the `configs:` block.
 * Error messages carry line numbers only, never line content.
 * @param {string} text YAML source
 * @returns {Record<string, string>} config key → string value
 * @throws {ConfigParseError}
 */
export function extractYamlConfigs(text) {
  const lines = text.split(/\r?\n/);
  const headerIdx = lines.findIndex((l) => /^\s*configs:/.test(l));
  if (headerIdx < 0) throw new ConfigParseError("no `configs:` block found");
  if (!/^\s*configs:\s*(#.*)?$/.test(lines[headerIdx])) {
    throw new ConfigParseError(`line ${headerIdx + 1}: only block-form \`configs:\` is supported`);
  }
  const baseIndent = indentOf(lines[headerIdx]);
  const out = {};
  let pendingKey = null;
  let pendingLine = 0;

  for (let i = headerIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (isSkippable(line)) continue;
    if (indentOf(line) <= baseIndent) break; // end of configs block

    const keyMatch = /^\s*-\s+key:\s*(.*)$/.exec(line);
    if (keyMatch) {
      if (pendingKey !== null) throw new ConfigParseError(`line ${pendingLine}: key without a value`);
      const m = /^([A-Za-z0-9_.-]+)\s*(#.*)?$/.exec(keyMatch[1]);
      if (!m) throw new ConfigParseError(`line ${i + 1}: unsupported key syntax`);
      if (Object.hasOwn(out, m[1])) throw new ConfigParseError(`line ${i + 1}: duplicate key`);
      pendingKey = m[1];
      pendingLine = i + 1;
      continue;
    }

    const valMatch = /^(\s*)value:\s*/.exec(line);
    if (valMatch && pendingKey !== null) {
      const start = valMatch[0].length;
      const q = line[start];
      if (q === '"') {
        out[pendingKey] = parseDoubleQuoted(line, start, i + 1);
      } else if (q === "'") {
        const { value, endIndex } = parseSingleQuoted(lines, i, start);
        out[pendingKey] = value;
        i = endIndex;
      } else {
        throw new ConfigParseError(`line ${i + 1}: unsupported value syntax (only quoted strings are supported)`);
      }
      pendingKey = null;
      continue;
    }

    throw new ConfigParseError(`line ${i + 1}: unsupported construct in configs block`);
  }
  if (pendingKey !== null) throw new ConfigParseError(`line ${pendingLine}: key without a value`);
  return out;
}

// ---------------------------------------------------------------- loading

/**
 * Read and extract `data.configs` from the YAML file.
 * @param {string} [path]
 * @returns {Promise<Record<string, string>>}
 */
export async function loadYamlConfigs(path = DEFAULT_YAML_PATH) {
  return extractYamlConfigs(await readFile(path, "utf8"));
}

/**
 * Dynamically import the embedded config module and return a copy of
 * EMBEDDED_CONFIGS only.
 * @param {string} [path]
 * @returns {Promise<Record<string, string>>}
 */
export async function loadEmbeddedConfigs(path = DEFAULT_EMBEDDED_PATH) {
  const mod = await import(pathToFileURL(path).href);
  if (!mod.EMBEDDED_CONFIGS || typeof mod.EMBEDDED_CONFIGS !== "object") {
    throw new ConfigParseError("EMBEDDED_CONFIGS export not found");
  }
  return { ...mod.EMBEDDED_CONFIGS };
}

/**
 * Parse a policy JSON string into a header-value-free summary.
 * JSON.parse errors are rethrown without the parser's text excerpt.
 * @param {string} json
 * @param {string} source label for error messages
 * @returns {{ rules: Map<string, {tier?: string, audience: string[], upstream?: string, recaptcha: boolean, headerNames: string[]}>, default_tier?: string, defaultHeaderNames: string[] }}
 */
export function summarizePolicy(json, source) {
  let raw;
  try {
    raw = typeof json === "string" ? JSON.parse(json) : json;
  } catch {
    throw new ConfigParseError(`${source}: policy is not valid JSON`);
  }
  if (!raw || !Array.isArray(raw.rules)) throw new ConfigParseError(`${source}: policy.rules missing`);
  const names = (h) => Object.keys(h ?? {}).map((n) => n.toLowerCase()).sort();
  const rules = new Map();
  for (const r of raw.rules) {
    if (!r || typeof r.path !== "string") throw new ConfigParseError(`${source}: rule without a path`);
    if (rules.has(r.path)) throw new ConfigParseError(`${source}: duplicate rule path ${r.path}`);
    rules.set(r.path, {
      tier: r.tier,
      audience: [...new Set(r.audience ?? [])].sort(),
      upstream: r.upstream,
      recaptcha: r.recaptcha === true,
      headerNames: names(r.headers),
    });
  }
  return { rules, default_tier: raw.default_tier, defaultHeaderNames: names(raw.default_headers) };
}

// ---------------------------------------------------------------- comparison

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * Diff two flat scalar config maps (the `policy` key is excluded). Values of
 * secret-looking keys are replaced by "<redacted>".
 * @param {Record<string, string>} embedded
 * @param {Record<string, string>} yaml
 * @returns {Array<{id: string, key: string, kind: string, embedded?: string, yaml?: string}>}
 */
export function diffScalars(embedded, yaml) {
  const diffs = [];
  const keys = [...new Set([...Object.keys(embedded), ...Object.keys(yaml)])].sort();
  for (const key of keys) {
    if (STRUCTURED_KEYS.has(key)) continue;
    const show = (v) => (SECRET_KEY_RE.test(key) ? "<redacted>" : v);
    const inE = Object.hasOwn(embedded, key);
    const inY = Object.hasOwn(yaml, key);
    if (!inY) diffs.push({ id: `scalar:${key}:missing-in-yaml`, key, kind: "missing-in-yaml" });
    else if (!inE) diffs.push({ id: `scalar:${key}:missing-in-embedded`, key, kind: "missing-in-embedded" });
    else if (String(embedded[key]) !== String(yaml[key])) {
      diffs.push({ id: `scalar:${key}`, key, kind: "value", embedded: show(String(embedded[key])), yaml: show(String(yaml[key])) });
    }
  }
  return diffs;
}

/**
 * Diff two policies rule-by-rule (by path) plus default_tier / default_headers
 * names. Accepts policy JSON strings or objects. Header values are never read.
 * @param {string|object} embeddedPolicy
 * @param {string|object} yamlPolicy
 * @returns {Array<{id: string, path?: string, kind: string, field?: string, embedded?: unknown, yaml?: unknown}>}
 */
export function diffPolicies(embeddedPolicy, yamlPolicy) {
  const e = summarizePolicy(embeddedPolicy, "embedded");
  const y = summarizePolicy(yamlPolicy, "yaml");
  const diffs = [];
  const paths = [...new Set([...e.rules.keys(), ...y.rules.keys()])];
  for (const path of paths) {
    const er = e.rules.get(path);
    const yr = y.rules.get(path);
    if (!yr) { diffs.push({ id: `rule:${path}:missing-in-yaml`, path, kind: "missing-in-yaml" }); continue; }
    if (!er) { diffs.push({ id: `rule:${path}:missing-in-embedded`, path, kind: "missing-in-embedded" }); continue; }
    for (const [field, ev, yv] of [
      ["tier", er.tier, yr.tier],
      ["audience", er.audience, yr.audience],
      ["upstream", er.upstream, yr.upstream],
      ["recaptcha", er.recaptcha, yr.recaptcha],
      ["headers", er.headerNames, yr.headerNames],
    ]) {
      if (!same(ev, yv)) diffs.push({ id: `rule:${path}:${field}`, path, kind: "field", field, embedded: ev, yaml: yv });
    }
  }
  if (e.default_tier !== y.default_tier) {
    diffs.push({ id: "policy:default_tier", kind: "field", field: "default_tier", embedded: e.default_tier, yaml: y.default_tier });
  }
  if (!same(e.defaultHeaderNames, y.defaultHeaderNames)) {
    diffs.push({ id: "policy:default_headers", kind: "field", field: "default_headers", embedded: e.defaultHeaderNames, yaml: y.defaultHeaderNames });
  }
  return diffs;
}

/**
 * Compare full config maps and classify each diff against an allowlist.
 * @param {Record<string, string>} embedded
 * @param {Record<string, string>} yaml
 * @param {ReadonlyArray<{id: string, expected: string, reason: string}>} [known]
 * @returns {{ scalars: object[], rules: object[], summary: {total: number, known: number, unexpected: number, unexpectedIds: string[], staleKnownIds: string[]} }}
 */
export function compareConfigs(embedded, yaml, known = KNOWN_DIVERGENCES) {
  const byId = new Map(known.map((k) => [k.id, k]));
  const tag = (d) => {
    const k = byId.get(d.id);
    return k ? { ...d, known: true, expected: k.expected, reason: k.reason } : { ...d, known: false };
  };
  const scalars = diffScalars(embedded, yaml).map(tag);
  let rules = [];
  if (Object.hasOwn(embedded, "policy") && Object.hasOwn(yaml, "policy")) {
    rules = diffPolicies(embedded.policy, yaml.policy).map(tag);
  } else if (Object.hasOwn(embedded, "policy") !== Object.hasOwn(yaml, "policy")) {
    const side = Object.hasOwn(yaml, "policy") ? "embedded" : "yaml";
    scalars.push(tag({ id: `scalar:policy:missing-in-${side}`, key: "policy", kind: `missing-in-${side}` }));
  }
  const all = [...scalars, ...rules];
  const seen = new Set(all.map((d) => d.id));
  const unexpectedIds = all.filter((d) => !d.known).map((d) => d.id);
  return {
    scalars,
    rules,
    summary: {
      total: all.length,
      known: all.length - unexpectedIds.length,
      unexpected: unexpectedIds.length,
      unexpectedIds,
      staleKnownIds: known.map((k) => k.id).filter((id) => !seen.has(id)),
    },
  };
}

// ---------------------------------------------------------------- report

const fmt = (v) => (v === undefined ? "(unset)" : Array.isArray(v) ? `[${v.join(", ")}]` : String(v));

/**
 * Render a human-readable report of a compareConfigs() result.
 * @param {ReturnType<typeof compareConfigs>} result
 * @returns {string}
 */
export function formatReport(result) {
  const out = ["Config parity: src/embedded-config.js (sandbox) vs config/edgeFunctions.yaml (provisioned)", ""];
  const line = (d) => {
    const mark = d.known ? `KNOWN (${d.expected})` : "UNEXPECTED";
    const detail = d.kind.startsWith("missing") ? d.kind : `embedded=${fmt(d.embedded)}  yaml=${fmt(d.yaml)}`;
    out.push(`  [${mark}] ${d.id}`);
    out.push(`      ${detail}`);
    if (d.reason) out.push(`      reason: ${d.reason}`);
  };
  for (const [title, list] of [["Scalars", result.scalars], ["Policy", result.rules]]) {
    out.push(list.length ? `${title}:` : `${title}: no differences`);
    list.forEach(line);
    out.push("");
  }
  const s = result.summary;
  out.push(`Summary: ${s.total} difference(s), ${s.known} known, ${s.unexpected} unexpected.`);
  if (s.staleKnownIds.length) {
    out.push(`Warning: allowlisted but no longer different (remove from KNOWN_DIVERGENCES): ${s.staleKnownIds.join(", ")}`);
  }
  return out.join("\n");
}

/**
 * CLI entry point. Returns the exit code (0 ok, 1 unexpected drift, 2 parse error).
 * @param {string[]} argv
 * @param {{ yamlPath?: string, embeddedPath?: string, log?: (s: string) => void }} [opts]
 * @returns {Promise<number>}
 */
export async function main(argv = [], { yamlPath, embeddedPath, log = console.log } = {}) {
  let result;
  try {
    const [embedded, yaml] = await Promise.all([loadEmbeddedConfigs(embeddedPath), loadYamlConfigs(yamlPath)]);
    result = compareConfigs(embedded, yaml);
  } catch (err) {
    const msg = err instanceof ConfigParseError ? err.message : `${err?.name ?? "Error"}${err?.code ? ` (${err.code})` : ""} while loading config`;
    log(argv.includes("--json") ? JSON.stringify({ error: msg }) : `Parse error: ${msg}`);
    return 2;
  }
  log(argv.includes("--json") ? JSON.stringify(result, null, 2) : formatReport(result));
  return result.summary.unexpected ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
