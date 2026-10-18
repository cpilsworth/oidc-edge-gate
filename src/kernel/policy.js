// Policy v2 compiler (W1.2). Compiles the raw `policy` config JSON once at
// load time into a CompiledPolicy (src/kernel/types.js), and resolves a
// normalized request path to a Classification per request.
//
// Spec: docs/architecture/plugins.md §10. Everything that is wrong with a
// policy surfaces HERE, at load, as a PolicyError (fail closed): unknown keys,
// unknown/phase-less plugins, reserved header names, an identity-requiring
// policy without an authenticator (kernel invariant 6), and so on.
//
// Matching semantics are copied verbatim from the legacy src/policy.js:
// most-specific-first (exact patterns beat globs, then the longest literal
// prefix before the first "*"), a trailing "/*" also covers the bare section
// path, and unmatched paths fall to `default_tier` (deny-by-default).
//
// Runs on the Fastly Compute runtime: no Node-only APIs, no `fastly:*`.

import { CORE_HEADER_PREFIX } from "../sdk/index.js";

/**
 * @typedef {import("./types.js").Registry} Registry
 * @typedef {import("./types.js").CompiledPolicy} CompiledPolicy
 * @typedef {import("./types.js").CompiledRule} CompiledRule
 * @typedef {import("./types.js").MiddlewareRef} MiddlewareRef
 * @typedef {import("./types.js").Classification} Classification
 * @typedef {import("./types.js").PredicateInput} PredicateInput
 * @typedef {import("../sdk/index.js").Platform} Platform
 * @typedef {import("../sdk/index.js").Identity} Identity
 */

/** Thrown by compilePolicy/compilePredicate for any invalid policy. Fails config load. */
export class PolicyError extends Error {
  constructor(message, options) {
    super(`policy: ${message}`, options);
    this.name = "PolicyError";
  }
}

const TIERS = new Set(["public", "protected", "secured"]);
const AUTH_MODES = new Set(["none", "optional", "required"]);
/** Which `auth` modes each tier allows; the first entry is the tier's default. */
const TIER_AUTH = Object.freeze({
  public: ["none", "optional"],
  protected: ["required"],
  secured: ["required"],
});
const ON_ERROR = new Set(["fail", "skip"]);

const TOP_LEVEL_KEYS = new Set([
  "version", "default_tier", "authentication", "plugins", "middleware", "default_headers", "rules",
]);
const RULE_KEYS = new Set([
  "path", "tier", "auth", "audience", "upstream", "headers", "secret_headers", "forward_identity",
  "handler", "middleware",
  // legacy, upgraded with a warning
  "recaptcha", "session",
]);
const REF_KEYS = new Set(["use", "options", "when", "on_error"]);
const AUTHENTICATION_KEYS = new Set(["use", "options"]);
const PREDICATE_KEYS = new Set(["authenticated", "methods", "groups_any", "content_types", "accept"]);
const ACCEPT_VALUES = new Set(["html", "json"]);

// Header names the gate manages itself (identity injection, EDS BYO-CDN
// contract, cookie transport). Policy-configured `headers`/`default_headers`
// may not set these — allowing it would let a static config value silently
// shadow a per-request, gate-computed value (e.g. a misconfigured
// `x-auth-subject` on a public rule would look like verified identity to an
// origin that trusts the gate). Plugin-trusted prefixes (e.g. `x-recaptcha-`,
// so a static `x-recaptcha-score` can't masquerade as a real verification
// result) come from the registry: registry.reservedHeaderPrefixes().
const RESERVED_HEADER_NAMES = new Set(["host", "cookie", "set-cookie", "x-forwarded-host", "x-push-invalidation"]);
const HEADER_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const SECRET_KEY_RE = /^[a-z][a-z0-9_]*$/;
const METHOD_RE = /^[A-Z]+$/;
const MEDIA_TYPE_RE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

const ALWAYS = Object.freeze(Object.assign(() => true, { predicate: Object.freeze({}) }));

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const q = (v) => JSON.stringify(v);

// Precomputed classifications for policies built by compilePolicy (classify()
// then returns a shared frozen object instead of allocating per request).
const PRECOMPUTED = new WeakMap();

// --- predicates ------------------------------------------------------------------

/**
 * Compile a declarative `when` (sdk Predicate) into a function over
 * PredicateInput. Every present key must match. Absent/undefined `when`
 * compiles to an always-true predicate. Throws PolicyError on unknown keys or
 * wrong types. The returned function carries the normalized source as
 * `.predicate` (read-only) for introspection and logs.
 *
 * @param {unknown} when
 * @param {string} [label] location prefix for error messages
 * @returns {((input: PredicateInput) => boolean) & {predicate: Readonly<Object>}}
 */
export function compilePredicate(when, label = "when") {
  if (when === undefined) return ALWAYS;
  if (!isPlainObject(when)) throw new PolicyError(`${label} must be an object`);
  for (const k of Object.keys(when)) {
    if (!PREDICATE_KEYS.has(k)) throw new PolicyError(`${label}: unknown predicate key ${q(k)}`);
  }
  const spec = {};
  const tests = [];

  if (when.authenticated !== undefined) {
    if (typeof when.authenticated !== "boolean") throw new PolicyError(`${label}.authenticated must be a boolean`);
    const want = when.authenticated;
    spec.authenticated = want;
    tests.push((i) => i.authenticated === want);
  }
  if (when.methods !== undefined) {
    const list = stringList(when.methods, `${label}.methods`);
    for (const m of list) {
      if (!METHOD_RE.test(m)) throw new PolicyError(`${label}.methods: ${q(m)} must be an uppercase HTTP method`);
    }
    const set = new Set(list);
    spec.methods = Object.freeze([...set]);
    tests.push((i) => set.has(i.method));
  }
  if (when.groups_any !== undefined) {
    const list = stringList(when.groups_any, `${label}.groups_any`);
    const set = new Set(list);
    spec.groups_any = Object.freeze([...set]);
    tests.push((i) => Array.isArray(i.groups) && i.groups.some((g) => set.has(g)));
  }
  if (when.content_types !== undefined) {
    const list = stringList(when.content_types, `${label}.content_types`);
    for (const t of list) {
      if (!MEDIA_TYPE_RE.test(t)) {
        throw new PolicyError(`${label}.content_types: ${q(t)} must be a lowercase media type like "application/json" (no parameters)`);
      }
    }
    const set = new Set(list);
    spec.content_types = Object.freeze([...set]);
    tests.push((i) => set.has(i.contentType));
  }
  if (when.accept !== undefined) {
    if (!ACCEPT_VALUES.has(when.accept)) throw new PolicyError(`${label}.accept must be "html" or "json"`);
    const want = when.accept;
    spec.accept = want;
    tests.push((i) => i.accept === want);
  }

  const fn = tests.length === 0 ? () => true : (input) => tests.every((t) => t(input));
  fn.predicate = Object.freeze(spec);
  return Object.freeze(fn);
}

/** A non-empty array of non-empty strings. */
function stringList(v, label) {
  if (!Array.isArray(v) || v.length === 0) throw new PolicyError(`${label} must be a non-empty array of strings`);
  for (const s of v) if (typeof s !== "string" || s.length === 0) throw new PolicyError(`${label} must contain only non-empty strings`);
  return v;
}

// --- compile ---------------------------------------------------------------------

/**
 * Compile a raw policy (as parsed from config JSON) once at load time.
 *
 * - `version: 2` is the v2 shape; no `version` key is the legacy shape, which
 *   is upgraded in place (each upgrade adds a `warnings` entry). Any other
 *   version is a load error.
 * - Rules are validated, given a precompiled matcher RegExp, and sorted
 *   most-specific-first, so classify() is a single ordered `find()` with no
 *   per-request regex construction.
 * - `default_headers` is validated but intentionally NOT merged into each
 *   rule: whether it applies depends on where a request is forwarded (the EDS
 *   origin vs. a rule's `upstream` override), which classify() can't know. The
 *   forward step applies it only when there is no `upstream`, so a secret meant
 *   to gate the site's own origin never leaks to a third-party upstream.
 *
 * @param {Object} raw
 * @param {Registry} registry
 * @param {{platform?: Platform}} [env]
 * @returns {CompiledPolicy}
 */
export function compilePolicy(raw, registry, { platform } = {}) {
  if (!isPlainObject(raw)) throw new PolicyError("policy must be a JSON object");
  if (!registry || typeof registry.get !== "function" || typeof registry.has !== "function") {
    throw new TypeError("compilePolicy requires a plugin registry");
  }

  let version;
  if (!Object.prototype.hasOwnProperty.call(raw, "version")) version = 1;
  else if (raw.version === 2) version = 2;
  else throw new PolicyError(`unsupported version ${q(raw.version)} (expected 2, or no "version" key for the legacy shape)`);

  for (const k of Object.keys(raw)) {
    if (!TOP_LEVEL_KEYS.has(k)) throw new PolicyError(`unknown top-level key ${q(k)}`);
  }

  /** @type {string[]} */
  const warnings = [];
  const env = { platform };

  // Reserved header names/prefixes for policy-configured static headers.
  const reservedPrefixes = [...new Set([
    CORE_HEADER_PREFIX,
    ...(typeof registry.reservedHeaderPrefixes === "function" ? registry.reservedHeaderPrefixes() : []),
  ].map((p) => String(p).toLowerCase()))];

  // --- plugins block (base options) ---
  const pluginsBlock = raw.plugins === undefined ? {} : raw.plugins;
  if (!isPlainObject(pluginsBlock)) throw new PolicyError("plugins must be an object of plugin name -> base options");
  for (const [name, opts] of Object.entries(pluginsBlock)) {
    if (!registry.has(name)) throw new PolicyError(`plugins: unknown plugin ${q(name)}`);
    if (!isPlainObject(opts)) throw new PolicyError(`plugins.${name} must be an options object`);
  }

  // validate() runs once per distinct (plugin, merged options).
  const validated = new Map();
  const validateOptions = (name, merged, label) => {
    let perPlugin = validated.get(name);
    if (!perPlugin) validated.set(name, (perPlugin = new Map()));
    let cacheKey;
    try { cacheKey = JSON.stringify(merged); } catch (err) {
      throw new PolicyError(`${label}: options must be JSON-serializable`, { cause: err });
    }
    if (perPlugin.has(cacheKey)) return perPlugin.get(cacheKey);
    const manifest = registry.get(name);
    let out = { ...merged };
    if (typeof manifest.validate === "function") {
      let result;
      try {
        result = manifest.validate({ ...merged }, env);
      } catch (err) {
        throw new PolicyError(`${label}: invalid options for plugin ${q(name)}: ${err && err.message}`, { cause: err });
      }
      if (result !== undefined) {
        if (!isPlainObject(result)) throw new PolicyError(`${label}: plugin ${q(name)} validate() must return an options object`);
        out = { ...result };
      }
    }
    const frozen = Object.freeze(out);
    perPlugin.set(cacheKey, frozen);
    return frozen;
  };
  const baseOptions = (name) => validateOptions(name, { ...(pluginsBlock[name] || {}) }, `plugins.${name}`);

  /** @type {Map<string, Readonly<Object>>} */
  const enabled = new Map();
  const enable = (name, options) => { if (!enabled.has(name)) enabled.set(name, options); };

  // --- authentication ---
  let authSpec = raw.authentication;
  if (authSpec === undefined && version === 1 && registry.has("oidc-auth")) {
    authSpec = { use: "oidc-auth", options: {} };
    warnings.push("legacy policy: no \"authentication\"; defaulted to {\"use\": \"oidc-auth\"}");
  }
  /** @type {{use: string, options: Readonly<Object>}|null} */
  let authentication = null;
  if (authSpec !== undefined && authSpec !== null) {
    if (!isPlainObject(authSpec)) throw new PolicyError("authentication must be an object {use, options?}");
    for (const k of Object.keys(authSpec)) {
      if (!AUTHENTICATION_KEYS.has(k)) throw new PolicyError(`authentication: unknown key ${q(k)}`);
    }
    const { use } = authSpec;
    if (typeof use !== "string" || !registry.has(use)) throw new PolicyError(`authentication: unknown plugin ${q(use)}`);
    if (registry.get(use).kind !== "authenticator") {
      throw new PolicyError(`authentication: plugin ${q(use)} is not an authenticator`);
    }
    const own = authSpec.options === undefined ? {} : authSpec.options;
    if (!isPlainObject(own)) throw new PolicyError("authentication.options must be an object");
    const options = validateOptions(use, { ...(pluginsBlock[use] || {}), ...own }, "authentication");
    authentication = Object.freeze({ use, options });
    enable(use, options);
  } else if (authSpec === null) {
    throw new PolicyError("authentication must be an object {use, options?}");
  }

  for (const name of Object.keys(pluginsBlock)) enable(name, baseOptions(name));

  // --- middleware refs ---
  const compileRef = (ref, source, label) => {
    if (!isPlainObject(ref)) throw new PolicyError(`${label} must be an object {use, options?, when?, on_error?}`);
    for (const k of Object.keys(ref)) {
      if (!REF_KEYS.has(k)) throw new PolicyError(`${label}: unknown key ${q(k)}`);
    }
    const { use } = ref;
    if (typeof use !== "string" || !registry.has(use)) throw new PolicyError(`${label}: unknown plugin ${q(use)}`);
    const manifest = registry.get(use);
    if (manifest.kind !== "middleware") throw new PolicyError(`${label}: plugin ${q(use)} is not a middleware plugin`);
    const phases = manifest.phases || [];
    if (phases.length === 0) throw new PolicyError(`${label}: plugin ${q(use)} declares no middleware phase, so it cannot be used as middleware`);
    const defaults = manifest.defaults || {};

    // `when` on the ref REPLACES the plugin default (no merge).
    const rawWhen = ref.when !== undefined ? ref.when : defaults.when;
    const when = compilePredicate(rawWhen, `${label}.when`);
    if (when.predicate.authenticated === true && phases.every((p) => p === "request")) {
      throw new PolicyError(`${label}: plugin ${q(use)} runs only in the "request" phase (before authentication), so when.authenticated: true could never match`);
    }

    const onError = ref.on_error !== undefined ? ref.on_error : (defaults.on_error || "fail");
    if (!ON_ERROR.has(onError)) throw new PolicyError(`${label}.on_error must be "fail" or "skip"`);
    if (onError === "skip" && manifest.allowSkipOnError !== true) {
      throw new PolicyError(`${label}: on_error "skip" is not allowed for plugin ${q(use)} (allowSkipOnError is not set)`);
    }

    const own = ref.options === undefined ? {} : ref.options;
    if (!isPlainObject(own)) throw new PolicyError(`${label}.options must be an object`);
    const options = validateOptions(use, { ...(pluginsBlock[use] || {}), ...own }, label);
    enable(use, baseOptions(use));
    return Object.freeze({ use, options, when, onError, source });
  };

  const globalRaw = raw.middleware === undefined ? [] : raw.middleware;
  if (!Array.isArray(globalRaw)) throw new PolicyError("middleware must be an array of plugin refs");
  const middleware = Object.freeze(globalRaw.map((ref, i) => compileRef(ref, "global", `middleware[${i}]`)));

  // --- headers ---
  const validateHeaderName = (name, label) => {
    const lower = name.toLowerCase();
    if (RESERVED_HEADER_NAMES.has(lower) || reservedPrefixes.some((p) => lower.startsWith(p))) {
      throw new PolicyError(`${label}: header ${q(name)} is gate-managed and cannot be set via policy config`);
    }
    if (!HEADER_TOKEN_RE.test(name)) throw new PolicyError(`${label}: ${q(name)} is not a valid header name`);
  };
  const validateHeaders = (headers, label) => {
    if (headers == null) return undefined;
    if (!isPlainObject(headers)) throw new PolicyError(`${label} must be an object of header name -> string value`);
    for (const [name, value] of Object.entries(headers)) {
      validateHeaderName(name, label);
      // Never echo the value: these maps carry shared secrets.
      if (typeof value !== "string") throw new PolicyError(`${label}: header ${q(name)} value must be a string`);
    }
    return Object.freeze({ ...headers });
  };

  const defaultHeaders = validateHeaders(raw.default_headers, "default_headers");

  // --- default tier ---
  const defaultTier = raw.default_tier === undefined || raw.default_tier === null ? "protected" : raw.default_tier;
  if (!TIERS.has(defaultTier)) throw new PolicyError(`unknown default_tier: ${q(defaultTier)}`);

  // --- rules ---
  const rulesRaw = raw.rules === undefined || raw.rules === null ? [] : raw.rules;
  if (!Array.isArray(rulesRaw)) throw new PolicyError("rules must be an array");

  const rules = rulesRaw.map((r, i) => {
    if (!isPlainObject(r)) throw new PolicyError(`rules[${i}] must be an object`);
    const { path } = r;
    if (typeof path !== "string" || path.length === 0 || !path.startsWith("/")) {
      throw new PolicyError(`rules[${i}]: path must be a non-empty string starting with "/"`);
    }
    const label = `rule ${q(path)}`;
    for (const k of Object.keys(r)) {
      if (!RULE_KEYS.has(k)) throw new PolicyError(`${label}: unknown key ${q(k)}`);
    }

    if (!TIERS.has(r.tier)) throw new PolicyError(`${label}: unknown policy tier: ${q(r.tier)}`);
    const tier = r.tier;

    // auth (legacy `session` -> `auth`)
    let authRaw = r.auth;
    if (r.session !== undefined) {
      if (r.auth !== undefined) throw new PolicyError(`${label}: set "auth" only (legacy "session" is its old name)`);
      authRaw = r.session;
      warnings.push(`${label}: legacy "session" upgraded to "auth"`);
    }
    const auth = authRaw === undefined ? TIER_AUTH[tier][0] : authRaw;
    if (!AUTH_MODES.has(auth)) throw new PolicyError(`${label}: auth must be "none", "optional" or "required"`);
    if (!TIER_AUTH[tier].includes(auth)) {
      throw new PolicyError(`${label}: auth ${q(auth)} is not allowed on a ${tier} rule (allowed: ${TIER_AUTH[tier].join(", ")})`);
    }

    // audience
    let audience;
    if (r.audience !== undefined) {
      if (!Array.isArray(r.audience) || r.audience.some((a) => typeof a !== "string" || a.length === 0)) {
        throw new PolicyError(`${label}: audience must be an array of non-empty strings`);
      }
      if (r.audience.length > 0 && auth === "none") {
        throw new PolicyError(`${label}: audience requires an identity, but the rule has auth "none"`);
      }
      audience = Object.freeze([...r.audience]);
    }

    // handler
    const handler = r.handler === undefined ? "origin" : r.handler;
    if (typeof handler !== "string") throw new PolicyError(`${label}: handler must be "origin" or a plugin name`);
    if (handler !== "origin") {
      if (!registry.has(handler)) throw new PolicyError(`${label}: unknown handler plugin ${q(handler)}`);
      if (typeof registry.get(handler).handle !== "function") {
        throw new PolicyError(`${label}: handler plugin ${q(handler)} has no handle()`);
      }
    }

    // upstream
    let upstream;
    if (r.upstream !== undefined) {
      upstream = validateUpstream(r.upstream, label);
      if (handler !== "origin") throw new PolicyError(`${label}: upstream applies only to handler "origin"`);
    }

    const headers = validateHeaders(r.headers, `${label} headers`);

    let secretHeaders;
    if (r.secret_headers !== undefined) {
      if (!isPlainObject(r.secret_headers)) throw new PolicyError(`${label}: secret_headers must be an object of header name -> secret key`);
      const plain = new Set(Object.keys(headers || {}).map((n) => n.toLowerCase()));
      for (const [name, key] of Object.entries(r.secret_headers)) {
        validateHeaderName(name, `${label} secret_headers`);
        if (typeof key !== "string" || !SECRET_KEY_RE.test(key)) {
          throw new PolicyError(`${label} secret_headers: header ${q(name)} must name a snake_case secret key`);
        }
        if (plain.has(name.toLowerCase())) {
          throw new PolicyError(`${label}: header ${q(name)} is set in both headers and secret_headers`);
        }
      }
      secretHeaders = Object.freeze({ ...r.secret_headers });
    }

    if (r.forward_identity !== undefined && typeof r.forward_identity !== "boolean") {
      throw new PolicyError(`${label}: forward_identity must be a boolean`);
    }
    const forwardIdentity = r.forward_identity === true;

    // middleware (legacy `recaptcha: true` -> recaptcha ref, POST only)
    const refsRaw = r.middleware === undefined ? [] : r.middleware;
    if (!Array.isArray(refsRaw)) throw new PolicyError(`${label}: middleware must be an array of plugin refs`);
    const refs = refsRaw.map((ref, j) => compileRef(ref, "rule", `${label} middleware[${j}]`));
    if (r.recaptcha !== undefined) {
      if (typeof r.recaptcha !== "boolean") throw new PolicyError(`${label}: recaptcha must be a boolean`);
      if (r.recaptcha) {
        refs.unshift(compileRef({ use: "recaptcha", when: { methods: ["POST"] } }, "rule", `${label} recaptcha`));
        warnings.push(`${label}: legacy "recaptcha: true" upgraded to middleware {"use": "recaptcha", "when": {"methods": ["POST"]}}`);
      } else {
        warnings.push(`${label}: legacy "recaptcha: false" ignored`);
      }
    }

    if (handler !== "origin") enable(handler, baseOptions(handler));

    return Object.freeze({
      path,
      re: globToRegExp(path),
      spec: specificity(path),
      tier,
      auth,
      audience,
      upstream,
      headers,
      secretHeaders,
      forwardIdentity,
      handler,
      middleware: Object.freeze(refs),
    });
  }).sort((a, b) => b.spec - a.spec);

  // --- kernel invariant 6: anything that needs an identity needs an authenticator ---
  const needsIdentity = defaultTier !== "public" || rules.some((r) => r.auth !== "none");
  if (needsIdentity && !authentication) {
    throw new PolicyError("the policy needs an identity (a non-public tier or an auth: optional rule) but no \"authentication\" plugin is configured");
  }

  const policy = Object.freeze({
    version,
    defaultTier,
    authentication,
    enabled: Object.freeze(enabled),
    middleware,
    rules: Object.freeze(rules),
    defaultHeaders,
    warnings: Object.freeze(warnings),
  });

  PRECOMPUTED.set(policy, {
    byRule: new Map(rules.map((r) => [r, buildClassification(r, policy)])),
    fallback: buildClassification(null, policy),
  });
  return policy;
}

function validateUpstream(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new PolicyError(`${label}: upstream must be an absolute URL string`);
  let u;
  try { u = new URL(value); } catch { throw new PolicyError(`${label}: upstream is not an absolute URL`); }
  const loopback = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    throw new PolicyError(`${label}: upstream must be https (http only for localhost/127.0.0.1)`);
  }
  if (u.username || u.password) throw new PolicyError(`${label}: upstream must not contain credentials`);
  if (u.search || u.hash || /[?#]/.test(value)) throw new PolicyError(`${label}: upstream must not contain a query or fragment`);
  return value;
}

// --- classify --------------------------------------------------------------------

/**
 * Resolve a normalized request path to its Classification using the
 * most-specific matching rule. Expects a policy compiled by compilePolicy
 * (rules carry a precompiled `re` and are pre-sorted, so the first match wins).
 * "Most specific" = the rule whose pattern has the longest literal prefix
 * before any `*`; an exact (wildcard-free) pattern always wins over a glob. A
 * pattern ending in `/*` also matches its bare prefix ("/a/b/*" covers "/a/b"),
 * so a section's rule applies to the section path itself. Unmatched paths fall
 * to the default tier (`rule: null`, handler "origin", global middleware only).
 *
 * @param {string} pathname
 * @param {CompiledPolicy} policy
 * @returns {Classification}
 */
export function classify(pathname, policy) {
  const best = (policy.rules || []).find((r) => r.re.test(pathname)) || null;
  const pre = PRECOMPUTED.get(policy);
  if (pre) return best ? pre.byRule.get(best) : pre.fallback;
  return buildClassification(best, policy);
}

function buildClassification(rule, policy) {
  const global = policy.middleware || [];
  if (!rule) {
    const tier = policy.defaultTier;
    return Object.freeze({
      rule: null,
      tier,
      auth: TIER_AUTH[tier][0],
      audience: undefined,
      upstream: undefined,
      headers: undefined,
      secretHeaders: undefined,
      forwardIdentity: false,
      handler: "origin",
      middleware: Object.freeze([...global]),
    });
  }
  return Object.freeze({
    rule,
    tier: rule.tier,
    auth: rule.auth,
    audience: rule.audience,
    upstream: rule.upstream,
    headers: rule.headers,
    secretHeaders: rule.secretHeaders,
    forwardIdentity: rule.forwardIdentity,
    handler: rule.handler,
    middleware: Object.freeze([...global, ...(rule.middleware || [])]),
  });
}

/**
 * Authorization: an empty/absent audience admits any identity; otherwise the
 * identity's groups must intersect it. No identity never satisfies a
 * non-empty audience.
 * @param {Identity|null|undefined} identity
 * @param {ReadonlyArray<string>|undefined} audience
 */
export function audienceAllows(identity, audience) {
  if (!audience || audience.length === 0) return true;
  const groups = identity && Array.isArray(identity.groups) ? identity.groups : [];
  return audience.some((a) => groups.includes(a));
}

// --- matching (copied verbatim from the legacy src/policy.js) ----------------------

function specificity(pattern) {
  const star = pattern.indexOf("*");
  if (star === -1) return 1000 + pattern.length;   // exact patterns rank above any glob
  return pattern.slice(0, star).length;            // else longest literal prefix wins
}

function globToRegExp(pattern) {
  // A trailing "/*" covers the section's own bare path as well as everything
  // under it: "/protected/medical/*" matches "/protected/medical",
  // "/protected/medical/" and "/protected/medical/x". Without this, the bare
  // path fell through to a broader rule (e.g. "/protected/*") and skipped the
  // section's audience check. Specificity is unchanged (literal prefix before
  // the first "*"), so the section rule still beats broader globs for the bare
  // path too. A wildcard elsewhere ("/media_*", "/*.plain.html") keeps the plain
  // "* = any characters" meaning.
  if (pattern.endsWith("/*")) {
    const base = pattern.slice(0, -2);
    return new RegExp("^" + base.split("*").map(escapeRe).join(".*") + "(?:/.*)?$", "s");
  }
  // "s" (dotAll): "*" must match ANY character, including CR/LF, or a path
  // containing one would drop past its section rule to a broader one.
  return new RegExp("^" + pattern.split("*").map(escapeRe).join(".*") + "$", "s");
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
