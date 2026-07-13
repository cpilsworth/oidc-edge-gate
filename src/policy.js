/**
 * @typedef {import("./config.js").Config} Config
 */

const VALID_TIERS = new Set(["public", "protected", "secured"]);

// Header names the gate manages itself (identity injection, EDS BYO-CDN
// contract, cookie transport). Policy-configured `headers`/`default_headers`
// may not set these — allowing it would let a static config value silently
// shadow a per-request, gate-computed value (e.g. a misconfigured
// `x-auth-subject` on a public rule would look like verified identity to an
// origin that trusts the gate).
const RESERVED_HEADER_NAMES = new Set(["host", "cookie", "set-cookie", "x-forwarded-host", "x-push-invalidation"]);

/**
 * Validate a policy-configured header map (`headers` on a rule, or the
 * top-level `default_headers`). Returns undefined when absent so callers can
 * omit an empty `headers` key from their result (kept out of classify()'s
 * return shape when nothing is configured).
 */
function validateHeaders(headers, label) {
  if (headers == null) return undefined;
  if (typeof headers !== "object" || Array.isArray(headers)) {
    throw new Error(`${label} must be an object of header name -> string value`);
  }
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (RESERVED_HEADER_NAMES.has(lower) || lower.startsWith("x-auth-")) {
      throw new Error(`${label}: header "${name}" is gate-managed and cannot be set via policy config`);
    }
    if (typeof value !== "string") {
      throw new Error(`${label}: header "${name}" value must be a string`);
    }
  }
  return { ...headers };
}

/**
 * Precompile a raw policy (as parsed from config JSON) once at load time: build
 * each rule's matcher RegExp, validate its headers, and sort rules
 * most-specific-first. classify() then reduces to a single ordered `find()`
 * with no per-request regex construction, and a malformed pattern, unknown
 * tier, or invalid header map surfaces at config load rather than at match
 * time.
 *
 * `default_headers` is validated here but intentionally NOT merged into each
 * rule: whether it applies depends on where a request is ultimately forwarded
 * (the EDS origin vs. a rule's `upstream` override), which classify() can't
 * know. forwardToOrigin (origin.js) applies `default_headers` only when there
 * is no `upstream` override — otherwise a secret meant to gate the site's own
 * origin would also leak to any third-party upstream a rule proxies to.
 * @returns {Config["policy"]} policy with `rules` carrying precompiled `re`
 */
export function compilePolicy(policy) {
  const defaultHeaders = validateHeaders(policy.default_headers, "policy.default_headers");
  const rules = (policy.rules || []).map((r) => {
    if (!VALID_TIERS.has(r.tier)) {
      throw new Error(`unknown policy tier: ${JSON.stringify(r.tier)}`);
    }
    const headers = validateHeaders(r.headers, `policy rule ${JSON.stringify(r.path)} headers`);
    return { ...r, re: globToRegExp(r.path), spec: specificity(r.path), headers };
  }).sort((a, b) => b.spec - a.spec);
  const defaultTier = policy.default_tier || "protected";
  if (!VALID_TIERS.has(defaultTier)) {
    throw new Error(`unknown default_tier: ${JSON.stringify(defaultTier)}`);
  }
  return { ...policy, rules, default_tier: defaultTier, default_headers: defaultHeaders };
}

/**
 * Resolve a request path to its tier and (optional) required audience using the
 * most-specific matching rule. Expects a policy compiled by {@link compilePolicy}
 * (rules carry a precompiled `re` and are pre-sorted, so the first match wins).
 * "Most specific" = the rule whose pattern has the longest literal prefix before
 * any `*`; an exact (wildcard-free) pattern always wins over a glob. Unmatched
 * paths fall to `policy.default_tier`.
 * A matched rule may carry an optional `upstream` (origin-base URL) to proxy the
 * route to a different origin than the EDS default, and/or `headers` (static
 * name -> value pairs) to attach to the forwarded request regardless of
 * target — e.g. an API key for that specific upstream. Both are surfaced for
 * the caller to pass to forwardToOrigin, which layers the policy's top-level
 * `default_headers` in underneath (EDS-origin only; see compilePolicy).
 * @returns {{ tier: string, audience: (string[]|undefined), upstream: (string|undefined), headers: (Object<string,string>|undefined) }}
 */
export function classify(pathname, policy) {
  const best = (policy.rules || []).find((r) => r.re.test(pathname));
  if (!best) return { tier: policy.default_tier, audience: undefined, upstream: undefined, headers: undefined };
  return { tier: best.tier, audience: best.audience, upstream: best.upstream, headers: best.headers };
}

/** Authenticated-session authorization: empty/absent audience = any session OK. */
export function isAuthorized(session, audience) {
  if (!audience || audience.length === 0) return true;
  const groups = Array.isArray(session.groups) ? session.groups : [];
  return audience.some((a) => groups.includes(a));
}

function specificity(pattern) {
  const star = pattern.indexOf("*");
  if (star === -1) return 1000 + pattern.length;   // exact patterns rank above any glob
  return pattern.slice(0, star).length;            // else longest literal prefix wins
}

function globToRegExp(pattern) {
  return new RegExp("^" + pattern.split("*").map(escapeRe).join(".*") + "$");
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
