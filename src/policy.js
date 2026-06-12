/**
 * @typedef {import("./config.js").Config} Config
 */

/**
 * Precompile a raw policy (as parsed from config JSON) once at load time: build
 * each rule's matcher RegExp and sort rules most-specific-first. classify() then
 * reduces to a single ordered `find()` with no per-request regex construction,
 * and a malformed pattern surfaces at config load rather than at match time.
 * @returns {Config["policy"]} policy with `rules` carrying precompiled `re`
 */
export function compilePolicy(policy) {
  const rules = (policy.rules || [])
    .map((r) => ({ ...r, re: globToRegExp(r.path), spec: specificity(r.path) }))
    .sort((a, b) => b.spec - a.spec);
  return { ...policy, rules };
}

/**
 * Resolve a request path to its tier and (optional) required audience using the
 * most-specific matching rule. Expects a policy compiled by {@link compilePolicy}
 * (rules carry a precompiled `re` and are pre-sorted, so the first match wins).
 * "Most specific" = the rule whose pattern has the longest literal prefix before
 * any `*`; an exact (wildcard-free) pattern always wins over a glob. Unmatched
 * paths fall to `policy.default_tier`.
 * @returns {{ tier: string, audience: (string[]|undefined) }}
 */
export function classify(pathname, policy) {
  const best = (policy.rules || []).find((r) => r.re.test(pathname));
  if (!best) return { tier: policy.default_tier, audience: undefined };
  return { tier: best.tier, audience: best.audience };
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
