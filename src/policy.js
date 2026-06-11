/**
 * @typedef {import("./config.js").Config} Config
 */

/**
 * Resolve a request path to its tier and (optional) required audience using the
 * most-specific matching rule. "Most specific" = the rule whose pattern has the
 * longest literal prefix before any `*`; an exact (wildcard-free) pattern always
 * wins over a glob. Unmatched paths fall to `policy.default_tier`.
 * @returns {{ tier: string, audience: (string[]|undefined) }}
 */
export function classify(pathname, policy) {
  const matches = (policy.rules || []).filter((r) => matchGlob(r.path, pathname));
  if (matches.length === 0) return { tier: policy.default_tier, audience: undefined };
  matches.sort((a, b) => specificity(b.path) - specificity(a.path));
  const best = matches[0];
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

function matchGlob(pattern, path) {
  const re = new RegExp("^" + pattern.split("*").map(escapeRe).join(".*") + "$");
  return re.test(path);
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
