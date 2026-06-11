import { CacheOverride } from "fastly:cache-override";

/**
 * Forward a request to the EDS origin per AEM BYO-CDN rules. For protected/secured
 * tiers, disable edge caching and rewrite the response so per-user content can never
 * be stored or cross-served. Public responses pass through with origin caching intact.
 *
 * Platform note (vs the Cloudflare sibling): there is no `cf:{cacheTtl}` request
 * option on Fastly. Caching of per-user content is suppressed two ways — a
 * `CacheOverride("pass")` on the origin fetch (stops the function's own Fastly
 * cache storing it) plus `Cache-Control: private, no-store` on the response (stops
 * anything downstream, including the AEM-managed CDN cache). See
 * worker-gate-parity-plan.md §2.0 / §2.2.
 *
 * @param {Request} request
 * @param {object|null} session  null for the public tier
 * @param {string} tier          "public" | "protected" | "secured"
 * @param {import("./config.js").Config} config
 */
const GATE_COOKIE_NAMES = new Set(["__edge_session", "__edge_login"]);

export async function forwardToOrigin(request, session, tier, config) {
  const inUrl = new URL(request.url);
  const originUrl = `https://${config.originHostname}${inUrl.pathname}${inUrl.search}`;

  const headers = new Headers(request.headers);
  headers.delete("cookie"); // never leak the gate session to origin
  // Strip any client-supplied trusted headers so they cannot be spoofed to the origin.
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith("x-auth-")) headers.delete(name);
  }
  headers.delete("x-push-invalidation");
  headers.set("host", config.originHostname);
  headers.set("x-forwarded-host", config.forwardedHost);
  if (config.pushInvalidation) headers.set("x-push-invalidation", "enabled");

  if (session) {
    headers.set("x-auth-subject", session.sub || "");
    headers.set("x-auth-email", session.email || "");
    headers.set("x-auth-groups", Array.isArray(session.groups) ? session.groups.join(",") : "");
  }
  // Edge↔origin correlation (see README Observability).
  headers.set("x-auth-request-id", requestId(request));

  const cacheOff = tier !== "public";
  const forwarded = new Request(originUrl, {
    method: request.method,
    headers,
    body: request.body,
  });

  // Never cache at the *function* layer for now. The AEM edge-function cache is
  // purgeable by surrogate key, but EDS has no hook to purge it on publication
  // yet, so a cached entry could go stale with no way to evict it — so we bypass
  // it on every tier (mode: "pass"). The outer AEM CDN still caches public
  // content via the origin's own (passed-through) cache/surrogate headers; once
  // an out-of-band "observe publish → purge by surrogate key" path exists, public
  // tiers could opt back into function caching.
  // Docs: experienceleague.adobe.com/.../developing/edge-functions-caching
  const res = await fetch(forwarded, {
    backend: config.backends.origin,
    cacheOverride: new CacheOverride({ mode: "pass" }),
  });
  const out = new Response(res.body, res);
  stripGateSetCookies(out.headers);
  if (!cacheOff) return out;

  // protected/secured: keep per-user content out of every cache.
  // Surrogate-Control: private stops the outer AEM CDN from caching the function
  // response; Cache-Control stops the browser; Age is dropped so no stale age is
  // implied downstream.
  out.headers.set("surrogate-control", "private");
  out.headers.set("cache-control", "private, no-store");
  out.headers.delete("age");
  return out;
}

/** Edge↔origin correlation id. Prefer Fastly's trace id; otherwise generate one. */
function requestId(request) {
  const trace = request.headers.get("fastly-trace-id");
  if (trace) return trace;
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function stripGateSetCookies(headers) {
  const setCookies = headers.getSetCookie ? headers.getSetCookie() : [headers.get("set-cookie")].filter(Boolean);
  if (setCookies.length === 0) return;

  headers.delete("set-cookie");
  for (const line of setCookies) {
    if (!GATE_COOKIE_NAMES.has(cookieName(line))) headers.append("set-cookie", line);
  }
}

function cookieName(setCookieLine) {
  return setCookieLine.slice(0, setCookieLine.indexOf("=")).trim();
}
