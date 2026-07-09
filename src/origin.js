import { CacheOverride } from "fastly:cache-override";
import { NO_STORE_HEADERS, errorResponse, requestId } from "./http.js";
import { SESSION_COOKIE, STATE_COOKIE } from "./session.js";

/**
 * Forward a request to the EDS origin per AEM BYO-CDN rules, and rewrite the
 * response so nothing is cached — not the function cache, the outer AEM CDN, or
 * the browser — on ANY tier. (This POC runs on a sandbox program where per-page
 * cache purge isn't wired up, so caching risks serving stale content, e.g. a
 * stale error; disabling it keeps every response fresh.)
 *
 * Platform note (vs the Cloudflare sibling): there is no `cf:{cacheTtl}` request
 * option on Fastly. Two caches, two levers (see worker-gate-parity-plan.md §2.2):
 *   - the *function* cache (function↔origin) is bypassed on every tier via
 *     `CacheOverride({ mode: "pass" })` on the origin fetch;
 *   - the *outer AEM CDN* is kept off per-user content with `Surrogate-Control:
 *     private` on the response (Cache-Control only reaches the browser);
 *   - the browser is kept off it with `Cache-Control: private, no-store`.
 *
 * @param {Request} request
 * @param {object|null} session  null for the public tier
 * @param {string} tier          "public" | "protected" | "secured"
 * @param {import("./config.js").Config} config
 */
const GATE_COOKIE_NAMES = new Set([SESSION_COOKIE, STATE_COOKIE]);

/**
 * @param {Request} request
 * @param {object|null} session
 * @param {string} tier
 * @param {import("./config.js").Config} config
 * @param {?string} upstream  optional origin-base URL override for this route
 *   (e.g. "https://swapi.dev"); the request path is preserved. When set, the
 *   target is a third-party API, so EDS BYO-CDN headers and user-identity headers
 *   are NOT sent (avoids leaking identity to an external service).
 */
export async function forwardToOrigin(request, session, tier, config, upstream = null) {
  const inUrl = new URL(request.url);
  const targetHost = upstream ? new URL(upstream).host : config.originHostname;
  const base = upstream ? upstream.replace(/\/+$/, "") : `https://${config.originHostname}`;
  const originUrl = `${base}${inUrl.pathname}${inUrl.search}`;

  const headers = new Headers(request.headers);
  headers.delete("cookie"); // never leak the gate session to origin
  // Strip any client-supplied trusted headers so they cannot be spoofed to the origin.
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith("x-auth-")) headers.delete(name);
  }
  headers.delete("x-push-invalidation");
  headers.set("host", targetHost);

  if (!upstream) {
    // EDS origin only: BYO-CDN contract + forwarded identity.
    headers.set("x-forwarded-host", config.forwardedHost);
    if (config.pushInvalidation) headers.set("x-push-invalidation", "enabled");
    if (session) {
      headers.set("x-auth-subject", session.sub || "");
      headers.set("x-auth-email", session.email || "");
      headers.set("x-auth-groups", Array.isArray(session.groups) ? session.groups.join(",") : "");
    }
  }
  // Edge↔origin correlation (see README Observability).
  headers.set("x-auth-request-id", requestId(request));

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
  // No `backend` option — dynamic backend from the absolute origin URL. AEM
  // Edge Functions enable dynamic backends by default; a named backend would
  // need an `origins:` declaration the config pipeline rejects (see
  // config/edgeFunctions.yaml).
  const res = await fetch(forwarded, {
    cacheOverride: new CacheOverride({ mode: "pass" }),
  });
  const out = new Response(res.body, res);
  stripGateSetCookies(out.headers);

  // Keep every response out of every cache, all tiers. Surrogate-Control:
  // private stops the outer AEM CDN from caching the function response;
  // Cache-Control stops the browser; Age is dropped so no stale age is implied
  // downstream. (The function↔origin cache is already bypassed above via
  // CacheOverride mode: "pass".)
  for (const [k, v] of Object.entries(NO_STORE_HEADERS)) out.headers.set(k, v);
  out.headers.delete("age");
  return out;
}

/**
 * Serve a branded error page fetched from the origin at `/errors/{status}` (e.g.
 * a 403 renders the site's /errors/403 page), returning it with the original
 * error status. Falls back to `fallbackBody` (JSON/text via errorResponse) if the
 * origin has no such page or the fetch fails, so an error is always returned.
 * The response is never cached (all-tiers no-store, like forwardToOrigin).
 *
 * @param {number} status        HTTP error status (also the /errors/{status} path)
 * @param {import("./config.js").Config} config
 * @param {Request} request
 * @param {string|object} fallbackBody  body used when the origin page is unavailable
 */
export async function originErrorPage(status, config, request, fallbackBody) {
  const id = requestId(request);
  try {
    const url = `https://${config.originHostname}/errors/${status}`;
    // No `backend` option — dynamic backend from the absolute URL (see forwardToOrigin).
    const res = await fetch(url, {
      headers: { host: config.originHostname, "x-forwarded-host": config.forwardedHost },
      cacheOverride: new CacheOverride({ mode: "pass" }),
    });
    if (res.ok) {
      const out = new Response(res.body, { status });
      out.headers.set("content-type", res.headers.get("content-type") || "text/html; charset=utf-8");
      for (const [k, v] of Object.entries(NO_STORE_HEADERS)) out.headers.set(k, v);
      out.headers.set("x-auth-request-id", id);
      return out;
    }
  } catch {
    /* origin unreachable / no error page — fall through to the plain error */
  }
  return errorResponse(status, fallbackBody, { headers: { "x-auth-request-id": id } });
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
  const idx = setCookieLine.indexOf("=");
  // A Set-Cookie line without `=` is malformed; return a name that matches no
  // gate cookie so it falls through `GATE_COOKIE_NAMES.has` unstripped (the
  // caller only strips our own cookie names). Avoids the indexOf === -1 trap
  // where slice(0, -1) would yield the whole string minus one char.
  if (idx === -1) return "";
  return setCookieLine.slice(0, idx).trim();
}
