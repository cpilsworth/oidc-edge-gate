// Small HTTP helpers for the OIDC routes: the generic authentication-error
// page, redirects, the callback URI, the post-login return path and the
// same-site check for logout.

import { NO_STORE_HEADERS, errorResponse } from "../../../src/sdk/http.js";

/**
 * Generic client-facing authentication error. `detail` is logged (with the
 * kernel's request id) but never sent, so error responses can't be used for
 * reconnaissance ("azp mismatch", "no JWKS key for kid X", raw IdP error params).
 * Body and header carry the same request id.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {number} status
 * @param {string} detail  log-only
 */
export function authError(ctx, status, detail) {
  const id = ctx.requestId;
  ctx.log.error("oidc authentication error", { status, detail });
  return errorResponse(status, `${status} — authentication error (request-id: ${id})\n`, {
    headers: { "x-auth-request-id": id },
  });
}

/** A never-cached redirect. */
export function redirect(status, location) {
  return new Response(null, { status, headers: { location, ...NO_STORE_HEADERS } });
}

// Exactly the pre-plugin set (URL.hostname of an IPv6 literal is "[::1]", so
// "::1" never matches; kept as-is to avoid a behaviour change).
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/**
 * The OIDC redirect_uri. Deployed: the configured value. Served locally
 * (`fastly compute serve`): derived from the request origin, so the login
 * round-trips through localhost. Login and callback both call this with their
 * own request URL, so the two legs byte-match (OIDC requires that). The local
 * URI must also be registered with the IdP for a local login to complete.
 * @param {{redirectUri: string, callbackPath: string}} s
 * @param {URL} url
 */
export function effectiveRedirectUri(s, url) {
  if (LOOPBACK_HOSTS.has(url.hostname)) return `${url.origin}${s.callbackPath}`;
  return s.redirectUri;
}

/**
 * The post-logout redirect URI (W2.R R7): the site origin the browser
 * actually posted the logout from, as already validated by sameSiteOrigin()
 * (its Origin, else its Referer's origin, and only when that is this site:
 * the configured public host `https://${forwardedHost}` or the request
 * origin). Behind the CDN the function sees an internal Host, but the
 * browser's Origin is the public host, so the IdP sends the user back to the
 * public site; served locally it is the localhost origin. Falls back to
 * `https://${forwardedHost}/` (non-loopback) or the request origin.
 * @param {Request} request
 * @param {{forwardedHost?: string|null}} s
 * @param {URL} url
 */
export function postLogoutRedirectUri(request, s, url) {
  const site = sameSiteOrigin(request, url, s.forwardedHost);
  if (site) return `${site}/`;
  if (s.forwardedHost && !LOOPBACK_HOSTS.has(url.hostname)) return `https://${s.forwardedHost}/`;
  return `${url.origin}/`;
}

/**
 * Same-origin relative return path only (no open redirect). Resolving against
 * the origin also catches `//evil.com` and `/\evil.com`.
 * @param {unknown} returnTo
 * @param {string} origin
 */
export function safeReturnTo(returnTo, origin) {
  if (typeof returnTo !== "string" || !returnTo.startsWith("/")) return "/";
  try {
    const resolved = new URL(returnTo, origin);
    if (resolved.origin !== origin) return "/";
    return resolved.pathname + resolved.search;
  } catch {
    return "/";
  }
}

/**
 * CSRF check for state-changing routes (logout). The request's Origin, or the
 * Referer's origin when a browser omitted Origin, must be this site: the origin
 * the request was addressed to, or the configured public host (forwarded_host)
 * when the function sees an internal hostname behind the CDN. `Origin: null`,
 * a malformed Referer, or neither header is rejected.
 * @param {Request} request
 * @param {URL} url
 * @param {string|null|undefined} forwardedHost
 */
export function isSameSiteRequest(request, url, forwardedHost) {
  return sameSiteOrigin(request, url, forwardedHost) !== null;
}

/**
 * The site origin a state-changing request came from (its Origin header, or
 * the Referer's origin when the browser omitted Origin), or null when that is
 * not this site (see isSameSiteRequest).
 * @param {Request} request
 * @param {URL} url
 * @param {string|null|undefined} forwardedHost
 * @returns {string|null}
 */
export function sameSiteOrigin(request, url, forwardedHost) {
  const allowed = new Set([url.origin]);
  if (forwardedHost) allowed.add(`https://${forwardedHost}`);
  const origin = request.headers.get("origin");
  if (origin) return allowed.has(origin) ? origin : null;
  const referer = request.headers.get("referer");
  if (!referer) return null;
  try {
    const o = new URL(referer).origin;
    return allowed.has(o) ? o : null;
  } catch {
    return null;
  }
}
