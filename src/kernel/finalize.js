// Response finalizer (W1.1) — kernel invariant 7. Applied by the pipeline to
// EVERY response: routes, short-circuits, challenges, errors and handler
// responses. Contract: docs/architecture/plugins.md §6.
//
// Order:
//   1. Owned-cookie Set-Cookie lines are removed:
//        - "handler" (origin / rule handler / afterForward) and "kernel"
//          (errorPage, 401, …) responses: every registry-owned cookie, so the
//          origin can never set a gate cookie;
//        - "plugin" responses (route, short-circuit, challenge): owned cookies
//          NOT declared by the producing plugin (it may set its own).
//   2. Plugin cookie writes (ctx.cookies) are appended.
//   3. ctx.responseHeaders are merged, except set-cookie, cache headers and
//      reserved prefixes (x-auth- + plugin prefixes), which are ignored with a warning.
//   4. NO_STORE_HEADERS are set and `age` is removed.
//   5. Status >= 400 without x-auth-request-id gets one.
// A new Response is returned; the input's (possibly immutable) headers are never mutated.

import { NO_STORE_HEADERS } from "../sdk/http.js";

/** Headers plugins may never set through ctx.responseHeaders (lowercase). */
export const PROTECTED_RESPONSE_HEADERS = Object.freeze([
  "set-cookie", "cache-control", "surrogate-control", "cdn-cache-control", "surrogate-key", "age", "expires", "pragma",
]);

/** @returns {string[]} every Set-Cookie line of a Headers object */
export function getSetCookies(headers) {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  const raw = headers.get("set-cookie");
  return raw ? [raw] : [];
}

/** Cookie name of a Set-Cookie line ("" if malformed, which matches no owned cookie). */
export function setCookieName(line) {
  const idx = line.indexOf("=");
  if (idx === -1) return "";
  return line.slice(0, idx).trim();
}

/**
 * @param {Response} response
 * @param {Object} opts
 * @param {string} opts.requestId
 * @param {"handler"|"plugin"|"kernel"} opts.source   who produced the response
 * @param {{cookies: ReadonlyArray<string>, name: string}} [opts.producer]  the plugin, for source "plugin"
 * @param {string[]} [opts.ownedCookies]          registry.ownedCookies()
 * @param {string[]} [opts.reservedPrefixes]      registry.reservedHeaderPrefixes() (lowercase)
 * @param {string[]} [opts.cookieWrites]          serialized Set-Cookie lines from ctx.cookies
 * @param {Array<{plugin: string, headers: Headers}>} [opts.responseHeaders]  ctx.responseHeaders per plugin
 * @param {{warn: Function}} [opts.log]
 * @returns {Response}
 */
export function finalizeResponse(response, {
  requestId,
  source = "kernel",
  producer,
  ownedCookies = [],
  reservedPrefixes = ["x-auth-"],
  cookieWrites = [],
  responseHeaders = [],
  log,
} = {}) {
  if (!(response instanceof Response)) throw new TypeError("finalizeResponse expects a Response");
  const headers = new Headers(response.headers);

  // 1. owned cookies
  const owned = new Set(ownedCookies);
  const keep = source === "plugin" && producer ? new Set(producer.cookies) : new Set();
  const lines = getSetCookies(headers);
  if (lines.length) {
    headers.delete("set-cookie");
    for (const line of lines) {
      const name = setCookieName(line);
      if (owned.has(name) && !keep.has(name)) {
        if (log) log.warn("stripped owned cookie from response", { cookie: name, source });
        continue;
      }
      headers.append("set-cookie", line);
    }
  }

  // 2. plugin cookie writes
  for (const line of cookieWrites) headers.append("set-cookie", line);

  // 3. plugin response headers
  const protectedNames = new Set(PROTECTED_RESPONSE_HEADERS);
  for (const { plugin, headers: extra } of responseHeaders) {
    for (const [name, value] of extra) {
      const lower = name.toLowerCase();
      if (protectedNames.has(lower) || reservedPrefixes.some((p) => lower.startsWith(p))) {
        if (log) log.warn("ignored protected response header", { header: lower, from: plugin });
        continue;
      }
      headers.set(lower, value);
    }
  }

  // 4. never cache
  for (const [k, v] of Object.entries(NO_STORE_HEADERS)) headers.set(k, v);
  headers.delete("age");

  // 5. correlation id on errors
  if (response.status >= 400 && !headers.has("x-auth-request-id") && requestId) headers.set("x-auth-request-id", requestId);

  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
