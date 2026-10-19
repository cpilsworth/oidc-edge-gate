// The kernel's "origin" handler and branded error pages (W1.3; was src/origin.js).
//
// forward(input, gate) sends the (normalized, sanitized) request to the EDS
// origin per the AEM BYO-CDN contract, or to a rule's `upstream` override.
// errorPage(status, input, fallback, gate) serves the site's branded
// /errors/{status} page with a JSON fallback.
//
// `gate` holds the scalar config this module needs and is bound once in
// src/index.js: { originHostname, forwardedHost, pushInvalidation, defaultHeaders }.
// `input` is a ForwardInput (src/kernel/types.js) built by the pipeline.
//
// Responsibilities that moved to the finalizer (src/kernel/finalize.js) and are
// deliberately NOT repeated here: the all-tiers no-store rewrite
// (Surrogate-Control/Cache-Control, Age dropped) and stripping gate-owned
// Set-Cookie lines from the origin's response.
//
// Every fetch goes through `input.fetch`: budgeted, and CacheOverride("pass")
// by default, so the function↔origin cache is bypassed on every tier (the mode
// is positional; see CLAUDE.md "Caching"). No `backend` option: AEM Edge
// Functions use dynamic backends from the absolute URL (a named backend needs
// the `origins:` declaration the config pipeline rejects).

import { errorResponse } from "../sdk/http.js";
import { isReservedHeaderName } from "./context.js";

/**
 * @typedef {Object} GateForwardConfig
 * @property {string} originHostname        EDS delivery host
 * @property {string} [forwardedHost]       public host sent as X-Forwarded-Host
 * @property {boolean} [pushInvalidation]   send X-Push-Invalidation: enabled
 * @property {Readonly<Object<string,string>>} [defaultHeaders]  policy default_headers (EDS origin only)
 */

/**
 * Forward a request to the EDS origin (or the rule's `upstream`).
 *
 * Header order, last write wins:
 *   inbound headers − cookie − reserved prefixes (x-auth-, plugin prefixes) − x-push-invalidation
 *   → host → [EDS only] x-forwarded-host (localhost-aware), x-push-invalidation
 *   → identity (x-auth-subject/email/groups: EDS always, upstream only with forwardIdentity)
 *   → [EDS only] policy default_headers → rule headers → rule secret_headers
 *   → plugin headers (ctx.forwardHeaders; identity-carrying ones, manifest
 *     identityHeaders, to an upstream only with forwardIdentity) → x-auth-request-id.
 *
 * @param {import("./types.js").ForwardInput} input
 * @param {GateForwardConfig} gate
 * @returns {Promise<Response>}
 */
export async function forward(input, gate) {
  const { request, classification: c, identity } = input;
  const upstream = c.upstream || null;
  const inUrl = new URL(request.url);
  const targetHost = upstream ? new URL(upstream).host : gate.originHostname;
  const base = upstream ? upstream.replace(/\/+$/, "") : `https://${gate.originHostname}`;
  const originUrl = `${base}${inUrl.pathname}${inUrl.search}`;

  const headers = new Headers(request.headers);
  // Never forward the inbound Cookie header (it carries the gate session).
  // Reserved prefixes (x-auth- + every plugin's declared prefixes) and
  // x-push-invalidation are already stripped by the pipeline; doing it again
  // here keeps forward() safe on its own, so an origin can always trust that
  // their presence means the gate set them. "_" lookalikes (x_auth_groups,
  // x_push_invalidation) count as the dashed name (F10).
  const strip = (input.stripPrefixes || ["x-auth-"]).map((p) => p.toLowerCase());
  for (const name of [...headers.keys()]) {
    if (isReservedHeaderName(name, strip, ["cookie", "x-push-invalidation"])) headers.delete(name);
  }
  headers.set("host", targetHost);

  if (!upstream) {
    // EDS BYO-CDN contract. x-forwarded-host tells EDS the public host to build
    // absolute URLs from: the configured public domain in a real deployment,
    // the actual request host when served locally (`fastly compute serve`).
    headers.set("x-forwarded-host", isLocalHost(inUrl.hostname) ? inUrl.host : gate.forwardedHost);
    if (gate.pushInvalidation) headers.set("x-push-invalidation", "enabled");
  }
  // Identity: always to the EDS origin, to a (possibly third-party) upstream
  // only when the rule opts in with forward_identity.
  if (identity && (!upstream || c.forwardIdentity === true)) {
    headers.set("x-auth-subject", identity.sub || "");
    headers.set("x-auth-email", identity.email || "");
    headers.set("x-auth-groups", Array.isArray(identity.groups) ? identity.groups.join(",") : "");
  }
  // Policy default_headers (e.g. a shared secret proving a request came
  // through the gate) are for the site's own origin only, never an upstream.
  if (!upstream && gate.defaultHeaders) {
    for (const [name, value] of Object.entries(gate.defaultHeaders)) headers.set(name, value);
  }
  // A rule's own headers apply to whichever target it resolves to.
  if (c.headers) {
    for (const [name, value] of Object.entries(c.headers)) headers.set(name, value);
  }
  if (c.secretHeaders) {
    for (const [name, key] of Object.entries(c.secretHeaders)) {
      const value = typeof input.secret === "function" ? input.secret(key) : undefined;
      // Fail closed: a rule that must prove itself with a secret is never
      // forwarded without it. The key NAME is safe to report; the value never is.
      if (typeof value !== "string" || value === "") throw new Error(`secret_headers: secret ${JSON.stringify(key)} is not configured`);
      headers.set(name, value);
    }
  }
  // Plugin-computed headers (already prefix-checked by ctx.forwardHeaders).
  // Those of a plugin with identityHeaders: true (e.g. user-info's x-user-*
  // profile) carry identity/PII: same rule as x-auth-*, so an upstream gets
  // them only with forward_identity (W2.R R2).
  if (input.pluginHeaders) {
    const identityPrefixes = (input.identityHeaderPrefixes || []).map((p) => p.toLowerCase());
    const withholdIdentity = upstream && c.forwardIdentity !== true;
    for (const [name, value] of input.pluginHeaders) {
      if (withholdIdentity && identityPrefixes.some((p) => name.toLowerCase().startsWith(p))) continue;
      headers.set(name, value);
    }
  }
  // Edge↔origin correlation (see README Observability).
  headers.set("x-auth-request-id", input.requestId);

  const forwarded = new Request(originUrl, {
    method: request.method,
    headers,
    body: request.body,
    // undici requires `duplex` whenever a streaming body is set (request.body is
    // always a ReadableStream when non-null); Fastly's RequestInit ignores it.
    ...(request.body ? { duplex: "half" } : {}),
  });
  return input.fetch(forwarded, undefined, { purpose: "forward" });
}

/**
 * Serve the origin's branded `/errors/{status}` page under the error status,
 * falling back to `fallbackBody` (JSON/text via errorResponse) when the page is
 * unavailable or the fetch fails, so an error is always returned.
 *
 * @param {number} status          HTTP error status (also the /errors/{status} path)
 * @param {import("./types.js").ForwardInput} input
 * @param {string|object} fallbackBody
 * @param {GateForwardConfig} gate
 * @returns {Promise<Response>}
 */
export async function errorPage(status, input, fallbackBody, gate) {
  const id = input.requestId;
  try {
    const url = `https://${gate.originHostname}/errors/${status}`;
    // Same origin as forward(), outside any matched rule: only the policy's
    // default_headers (e.g. a shared secret the origin requires) apply.
    const headers = { host: gate.originHostname, "x-forwarded-host": gate.forwardedHost };
    if (gate.defaultHeaders) Object.assign(headers, gate.defaultHeaders);
    const res = await input.fetch(url, { headers }, { purpose: "error-page" });
    if (res.ok) {
      const out = new Response(res.body, { status });
      out.headers.set("content-type", res.headers.get("content-type") || "text/html; charset=utf-8");
      out.headers.set("x-auth-request-id", id);
      return out;
    }
  } catch {
    /* origin unreachable / no error page: fall through to the plain error.
       A fetch-budget violation is still enforced by the pipeline's finalizer step. */
  }
  return errorResponse(status, fallbackBody, { headers: { "x-auth-request-id": id } });
}

function isLocalHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}
