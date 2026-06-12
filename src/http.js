// Shared HTTP response helpers.
//
// Every response the gate generates itself (auth-initiation 302s, 401/403/4xx
// error pages, and the rewritten protected/secured origin response) must stay
// out of every cache: Surrogate-Control stops the outer AEM CDN, Cache-Control
// stops the browser. Centralising the header pair here means the half-dozen
// hand-written copies can't drift, and gives one place for the security headers
// (nosniff, WWW-Authenticate) to live.

// Surrogate-Control: private stops the outer AEM CDN from storing per-user
// content; Cache-Control: private, no-store stops the browser;
// X-Content-Type-Options: nosniff stops MIME-sniffing of gate-generated bodies.
export const NO_STORE_HEADERS = Object.freeze({
  "surrogate-control": "private",
  "cache-control": "private, no-store",
  "x-content-type-options": "nosniff",
});

/**
 * Edge↔origin correlation id. Prefer Fastly's trace id; otherwise generate one.
 * Emitted to clients on error responses and to the origin on forwarded ones so a
 * single id ties the two together (see README Observability).
 * @param {Request} [request]
 */
export function requestId(request) {
  const trace = request && request.headers ? request.headers.get("fastly-trace-id") : null;
  if (trace) return trace;
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Build a gate-generated response that is never cached. A string body is sent as
 * text/plain; an object body is JSON-encoded. Extra headers (e.g. WWW-Authenticate,
 * x-auth-request-id) merge in last.
 * @param {number} status
 * @param {string|object} body
 * @param {{ type?: string, headers?: Record<string,string> }} [opts]
 */
export function errorResponse(status, body, { type, headers = {} } = {}) {
  const isObject = body !== null && typeof body === "object";
  const contentType = type || (isObject ? "application/json" : "text/plain");
  const payload = isObject ? JSON.stringify(body) : String(body);
  return new Response(payload, {
    status,
    headers: {
      "content-type": `${contentType}; charset=utf-8`,
      ...NO_STORE_HEADERS,
      ...headers,
    },
  });
}
