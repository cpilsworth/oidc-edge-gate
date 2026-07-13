/// <reference types="@fastly/js-compute" />
import { loadConfig } from "./config.js";
import { OidcClient } from "./oidc.js";
import { readSession } from "./session.js";
import { classify, isAuthorized } from "./policy.js";
import { forwardToOrigin, originErrorPage } from "./origin.js";
import { errorResponse, requestId } from "./http.js";
import { normalizePathname } from "./path.js";
import { extractRecaptchaToken, verifyRecaptcha, passesRecaptcha, recaptchaResultHeaders } from "./recaptcha.js";

// AEM Edge Function entry point. Runs on the Fastly Compute JS runtime and sits
// between the CDN cache and the EDS origin. Every request is classified against
// the three-tier path policy:
//
//   public    -> forwarded straight to origin, no auth, origin caching intact.
//   protected -> needs a valid session; HTML clients without one are 302'd to
//                the IdP to log in.
//   secured   -> needs a valid session; clients without one get a 401 JSON
//                response (suited to API/XHR callers, which can't follow a 302).
//
// /.auth/callback and /.auth/logout are owned by the gate itself. Only those
// routes and unauthenticated logins ever touch the IdP backend; authenticated
// traffic is validated locally (HMAC, no backend round-trip) and passed through.

// Guarded so the module can be imported under plain node (unit tests) where
// `addEventListener` does not exist; on the Fastly Compute runtime it always does.
if (typeof addEventListener === "function") {
  addEventListener("fetch", (event) => event.respondWith(handleRequest(event)));
}

// Exported for unit testing (node-vitest). handleRequest returns the Response
// promise directly; the listener above just wires it to event.respondWith.
export async function handleRequest(event) {
  // Catch-all so an unexpected throw (config load, backend fetch, etc.) becomes a
  // diagnosable 500 with the correlation id instead of an opaque runtime trap
  // (empty-body 500 from the platform). Detail is logged server-side (visible via
  // `aio aem edge-functions tail-logs`); the client body stays generic so we
  // don't leak internals.
  try {
    return await handleRequestInner(event);
  } catch (err) {
    const id = requestId(event.request);
    console.error(`gate error [${id}]:`, (err && err.stack) || String(err));
    return errorResponse(500, { error: "internal_error" }, {
      headers: { "x-auth-request-id": id },
    });
  }
}

async function handleRequestInner(event) {
  const request = event.request;
  const url = new URL(request.url);
  const config = await loadConfig();
  const oidc = new OidcClient(config);

  // Normalize the path before anything classifies or routes on it, so the gate
  // and origin agree on what was requested (H1). Rebuild the request with the
  // normalized URL so the same path is forwarded to origin, not the raw one.
  let pathname;
  try {
    pathname = normalizePathname(url.pathname);
  } catch {
    return badRequest(request);
  }
  let req = request;
  if (pathname !== url.pathname) {
    url.pathname = pathname;
    req = new Request(url.toString(), request);
  }

  // Gate-owned routes first.
  if (pathname === config.routes.callback) return oidc.handleCallback(req, url);
  if (pathname === config.routes.logout) return oidc.handleLogout(req, url);

  const { tier, audience, upstream, headers, recaptcha } = classify(pathname, config.policy);
  let forwardHeaders = headers;

  // A rule flagged `recaptcha: true` requires a POST submission to carry a
  // verifiable g-recaptcha-response field. Only POST is checked — a GET to the
  // same route (e.g. loading the form page itself) has no body to validate.
  if (recaptcha && req.method === "POST") {
    const outcome = await verifyFormRecaptcha(req, config);
    if (outcome instanceof Response) return outcome;
    req = outcome.request; // body was buffered to inspect it; re-attached for forwarding
    // Trusted x-recaptcha-* headers (score/hostname/challenge_ts) computed from
    // Google's response — merged over any policy-configured `headers` (both
    // are gate-applied via forwardToOrigin's extraHeaders; recaptcha result
    // names are reserved from policy config, see policy.js, so there's no
    // real collision to resolve here).
    forwardHeaders = { ...headers, ...outcome.headers };
  }

  // public: forward before touching the cookie.
  if (tier === "public") return forwardToOrigin(req, null, "public", config, upstream, forwardHeaders);

  // protected / secured: validate the local session.
  const session = await readSession(req, config);
  if (!session) {
    return tier === "secured" ? unauthorizedJson(req) : oidc.startLogin(req, url);
  }
  if (!isAuthorized(session, audience)) return forbidden(req, config);

  return forwardToOrigin(req, session, tier, config, upstream, forwardHeaders);
}

/**
 * Verify a POST body's g-recaptcha-response field against Google's siteverify
 * endpoint. Reading the body consumes `req`'s stream, so on success this
 * returns `{ request, headers }`: a fresh Request (same method/headers/URL,
 * body re-attached from the buffered raw bytes) for the caller to forward
 * instead of the original, plus the trusted `x-recaptcha-*` headers to attach
 * to it (see recaptcha.js#recaptchaResultHeaders). The body is buffered as
 * bytes, not text — multipart/form-data can carry a binary file part, and
 * decoding+re-encoding as UTF-8 would corrupt it; a lossy text *view* of the
 * same bytes is decoded only to locate the token, which is always plain
 * ASCII. On failure — misconfiguration or a failed/missing token — returns a
 * Response for the caller to return directly.
 * @returns {Promise<{request:Request, headers:Object<string,string>}|Response>}
 */
async function verifyFormRecaptcha(req, config) {
  const id = requestId(req);
  if (!config.recaptchaSecret) {
    // A rule requires recaptcha but no secret is provisioned: fail closed
    // rather than silently letting unverified submissions through.
    console.error(`gate misconfig [${id}]: recaptcha required but recaptcha_secret is not configured`);
    return errorResponse(500, { error: "internal_error" }, { headers: { "x-auth-request-id": id } });
  }

  const bodyBuf = await req.arrayBuffer();
  const bodyTextView = new TextDecoder().decode(bodyBuf);
  const token = extractRecaptchaToken(bodyTextView, req.headers.get("content-type"));
  const result = await verifyRecaptcha(token, config.recaptchaSecret);
  if (!passesRecaptcha(result, config.recaptchaMinScore)) {
    console.error(`recaptcha failed [${id}]:`, (result && result["error-codes"]) || result);
    return errorResponse(400, { error: "recaptcha_failed" }, { headers: { "x-auth-request-id": id } });
  }

  const request = new Request(req.url, { method: req.method, headers: req.headers, body: bodyBuf });
  return { request, headers: recaptchaResultHeaders(result) };
}

function badRequest(request) {
  return errorResponse(400, { error: "bad_request" }, {
    headers: { "x-auth-request-id": requestId(request) },
  });
}

function unauthorizedJson(request) {
  return errorResponse(401, { error: "unauthorized" }, {
    headers: { "www-authenticate": "Bearer", "x-auth-request-id": requestId(request) },
  });
}

// 403: serve the site's branded /errors/403 page from origin, falling back to a
// JSON body if that page is unavailable.
function forbidden(request, config) {
  return originErrorPage(403, config, request, { error: "forbidden" });
}
