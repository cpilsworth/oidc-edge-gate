/// <reference types="@fastly/js-compute" />
import { loadConfig } from "./config.js";
import { OidcClient } from "./oidc.js";
import { readSession } from "./session.js";
import { classify, isAuthorized } from "./policy.js";
import { forwardToOrigin } from "./origin.js";
import { errorResponse, requestId } from "./http.js";
import { normalizePathname } from "./path.js";

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

  const { tier, audience } = classify(pathname, config.policy);

  // public: forward before touching the cookie.
  if (tier === "public") return forwardToOrigin(req, null, "public", config);

  // protected / secured: validate the local session.
  const session = await readSession(req, config);
  if (!session) {
    return tier === "secured" ? unauthorizedJson(req) : oidc.startLogin(req, url);
  }
  if (!isAuthorized(session, audience)) return forbidden(req);

  return forwardToOrigin(req, session, tier, config);
}

function badRequest(request) {
  return errorResponse(400, { error: "bad_request" }, {
    headers: { "x-auth-request-id": requestId(request) },
  });
}

function unauthorizedJson(request) {
  return errorResponse(401, { error: "unauthorized" }, {
    headers: { "x-auth-request-id": requestId(request) },
  });
}

function forbidden(request) {
  return errorResponse(403, { error: "forbidden" }, {
    headers: { "x-auth-request-id": requestId(request) },
  });
}
