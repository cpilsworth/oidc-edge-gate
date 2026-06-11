/// <reference types="@fastly/js-compute" />
import { loadConfig } from "./config.js";
import { OidcClient } from "./oidc.js";
import { readSession } from "./session.js";
import { classify, isAuthorized } from "./policy.js";
import { forwardToOrigin } from "./origin.js";

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

  // Gate-owned routes first.
  if (url.pathname === config.routes.callback) return oidc.handleCallback(request, url);
  if (url.pathname === config.routes.logout) return oidc.handleLogout(request, url);

  const { tier, audience } = classify(url.pathname, config.policy);

  // public: forward before touching the cookie.
  if (tier === "public") return forwardToOrigin(request, null, "public", config);

  // protected / secured: validate the local session.
  const session = await readSession(request, config);
  if (!session) {
    return tier === "secured" ? unauthorizedJson() : oidc.startLogin(request, url);
  }
  if (!isAuthorized(session, audience)) return forbidden();

  return forwardToOrigin(request, session, tier, config);
}

function unauthorizedJson() {
  return new Response(JSON.stringify({ error: "unauthorized" }), {
    status: 401,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "surrogate-control": "private",
      "cache-control": "private, no-store",
    },
  });
}

function forbidden() {
  return new Response(JSON.stringify({ error: "forbidden" }), {
    status: 403,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "surrogate-control": "private",
      "cache-control": "private, no-store",
    },
  });
}
