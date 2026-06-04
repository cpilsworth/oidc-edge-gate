/// <reference types="@fastly/js-compute" />
import { loadConfig } from "./config.js";
import { OidcClient } from "./oidc.js";
import { readSession } from "./session.js";

// AEM Edge Function entry point. Runs on the Fastly Compute JS runtime and sits
// between the CDN cache and the site origin. Every request is gated:
//
//   1. /.auth/callback and /.auth/logout are handled by the gate itself.
//   2. A valid, in-policy session cookie -> request is forwarded to origin.
//   3. Anything else -> the OIDC authorization-code flow is started.
//
// Only the callback/logout paths and unauthenticated requests ever touch the
// IdP backend; authenticated traffic is validated locally (HMAC) and passed
// straight through, keeping fetch() usage minimal.

addEventListener("fetch", (event) => event.respondWith(handleRequest(event)));

async function handleRequest(event) {
  const req = event.request;
  const url = new URL(req.url);
  const config = await loadConfig();
  const oidc = new OidcClient(config);

  // Routes the gate owns.
  if (url.pathname === config.routes.callback) return oidc.handleCallback(req, url);
  if (url.pathname === config.routes.logout) return oidc.handleLogout(req, url);

  // Validate access on every request (cheap, no backend round-trip).
  const session = await readSession(req, config);
  if (!session) return oidc.startLogin(req, url);

  if (!isAuthorized(session, config.policy)) {
    return new Response("403 — You are authenticated but not authorized for this resource.\n", {
      status: 403,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  return forwardToOrigin(req, session, config);
}

/**
 * Coarse claim-based authorization. With a policy of
 * `{ require_claim: "groups", allow_values: [...] }`, the session must carry at
 * least one matching value. No policy => any authenticated user is allowed.
 */
function isAuthorized(session, policy) {
  if (!policy || !policy.require_claim) return true;
  const claim = session[policy.require_claim];
  const have = Array.isArray(claim) ? claim : claim != null ? [claim] : [];
  return (policy.allow_values || []).some((v) => have.includes(v));
}

/**
 * Forward the authenticated request to the protected origin, passing the
 * verified identity downstream as trusted headers so the site can personalize
 * without re-doing auth. The session cookie is stripped before it reaches origin.
 */
function forwardToOrigin(req, session, config) {
  const headers = new Headers(req.headers);
  headers.delete("cookie"); // don't leak the gate session to origin
  headers.set("x-auth-subject", session.sub || "");
  headers.set("x-auth-email", session.email || "");
  if (Array.isArray(session.groups)) headers.set("x-auth-groups", session.groups.join(","));

  const forwarded = new Request(req.url, {
    method: req.method,
    headers,
    body: req.body,
  });
  return fetch(forwarded, { backend: config.backends.origin });
}
