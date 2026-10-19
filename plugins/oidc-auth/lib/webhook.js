// IdP revocation webhook: adapter skeleton (docs/architecture/plugins.md §15.6).
//
// The route is claimed only when the `webhook_path` option is set, together
// with `webhook_adapter` (lib/options.js validates the pair).
//
// Adapter interface:
//
//   {
//     name: string,
//     // Authenticate the delivery and translate it into revocation events.
//     // MUST reject (throw) anything it cannot authenticate; it reads the body
//     // itself and SHOULD cap it (readBodyCapped in ./admin.js). Throw
//     // WebhookNotImplementedError while the adapter is a stub.
//     verify(ctx, request): Promise<Array<{scope: "session", sid: string} | {scope: "user", sub: string}>>
//   }
//
// handleWebhook, in order (status):
//   1. available: the admin route's rule (provisioned, revocation mode not
//      disabled, revocation_admin_key set)          else 404 not_found (any method)
//   2. method POST                                  else 405 method_not_allowed, Allow: POST
//   3. resolve the adapter named by the instance's `webhook_adapter` option
//      (unknown → 500 internal_error, a misconfiguration validate() prevents)
//   4. adapter.verify(ctx, ctx.request)              WebhookNotImplementedError → 501 not_implemented
//                                                    any other failure          → 401 unauthorized
//   5. events: an array of at most 10 well-formed events
//      (exactly {scope, sid} or {scope, sub})       else 400 bad_request
//   6. ctx.kv present                               else 503 revocation_unavailable
//   7. apply each through revocation-store.js       a write error → 503 kv_write_failed
//   → 200 {"applied": n}
//
// How the route finds its adapter: route handlers receive OidcSettings, which
// carry no plugin options, so the adapter name is read from ctx.options (the
// plugin instance's options, the same object the route was resolved with).
//
// The adapter registry is injectable (the third argument), so the apply path is
// tested with a fake adapter while the only real one is still a stub.

import { errorResponse } from "../../../src/sdk/http.js";
import { revocationApiUnavailableReason } from "./admin.js";
import { isSessionId, isSubject, revokeSession, revokeSubject } from "./revocation-store.js";

/** Adapter names accepted by the `webhook_adapter` option. */
export const WEBHOOK_ADAPTERS = Object.freeze(["janrain"]);
/** Most events one delivery may carry. */
export const MAX_WEBHOOK_EVENTS = 10;

/** Thrown by an adapter (or a part of one) that is not implemented yet. */
export class WebhookNotImplementedError extends Error {
  constructor(message = "webhook adapter not implemented") {
    super(message);
    this.name = "WebhookNotImplementedError";
  }
}

/**
 * Janrain (Akamai Identity Cloud) adapter: a STUB.
 *
 * Unverified, so nothing is implemented (docs/providers/janrain.md):
 * - whether and how Akamai Identity Cloud delivers webhooks for session or
 *   user events (event names, e.g. entity delete/update, and their JSON shape);
 * - how a delivery is authenticated (signature header name, algorithm, the
 *   bytes it covers, key provisioning and rotation, timestamp/replay fields);
 * - which identifier it carries (the `uuid` that the ID token's `sub` holds,
 *   and whether any session identifier exists at all).
 * No secret is declared until these are known (§15.6).
 */
export const janrainAdapter = Object.freeze({
  name: "janrain",
  async verify() {
    throw new WebhookNotImplementedError("janrain webhook adapter is not implemented");
  },
});

/** The built-in adapters, by `webhook_adapter` name. */
export const ADAPTERS = Object.freeze({ janrain: janrainAdapter });

/**
 * Validate an adapter's events. Returns a fresh normalized array, or null when
 * it is not an array of at most MAX_WEBHOOK_EVENTS well-formed events.
 * @param {unknown} events
 */
export function normalizeWebhookEvents(events) {
  if (!Array.isArray(events) || events.length > MAX_WEBHOOK_EVENTS) return null;
  const out = [];
  for (const e of events) {
    if (e === null || typeof e !== "object" || Array.isArray(e)) return null;
    const keys = Object.keys(e).sort().join(",");
    if (e.scope === "session" && keys === "scope,sid" && isSessionId(e.sid)) out.push({ scope: "session", sid: e.sid });
    else if (e.scope === "user" && keys === "scope,sub" && isSubject(e.sub)) out.push({ scope: "user", sub: e.sub });
    else return null;
  }
  return out;
}

/**
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {import("./settings.js").OidcSettings} s
 * @param {{adapters?: Object<string, {verify: Function}>, nowMs?: () => number}} [deps]
 * @returns {Promise<Response>}
 */
export async function handleWebhook(ctx, s, { adapters = ADAPTERS, nowMs = Date.now } = {}) {
  const id = ctx.requestId;
  const respond = (status, body, headers = {}) => errorResponse(status, body, { headers: { "x-auth-request-id": id, ...headers } });
  const fail = (status, error, reason, extra = {}) => {
    ctx.log[status >= 500 ? "error" : "warn"]("oidc webhook rejected", { outcome: "rejected", status, reason, ...extra });
    return respond(status, { error });
  };

  const unavailable = revocationApiUnavailableReason(ctx);
  if (unavailable) {
    ctx.log.info("oidc webhook unavailable", { outcome: "not_found", reason: unavailable });
    return respond(404, { error: "not_found" });
  }
  if (ctx.request.method !== "POST") {
    ctx.log.warn("oidc webhook rejected", { outcome: "rejected", status: 405, reason: "method" });
    return respond(405, { error: "method_not_allowed" }, { allow: "POST" });
  }

  const name = ctx.options ? ctx.options.webhook_adapter : undefined;
  const adapter = typeof name === "string" && Object.prototype.hasOwnProperty.call(adapters, name) ? adapters[name] : null;
  if (!adapter || typeof adapter.verify !== "function") return fail(500, "internal_error", "unknown_adapter");

  let events;
  try {
    events = await adapter.verify(ctx, ctx.request);
  } catch (e) {
    if (e instanceof WebhookNotImplementedError) return fail(501, "not_implemented", "not_implemented", { adapter: name });
    return fail(401, "unauthorized", "verify_failed", { adapter: name });
  }
  const normalized = normalizeWebhookEvents(events);
  if (!normalized) return fail(400, "bad_request", "bad_events", { adapter: name });

  const kv = ctx.kv;
  if (!kv) return fail(503, "revocation_unavailable", "kv_unavailable", { adapter: name });

  let applied = 0;
  try {
    for (const e of normalized) {
      const ttl = { sessionTtlSeconds: s.sessionTtlSeconds, nowMs: nowMs() };
      if (e.scope === "session") await revokeSession(kv, e.sid, ttl);
      else await revokeSubject(kv, e.sub, ttl);
      applied += 1;
    }
  } catch (err) {
    return fail(503, "kv_write_failed", "kv_write_failed", { adapter: name, applied, error: (err && err.name) || "Error" });
  }
  ctx.log.info("oidc webhook applied", { outcome: "applied", adapter: name, applied });
  return respond(200, { applied });
}
