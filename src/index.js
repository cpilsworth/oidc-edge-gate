/// <reference types="@fastly/js-compute" />
// AEM Edge Function entry point (Fastly Compute JS runtime). Composition root:
// it loads the gate configuration, builds the plugin registry, compiles the
// policy and hands every request to the kernel pipeline.
//
//   loadGateConfig()        src/kernel/config.js    platform profile, scalar config, secrets, KV, raw policy
//   createRegistry(plugins) src/kernel/registry.js  the static plugin list (plugins/index.js)
//   compilePolicy(...)      src/kernel/policy.js    policy v2 (legacy shapes upgraded)
//   createPipeline({...})   src/kernel/pipeline.js  normalize → routes → classify → [request] →
//                                                   authenticate → enforce → authorize →
//                                                   [beforeForward] → handler → [afterForward] → finalize
//
// Lifecycle and caching: the registry is built once per instance. The compiled
// policy is memoized per instance, keyed by its inputs (profile + raw policy +
// injected route options), and its warnings are logged once per instance. The
// raw config/secret/KV reads happen per request (cheap local store reads), so
// a store update is picked up without a redeploy and the pipeline always sees
// the current KV handle; createPipeline is called on that load path, so a route
// collision fails closed. A failed load is never cached: every request retries
// it and gets a JSON 500 with x-auth-request-id until it succeeds.
//
// Contracts: docs/architecture/plugins.md.

import plugins from "../plugins/index.js";
import { loadGateConfig } from "./kernel/config.js";
import { createRegistry } from "./kernel/registry.js";
import { classify, compilePolicy } from "./kernel/policy.js";
import { createPipeline } from "./kernel/pipeline.js";
import { errorPage, forward } from "./kernel/forward.js";
import { normalizePathname } from "./kernel/path.js";
import { errorResponse, requestId } from "./sdk/http.js";

/** The authenticator whose route paths come from the `routes` config key. */
const ROUTES_PLUGIN = "oidc-auth";

// Guarded so the module can be imported under plain node (unit tests) where
// `addEventListener` does not exist; on the Fastly Compute runtime it always does.
if (typeof addEventListener === "function") {
  addEventListener("fetch", (event) => event.respondWith(handleRequest(event)));
}

// --- per-instance memo (never holds a failed load) ------------------------------
let registryMemo = null;
let policyMemo = null; // { key, policy }
const loggedWarnings = new Set();

function warnOnce(message) {
  if (loggedWarnings.has(message)) return;
  loggedWarnings.add(message);
  console.warn(JSON.stringify({ event: "gate config warning", level: "warn", warning: message }));
}

/**
 * The `routes` config key (callback/logout paths) is a gate-level setting, but
 * the routes themselves belong to the oidc-auth plugin, which reads them from
 * its options. Inject them as `plugins["oidc-auth"]` base options when
 * oidc-auth is (or, for a legacy policy without `authentication`, becomes) the
 * authenticator. Options the policy sets itself win. Returns a new object; the
 * input is not mutated.
 * @param {Object} raw
 * @param {{callback: string, logout: string}} routes
 */
export function withAuthRouteOptions(raw, routes) {
  const auth = raw.authentication;
  const legacyDefault = auth === undefined && !Object.prototype.hasOwnProperty.call(raw, "version");
  const explicit = auth !== null && typeof auth === "object" && auth.use === ROUTES_PLUGIN;
  if (!legacyDefault && !explicit) return raw;
  const block = raw.plugins === undefined ? {} : raw.plugins;
  if (block === null || typeof block !== "object" || Array.isArray(block)) return raw; // compilePolicy rejects it
  const own = block[ROUTES_PLUGIN] === undefined ? {} : block[ROUTES_PLUGIN];
  if (own === null || typeof own !== "object" || Array.isArray(own)) return raw; // compilePolicy rejects it
  return {
    ...raw,
    plugins: { ...block, [ROUTES_PLUGIN]: { callback_path: routes.callback, logout_path: routes.logout, ...own } },
  };
}

/**
 * Load (or reuse) everything a request needs and build its pipeline. Throws on
 * any configuration error; nothing is memoized unless the step succeeded.
 * @returns {Promise<{handle: (request: Request) => Promise<Response>}>}
 */
async function loadGate() {
  const loaded = await loadGateConfig();
  for (const w of loaded.warnings) warnOnce(w);

  if (!registryMemo) registryMemo = createRegistry(plugins);
  const registry = registryMemo;

  const raw = withAuthRouteOptions(loaded.rawPolicy, loaded.config.routes);
  const key = `${loaded.platform.profile}\n${JSON.stringify(raw)}`;
  if (!policyMemo || policyMemo.key !== key) {
    const policy = compilePolicy(raw, registry, { platform: loaded.platform });
    policyMemo = { key, policy };
    for (const w of policy.warnings) warnOnce(w);
  }
  const { policy } = policyMemo;

  const gate = Object.freeze({
    originHostname: loaded.config.originHostname,
    forwardedHost: loaded.config.forwardedHost,
    pushInvalidation: loaded.config.pushInvalidation,
    defaultHeaders: policy.defaultHeaders,
  });

  return createPipeline({
    policy,
    registry,
    classify,
    normalizePath: normalizePathname,
    forward: (input) => forward(input, gate),
    errorPage: (status, input, fallback) => errorPage(status, input, fallback, gate),
    platform: loaded.platform,
    config: loaded.config,
    secret: loaded.secret,
    kv: loaded.kv,
  });
}

// Exported for unit testing (node-vitest). handleRequest returns the Response
// promise directly; the listener above just wires it to event.respondWith.
export async function handleRequest(event) {
  // Catch-all so an unexpected throw (config load, policy compile, ...) becomes
  // a diagnosable 500 with the correlation id instead of an opaque runtime trap.
  // Detail is logged server-side (`aio aem edge-functions tail-logs`); the
  // client body stays generic so internals never leak. The pipeline has its
  // own equivalent catch for request-time errors.
  try {
    const gate = await loadGate();
    return await gate.handle(event.request);
  } catch (err) {
    const id = requestId(event.request);
    console.error(`gate error [${id}]:`, (err && err.stack) || String(err));
    return errorResponse(500, { error: "internal_error" }, {
      headers: { "x-auth-request-id": id },
    });
  }
}
