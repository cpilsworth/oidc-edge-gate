// Request pipeline (W1.1). Implements docs/architecture/plugins.md §4 (request
// lifecycle) and §5 (errors):
//
//   normalize ─ routes ─ classify ─ [request] ─ authenticate ─ enforce ─ authorize
//             ─ [beforeForward] ─ handler ─ [afterForward] ─ finalize
//
// Everything is injected through KernelDeps (src/kernel/types.js), so the
// pipeline is unit-tested with fake plugins, a fake classify() and a fake
// CompiledPolicy. `createPipeline` resolves routes eagerly, so a route
// collision fails at load, not per request.

import { PluginError, isIdentity } from "../sdk/index.js";
import { errorResponse, requestId as makeRequestId } from "../http.js";
import { resolveRoutes } from "./registry.js";
import { DEFAULT_FETCH_BUDGET, createFetchBudget, isFatalError } from "./fetch.js";
import { createRequestScope, defaultLogSink, errorSummary, makeLogger, rebuildRequest, stripReservedHeaders } from "./context.js";
import { finalizeResponse } from "./finalize.js";

const TIERS = new Set(["public", "protected", "secured"]);
const AUTH_MODES = new Set(["none", "optional", "required"]);

/** Internal marker: a kernel-detected invariant violation (always 500 internal_error). */
class KernelInvariantError extends Error {
  constructor(message) {
    super(message);
    this.name = "KernelInvariantError";
  }
}

/**
 * Build the PredicateInput a compiled `when` predicate is evaluated against.
 * @param {Request} request
 * @param {import("../sdk/index.js").Identity|null} identity  null in the request phase
 * @returns {import("./types.js").PredicateInput}
 */
export function predicateInput(request, identity) {
  const contentType = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  const acc = (request.headers.get("accept") || "").toLowerCase();
  let accept = "other";
  if (acc.includes("text/html")) accept = "html";
  else if (acc.includes("application/json")) accept = "json";
  return Object.freeze({
    method: request.method.toUpperCase(),
    authenticated: identity !== null && identity !== undefined,
    groups: identity ? identity.groups : Object.freeze([]),
    contentType,
    accept,
  });
}

/**
 * Accept an authenticator's return value as an Identity, or throw. Only values
 * minted by the SDK's createIdentity() are accepted (see isIdentity).
 * @returns {import("../sdk/index.js").Identity|null}
 */
export function acceptIdentity(value) {
  if (value === null || value === undefined) return null;
  // Only identities minted by the SDK's createIdentity() are accepted (they are
  // deeply frozen and branded in a module-private WeakSet). Any lookalike,
  // even a fully frozen one with the right keys, is an invariant violation.
  if (!isIdentity(value)) {
    throw new KernelInvariantError("authenticator returned a non-Identity value (use createIdentity())");
  }
  return value;
}

/**
 * @param {import("./types.js").KernelDeps} deps
 * @returns {{handle: (request: Request) => Promise<Response>}}
 */
export function createPipeline(deps) {
  for (const k of ["policy", "registry", "classify", "normalizePath", "forward", "errorPage"]) {
    if (!deps || deps[k] === undefined || deps[k] === null) throw new TypeError(`createPipeline: deps.${k} is required`);
  }
  const { policy, registry } = deps;
  const logSink = deps.logSink || defaultLogSink;
  const limit = deps.fetchBudget ?? DEFAULT_FETCH_BUDGET;
  const config = deps.config && !Object.isFrozen(deps.config) ? Object.freeze({ ...deps.config }) : (deps.config ?? Object.freeze({}));
  const enabled = policy.enabled ?? new Map();
  const routes = resolveRoutes(registry, enabled); // throws at load on collisions (invariant 5)
  const reserved = registry.reservedHeaderPrefixes().map((p) => p.toLowerCase());
  const ownedCookies = registry.ownedCookies();
  const globalRefs = policy.middleware ?? [];

  async function handle(request) {
    const rid = makeRequestId(request);
    const log = makeLogger(logSink, { requestId: rid, plugin: undefined });
    try {
      return await run(request, rid, log);
    } catch (err) {
      // Top-level catch: never an opaque trap, never internals to the client.
      // A budget/egress violation raised inside a kernel step (forward, errorPage)
      // keeps its 503/500 code; anything else is a generic 500.
      const fatal = isFatalError(err);
      log.error(fatal ? "fetch policy violation" : "gate error", { error: errorSummary(err), stack: !fatal && err && err.stack ? String(err.stack) : undefined });
      const res = fatal
        ? errorResponse(err.status, { error: err.code }, { headers: { "x-auth-request-id": rid } })
        : errorResponse(500, { error: "internal_error" }, { headers: { "x-auth-request-id": rid } });
      try {
        return finalizeResponse(res, { requestId: rid, source: "kernel", ownedCookies, reservedPrefixes: reserved });
      } catch {
        return res;
      }
    }
  }

  async function run(inbound, rid, log) {
    // --- normalize -------------------------------------------------------------
    const url = new URL(inbound.url);
    let path;
    try {
      path = deps.normalizePath(url.pathname);
    } catch {
      return finalizeResponse(errorResponse(400, { error: "bad_request" }, { headers: { "x-auth-request-id": rid } }), {
        requestId: rid, source: "kernel", ownedCookies, reservedPrefixes: reserved,
      });
    }
    let req = inbound;
    if (path !== url.pathname) {
      url.pathname = path;
      req = rebuildRequest(inbound, url.toString());
    }
    // Invariant 3: reserved prefixes are stripped from every inbound request,
    // before any plugin or the forward step sees it.
    const inboundCookieHeader = req.headers.get("cookie");
    req = stripReservedHeaders(req, reserved);

    const budget = createFetchBudget({
      limit, fetchImpl: deps.fetchImpl, cacheOverride: deps.cacheOverride, logSink, requestId: rid,
    });
    const scope = createRequestScope({
      request: req, url, path, requestId: rid, inboundCookieHeader, registry, enabled,
      platform: deps.platform, config, secret: deps.secret, kv: deps.kv ?? null, budget, logSink,
    });

    const finish = (response, source, producer) => {
      let res = response;
      let src = source;
      // Invariant 7: a budget/egress violation always wins, even if a plugin
      // swallowed the throw or on_error was "skip".
      const v = budget.violation();
      if (v) {
        res = errorResponse(v.status, { error: v.code }, { headers: { "x-auth-request-id": rid } });
        src = "kernel";
      }
      return finalizeResponse(res, {
        requestId: rid,
        source: src,
        producer,
        ownedCookies,
        reservedPrefixes: reserved,
        cookieWrites: scope.cookieWriteLines(),
        responseHeaders: scope.responseHeaderSets(),
        log,
      });
    };

    const pluginErrorResponse = (err) => errorResponse(err.status, { error: err.code }, { headers: { "x-auth-request-id": rid } });
    const internalError = () => errorResponse(500, { error: "internal_error" }, { headers: { "x-auth-request-id": rid } });

    /**
     * Run one plugin hook with §5 error semantics.
     * @returns {Promise<{value?: unknown, error?: Response, skipped?: boolean}>}
     */
    const invoke = async (plugin, label, fn, onError = "fail") => {
      try {
        const value = await fn();
        const v = budget.violation();
        if (v) return { error: pluginErrorResponse(v) };
        return { value };
      } catch (err) {
        const fields = { plugin: plugin.name, hook: label, error: errorSummary(err) };
        if (isFatalError(err) || budget.violation()) {
          log.error("fetch policy violation", fields);
          return { error: pluginErrorResponse(budget.violation() || err) };
        }
        if (err instanceof PluginError) {
          log.warn("plugin error", { ...fields, status: err.status, code: err.code });
          return { error: pluginErrorResponse(err) };
        }
        if (onError === "skip" && plugin.allowSkipOnError === true) {
          log.warn("plugin hook failed; skipped (on_error: skip)", fields);
          return { skipped: true };
        }
        log.error("plugin hook failed", fields);
        return { error: internalError() };
      }
    };

    const requirePlugin = (name, why) => {
      const p = registry.get(name);
      if (!p) throw new KernelInvariantError(`${why}: plugin ${JSON.stringify(name)} is not registered`);
      return p;
    };

    // --- routes ------------------------------------------------------------------
    const route = routes.get(path);
    if (route) {
      scope.tier = "public";
      scope.rule = Object.freeze({ path, tier: "public", auth: "none", handler: route.plugin.name, route: true });
      scope.identity = null;
      const ctx = scope.contextFor(route.plugin, route.options);
      const r = await invoke(route.plugin, `route ${path}`, () => route.handler(ctx, route.options));
      if (r.error) return finish(r.error, "kernel");
      if (!(r.value instanceof Response)) {
        log.error("route handler did not return a Response", { plugin: route.plugin.name });
        return finish(internalError(), "kernel");
      }
      return finish(r.value, "plugin", route.plugin);
    }

    // --- classify ----------------------------------------------------------------
    const c = deps.classify(path, policy);
    if (!c || !TIERS.has(c.tier) || !AUTH_MODES.has(c.auth)) throw new KernelInvariantError("classify() returned an invalid classification");
    // Defence in depth for invariants 1 and 6 (the policy compiler should already
    // have rejected these): a non-public tier always requires an identity, and
    // anything that wants an identity needs exactly one configured authenticator.
    if (c.tier !== "public" && c.auth !== "required") {
      throw new KernelInvariantError(`tier ${c.tier} classified with auth ${c.auth}`);
    }
    let authenticator = null;
    if (c.auth !== "none") {
      if (!policy.authentication || !policy.authentication.use) throw new KernelInvariantError("identity required but no authenticator configured");
      authenticator = requirePlugin(policy.authentication.use, "authentication");
      if (authenticator.kind !== "authenticator") throw new KernelInvariantError(`${authenticator.name} is not an authenticator`);
    }
    scope.tier = c.tier;
    scope.rule = Object.freeze(c.rule ? { ...c.rule } : {
      path: null, tier: c.tier, auth: c.auth, audience: c.audience, upstream: c.upstream,
      forwardIdentity: c.forwardIdentity, handler: c.handler, default: true,
    });

    const refs = c.middleware ?? globalRefs;

    /** Run every ref of one middleware phase. Returns a short-circuit Response or null. */
    const runPhase = async (phase, identity) => {
      for (const ref of refs) {
        const plugin = requirePlugin(ref.use, `middleware ref (${ref.source || "?"})`);
        if (!plugin.phases.includes(phase) || typeof plugin[phase] !== "function") continue;
        const when = typeof ref.when === "function" ? ref.when : () => true;
        if (!when(predicateInput(scope.request, identity))) continue;
        const ctx = scope.contextFor(plugin, ref.options);
        const r = await invoke(plugin, phase, () => plugin[phase](ctx, ref.options), ref.onError);
        if (r.error) return { response: r.error, source: "kernel" };
        if (r.value instanceof Response) return { response: r.value, source: "plugin", producer: plugin };
        // Any other return value (e.g. an identity-shaped object) has no effect.
      }
      return null;
    };

    // --- request phase -------------------------------------------------------------
    const pre = await runPhase("request", null);
    if (pre) return finish(pre.response, pre.source, pre.producer);

    // --- authenticate ----------------------------------------------------------------
    let identity = null;
    if (authenticator) {
      const authOptions = policy.authentication.options ?? Object.freeze({});
      const ctx = scope.contextFor(authenticator, authOptions);
      let raw;
      try {
        raw = await authenticator.authenticate(ctx, authOptions);
      } catch (err) {
        if (isFatalError(err) || budget.violation()) return finish(pluginErrorResponse(budget.violation() || err), "kernel");
        if (c.auth === "optional") {
          log.warn("optional authentication failed; continuing anonymously", { plugin: authenticator.name, error: errorSummary(err) });
          raw = null;
        } else if (err instanceof PluginError) {
          log.warn("authentication error", { plugin: authenticator.name, status: err.status, code: err.code, error: errorSummary(err) });
          return finish(pluginErrorResponse(err), "kernel");
        } else {
          log.error("authentication failed", { plugin: authenticator.name, error: errorSummary(err) });
          return finish(internalError(), "kernel");
        }
      }
      if (budget.violation()) return finish(pluginErrorResponse(budget.violation()), "kernel");
      identity = acceptIdentity(raw); // invariant 2: throws -> 500
      scope.identity = identity;
    }

    // --- enforce -------------------------------------------------------------------
    if (c.auth === "required" && !identity) {
      if (typeof authenticator.challenge === "function") {
        const authOptions = policy.authentication.options ?? Object.freeze({});
        const ctx = scope.contextFor(authenticator, authOptions);
        const r = await invoke(authenticator, "challenge",
          () => authenticator.challenge(ctx, authOptions, { interactive: c.tier === "protected" }));
        if (r.error) return finish(r.error, "kernel");
        if (r.value instanceof Response) return finish(r.value, "plugin", authenticator);
      }
      return finish(errorResponse(401, { error: "unauthorized" }, {
        headers: { "www-authenticate": "Bearer", "x-auth-request-id": rid },
      }), "kernel");
    }
    // Invariant 1, re-asserted: nothing non-public proceeds without an identity.
    if (c.tier !== "public" && !identity) throw new KernelInvariantError("non-public request reached authorize without an identity");

    const forwardInput = () => ({
      request: scope.request,
      url: new URL(scope.request.url),
      classification: c,
      identity,
      pluginHeaders: new Headers(scope.pluginHeaders),
      stripPrefixes: [...reserved],
      ownedCookies: [...ownedCookies],
      secret: (key) => (typeof deps.secret === "function" ? deps.secret(key) : undefined),
      fetch: (input, init, opts) => budget.kernelFetch(input, init, { purpose: "forward", ...opts }),
      requestId: rid,
    });

    // --- authorize -------------------------------------------------------------------
    if (Array.isArray(c.audience) && c.audience.length > 0) {
      const groups = identity ? identity.groups : [];
      if (!c.audience.some((g) => groups.includes(g))) {
        const page = await deps.errorPage(403, forwardInput(), { error: "forbidden" });
        return finish(page, "kernel");
      }
    }

    // --- beforeForward ---------------------------------------------------------------
    const before = await runPhase("beforeForward", identity);
    if (before) return finish(before.response, before.source, before.producer);

    // --- handler ---------------------------------------------------------------------
    // Invariant 1, at the last moment before anything is forwarded or handled.
    if (c.tier !== "public" && !identity) throw new KernelInvariantError("refusing to forward a non-public request without an identity");
    let response;
    const handlerName = c.handler || "origin";
    if (handlerName === "origin") {
      response = await deps.forward(forwardInput());
      if (!(response instanceof Response)) throw new KernelInvariantError("forward() did not return a Response");
    } else {
      const plugin = requirePlugin(handlerName, "rule handler");
      if (typeof plugin.handle !== "function") throw new KernelInvariantError(`handler plugin ${plugin.name} has no handle()`);
      const options = (enabled instanceof Map ? enabled.get(plugin.name) : enabled[plugin.name]) ?? Object.freeze({});
      const ctx = scope.contextFor(plugin, options);
      const r = await invoke(plugin, "handle", () => plugin.handle(ctx, options));
      if (r.error) return finish(r.error, "kernel");
      if (!(r.value instanceof Response)) {
        log.error("handler did not return a Response", { plugin: plugin.name });
        return finish(internalError(), "kernel");
      }
      response = r.value;
    }

    // --- afterForward (handler responses only) ---------------------------------------
    for (const ref of refs) {
      const plugin = requirePlugin(ref.use, `middleware ref (${ref.source || "?"})`);
      if (!plugin.phases.includes("afterForward") || typeof plugin.afterForward !== "function") continue;
      const when = typeof ref.when === "function" ? ref.when : () => true;
      if (!when(predicateInput(scope.request, identity))) continue;
      const ctx = scope.contextFor(plugin, ref.options);
      const current = response;
      const r = await invoke(plugin, "afterForward", () => plugin.afterForward(ctx, ref.options, current), ref.onError);
      if (r.error) return finish(r.error, "kernel");
      if (r.value instanceof Response) response = r.value;
    }

    // --- finalize --------------------------------------------------------------------
    return finish(response, "handler");
  }

  return { handle };
}
