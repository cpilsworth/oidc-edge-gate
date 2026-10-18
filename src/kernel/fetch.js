// Fetch budget, egress and cache policy (W1.1). One budget per request
// execution; every fetch — the kernel's own forward and error-page fetches and
// every plugin's ctx.fetch — goes through it. Contract: docs/architecture/plugins.md §7.
//
// - Global cap: `limit` fetches per execution (default 16; the platform's hard cap is 32).
// - Per-plugin cap: a plugin's manifest `maxFetches`, counted per plugin NAME per
//   execution (all of a plugin's refs/options share it).
// - Egress: a plugin may only fetch URLs whose origin is in resolveEgress(manifest, options).
// - Cache: "pass" by default; `{ttl}` -> CacheOverride("override", {ttl}). The mode
//   is ALWAYS the positional first argument (see CLAUDE.md "Caching").
// - Logs: one line per fetch with purpose, host, status and duration only.
// - Timeouts: none. This work package adds no fetch timeout; a slow backend is
//   bounded only by the platform's own limits. (A future WP may add AbortSignal
//   or Fastly first-byte timeouts here.)
//
// Budget and egress violations are FATAL: they are PluginErrors marked
// `fatal = true` (class KernelFetchError) and are also recorded on the budget
// (`violation()`), so the pipeline turns them into 503/500 even when a plugin
// catches and swallows the throw, and never honours `on_error: "skip"` for them.

import { CacheOverride } from "fastly:cache-override";
import { PluginError } from "../sdk/index.js";
import { defaultLogSink, safeLog } from "./context.js";
import { resolveEgress } from "./registry.js";

export const DEFAULT_FETCH_BUDGET = 16;

/** A non-skippable fetch-policy violation (budget or egress). */
export class KernelFetchError extends PluginError {
  constructor(status, code, message) {
    super(status, code, message);
    this.name = "KernelFetchError";
    this.fatal = true;
  }
}

/** @returns {boolean} true for budget/egress violations that must never be skipped */
export function isFatalError(err) {
  return err instanceof KernelFetchError;
}

/**
 * Default CacheOverride factory. Mode is always positional.
 * @param {"pass"|{ttl: number}} passOrTtl
 */
export function defaultCacheOverride(passOrTtl) {
  if (passOrTtl === undefined || passOrTtl === "pass") return new CacheOverride("pass");
  if (passOrTtl && typeof passOrTtl === "object" && Number.isFinite(passOrTtl.ttl) && passOrTtl.ttl >= 0) {
    return new CacheOverride("override", { ttl: passOrTtl.ttl });
  }
  throw new TypeError("cache must be \"pass\" or {ttl: seconds}");
}

/** Validate/normalize a `cache` option to what the cacheOverride factory takes. */
function cacheMode(cache) {
  if (cache === undefined || cache === "pass") return "pass";
  if (cache && typeof cache === "object" && Number.isFinite(cache.ttl) && cache.ttl >= 0) return { ttl: cache.ttl };
  throw new TypeError("cache must be \"pass\" or {ttl: seconds}");
}

/** @returns {URL|null} the absolute target URL of a fetch input, or null if it has none */
function targetUrl(input) {
  try {
    if (typeof input === "string") return new URL(input);
    if (input instanceof URL) return new URL(input.href);
    if (input && typeof input.url === "string") return new URL(input.url);
  } catch {
    /* relative or malformed */
  }
  return null;
}

/**
 * @param {{limit?: number, fetchImpl?: typeof fetch, cacheOverride?: (m: "pass"|{ttl:number}) => object,
 *          logSink?: (event: string, fields: Object) => void, requestId?: string}} [opts]
 */
export function createFetchBudget({
  limit = DEFAULT_FETCH_BUDGET,
  fetchImpl,
  cacheOverride = defaultCacheOverride,
  logSink = defaultLogSink,
  requestId,
} = {}) {
  if (!Number.isInteger(limit) || limit < 0) throw new TypeError("fetch budget limit must be a non-negative integer");
  // Resolved per call so a test (or the runtime) can swap globalThis.fetch later.
  const doFetchImpl = fetchImpl || ((input, init) => globalThis.fetch(input, init));

  let used = 0;
  const perPlugin = new Map(); // plugin name -> fetches used
  let violation = null;

  const fatal = (status, code, message) => {
    const err = new KernelFetchError(status, code, message);
    if (!violation) violation = err;
    return err;
  };

  const reserve = (pluginName, max) => {
    if (used >= limit) throw fatal(503, "budget_exceeded", `global fetch budget of ${limit} exhausted${pluginName ? ` (plugin ${pluginName})` : ""}`);
    if (pluginName !== undefined) {
      const n = perPlugin.get(pluginName) || 0;
      if (n >= max) throw fatal(503, "budget_exceeded", `plugin ${pluginName} exceeded maxFetches ${max}`);
      perPlugin.set(pluginName, n + 1);
    }
    used += 1;
  };

  const run = async (input, init, { purpose, plugin }) => {
    const url = targetUrl(input);
    const host = url ? url.host : "";
    const started = Date.now();
    try {
      const res = await doFetchImpl(input, init);
      safeLog(logSink, "fetch", { level: "info", requestId, plugin, purpose, host, status: res.status, ms: Date.now() - started });
      return res;
    } catch (err) {
      // Error messages can embed the URL; log the error name only.
      safeLog(logSink, "fetch", { level: "warn", requestId, plugin, purpose, host, status: 0, ms: Date.now() - started, error: (err && err.name) || "Error" });
      throw err;
    }
  };

  /**
   * Kernel fetch: counts against the global budget only, no egress check.
   * An explicit `init.cacheOverride` is honoured; otherwise `opts.cache` (default "pass").
   */
  const kernelFetch = async (input, init, { purpose = "kernel", cache } = {}) => {
    const co = init && init.cacheOverride ? init.cacheOverride : cacheOverride(cacheMode(cache));
    reserve(undefined, Infinity);
    return run(input, { ...(init || {}), cacheOverride: co }, { purpose });
  };

  /**
   * Bind a budgeted, egress-checked fetch for one plugin instance. The egress
   * list is resolved (and validated) here, from the instance's options.
   * @param {import("./types.js").PluginManifest} manifest
   * @param {Readonly<Object>} options
   */
  const forPlugin = (manifest, options) => {
    const allowed = resolveEgress(manifest, options);
    const max = manifest.maxFetches ?? 0;
    return async (input, init, { purpose, cache } = {}) => {
      // Canonicalize FIRST (F6): the egress check must look at exactly the URL
      // that will be fetched. Checking `input.url` and then passing `input` to
      // fetch() let an object whose `url` is allowed but whose toString() names
      // another host bypass the allow-list. Plugins never pick a named backend
      // (the platform rejects `origins:`), so `backend` is dropped before the
      // Request is built, and a Request already carrying one is refused.
      const { backend: _backend, cacheOverride: _co, ...rest } = init || {};
      let req = null;
      try { req = new Request(input, rest); } catch { /* relative or malformed */ }
      const url = req ? targetUrl(req.url) : null;
      if (!url || !allowed.has(url.origin)) {
        throw fatal(500, "egress_denied", `plugin ${manifest.name} fetch to ${url ? url.origin : "a non-absolute URL"} is not in its egress list`);
      }
      if (req.backend != null || (input instanceof Request && input.backend != null)) {
        throw fatal(500, "egress_denied", `plugin ${manifest.name} fetch must not select a backend`);
      }
      const co = cacheOverride(cacheMode(cache));
      reserve(manifest.name, max);
      // Never follow redirects (a redirect could leave the egress allow-list).
      // Fastly's fetch does not follow redirects anyway; this pins node/tests.
      const safeInit = { cacheOverride: co, redirect: "manual" };
      return run(req, safeInit, { purpose: purpose || manifest.name, plugin: manifest.name });
    };
  };

  return {
    kernelFetch,
    forPlugin,
    used: () => used,
    remaining: () => Math.max(0, limit - used),
    /** The first budget/egress violation of this execution, or null. */
    violation: () => violation,
  };
}
