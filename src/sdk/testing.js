// Test helpers for plugin unit tests. Plugin tests build their Context with
// createTestContext() instead of reaching into kernel internals
// (src/kernel/**), so they keep working as the kernel evolves.
//
// Not used at runtime and never bundled by the gate itself (nothing in src/
// imports it). Web APIs only, so it runs under node-vitest and Fastly alike.
//
// The fake mirrors the kernel's per-plugin checks when a `plugin` manifest is
// passed (declared header prefixes, cookies, secrets, egress and maxFetches,
// replaceRequest keeping URL and method), and records what the plugin did:
//
//   const ctx = createTestContext({ plugin, request, secrets: { k: "v" }, fetch: myFetch });
//   await plugin.beforeForward(ctx, options);
//   ctx.recorded.forwardHeaders.get("x-mine-result");
//   ctx.recorded.fetches[0].url;
//   ctx.recorded.cookies;   // [{ name, value, attrs } | { name, cleared: true }]

import { CORE_HEADER_PREFIX, PluginError } from "./index.js";
import { parseCookies } from "./cookies.js";

const NO_PLATFORM_CAPS = Object.freeze([]);

/**
 * @typedef {Object} TestContextRecord
 * @property {Headers} forwardHeaders      ctx.forwardHeaders writes
 * @property {Array<{name: string, value?: string, attrs?: Object, cleared?: boolean}>} cookies  ctx.cookies writes, in order
 * @property {Array<{url: string, method: string, init: Object|undefined, opts: Object|undefined}>} fetches  ctx.fetch calls, in order
 * @property {Array<{level: string, msg: string, fields: Object|undefined}>} logs
 * @property {Map<string, string>|null} kv  backing store of ctx.kv (un-namespaced keys), or null
 * @property {Array<{event: "login"|"logout", value: unknown}>} lifecycle  emitLogin/emitLogout calls
 * @property {Request|null} replacedRequest  the last ctx.replaceRequest() argument
 */

/**
 * Build a Context-shaped fake for one hook invocation.
 *
 * @param {Object} [opts]
 * @param {Request} [opts.request]          default: GET https://www.example.com/
 * @param {Object} [opts.options]           the plugin instance's options (frozen)
 * @param {import("./index.js").Identity|null} [opts.identity]
 * @param {Object} [opts.config]            gate scalar config (frozen; never put secrets here)
 * @param {Object<string,string>} [opts.secrets]  values ctx.secret(key) returns
 * @param {Object<string,string>|Map<string,string>|boolean|null} [opts.kv]
 *        initial KV contents (or `true` for an empty KV); omitted/null means ctx.kv is null
 * @param {(input: string|URL|Request, init?: Object) => Promise<Response>|Response} [opts.fetch]
 *        responder for ctx.fetch; default: every fetch throws
 * @param {{profile?: "provisioned"|"sandbox", capabilities?: string[]}} [opts.platform]
 * @param {Object} [opts.plugin]            the manifest under test; enables the kernel's declaration checks
 * @param {"public"|"protected"|"secured"} [opts.tier]
 * @param {Object} [opts.rule]
 * @param {{emitLogin?: Function, emitLogout?: Function}} [opts.lifecycle]  override the recorded no-op events
 * @returns {import("./index.js").Context & {recorded: TestContextRecord}}
 */
export function createTestContext({
  request,
  options = {},
  identity = null,
  config = {},
  secrets = {},
  kv = null,
  fetch: responder,
  platform,
  plugin,
  tier = "public",
  rule = {},
  lifecycle,
} = {}) {
  let currentRequest = request instanceof Request ? request : new Request(request || "https://www.example.com/");
  // Mirror the kernel (W1.R F11): plugins read cookies only via ctx.cookies, so
  // the raw Cookie header is captured for the jar and removed from ctx.request.
  const inboundCookieHeader = currentRequest.headers.get("cookie") || "";
  currentRequest = withoutCookieHeader(currentRequest);
  const url = new URL(currentRequest.url);
  const name = plugin && plugin.name ? plugin.name : "test-plugin";

  /** @type {TestContextRecord} */
  const recorded = {
    forwardHeaders: new Headers(),
    cookies: [],
    fetches: [],
    logs: [],
    kv: null,
    lifecycle: [],
    replacedRequest: null,
  };

  // --- headers / cookies / secrets, checked against the manifest if given ---
  const ownsHeader = (header) => {
    const lower = String(header).toLowerCase();
    if (lower.startsWith(CORE_HEADER_PREFIX)) return false;
    if (!plugin) return true;
    return (plugin.trustedHeaderPrefixes || []).some((p) => lower.startsWith(p.toLowerCase()) && lower.length > p.length);
  };
  const checkHeader = (header) => {
    if (typeof header !== "string" || !ownsHeader(header)) {
      throw new Error(`plugin ${name} may not forward header ${JSON.stringify(header)}: only names under its declared trustedHeaderPrefixes`);
    }
  };
  const checkCookie = (cookie) => {
    if (plugin && !(plugin.cookies || []).includes(cookie)) throw new Error(`plugin ${name} did not declare cookie ${JSON.stringify(cookie)}`);
  };
  const inboundCookies = parseCookies(inboundCookieHeader);

  // --- kv ---
  let kvView = null;
  if (kv !== null && kv !== undefined && kv !== false) {
    const store = kv instanceof Map ? new Map(kv) : new Map(kv === true ? [] : Object.entries(kv));
    recorded.kv = store;
    const checkKey = (key) => {
      if (typeof key !== "string" || key.length === 0) throw new TypeError("kv key must be a non-empty string");
      return key;
    };
    kvView = Object.freeze({
      async get(key) { return store.has(checkKey(key)) ? store.get(key) : null; },
      async put(key, value, putOpts) {
        if (typeof value !== "string") throw new TypeError("kv value must be a string");
        const ttl = putOpts && putOpts.ttl;
        if (ttl !== undefined && (!Number.isInteger(ttl) || ttl <= 0)) throw new TypeError("kv ttl must be a positive integer (seconds)");
        store.set(checkKey(key), value);
      },
      async delete(key) { store.delete(checkKey(key)); },
    });
  }

  // --- fetch ---
  const egressFor = () => {
    if (!plugin) return null;
    const raw = plugin.egress === undefined ? [] : plugin.egress;
    const list = typeof raw === "function" ? raw(options) : raw;
    return new Set(list.map((e) => new URL(e).origin));
  };
  const fetchFn = async (input, init, fetchOpts) => {
    const target = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const allowed = egressFor();
    if (allowed && !allowed.has(new URL(target).origin)) {
      throw new PluginError(500, "egress_denied", `plugin ${name} fetch to ${new URL(target).origin} is not in its egress list`);
    }
    if (plugin && recorded.fetches.length >= (plugin.maxFetches ?? 0)) {
      throw new PluginError(503, "budget_exceeded", `plugin ${name} exceeded maxFetches ${plugin.maxFetches ?? 0}`);
    }
    const method = (init && init.method) || (input instanceof Request ? input.method : "GET");
    recorded.fetches.push({ url: target, method: String(method).toUpperCase(), init, opts: fetchOpts });
    if (typeof responder !== "function") throw new Error(`createTestContext: unexpected fetch to ${target} (pass opts.fetch)`);
    return responder(input, init);
  };

  // --- platform ---
  const caps = new Set(platform && platform.capabilities ? platform.capabilities : NO_PLATFORM_CAPS);
  if (kvView) caps.add("kv");
  const platformView = Object.freeze({
    profile: (platform && platform.profile) || "sandbox",
    has: (cap) => caps.has(cap),
  });

  const log = (level) => (msg, fields) => { recorded.logs.push({ level, msg: String(msg), fields }); };

  const ctx = {
    get request() { return currentRequest; },
    replaceRequest(req) {
      if (!(req instanceof Request)) throw new TypeError("replaceRequest expects a Request");
      if (req.url !== currentRequest.url) throw new Error(`plugin ${name}: replaceRequest must keep the request URL`);
      if (req.method !== currentRequest.method) throw new Error(`plugin ${name}: replaceRequest must keep the request method`);
      currentRequest = withoutCookieHeader(req);
      recorded.replacedRequest = req;
    },
    url: new URL(url.href),
    path: url.pathname,
    requestId: "test-request-id",
    tier,
    rule: Object.freeze({ ...rule }),
    identity,
    authenticated: identity !== null && identity !== undefined,
    platform: platformView,
    options: Object.freeze({ ...options }),
    config: Object.freeze({ ...config }),
    fetch: fetchFn,
    kv: kvView,
    secret(key) {
      if (plugin && !(plugin.secrets || []).includes(key)) {
        recorded.logs.push({ level: "warn", msg: "secret access denied: key not declared in manifest.secrets", fields: { key: String(key) } });
        return undefined;
      }
      return Object.prototype.hasOwnProperty.call(secrets, key) ? secrets[key] : undefined;
    },
    forwardHeaders: Object.freeze({
      set(header, value) { checkHeader(header); recorded.forwardHeaders.set(header, String(value)); },
      delete(header) { checkHeader(header); recorded.forwardHeaders.delete(header); },
    }),
    responseHeaders: new Headers(),
    cookies: Object.freeze({
      get(cookie) { checkCookie(cookie); return Object.prototype.hasOwnProperty.call(inboundCookies, cookie) ? inboundCookies[cookie] : undefined; },
      set(cookie, value, attrs = {}) { checkCookie(cookie); recorded.cookies.push({ name: cookie, value, attrs }); },
      clear(cookie) { checkCookie(cookie); recorded.cookies.push({ name: cookie, cleared: true }); },
    }),
    state: new Map(),
    log: Object.freeze({ info: log("info"), warn: log("warn"), error: log("error") }),
    recorded,
  };
  if ((plugin && plugin.kind === "authenticator") || lifecycle) {
    ctx.lifecycle = Object.freeze({
      async emitLogin(draft) {
        recorded.lifecycle.push({ event: "login", value: draft });
        if (lifecycle && typeof lifecycle.emitLogin === "function") await lifecycle.emitLogin(draft);
      },
      async emitLogout(id) {
        recorded.lifecycle.push({ event: "logout", value: id });
        if (lifecycle && typeof lifecycle.emitLogout === "function") await lifecycle.emitLogout(id);
      },
    });
  }
  return ctx;
}

/** A copy of `req` without the Cookie header (the same Request when it has none). */
function withoutCookieHeader(req) {
  if (!req.headers.has("cookie")) return req;
  const headers = new Headers(req.headers);
  headers.delete("cookie");
  return new Request(req, { headers, ...(req.body ? { duplex: "half" } : {}) });
}
