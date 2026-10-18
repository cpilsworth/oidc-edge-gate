// Per-request state and per-plugin Context (W1.1). The pipeline creates one
// RequestScope per request; every hook invocation gets a fresh, frozen Context
// view built by `scope.contextFor(manifest, options)`. Plugin-private state
// (ctx.state, cookie writes, response headers, KV view, fetch counters) lives
// on the scope keyed by plugin name, so it is private to a plugin and shared
// across that plugin's hooks for the request.
//
// Shapes: Context in src/sdk/index.js. Rules: docs/architecture/plugins.md §8, §9.

import { CORE_HEADER_PREFIX } from "../sdk/index.js";
import { parseCookies, serializeCookie } from "../cookies.js";

// --- logging -----------------------------------------------------------------------

/**
 * Default log sink: one JSON line per event on the console (visible via
 * `aio aem edge-functions tail-logs`).
 * @param {string} event
 * @param {Object} fields
 */
export function defaultLogSink(event, fields) {
  const level = fields && fields.level;
  const line = JSON.stringify({ event, ...fields });
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

/** Call a log sink without ever letting a broken sink break the request. */
export function safeLog(sink, event, fields) {
  try {
    sink(event, fields);
  } catch {
    /* logging must never fail a request */
  }
}

/**
 * Structured logger. Kernel fields (`requestId`, `plugin`, `level`) win over
 * caller fields so a plugin cannot spoof them.
 * @param {(event: string, fields: Object) => void} sink
 * @param {{requestId?: string, plugin?: string}} base
 */
export function makeLogger(sink, base) {
  const fixed = {};
  for (const [k, v] of Object.entries(base || {})) if (v !== undefined) fixed[k] = v;
  const emit = (level) => (msg, fields) => {
    const extra = fields && typeof fields === "object" ? fields : {};
    safeLog(sink, String(msg), { ...extra, level, ...fixed });
  };
  return Object.freeze({ info: emit("info"), warn: emit("warn"), error: emit("error") });
}

// --- request hygiene ------------------------------------------------------------------

/**
 * Remove every header under a reserved prefix (x-auth- plus every plugin's
 * declared prefixes) from a request. Returns the same request when nothing
 * needs removing, else a rebuilt one (same URL/method/body).
 * @param {Request} request
 * @param {string[]} reservedPrefixes  lowercase
 * @returns {Request}
 */
export function stripReservedHeaders(request, reservedPrefixes) {
  const doomed = [...request.headers.keys()].filter((name) => {
    const lower = name.toLowerCase();
    return reservedPrefixes.some((p) => lower.startsWith(p));
  });
  if (doomed.length === 0) return request;
  const headers = new Headers(request.headers);
  for (const name of doomed) headers.delete(name);
  return rebuildRequest(request, request.url, headers);
}

/**
 * Rebuild a request with a new URL and/or headers, keeping method and body.
 * Same construction as forwardToOrigin, which is proven on the Fastly runtime.
 */
export function rebuildRequest(request, url, headers = request.headers) {
  return new Request(url, {
    method: request.method,
    headers,
    body: request.body,
    // undici requires duplex for a streaming body; Fastly ignores it.
    ...(request.body ? { duplex: "half" } : {}),
  });
}

// --- cookies ------------------------------------------------------------------------

const SAME_SITE = new Set(["Lax", "Strict", "None"]);

// --- request scope -------------------------------------------------------------------

/**
 * @typedef {Object} RequestScope
 * @property {Request} request          current (possibly replaced) request
 * @property {URL} url                  normalized URL
 * @property {string} path
 * @property {string} requestId
 * @property {"public"|"protected"|"secured"} tier
 * @property {Readonly<Object>} rule
 * @property {import("../sdk/index.js").Identity|null} identity
 * @property {Headers} pluginHeaders    collected ctx.forwardHeaders writes (prefix-checked)
 * @property {(manifest: object, options: object) => import("../sdk/index.js").Context} contextFor
 * @property {() => string[]} cookieWriteLines
 * @property {() => Array<{plugin: string, headers: Headers}>} responseHeaderSets
 */

/**
 * @param {Object} p
 * @param {Request} p.request          sanitized inbound request (path normalized)
 * @param {URL} p.url
 * @param {string} p.path
 * @param {string} p.requestId
 * @param {string|null} p.inboundCookieHeader  the inbound Cookie header, read by ctx.cookies.get
 * @param {import("./types.js").Registry} p.registry
 * @param {ReadonlyMap<string, object>} p.enabled        policy.enabled (lifecycle subscribers)
 * @param {import("../sdk/index.js").Platform} p.platform
 * @param {Readonly<Object>} p.config
 * @param {(key: string) => string|undefined} [p.secret]
 * @param {object|null} [p.kv]          raw KV store handle
 * @param {{forPlugin: Function}} p.budget
 * @param {(event: string, fields: Object) => void} p.logSink
 * @returns {RequestScope}
 */
export function createRequestScope({
  request, url, path, requestId, inboundCookieHeader, registry, enabled, platform, config, secret, kv, budget, logSink,
}) {
  const reserved = registry.reservedHeaderPrefixes();
  const inboundCookies = parseCookies(inboundCookieHeader || "");
  const kernelLog = makeLogger(logSink, { requestId, plugin: undefined });
  const records = new Map(); // plugin name -> per-plugin request state
  let emitting = false;

  const enabledMap = enabled instanceof Map ? enabled : new Map(Object.entries(enabled || {}));

  const scope = {
    request,
    url,
    path,
    requestId,
    tier: "public",
    rule: Object.freeze({}),
    identity: null,
    pluginHeaders: new Headers(),
    kernelLog,
    contextFor,
    cookieWriteLines,
    responseHeaderSets,
  };

  function recordFor(manifest) {
    let r = records.get(manifest.name);
    if (!r) {
      r = {
        state: new Map(),
        responseHeaders: new Headers(),
        cookieWrites: new Map(), // cookie name -> Set-Cookie line (last write wins)
        fetchers: new Map(), // options object -> bound fetch
        kv: undefined,
        log: makeLogger(logSink, { requestId, plugin: manifest.name }),
      };
      records.set(manifest.name, r);
    }
    return r;
  }

  function kvViewFor(manifest, rec) {
    if (rec.kv !== undefined) return rec.kv;
    if (!kv) { rec.kv = null; return null; }
    const prefix = `plugin:${manifest.name}:`;
    const checkKey = (key) => {
      if (typeof key !== "string" || key.length === 0) throw new TypeError("kv key must be a non-empty string");
      return prefix + key;
    };
    rec.kv = Object.freeze({
      async get(key) {
        const entry = await kv.get(checkKey(key));
        if (!entry) return null;
        return typeof entry === "string" ? entry : entry.text();
      },
      async put(key, value, opts) {
        if (typeof value !== "string") throw new TypeError("kv value must be a string");
        const ttl = opts && opts.ttl;
        if (ttl !== undefined) {
          if (!Number.isInteger(ttl) || ttl <= 0) throw new TypeError("kv ttl must be a positive integer (seconds)");
          await kv.put(checkKey(key), value, { ttl });
        } else {
          await kv.put(checkKey(key), value);
        }
      },
      async delete(key) {
        await kv.delete(checkKey(key));
      },
    });
    return rec.kv;
  }

  function fetchFor(manifest, options, rec) {
    let f = rec.fetchers.get(options);
    if (!f) {
      // Lazily resolved so an egress() function that throws only fails a
      // plugin that actually fetches; the per-plugin counter is shared by name.
      let bound;
      f = (input, init, opts) => {
        if (!bound) bound = budget.forPlugin(manifest, options);
        return bound(input, init, opts);
      };
      rec.fetchers.set(options, f);
    }
    return f;
  }

  function ownsHeader(manifest, name) {
    const lower = String(name).toLowerCase();
    if (lower.startsWith(CORE_HEADER_PREFIX)) return false;
    return manifest.trustedHeaderPrefixes.some((p) => lower.startsWith(p.toLowerCase()) && lower.length > p.length);
  }

  function headerWriter(manifest) {
    const check = (name) => {
      if (typeof name !== "string" || !ownsHeader(manifest, name)) {
        throw new Error(`plugin ${manifest.name} may not forward header ${JSON.stringify(name)}: only names under its declared trustedHeaderPrefixes`);
      }
    };
    return Object.freeze({
      set(name, value) {
        check(name);
        scope.pluginHeaders.set(name, String(value));
      },
      delete(name) {
        check(name);
        scope.pluginHeaders.delete(name);
      },
    });
  }

  function cookieJar(manifest, rec) {
    const declared = new Set(manifest.cookies);
    const check = (name) => {
      if (!declared.has(name)) throw new Error(`plugin ${manifest.name} did not declare cookie ${JSON.stringify(name)}`);
    };
    return Object.freeze({
      get(name) {
        check(name);
        return Object.prototype.hasOwnProperty.call(inboundCookies, name) ? inboundCookies[name] : undefined;
      },
      set(name, value, attrs = {}) {
        check(name);
        if (typeof value !== "string") throw new TypeError("cookie value must be a string");
        const sameSite = attrs.sameSite === undefined ? "Lax" : attrs.sameSite;
        if (!SAME_SITE.has(sameSite)) throw new TypeError("cookie sameSite must be Lax, Strict or None");
        if (attrs.maxAge !== undefined && !Number.isInteger(attrs.maxAge)) throw new TypeError("cookie maxAge must be an integer (seconds)");
        // Secure defaults; Path=/ and no Domain also satisfy the __Host- prefix rules.
        rec.cookieWrites.set(name, serializeCookie(name, value, {
          path: "/", maxAge: attrs.maxAge, sameSite, httpOnly: true, secure: true,
        }));
      },
      clear(name) {
        check(name);
        rec.cookieWrites.set(name, serializeCookie(name, "", { path: "/", maxAge: 0, httpOnly: true, secure: true }));
      },
    });
  }

  function secretFor(manifest, rec) {
    const allowed = new Set(manifest.secrets);
    return (key) => {
      if (!allowed.has(key)) {
        rec.log.warn("secret access denied: key not declared in manifest.secrets", { key: String(key) });
        return undefined;
      }
      return typeof secret === "function" ? secret(key) : undefined;
    };
  }

  function replaceRequest(manifest) {
    return (req) => {
      if (!(req instanceof Request)) throw new TypeError("replaceRequest expects a Request");
      // The classification was made for this exact URL/method; a replacement
      // that changes either would forward something that was never classified.
      if (req.url !== scope.request.url) throw new Error(`plugin ${manifest.name}: replaceRequest must keep the request URL`);
      if (req.method !== scope.request.method) throw new Error(`plugin ${manifest.name}: replaceRequest must keep the request method`);
      scope.request = stripReservedHeaders(req, reserved);
    };
  }

  function lifecycleFor(manifest) {
    return Object.freeze({
      async emitLogin(draft) {
        if (!draft || typeof draft.addGroups !== "function" || typeof draft.toIdentity !== "function") {
          throw new TypeError("emitLogin expects an IdentityDraft (createIdentityDraft)");
        }
        if (emitting) throw new Error("lifecycle events cannot be emitted from a lifecycle hook");
        emitting = true;
        try {
          for (const p of registry.list()) {
            if (p.name === manifest.name || typeof p.onLogin !== "function" || !enabledMap.has(p.name)) continue;
            const opts = enabledMap.get(p.name) ?? {};
            // Errors propagate: a failed subscriber aborts the login (fail closed).
            await p.onLogin(contextFor(p, opts), draft, opts);
          }
        } finally {
          emitting = false;
        }
      },
      async emitLogout(identity) {
        if (emitting) throw new Error("lifecycle events cannot be emitted from a lifecycle hook");
        emitting = true;
        try {
          for (const p of registry.list()) {
            if (p.name === manifest.name || typeof p.onLogout !== "function" || !enabledMap.has(p.name)) continue;
            const opts = enabledMap.get(p.name) ?? {};
            try {
              await p.onLogout(contextFor(p, opts), identity ?? null, opts);
            } catch (err) {
              kernelLog.error("onLogout hook failed", { plugin: p.name, error: errorSummary(err) });
            }
          }
        } finally {
          emitting = false;
        }
      },
    });
  }

  /**
   * Build the frozen Context for one hook invocation.
   * @param {import("./types.js").PluginManifest} manifest
   * @param {Readonly<Object>} options
   */
  function contextFor(manifest, options) {
    const rec = recordFor(manifest);
    const opts = options ?? Object.freeze({});
    const ctx = {
      get request() { return scope.request; },
      replaceRequest: replaceRequest(manifest),
      url: new URL(scope.url.href),
      path: scope.path,
      requestId,
      tier: scope.tier,
      rule: scope.rule,
      get identity() { return scope.identity; },
      get authenticated() { return scope.identity !== null; },
      platform,
      options: opts,
      config,
      fetch: fetchFor(manifest, opts, rec),
      kv: kvViewFor(manifest, rec),
      secret: secretFor(manifest, rec),
      forwardHeaders: headerWriter(manifest),
      responseHeaders: rec.responseHeaders,
      cookies: cookieJar(manifest, rec),
      state: rec.state,
      log: rec.log,
    };
    if (manifest.kind === "authenticator") ctx.lifecycle = lifecycleFor(manifest);
    return Object.freeze(ctx);
  }

  function cookieWriteLines() {
    const out = [];
    for (const rec of records.values()) out.push(...rec.cookieWrites.values());
    return out;
  }

  function responseHeaderSets() {
    return [...records.entries()].map(([plugin, rec]) => ({ plugin, headers: rec.responseHeaders }));
  }

  return scope;
}

/** Log-safe summary of a thrown value (name + message, no stack/body). */
export function errorSummary(err) {
  if (err && typeof err === "object") return `${err.name || "Error"}: ${err.message || ""}`.trim();
  return String(err);
}
