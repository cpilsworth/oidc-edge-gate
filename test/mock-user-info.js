// In-test user-info backend (the groups/profile service the `user-info` plugin
// calls at login; docs/architecture/plugins.md §14.3) plus a fetch router that
// composes several mocks by origin.
//
//   const ui = createMockUserInfo({ users: { "sub-1": { groups: ["medical"], profile: { name: "A" } } } });
//   globalThis.fetch = routeFetch({ [opOrigin]: op, [ui.origin]: ui });
//
// The backend requires `Authorization: Basic base64(username:password)`
// (RFC 7617; plain user:pass, split at the first colon). It never records the
// password or the header; requests record only whether auth was present/valid.

const enc = new TextEncoder();

/** Set `value` at a dot path ("a.b.groups") inside `obj`, creating objects. */
function setPath(obj, path, value) {
  const parts = path.split(".");
  let o = obj;
  for (const p of parts.slice(0, -1)) {
    if (!o[p] || typeof o[p] !== "object") o[p] = {};
    o = o[p];
  }
  o[parts.at(-1)] = value;
}

/** Compile "/users/{sub}" into a matcher that returns { sub: "…" } (URL-decoded) or null. */
function compileTemplate(template) {
  const names = [];
  const re = template.replace(/[.*+?^$()|[\]\\]/g, "\\$&").replace(/\{(\w+)\}/g, (_, n) => { names.push(n); return "([^/]+)"; });
  const rx = new RegExp(`^${re}$`);
  return (pathname) => {
    const m = rx.exec(pathname);
    if (!m) return null;
    const vars = {};
    try { names.forEach((n, i) => { vars[n] = decodeURIComponent(m[i + 1]); }); } catch { return null; }
    return vars;
  };
}

function constantTimeEqual(a, b) {
  const x = enc.encode(a); const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason ?? new DOMException("aborted", "AbortError"));
    const t = setTimeout(resolve, ms);
    signal?.addEventListener?.("abort", () => { clearTimeout(t); reject(signal.reason ?? new DOMException("aborted", "AbortError")); }, { once: true });
  });
}

/** Failure modes a test can switch on with `ui.fail(mode)` (or the `failure` option). */
export const USER_INFO_FAILURES = Object.freeze([
  "status-500",        // 500 {"error":"server_error"}
  "malformed-json",    // 200, content-type JSON, body not JSON
  "missing-groups",    // 200, document without the groups path
  "groups-not-array",  // 200, groups is a string
  "groups-non-string", // 200, groups contains numbers/null/objects
  "groups-comma",      // 200, a group name contains a comma
  "network-error",     // handle() throws TypeError("fetch failed")
]);

/**
 * @param {object} [o]
 * @param {string} [o.origin]       https origin the backend answers on
 * @param {string} [o.username]
 * @param {string} [o.password]
 * @param {Record<string, {groups?: any, profile?: object}>} [o.users]  keyed by sub
 * @param {string} [o.groupsPath]   dot path of the groups array in responses
 * @param {string} [o.path]         groups lookup template ({sub} or {email})
 * @param {string} [o.profilePath]  profile lookup template ({sub} or {email})
 * @param {string|{status:number}|null} [o.failure]  initial failure mode
 * @param {number} [o.delayMs]      delay before every response (honours request.signal)
 */
export function createMockUserInfo({
  origin = "https://userinfo.test",
  username = "svc-user",
  password = "svc-pass",
  users = {},
  groupsPath = "groups",
  path = "/users/{sub}",
  profilePath = "/profiles/{sub}",
  failure = null,
  delayMs = 0,
} = {}) {
  const base = new URL(origin).origin;
  const matchGroups = compileTemplate(path);
  const matchProfile = profilePath ? compileTemplate(profilePath) : () => null;
  const userMap = new Map(Object.entries(users));
  const requests = [];
  let failMode = failure;
  let failTimes = Infinity;
  let delay = delayMs;

  function findUser(vars) {
    if (vars.sub !== undefined) return userMap.has(vars.sub) ? [vars.sub, userMap.get(vars.sub)] : null;
    if (vars.email !== undefined) {
      for (const [sub, u] of userMap) if ((u.profile?.email ?? u.email) === vars.email) return [sub, u];
    }
    return null;
  }

  function checkAuth(header) {
    if (header === null) return { present: false, valid: false };
    const m = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(header);
    if (!m) return { present: true, valid: false };
    let raw;
    try { raw = new TextDecoder().decode(Uint8Array.from(atob(m[1]), (c) => c.charCodeAt(0))); } catch { return { present: true, valid: false }; }
    const i = raw.indexOf(":");
    if (i < 0) return { present: true, valid: false };
    // Evaluate both comparisons (no short-circuit) to mirror a real service.
    const okUser = constantTimeEqual(raw.slice(0, i), username);
    const okPass = constantTimeEqual(raw.slice(i + 1), password);
    return { present: true, valid: okUser && okPass };
  }

  function document(sub, u, kind) {
    const doc = { sub, ...(u.profile || {}) };
    if (kind === "groups" || kind === "profile") setPath(doc, groupsPath, u.groups ?? []);
    return doc;
  }

  function applyFailure(mode, doc) {
    switch (mode) {
      case "missing-groups": {
        const parts = groupsPath.split(".");
        let o = doc;
        for (const p of parts.slice(0, -1)) o = o?.[p];
        if (o && typeof o === "object") delete o[parts.at(-1)];
        return Response.json(doc);
      }
      case "groups-not-array": setPath(doc, groupsPath, "medical,market-access"); return Response.json(doc);
      case "groups-non-string": setPath(doc, groupsPath, ["medical", 42, null, { name: "x" }]); return Response.json(doc);
      case "groups-comma": setPath(doc, groupsPath, ["medical,market-access", "readers"]); return Response.json(doc);
      default: return null;
    }
  }

  async function handle(request) {
    const url = new URL(request.url);
    const auth = checkAuth(request.headers.get("authorization"));
    const rec = {
      method: request.method, path: url.pathname, search: url.search, kind: null, sub: null,
      authPresent: auth.present, authValid: auth.valid, status: null, failure: null,
    };
    requests.push(rec);

    // A failure mode is consumed only when it actually applies (network errors
    // always apply; response-shape failures only to authenticated lookups).
    const pending = failMode && failTimes > 0 ? failMode : null;
    const consume = () => { failTimes -= 1; rec.failure = pending; return pending; };

    if (delay > 0) await sleep(delay, request.signal);
    if (pending === "network-error") { consume(); rec.status = "network-error"; throw new TypeError("fetch failed"); }

    const respond = (res) => { rec.status = res.status; return res; };
    if (url.origin !== base) return respond(new Response("not found", { status: 404 }));
    if (request.method !== "GET") return respond(Response.json({ error: "method_not_allowed" }, { status: 405 }));
    if (!auth.valid) {
      return respond(Response.json({ error: "unauthorized" },
        { status: 401, headers: { "www-authenticate": 'Basic realm="user-info"' } }));
    }
    let vars = matchGroups(url.pathname);
    rec.kind = vars ? "groups" : null;
    if (!vars) { vars = matchProfile(url.pathname); if (vars) rec.kind = "profile"; }
    if (!vars) return respond(Response.json({ error: "not_found" }, { status: 404 }));
    rec.sub = vars.sub ?? null;
    const mode = pending ? consume() : null;

    if (mode === "status-500") return respond(Response.json({ error: "server_error" }, { status: 500 }));
    if (mode && typeof mode === "object" && typeof mode.status === "number")
      return respond(Response.json({ error: "injected" }, { status: mode.status }));
    if (mode === "malformed-json")
      return respond(new Response('{"sub": "x", "groups": [', { status: 200, headers: { "content-type": "application/json" } }));

    const found = findUser(vars);
    if (!found) return respond(Response.json({ error: "user_not_found" }, { status: 404 }));
    const [sub, u] = found;
    rec.sub = sub;
    const doc = document(sub, u, rec.kind);
    return respond(applyFailure(mode, doc) ?? Response.json(doc));
  }

  return {
    origin: base, username, groupsPath, path, profilePath, requests, handle,
    /** URL template for the plugin's `endpoint` option. */
    endpoint: `${base}${path}`,
    profileEndpoint: profilePath ? `${base}${profilePath}` : null,
    /** Switch a failure mode on (all later requests, or the next `times`). `null` clears it. */
    fail(mode, { times = Infinity } = {}) {
      if (mode !== null && typeof mode !== "object" && !USER_INFO_FAILURES.includes(mode))
        throw new Error(`unknown user-info failure mode ${mode}`);
      failMode = mode; failTimes = times;
    },
    clearFailure() { failMode = null; failTimes = Infinity; },
    setDelay(ms) { delay = ms; },
    setUser(sub, u) { userMap.set(sub, u); },
    removeUser(sub) { userMap.delete(sub); },
    reset() { requests.length = 0; failMode = null; failTimes = Infinity; delay = 0; },
  };
}

/** `Authorization` header value for the given service credentials (for tests). */
export function basicAuth(username, password) {
  const bytes = enc.encode(`${username}:${password}`);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return `Basic ${btoa(bin)}`;
}

/**
 * Compose mocks into one fetch function, dispatching on the request origin.
 * Route values may be an object with `handle(request)` or a function
 * `(request) => Response`. Keys are origins ("https://op.test") or bare
 * hostnames ("main--site--org.aem.live"). Unmatched requests go to
 * `fallback(request)`; without one they reject with a TypeError (like a
 * failed network fetch) whose message names the origin.
 * The returned function records every call on `.calls` ({ method, url, origin, routed }).
 */
export function routeFetch(routes, fallback) {
  const byOrigin = new Map();
  const byHost = new Map();
  for (const [key, target] of Object.entries(routes)) {
    const fn = typeof target === "function" ? target : target && typeof target.handle === "function" ? (r) => target.handle(r) : null;
    if (!fn) throw new Error(`routeFetch: route ${key} has no handle()`);
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(key)) byOrigin.set(new URL(key).origin, fn);
    else byHost.set(key.toLowerCase(), fn);
  }
  const calls = [];
  const fetchFn = async (input, init) => {
    const request = input instanceof Request && init === undefined ? input : new Request(input, init);
    const url = new URL(request.url);
    const fn = byOrigin.get(url.origin) ?? byHost.get(url.hostname.toLowerCase());
    calls.push({ method: request.method, url: request.url, origin: url.origin, routed: !!fn });
    if (fn) return fn(request);
    if (fallback) return fallback(request);
    throw new TypeError(`routeFetch: no mock for ${url.origin}`);
  };
  fetchFn.calls = calls;
  return fetchFn;
}
