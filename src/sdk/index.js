// Plugin SDK for oidc-edge-gate. This is the ONLY kernel module a plugin may
// import (plus files inside its own plugins/<name>/ folder). Platform access
// (fetch, KV, secrets, config, cookies, forwarded headers) goes through the
// per-request `ctx` the kernel hands to each hook, never through `fastly:*`.
//
// Contracts and rules: docs/architecture/plugins.md. Kernel-internal shapes
// (compiled policy, registry, platform, kernel deps): src/kernel/types.js.

export const PLUGIN_KINDS = Object.freeze(["middleware", "authenticator"]);
/** Middleware phases, in execution order. Authenticators run in the kernel's own "authenticate" phase. */
export const MIDDLEWARE_PHASES = Object.freeze(["request", "beforeForward", "afterForward"]);
export const LIFECYCLE_HOOKS = Object.freeze(["onLogin", "onLogout"]);
/** Identity headers are written only by the kernel; no plugin may declare this prefix. */
export const CORE_HEADER_PREFIX = "x-auth-";
/** Only exact paths under this prefix can be claimed as plugin routes. */
export const GATE_ROUTE_PREFIX = "/.auth/";
/** Hard ceiling for any one plugin's maxFetches (the kernel's global budget is lower than the platform's 32). */
export const MAX_PLUGIN_FETCHES = 8;

const NAME_RE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const HEADER_PREFIX_RE = /^x-[a-z0-9]+(?:-[a-z0-9]+)*-$/;
const COOKIE_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const ROUTE_PATH_RE = /^\/\.auth\/[a-z0-9]+(?:[-/][a-z0-9]+)*$/;
const ON_ERROR = new Set(["fail", "skip"]);
const PREDICATE_KEYS = new Set(["authenticated", "methods", "groups_any", "content_types", "accept"]);

const MANIFEST_KEYS = new Set([
  "name", "kind", "description", "phases", "trustedHeaderPrefixes", "cookies", "routes", "egress",
  "secrets", "maxFetches", "defaults", "allowSkipOnError", "validate",
  // hooks
  "request", "beforeForward", "afterForward", "authenticate", "challenge", "handle", "onLogin", "onLogout",
]);

/** Thrown at definition/registration time when a plugin manifest is malformed. Fails config load. */
export class PluginDefinitionError extends Error {
  constructor(plugin, message) {
    super(`plugin ${JSON.stringify(plugin)}: ${message}`);
    this.name = "PluginDefinitionError";
    this.plugin = plugin;
  }
}

/** Thrown by a plugin's `validate(options)` when its configured options are invalid. Fails config load. */
export class PluginConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = "PluginConfigError";
  }
}

/**
 * Throw from a hook to end the request with a specific, client-safe error.
 * `status` and `code` reach the client as `{ error: code }`; `message` is only
 * logged (with the request id), never sent. Any other thrown value becomes a
 * generic 500 `internal_error` (or is skipped when the plugin instance is
 * configured `on_error: "skip"` and the plugin allows it).
 */
export class PluginError extends Error {
  /**
   * @param {number} status HTTP status (4xx/5xx)
   * @param {string} code   machine-readable error code returned as `{ error: code }`
   * @param {string} [message] log-only detail
   */
  constructor(status, code, message) {
    super(message || code);
    if (!Number.isInteger(status) || status < 400 || status > 599) throw new TypeError("PluginError status must be 4xx/5xx");
    if (typeof code !== "string" || !/^[a-z][a-z0-9_]*$/.test(code)) throw new TypeError("PluginError code must be snake_case");
    this.name = "PluginError";
    this.status = status;
    this.code = code;
  }
}

/**
 * Declare a plugin. Validates the manifest shape and returns it frozen. A
 * malformed manifest throws PluginDefinitionError, so a bad plugin fails at
 * module load / registry build, never at request time.
 *
 * @template {PluginManifest} T
 * @param {T} manifest
 * @returns {Readonly<T>}
 */
export function definePlugin(manifest) {
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new PluginDefinitionError("?", "manifest must be an object");
  }
  const name = manifest.name;
  const fail = (msg) => { throw new PluginDefinitionError(typeof name === "string" ? name : "?", msg); };

  if (typeof name !== "string" || !NAME_RE.test(name)) fail("name must be kebab-case, e.g. \"user-info\"");
  for (const key of Object.keys(manifest)) {
    if (!MANIFEST_KEYS.has(key)) fail(`unknown manifest key ${JSON.stringify(key)}`);
  }
  if (!PLUGIN_KINDS.includes(manifest.kind)) fail(`kind must be one of ${PLUGIN_KINDS.join(", ")}`);
  if (manifest.description !== undefined && typeof manifest.description !== "string") fail("description must be a string");

  const isFn = (k) => typeof manifest[k] === "function";
  const optionalFn = (k) => { if (manifest[k] !== undefined && !isFn(k)) fail(`${k} must be a function`); };

  // --- kind-specific hooks ---
  const phases = manifest.phases === undefined ? [] : manifest.phases;
  if (!Array.isArray(phases)) fail("phases must be an array");
  for (const p of phases) if (!MIDDLEWARE_PHASES.includes(p)) fail(`unknown phase ${JSON.stringify(p)}`);
  if (new Set(phases).size !== phases.length) fail("phases must not repeat");

  if (manifest.kind === "middleware") {
    for (const p of phases) if (!isFn(p)) fail(`declares phase "${p}" but has no ${p}() hook`);
    for (const p of MIDDLEWARE_PHASES) if (manifest[p] !== undefined && !phases.includes(p)) fail(`has a ${p}() hook but does not declare phase "${p}"`);
    if (manifest.authenticate !== undefined || manifest.challenge !== undefined) fail("only authenticators may define authenticate()/challenge()");
  } else {
    if (!isFn("authenticate")) fail("authenticators must define authenticate(ctx, options)");
    optionalFn("challenge");
    if (phases.length) fail("authenticators run in the kernel's authenticate phase and must not declare middleware phases");
    for (const p of MIDDLEWARE_PHASES) if (manifest[p] !== undefined) fail(`authenticators must not define ${p}()`);
  }
  optionalFn("handle");
  for (const h of LIFECYCLE_HOOKS) optionalFn(h);
  optionalFn("validate");

  // --- declared capabilities ---
  const prefixes = manifest.trustedHeaderPrefixes ?? [];
  if (!Array.isArray(prefixes)) fail("trustedHeaderPrefixes must be an array");
  for (const p of prefixes) {
    if (typeof p !== "string" || !HEADER_PREFIX_RE.test(p)) fail(`trustedHeaderPrefixes entry ${JSON.stringify(p)} must be lowercase like "x-name-"`);
    if (p.startsWith(CORE_HEADER_PREFIX)) fail(`"${CORE_HEADER_PREFIX}" headers are kernel-owned`);
  }

  const cookies = manifest.cookies ?? [];
  if (!Array.isArray(cookies)) fail("cookies must be an array");
  for (const c of cookies) if (typeof c !== "string" || !COOKIE_NAME_RE.test(c)) fail(`invalid cookie name ${JSON.stringify(c)}`);

  if (manifest.routes !== undefined) {
    const r = manifest.routes;
    if (typeof r !== "function" && (r === null || typeof r !== "object" || Array.isArray(r))) {
      fail("routes must be an object { \"/.auth/x\": handler } or a function (options) => that object");
    }
    if (typeof r === "object") validateRoutes(r, fail);
  }

  const egress = manifest.egress ?? [];
  if (typeof egress !== "function") {
    if (!Array.isArray(egress)) fail("egress must be an array of https origins or a function (options) => array");
    validateEgress(egress, fail);
  }

  const secrets = manifest.secrets ?? [];
  if (!Array.isArray(secrets) || secrets.some((s) => typeof s !== "string" || !/^[a-z][a-z0-9_]*$/.test(s))) {
    fail("secrets must be an array of snake_case key names");
  }

  const maxFetches = manifest.maxFetches ?? 0;
  if (!Number.isInteger(maxFetches) || maxFetches < 0 || maxFetches > MAX_PLUGIN_FETCHES) {
    fail(`maxFetches must be an integer 0..${MAX_PLUGIN_FETCHES}`);
  }

  const defaults = manifest.defaults ?? {};
  if (defaults === null || typeof defaults !== "object" || Array.isArray(defaults)) fail("defaults must be an object");
  for (const k of Object.keys(defaults)) if (k !== "when" && k !== "on_error") fail(`unknown defaults key ${JSON.stringify(k)}`);
  if (defaults.on_error !== undefined && !ON_ERROR.has(defaults.on_error)) fail("defaults.on_error must be \"fail\" or \"skip\"");
  if (defaults.when !== undefined) {
    if (defaults.when === null || typeof defaults.when !== "object" || Array.isArray(defaults.when)) fail("defaults.when must be an object");
    for (const k of Object.keys(defaults.when)) if (!PREDICATE_KEYS.has(k)) fail(`unknown predicate key ${JSON.stringify(k)} in defaults.when`);
  }
  if (manifest.allowSkipOnError !== undefined && typeof manifest.allowSkipOnError !== "boolean") fail("allowSkipOnError must be a boolean");
  if (defaults.on_error === "skip" && manifest.allowSkipOnError !== true) fail("defaults.on_error \"skip\" requires allowSkipOnError: true");

  return Object.freeze({
    ...manifest,
    phases: Object.freeze([...phases]),
    trustedHeaderPrefixes: Object.freeze([...prefixes]),
    cookies: Object.freeze([...cookies]),
    egress: typeof egress === "function" ? egress : Object.freeze([...egress]),
    secrets: Object.freeze([...secrets]),
    maxFetches,
    defaults: Object.freeze({ ...defaults }),
    allowSkipOnError: manifest.allowSkipOnError === true,
  });
}

/**
 * Validate a resolved routes object. Exported for the kernel registry, which
 * calls it again after resolving a `routes(options)` function.
 * @param {Object<string, Function>} routes
 * @param {(msg: string) => never} fail
 */
export function validateRoutes(routes, fail) {
  for (const [path, handler] of Object.entries(routes)) {
    if (!ROUTE_PATH_RE.test(path)) fail(`route ${JSON.stringify(path)} must be an exact lowercase path under ${GATE_ROUTE_PREFIX}`);
    if (typeof handler !== "function") fail(`route ${JSON.stringify(path)} handler must be a function`);
  }
}

/**
 * Validate an egress list: absolute https origins (scheme + host [+ port]),
 * no path/query. `http://localhost`/`127.0.0.1` are allowed for local dev.
 * @param {string[]} list
 * @param {(msg: string) => never} fail
 */
export function validateEgress(list, fail) {
  for (const entry of list) {
    let u;
    try { u = new URL(entry); } catch { fail(`egress entry ${JSON.stringify(entry)} is not a URL`); }
    const loopback = u.hostname === "localhost" || u.hostname === "127.0.0.1";
    if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) fail(`egress ${JSON.stringify(entry)} must be https`);
    if (u.username || u.password || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) {
      fail(`egress ${JSON.stringify(entry)} must be an origin only (no credentials/path/query)`);
    }
  }
}

// --- identity -----------------------------------------------------------------

// Identities minted by createIdentity(). The kernel accepts ONLY these from an
// authenticator (isIdentity), so a hand-built or hand-frozen lookalike object
// can never become the request identity. Module-private: not forgeable.
const MINTED_IDENTITIES = new WeakSet();

/**
 * True only for values returned by createIdentity() in this bundle.
 * @param {unknown} value
 * @returns {value is Identity}
 */
export function isIdentity(value) {
  return value !== null && typeof value === "object" && MINTED_IDENTITIES.has(value);
}

/**
 * Build a validated, frozen Identity. Authenticators return these from
 * authenticate(); the kernel never accepts anything else as an identity.
 * Groups are normalized: strings only, de-duplicated, order preserved.
 *
 * @param {{sub: string, email?: string, name?: string, groups?: unknown, method: string,
 *          sessionId?: string, issuedAt: number, expiresAt: number, attrs?: Object<string, string|number|boolean>}} fields
 * @returns {Identity}
 */
export function createIdentity(fields) {
  if (!fields || typeof fields !== "object") throw new TypeError("identity fields required");
  const { sub, email, name, method, sessionId, issuedAt, expiresAt, attrs } = fields;
  if (typeof sub !== "string" || !sub) throw new TypeError("identity.sub must be a non-empty string");
  if (typeof method !== "string" || !method) throw new TypeError("identity.method must be a non-empty string");
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)) throw new TypeError("identity.issuedAt/expiresAt must be numbers (epoch seconds)");
  for (const [k, v] of [["email", email], ["name", name], ["sessionId", sessionId]]) {
    if (v !== undefined && v !== null && typeof v !== "string") throw new TypeError(`identity.${k} must be a string`);
  }
  const cleanAttrs = {};
  if (attrs !== undefined && attrs !== null) {
    if (typeof attrs !== "object" || Array.isArray(attrs)) throw new TypeError("identity.attrs must be an object");
    for (const [k, v] of Object.entries(attrs)) {
      if (!["string", "number", "boolean"].includes(typeof v)) throw new TypeError(`identity.attrs.${k} must be a scalar`);
      cleanAttrs[k] = v;
    }
  }
  const identity = Object.freeze({
    sub,
    email: email ?? undefined,
    name: name ?? undefined,
    groups: Object.freeze(normalizeGroups(fields.groups)),
    method,
    sessionId: sessionId ?? undefined,
    issuedAt,
    expiresAt,
    attrs: Object.freeze(cleanAttrs),
  });
  MINTED_IDENTITIES.add(identity);
  return identity;
}

/**
 * Normalize a raw groups value to a de-duplicated array of non-empty strings.
 * A single string becomes a one-element array; anything else yields [].
 * Groups containing "," or a control character are dropped: `x-auth-groups`
 * is comma-joined, so "a,admin" would read as two groups at the origin, and
 * control characters are never valid in a header value.
 * @param {unknown} raw
 * @returns {string[]}
 */
export function normalizeGroups(raw) {
  const list = Array.isArray(raw) ? raw : typeof raw === "string" ? [raw] : [];
  // eslint-disable-next-line no-control-regex
  const unsafe = /[,\u0000-\u001f\u007f-\u009f]/;
  return [...new Set(list.filter((g) => typeof g === "string" && g.length > 0 && !unsafe.test(g)))];
}

/**
 * A mutable identity under construction during login. The authenticator
 * creates it after verifying the IdP token, emits the `login` lifecycle event
 * with it (plugins' onLogin hooks may add groups/attributes, e.g. from the
 * user-info backend), then calls `toIdentity()` to mint the session.
 * sub/email/name are fixed by the authenticator and read-only for subscribers.
 *
 * @param {{sub: string, email?: string, name?: string, groups?: unknown, claims?: Object}} base
 * @returns {IdentityDraft}
 */
export function createIdentityDraft(base) {
  if (!base || typeof base.sub !== "string" || !base.sub) throw new TypeError("draft.sub must be a non-empty string");
  const groups = normalizeGroups(base.groups);
  const attrs = {};
  const claims = Object.freeze({ ...(base.claims || {}) });
  let sealed = false;
  const guard = () => { if (sealed) throw new Error("identity draft is sealed"); };
  return Object.freeze({
    sub: base.sub,
    email: base.email,
    name: base.name,
    claims,
    get groups() { return Object.freeze([...groups]); },
    get attrs() { return Object.freeze({ ...attrs }); },
    addGroups(list) {
      guard();
      for (const g of normalizeGroups(list)) if (!groups.includes(g)) groups.push(g);
    },
    setAttr(key, value) {
      guard();
      if (typeof key !== "string" || !/^[a-zA-Z][a-zA-Z0-9_]*$/.test(key)) throw new TypeError("attr key must be an identifier");
      if (!["string", "number", "boolean"].includes(typeof value)) throw new TypeError("attr value must be a scalar");
      attrs[key] = value;
    },
    /** Seal the draft and produce the final Identity. */
    toIdentity({ method, sessionId, issuedAt, expiresAt }) {
      sealed = true;
      return createIdentity({
        sub: base.sub, email: base.email, name: base.name, groups, method, sessionId, issuedAt, expiresAt, attrs,
      });
    },
  });
}

// --- type definitions (JSDoc) ---------------------------------------------------

/**
 * @typedef {Object} Identity  Frozen; produced only by authenticators via createIdentity().
 * @property {string} sub
 * @property {string} [email]
 * @property {string} [name]
 * @property {ReadonlyArray<string>} groups
 * @property {string} method        e.g. "oidc-session"
 * @property {string} [sessionId]   the session's sid (revocation)
 * @property {number} issuedAt      epoch seconds
 * @property {number} expiresAt     epoch seconds
 * @property {Readonly<Object<string, string|number|boolean>>} attrs
 */

/**
 * @typedef {Object} IdentityDraft
 * @property {string} sub
 * @property {string} [email]
 * @property {string} [name]
 * @property {Readonly<Object>} claims        verified IdP claims (read-only)
 * @property {ReadonlyArray<string>} groups
 * @property {Readonly<Object>} attrs
 * @property {(groups: unknown) => void} addGroups
 * @property {(key: string, value: string|number|boolean) => void} setAttr
 * @property {(meta: {method: string, sessionId?: string, issuedAt: number, expiresAt: number}) => Identity} toIdentity
 */

/**
 * @typedef {Object} Predicate  Declarative `when` condition; every present key must match.
 * @property {boolean} [authenticated]
 * @property {string[]} [methods]        uppercase HTTP methods
 * @property {string[]} [groups_any]     identity has at least one of these groups
 * @property {string[]} [content_types]  request media type (no parameters) is one of these
 * @property {"html"|"json"} [accept]    client prefers HTML or JSON
 */

/**
 * @typedef {Object} Platform
 * @property {"provisioned"|"sandbox"} profile
 * @property {(capability: "config-store"|"secret-store"|"kv") => boolean} has
 */

/**
 * @typedef {Object} KvView  Namespaced to "plugin:<name>:"; null on ctx when KV is unavailable.
 * @property {(key: string) => Promise<string|null>} get
 * @property {(key: string, value: string, opts?: {ttl?: number}) => Promise<void>} put
 * @property {(key: string) => Promise<void>} delete
 */

/**
 * @typedef {Object} HeaderWriter  Only names under the plugin's declared trustedHeaderPrefixes.
 * @property {(name: string, value: string) => void} set
 * @property {(name: string) => void} delete
 */

/**
 * @typedef {Object} CookieJar  Only cookies the plugin declared in `cookies`.
 * @property {(name: string) => string|undefined} get
 * @property {(name: string, value: string, attrs?: {maxAge?: number, sameSite?: "Lax"|"Strict"|"None"}) => void} set
 * @property {(name: string) => void} clear
 */

/**
 * @typedef {Object} Logger  Structured; every line carries the request id. Never pass secrets, tokens, codes or cookies.
 * @property {(msg: string, fields?: Object) => void} info
 * @property {(msg: string, fields?: Object) => void} warn
 * @property {(msg: string, fields?: Object) => void} error
 */

/**
 * @typedef {Object} Context  Per-request, per-plugin view handed to every hook.
 * @property {Request} request
 * @property {(req: Request) => void} replaceRequest  e.g. re-attach a body a plugin had to buffer
 * @property {URL} url
 * @property {string} path            normalized pathname
 * @property {string} requestId
 * @property {"public"|"protected"|"secured"} tier
 * @property {Readonly<Object>} rule  the matched rule (read-only), or the default-tier pseudo-rule
 * @property {Identity|null} identity
 * @property {boolean} authenticated
 * @property {Platform} platform
 * @property {Readonly<Object>} options   this plugin instance's validated options
 * @property {Readonly<Object>} config    gate scalar config (read-only; no secrets)
 * @property {(input: string|URL|Request, init?: RequestInit, opts?: {purpose?: string, cache?: "pass"|{ttl: number}}) => Promise<Response>} fetch
 *           Budgeted (plugin maxFetches + global budget), egress-checked, default cache mode "pass".
 * @property {KvView|null} kv
 * @property {(key: string) => string|undefined} secret   only keys listed in the manifest's `secrets`
 * @property {HeaderWriter} forwardHeaders
 * @property {Headers} responseHeaders    extra headers for the final response (finalizer still applies no-store)
 * @property {CookieJar} cookies
 * @property {Map<string, unknown>} state  per-request scratch, private to this plugin
 * @property {Logger} log
 * @property {{emitLogin: (draft: IdentityDraft) => Promise<void>, emitLogout: (identity: Identity|null) => Promise<void>}} [lifecycle]
 *           Present only for authenticators.
 */

/**
 * @typedef {(ctx: Context, options: Readonly<Object>) => Promise<Response|void>|Response|void} PhaseHook
 * @typedef {(ctx: Context, options: Readonly<Object>, response: Response) => Promise<Response|void>|Response|void} AfterForwardHook
 * @typedef {(ctx: Context, options: Readonly<Object>) => Promise<Response>|Response} RouteHandler
 */

/**
 * @typedef {Object} PluginManifest
 * @property {string} name                       kebab-case, unique
 * @property {"middleware"|"authenticator"} kind
 * @property {string} [description]
 * @property {Array<"request"|"beforeForward"|"afterForward">} [phases]   middleware only
 * @property {string[]} [trustedHeaderPrefixes]  e.g. ["x-recaptcha-"]; stripped from every inbound request
 * @property {string[]} [cookies]                cookie names this plugin owns
 * @property {Object<string, RouteHandler>|((options: Object) => Object<string, RouteHandler>)} [routes]
 * @property {string[]|((options: Object) => string[])} [egress]  https origins this plugin may fetch
 * @property {string[]} [secrets]
 * @property {number} [maxFetches]               default 0 (no fetches)
 * @property {{when?: Predicate, on_error?: "fail"|"skip"}} [defaults]
 * @property {boolean} [allowSkipOnError]        default false: policy may not set on_error "skip"
 * @property {(options: Object, env: {platform: Platform}) => Object} [validate]  return normalized options or throw PluginConfigError
 * @property {PhaseHook} [request]
 * @property {PhaseHook} [beforeForward]
 * @property {AfterForwardHook} [afterForward]
 * @property {(ctx: Context, options: Object) => Promise<Identity|null>} [authenticate]       authenticators only
 * @property {(ctx: Context, options: Object, how: {interactive: boolean}) => Promise<Response|null>} [challenge]
 * @property {RouteHandler} [handle]             rule handler (`"handler": "<plugin name>"`)
 * @property {(ctx: Context, draft: IdentityDraft, options: Object) => Promise<void>} [onLogin]
 * @property {(ctx: Context, identity: Identity|null, options: Object) => Promise<void>} [onLogout]
 */
