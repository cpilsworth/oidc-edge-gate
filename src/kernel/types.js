// Kernel-internal contracts (JSDoc only). These are the seams between the
// Wave 1 work packages, so they can be built in parallel:
//
//   W1.2  src/kernel/policy.js     compilePolicy(raw, registry, env) -> CompiledPolicy
//                                  classify(path, policy)            -> Classification
//   W1.1  src/kernel/registry.js   createRegistry(manifests)         -> Registry
//         src/kernel/pipeline.js   createPipeline(deps: KernelDeps)  -> { handle(request) }
//   W1.5  src/kernel/platform/     detectPlatform(stores, opts)      -> PlatformDetection
//   W1.3  wires them together in src/index.js and supplies forward/errorPage/normalizePath.
//
// Plugin-facing types (PluginManifest, Context, Identity, Predicate, Platform)
// live in src/sdk/index.js. Design notes: docs/architecture/plugins.md.

export {};

/**
 * @typedef {import("../sdk/index.js").PluginManifest} PluginManifest
 * @typedef {import("../sdk/index.js").Identity} Identity
 * @typedef {import("../sdk/index.js").Predicate} Predicate
 * @typedef {import("../sdk/index.js").Platform} Platform
 */

// --- registry (W1.1) ------------------------------------------------------------

/**
 * Built once per execution from the static plugin list (plugins/index.js).
 * Construction throws PluginDefinitionError on duplicate names.
 *
 * @typedef {Object} Registry
 * @property {(name: string) => PluginManifest|undefined} get
 * @property {(name: string) => boolean} has
 * @property {() => PluginManifest[]} list
 * @property {() => string[]} reservedHeaderPrefixes  ["x-auth-", ...every plugin's trustedHeaderPrefixes], lowercase
 * @property {() => string[]} ownedCookies            every plugin's declared cookie names
 * @property {() => string[]} identityHeaderPrefixes  trustedHeaderPrefixes of plugins with `identityHeaders: true`, lowercase
 */

// --- compiled policy (W1.2) -----------------------------------------------------

/**
 * A plugin instance attached to a phase: the policy's `{ use, options, when, on_error }`
 * after merging plugin defaults + `plugins.<name>` base options + rule options,
 * and running the plugin's validate().
 *
 * @typedef {Object} MiddlewareRef
 * @property {string} use                     plugin name (registry key)
 * @property {Readonly<Object>} options       validated, merged options
 * @property {(input: PredicateInput) => boolean} when  compiled predicate (always present; `() => true` if none)
 * @property {"fail"|"skip"} onError
 * @property {"global"|"rule"} source         where it was attached (for logs)
 */

/**
 * What a compiled predicate is evaluated against. Built by the pipeline AFTER
 * the authenticate phase for beforeForward/afterForward, and BEFORE it for the
 * request phase (where `authenticated` is always false).
 *
 * @typedef {Object} PredicateInput
 * @property {string} method                   uppercase
 * @property {boolean} authenticated
 * @property {ReadonlyArray<string>} groups    [] when anonymous
 * @property {string} contentType              lowercased media type without parameters, "" if none
 * @property {"html"|"json"|"other"} accept    from the Accept header
 */

/**
 * @typedef {Object} CompiledRule
 * @property {string} path                     the pattern as configured
 * @property {RegExp} re
 * @property {number} spec                     specificity (exact > longest literal prefix)
 * @property {"public"|"protected"|"secured"} tier
 * @property {"none"|"optional"|"required"} auth
 * @property {string[]|undefined} audience
 * @property {string|undefined} upstream       origin-base URL override
 * @property {Readonly<Object<string,string>>|undefined} headers         static headers (validated names)
 * @property {Readonly<Object<string,string>>|undefined} secretHeaders   header name -> secret key
 * @property {boolean} forwardIdentity         send x-auth-* to an `upstream` too (EDS origin always gets them)
 * @property {string} handler                  "origin" (default: EDS or upstream) or a plugin name with handle()
 * @property {ReadonlyArray<MiddlewareRef>} middleware   rule-level refs (global refs are on the policy)
 */

/**
 * @typedef {Object} CompiledPolicy
 * @property {1|2} version                     1 = legacy shape (no "version" key), upgraded in place
 * @property {"public"|"protected"|"secured"} defaultTier
 * @property {{use: string, options: Readonly<Object>}|null} authentication  the single authenticator
 * @property {ReadonlyMap<string, Readonly<Object>>} enabled  every plugin in use (authenticator, `plugins`
 *           block, global or rule middleware) -> its validated BASE options. Routes and lifecycle hooks
 *           (onLogin/onLogout) are active only for enabled plugins.
 * @property {ReadonlyArray<MiddlewareRef>} middleware        global refs, run before rule refs in each phase
 * @property {ReadonlyArray<CompiledRule>} rules              sorted most-specific-first
 * @property {Readonly<Object<string,string>>|undefined} defaultHeaders   EDS-origin-only static headers
 * @property {ReadonlyArray<string>} warnings                 deprecations (e.g. legacy `recaptcha: true`)
 */

/**
 * classify() result. `rule` is null for the default tier.
 *
 * @typedef {Object} Classification
 * @property {CompiledRule|null} rule
 * @property {"public"|"protected"|"secured"} tier
 * @property {"none"|"optional"|"required"} auth
 * @property {string[]|undefined} audience
 * @property {string|undefined} upstream
 * @property {Readonly<Object<string,string>>|undefined} headers
 * @property {Readonly<Object<string,string>>|undefined} secretHeaders
 * @property {boolean} forwardIdentity
 * @property {string} handler
 * @property {ReadonlyArray<MiddlewareRef>} middleware   global refs followed by rule refs
 */

// --- platform (W1.5) -------------------------------------------------------------

/**
 * @typedef {Object} PlatformDetection
 * @property {Platform} platform
 * @property {{config: object|null, secret: object|null, kv: object|null}} stores  opened handles (null if absent)
 * @property {(key: string) => string|null} cfg      config lookup for this profile (no cross-profile fallback)
 * @property {() => Promise<Object<string,string>>} loadSecrets  secrets for this profile
 * @property {string[]} warnings
 */

// --- pipeline (W1.1) ---------------------------------------------------------------

/**
 * Everything the pipeline needs, injected so it can be unit-tested with fakes.
 *
 * @typedef {Object} KernelDeps
 * @property {CompiledPolicy} policy
 * @property {Registry} registry
 * @property {(path: string, policy: CompiledPolicy) => Classification} classify
 * @property {Platform} platform
 * @property {(key: string) => string|undefined} secret    full secret lookup; the pipeline scopes it per plugin
 * @property {object|null} kv                              raw KV store handle (or null); the pipeline namespaces it
 * @property {Readonly<Object>} config                     gate scalar config (no secrets), exposed read-only as ctx.config
 * @property {(pathname: string) => string} normalizePath  throws to reject the request (400 bad_request)
 * @property {(input: ForwardInput) => Promise<Response>} forward    the "origin" handler (EDS or rule.upstream)
 * @property {(status: number, input: ForwardInput, fallback: Object) => Promise<Response>} errorPage
 * @property {number} [fetchBudget]                        per-execution cap for ALL fetches (default 16)
 * @property {typeof fetch} [fetchImpl]                    defaults to globalThis.fetch
 * @property {(passOrTtl: "pass"|{ttl: number}) => object} [cacheOverride]  builds a CacheOverride; injected for tests
 * @property {(event: string, fields: Object) => void} [logSink]          defaults to console
 */

/**
 * Input to the origin handler and branded error pages.
 *
 * @typedef {Object} ForwardInput
 * @property {Request} request            the (possibly replaced) request, path already normalized
 * @property {URL} url
 * @property {Classification} classification
 * @property {Identity|null} identity     null on public/anonymous
 * @property {Headers} pluginHeaders      headers plugins added via ctx.forwardHeaders (already prefix-checked)
 * @property {string[]} [identityHeaderPrefixes]  registry.identityHeaderPrefixes(): plugin headers under these
 *           prefixes carry identity/PII (manifest `identityHeaders: true`). They always reach the EDS origin, and
 *           an `upstream` only when classification.forwardIdentity is true (the x-auth-* rule).
 * @property {string[]} stripPrefixes     registry.reservedHeaderPrefixes(): remove these from the inbound request
 * @property {string[]} ownedCookies      registry.ownedCookies(): never forwarded, never accepted from origin
 * @property {(key: string) => string|undefined} secret   for rule.secretHeaders
 * @property {(input: string|Request, init?: RequestInit) => Promise<Response>} fetch  budgeted kernel fetch
 * @property {string} requestId
 */
