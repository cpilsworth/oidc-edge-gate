# ADR: Kernel + plugin architecture

Status: accepted for Wave 1 · Plan: edge-gate platform plan v4 · Contracts: `src/sdk/index.js` (plugin-facing), `src/kernel/types.js` (kernel-internal)

## 1. Context

The gate is one AEM Edge Function (Fastly Compute JS) that classifies every request against a path policy and forwards, challenges, or rejects it. New behaviour has to be added without growing a monolithic `index.js`. That includes the Janrain identity provider, a user-info backend, server-side revocation, and reCAPTCHA (which already exists). It also has to work on two platforms: **provisioned** (ConfigStore, SecretStore and KV available) and **sandbox** (no stores).

## 2. Decision

A small **kernel** in `src/` owns the steps that can't be bypassed: normalization, classification, enforcement, forwarding and response finalization. Every feature, **authentication included**, is a **plugin** in its own folder under `plugins/<name>/`. Plugins are registered at build time (the Wasm bundle can't load code dynamically) and switched on by the policy.

## 3. Layout and folder rules

```
src/index.js            Fastly entry point; builds the kernel per execution
src/embedded-config.js  sandbox config; stays at this path (CI injects the client secret here)
src/kernel/             pipeline, context, policy, path, fetch, forward, finalize, config, registry, platform/
src/sdk/                the ONLY kernel code plugins may import
plugins/index.js        static list of registered plugins
plugins/<name>/         index.js (definePlugin) · README.md · lib/ · test/ [· providers/]
plugins/_template/      copy-me skeleton (not registered)
```

These rules are enforced by `test/plugin-boundaries.test.js`, which arrives in W1.3:
1. A plugin imports only `src/sdk/**`, files inside its own folder, and Node/Web built-ins. It never imports `fastly:*`, `src/kernel/**`, other `src/*` modules, or another plugin.
2. The kernel never imports from `plugins/` except `plugins/index.js`.
3. Every folder in `plugins/` except `_template` is registered in `plugins/index.js` and has `index.js`, `README.md`, and `test/`.
4. Plugins have no npm dependencies of their own. They are plain folders bundled into the single Wasm file.

## 4. Request lifecycle

```
normalize ─ routes ─ classify ─ [request] ─ authenticate ─ enforce ─ authorize ─ [beforeForward] ─ handler ─ [afterForward] ─ finalize
```

| Step | Owner | Semantics |
|---|---|---|
| normalize | kernel | `deps.normalizePath(url.pathname)`. A throw gives `400 {error:"bad_request"}`. If the path changed, the request is rebuilt with the normalized URL, so the same path is classified and forwarded. |
| routes | kernel | **Exact** match of the normalized path against routes claimed by **enabled** plugins. The handler runs with that plugin's ctx (tier `public`, `identity` null). Its response goes straight to finalize. |
| classify | kernel | `deps.classify(path, policy)` gives a `Classification` (most-specific rule; `P/*` also covers bare `P`). |
| request | plugins | Global refs, then rule refs, for plugins that declare the `request` phase and whose `when` matches. `authenticated` is always false here. On a **non-public** tier a short-circuit Response with status **< 300** is an invariant violation (it would serve content before authentication): logged and answered with `500 {error:"internal_error"}`. 3xx/4xx/5xx short-circuits (redirects, rate limiting) are allowed. |
| authenticate | kernel + authenticator | If `auth` is `none`, skip. Otherwise call `authenticator.authenticate(ctx, options)` to get an `Identity` or `null`. A non-`Identity` return value is an internal error. **`auth: optional`:** errors are logged and the request continues anonymously. **`auth: required`:** errors propagate. |
| enforce | kernel | `auth: required` with no identity calls `challenge(ctx, options, {interactive: tier === "protected"})`. A Response is returned as-is. `null` or no `challenge` gives `401 {error:"unauthorized"}` with `WWW-Authenticate: Bearer`. |
| authorize | kernel | A non-empty `audience` with no overlap with `identity.groups` gives `deps.errorPage(403, …, {error:"forbidden"})`. |
| beforeForward | plugins | Global refs, then rule refs, with `when` evaluated against the identity. |
| handler | kernel or plugin | `"origin"` calls `deps.forward(input)` (EDS, or `rule.upstream`). A plugin name calls that plugin's `handle(ctx, options)`. |
| afterForward | plugins | Runs **only on handler responses**: `hook(ctx, options, response)`, which may return a replacement Response. |
| finalize | kernel | Always runs, on every response including routes, short-circuits and errors. See §6. |

**Short-circuits.** Any `request` or `beforeForward` hook, route handler or challenge that returns a Response ends processing. That Response goes straight to finalize; `afterForward` is skipped.

**Order** within a phase is fixed: global refs in policy order, then rule refs in rule order. Configuration can't reorder or remove kernel steps.

## 5. Errors

| Situation | Result |
|---|---|
| Hook throws `PluginError(status, code)` | `status {error: code}`. The message is logged with the request id and never sent to the client. |
| Hook throws anything else, ref `onError: "skip"` (plugin has `allowSkipOnError`) | Logged and skipped, then processing continues. |
| Hook throws anything else, `onError: "fail"` (the default) | `500 {error:"internal_error"}` |
| Fetch budget or egress violation (`ctx.fetch`) | `503 {error:"budget_exceeded"}` or `500 {error:"egress_denied"}`. **Never skippable.** |
| Unexpected kernel error | `500 {error:"internal_error"}` with `x-auth-request-id` (the existing top-level catch) |

Client error bodies stay generic, and details go only to the logs.

## 6. Finalizer (kernel invariant 7)

Applied to every response:
- **Plugin-owned cookies:** `Set-Cookie` lines for any `registry.ownedCookies()` name are **removed from handler responses**, so the origin can't set gate cookies. Cookie writes made through `ctx.cookies` are then appended. A cookie can only be written by the plugin that declared it.
- **Response headers:** `ctx.responseHeaders` are merged in, except `set-cookie`, the cache headers, and reserved prefixes (`x-auth-` plus the plugin prefixes), which are ignored with a warning.
- **No caching:** `NO_STORE_HEADERS` are set (`surrogate-control: private`, `cache-control: private, no-store`, `x-content-type-options: nosniff`), and `age` is removed. This matches today's all-tiers no-store.
- **Request id:** responses with status ≥ 400 get `x-auth-request-id` if they don't already have one.

## 7. Fetch budget, egress and cache

- **One budget per execution:** default **16** fetches (`deps.fetchBudget`), shared by the kernel's own forward and error-page fetches and all plugins. The platform's hard limit is 32.
- **Per-plugin cap:** each plugin instance may make at most its manifest's `maxFetches` (default 0).
- **Egress:** `ctx.fetch` only allows URLs whose origin is in the plugin's `egress(options)` list.
- **Cache:** the default cache mode is **pass**. `opts.cache = {ttl}` gives `CacheOverride("override", {ttl})`. The mode is always the positional first argument (see CLAUDE.md).
- **Fetch logs:** a fetch log line contains purpose, host, status and duration only. URLs with query strings, headers and bodies are never logged.

## 8. Identity, headers and cookies

- **Identity:** only `kind: "authenticator"` plugins produce an identity, only in the authenticate step, and only as a `createIdentity()` value. The kernel freezes it; hooks see it read-only.
- **Inbound stripping:** every inbound request has all headers under `registry.reservedHeaderPrefixes()` removed (`x-auth-` plus every plugin's declared prefixes). This happens whether or not the plugin is active, so a header's presence always means the gate set it.
- **Identity headers:** the kernel's forward step injects `x-auth-subject`, `x-auth-email` and `x-auth-groups`. These go to the EDS origin whenever there is an identity. They go to an `upstream` only when `forwardIdentity` is set.
- **Plugin headers:** `ctx.forwardHeaders.set()` accepts only names under the plugin's own declared prefixes.
- **Cookies:** the inbound `cookie` header is never forwarded to any origin. `ctx.cookies` only sees and writes the plugin's declared cookies. Writes use secure defaults (`Secure; HttpOnly; Path=/; SameSite=Lax`) and honour `__Host-` rules.

## 9. Lifecycle events (authenticators)

`ctx.lifecycle.emitLogin(draft)` runs `onLogin(ctx, draft, options)` for every **enabled** plugin that defines it, except the emitter, in registry order. A subscriber may only `draft.addGroups()` and `draft.setAttr()`; sub, email and name are fixed. **An error aborts the login** and propagates to the authenticator, which decides the response. That is how "groups come from the user-info backend after authentication" fails closed.

`emitLogout(identity)` runs `onLogout` hooks. Errors there are logged but not fatal.

## 10. Policy v2 (compiled by W1.2)

```jsonc
{
  "version": 2,
  "default_tier": "protected",
  "authentication": { "use": "oidc-auth", "options": { } },   // exactly one authenticator
  "plugins": { "user-info": { } },                           // base options; also enables routes/onLogin
  "middleware": [ { "use": "security-headers" } ],           // global refs
  "default_headers": { },                                    // EDS-origin-only static headers
  "rules": [ { "path": "/form/*", "tier": "public",
               "middleware": [ { "use": "recaptcha", "when": { "methods": ["POST"] }, "options": { }, "on_error": "fail" } ],
               "upstream": "https://…", "headers": { }, "secret_headers": { "x-h": "secret_key" },
               "forward_identity": false, "handler": "origin", "auth": "none", "audience": [ ] } ]
}
```

- **`auth` defaults by tier:** public gets `none`, protected and secured get `required`. `optional` and `none` are allowed only on public rules, and `required` only on protected and secured ones.
- **Options merge:** plugin `defaults` (for `when` and `on_error`), then `plugins.<name>` base options, then the ref's own `options` (a shallow merge). The plugin's `validate()` runs once per distinct merged options object.
- **Legacy (no `version` key):**
  - `recaptcha: true` becomes `{use: "recaptcha", when: {methods: ["POST", "PUT", "PATCH", "DELETE"]}}` (every state-changing method; W1.F F7 — it was POST only).
  - `session` becomes `auth`.
  - A missing `authentication` becomes `{use: "oidc-auth", options: {}}` when the registry has `oidc-auth`, so today's configs keep working unchanged and the plugin reads its settings from the scalar config keys.
  - Each upgrade adds a `warnings` entry.
- **Load errors (fail closed):** an unknown plugin, phase-less use, unknown key or predicate key, a header name under a reserved prefix, `on_error: "skip"` without `allowSkipOnError`, an identity-requiring policy with no authenticator, a non-authenticator in `authentication`, or a `handler` plugin without `handle()`.

## 11. Platform profiles (W1.5)

| | provisioned | sandbox |
|---|---|---|
| Detected when | `ConfigStore("config_default")` opens | it throws |
| Config lookup | ConfigStore value, else the built-in default. **No fallback to embedded values** (a deliberate change; see below). | `src/embedded-config.js` |
| Secrets | SecretStore: the `secrets` JSON bundle, else per-key. **No embedded fallback.** | embedded (CI-injected) |
| KV | `kv_default` if it opens. **Features that need KV fail closed (503) when it's missing.** | none (`has("kv")` false) |
| Declared profile | `platform_profile` config key; if present it must equal the detected profile, otherwise a load error | same |
| Build pin | `EXPECTED_PLATFORM_PROFILE` in `src/build-profile.js`, passed to `detectPlatform` as `expectedProfile`. A provisioned build **sets `"provisioned"`**: a ConfigStore that fails to open is then a load error, never a silent switch to sandbox. `null` means detection alone decides. | a sandbox build may set `"sandbox"` (present stores are then a load error) |
| Required config | `issuer`, `client_id`, `redirect_uri`, `origin_hostname`, `forwarded_host` missing or empty → load error | same |

**Silent downgrade (W1.F, F5):** detection alone cannot tell "this is a sandbox" from "this provisioned environment's ConfigStore failed to open"; both look like a throwing constructor. Without a pin, the second case would run on the embedded sandbox config and secrets. The build pin closes that: the platform a build is meant for is fixed at build time, and any mismatch fails closed (generic 500 on every request) before a single request is classified.

**Deliberate change:** today, a key missing from ConfigStore silently falls back to the embedded (sandbox) value, for example the debug `forwarded_host`. Under `provisioned` that leak is removed. Tests that seed partial store config must seed the keys they rely on.

## 12. Kernel invariants (each has an "evil plugin" test in W1.1)

1. A non-public request is never forwarded or handled without an identity.
2. Only authenticators produce identities, only in the authenticate step, only as `createIdentity()` values. The identity is frozen.
3. Only the kernel writes `x-auth-*`. Reserved prefixes are stripped from every inbound request. A plugin writes only its own declared prefixes.
4. Plugin-declared cookies never reach the origin and can't be set by the origin. Only the declaring plugin can write them.
5. `/.auth/*` paths can only be claimed by enabled plugins that declare them. If two plugins claim one path, loading fails.
6. If anything needs an identity, exactly one authenticator is configured. Otherwise loading fails.
7. The finalizer and the fetch budget apply to every response and every fetch.

## 13. Wave 1 work packages and file ownership

| WP | Owns | Must keep green |
|---|---|---|
| W1.0 (orchestrator) | `src/sdk/index.js`, `src/kernel/types.js`, this ADR, `test/sdk/**` | — |
| W1.1 kernel runtime | `src/kernel/{pipeline,context,registry,fetch,finalize}.js`, `test/kernel/{pipeline,context,registry,fetch,finalize,invariants}.test.js` | everything, plus new tests built only on fake plugins |
| W1.2 policy v2 | `src/kernel/policy.js`, `test/kernel/policy.test.js` (ports `test/policy.test.js` cases) | everything |
| W1.5 platform | `src/kernel/platform/**`, `test/kernel/platform.test.js`, `test/helpers/profiles.js` | everything |
| W1.3 restructure | moves `path` → `src/kernel/path.js`, `origin` → `src/kernel/forward.js`, `config` → `src/kernel/config.js` (on `detectPlatform`), `http`/`encoding`/`cookies` → `src/sdk/`; deletes `src/policy.js`; moves `src/recaptcha.js` into `plugins/recaptcha/`; rewires `src/index.js`; adds `plugins/index.js`, a **temporary** `plugins/oidc-auth/` adapter over the legacy `src/oidc.js`/`session.js`/`jwt.js`/`pkce.js`/`kv.js` (which stay in `src/` until W1.4), `src/sdk/testing.js`, `test/plugin-boundaries.test.js` (with a temporary allowlist for the adapter), and the Vitest include | characterization, with approved deltas only: **D6** (reCAPTCHA after authentication on protected rules) and **§11** (no embedded fallback on provisioned) |
| W1.4 oidc-auth | real `plugins/oidc-auth/**` (lib/, providers/generic.js + auth0.js), all OIDC fetches through `ctx.fetch`, cookies through `ctx.cookies`; deletes legacy `src/oidc.js`/`session.js`/`jwt.js`/`pkce.js`/`kv.js` and the boundary allowlist | characterization unchanged |

## 14. Wave 2: identity providers, groups from user-info, session v2

### 14.1 Provider profiles (`plugins/oidc-auth/providers/`, W2.1)
A profile is still created with `defineProvider()`. It gains these keys:

- **`tokenEndpointAuthMethods`:** an ordered preference list drawn from `client_secret_post` and `client_secret_basic`, which replaces the single `tokenEndpointAuthMethod`. The method used is the first preference that discovery lists in `token_endpoint_auth_methods_supported`. If discovery omits that list, the first preference is used. A preference list with no overlap fails with a generic 500 and a logged reason. The `token_endpoint_auth_method` option pins a single method, which must still be supported when discovery lists methods.
- **`authorizeParams`:** unchanged. Janrain sets `response_mode=query` explicitly.
- **`logoutParams({clientId, postLogoutRedirectUri, state})`:** `state` is a fresh random value for providers that require it (Janrain).
- **`groupsSource`:** `"claim"` takes groups from the `groups_claim` ID-token claim, as today. `"user-info"` takes them from the `user-info` plugin at login; the draft starts with **no** groups, and token claims are ignored even if present.
- **`endSession`:** `"discovery"` uses `end_session_endpoint` when discovery has one. `"none"` always redirects to `/` after the local logout.

The `provider` option accepts `generic`, `auth0` or `janrain`. `generic` and `auth0` keep today's behaviour exactly (`client_secret_post` first, `claim`, `discovery`).

### 14.2 Session v2 (`lib/session.js`, `lib/state.js`, `lib/signed-cookie.js`, W3.1)
- **Token format:** `base64url(JSON).base64url(HMAC-SHA256)`, the same as today.
- **Session JSON:** `{v: 2, typ: "session", kid, sid, sub, email?, name?, groups, iat, exp}`.
  - `sid` is 16 random bytes in base64url. It is minted on **both** profiles, so revocation (Wave 3) needs no format change, and it becomes `identity.sessionId`.
  - `kid` is the first 8 base64url characters of SHA-256 of the signing key.
- **Keyring:**
  - `session_hmac_key` is the active key; it signs and verifies.
  - The optional secret `session_hmac_key_previous` only verifies, which allows rotation without logging everyone out.
  - Verification tries the keyring keys, at most two, and then requires the payload's `kid` to match the key that verified it. A `kid` never selects a key by itself.
- **Legacy (v1) cookies are rejected,** so users log in once more after the cutover.
- **Login-state cookie:** its payload carries `typ: "login"`. Each decoder requires its own `typ`, so a session token can't be used as login state or the reverse (review finding F19).
- **Size guard:** an encoded session value longer than 3500 bytes is never set. `writeSession` throws `SessionTooLargeError`, and the callback turns that into a 500 auth error with no session.
- **Lifetime:** the cookie's `Max-Age` and the payload's `exp` both come from `identity.expiresAt`, which already includes any `draft.limitLifetime()` cap from the SDK.

### 14.3 `plugins/user-info` (W4.1)
A middleware plugin. It has the `beforeForward` phase, an `onLogin` hook and `handle()`.

- **Secrets:** `user_info_username` and `user_info_password`, the HTTP Basic service credentials. They are sent as `Authorization: Basic base64(user:pass)` over HTTPS only. The header is never logged.
- **Options:**

  | Option | Default | Meaning |
  |---|---|---|
  | `endpoint` | required | `https://` URL template for the groups lookup at login |
  | `groups_path` | `"groups"` | dot path to a JSON array in the response |
  | `on_login_error` | `"fail"` | `"fail"` or `"degrade"` |
  | `degrade_ttl_seconds` | 300 | session lifetime when degraded |
  | `profile_endpoint` | `endpoint` | URL template for profile lookups |
  | `profile_fields` | `[]` | allowlist of top-level profile fields to expose |
  | `expose` | `"none"` | `"none"` or `"headers"` |
  | `cache_ttl_seconds` | 300 | profile cache lifetime in KV (provisioned only) |

  `egress` is the origin(s) of `endpoint` and `profile_endpoint`, and `maxFetches` is 1.
- **URL templates:** the only variables are `{sub}` and `{email}`. Their values come from the **verified** identity or draft and are URL-encoded; nothing comes from request input.
- **`onLogin(ctx, draft, options)`:** fetches `endpoint`, reads `groups_path` and calls `draft.addGroups()`.
  - A failure (network, non-2xx, bad JSON, missing path) with `"fail"` throws `PluginError(503, "user_info_unavailable")`.
  - With `"degrade"`, it logs a warning and calls `draft.limitLifetime(degrade_ttl_seconds)`, with no groups.
- **`beforeForward`** (default `when: {authenticated: true}`): with `expose: "headers"`, it adds `x-user-<field>` headers for the allowlisted `profile_fields` (prefix `x-user-`).
- **`handle(ctx, options)`:** a rule handler, e.g. `{ path: "/api/me", tier: "secured", handler: "user-info" }`. It returns JSON: `{sub, email, name, groups}` from the identity, plus the allowlisted profile fields.
- **Profile cache:** profile responses are cached in `ctx.kv` under `sha256(sub)` for `cache_ttl_seconds` on provisioned. On sandbox (no KV) every lookup fetches. The function fetch cache is never used (`cache` stays `pass`).

### 14.4 Wiring (W2.3)
- **Callback:**
  - The draft's groups come from `groupsSource`.
  - A subscriber `PluginError` with status 503 gives a 503 auth error page and no session; any other subscriber error stays 500.
  - The session is minted from `identity.expiresAt`.
  - `SessionTooLargeError` gives a 500.
- **Janrain + `user-info` not enabled:** the user simply has no groups, so audience pages return 403 (fail-safe), and a warning is logged once per login.
- **Tests:** end-to-end tests drive both the Janrain configuration (W2.2's mock OP in Janrain mode plus the mock user-info backend) and the Auth0 configuration through `handleRequest`, under both platform profiles.

### 14.5 Wave 2 file ownership

| WP | Owns (edit only these) |
|---|---|
| W2.0 (orchestrator) | `src/sdk/index.js` (`draft.limitLifetime`), this section |
| W2.1 Janrain provider | `plugins/oidc-auth/providers/**`; `lib/{login,token,logout,options,discovery,settings,http}.js`; the token-method line in `lib/callback.js` only; tests `providers`, `login`, `logout`, `discovery`, `token-auth` (new) |
| W2.2 mocks | `test/mock-op.js` (adds a Janrain mode; existing behaviour unchanged), `test/mock-user-info.js` (new), `test/mocks.test.js` (new) |
| W3.1 session v2 | `plugins/oidc-auth/lib/{session,state,signed-cookie}.js`, `plugins/oidc-auth/index.js`; tests `session`, `callback`, `manifest`, `pkce-kv`; session fixtures in `test/gate.test.js` |
| W4.1 user-info | `plugins/user-info/**`, `plugins/index.js`, `test/user-info-gate.test.js` (new) |
| W2.3 wiring | `plugins/oidc-auth/lib/callback.js`, the README, `docs/providers/janrain.md`, `CLAUDE.md`, `test/janrain-gate.test.js` + `test/auth0-gate.test.js` (new) |
