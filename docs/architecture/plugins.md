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
- **Identity-carrying plugin headers (W2.R R2):** a manifest may set `identityHeaders: true` (optional boolean, default false) to declare that its forward headers carry identity or PII. The registry lists those plugins' prefixes (`registry.identityHeaderPrefixes()`) and the pipeline passes them to forward as `ForwardInput.identityHeaderPrefixes`. Such headers follow the `x-auth-*` rule: always to the EDS origin, to an `upstream` only when the rule has `forward_identity: true`. `user-info` (`x-user-*`) sets it; `recaptcha` does not, so `x-recaptcha-*` still reaches the `/form/*` upstream.
- **Groups (W2.R R3):** `normalizeGroups()` (used by `createIdentity`, `createIdentityDraft` and `draft.addGroups`) keeps only strings of 1–128 printable ASCII characters (0x20–0x7E) with no `,` and no leading or trailing space, de-duplicated in order; anything else is dropped, never repaired. `x-auth-groups` is comma-joined, so a `,` would split one group into two at the origin. `draft.addGroups()` is linear-time (a Set beside the ordered array).
- **Secrets:** a secret key belongs to exactly one plugin: two manifests declaring the same key fail registry construction (`PluginDefinitionError`), like cookies and header prefixes (W2.R R11).
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
- **Time bounds (W2.R R10):** a session is rejected when `iat > now + 60` or `exp - iat > session_ttl_seconds + 60`. `readSession` takes the TTL from `ctx.config.sessionTtlSeconds` (authenticate and logout). Lowering `session_ttl_seconds` therefore also ends existing sessions minted with a longer lifetime.
- **Previous key at load (W2.R R9):** a non-empty `session_hmac_key_previous` shorter than 32 bytes fails the config load, like the active key (fail closed). The request-time check in `keyringFor` stays as defence in depth.
- **Login-state cookie:** its payload carries `typ: "login"`. Each decoder requires its own `typ`, so a session token can't be used as login state or the reverse (review finding F19).
- **Size guard:** an encoded session value longer than 3500 bytes is never set. `writeSession` throws `SessionTooLargeError`, and the callback turns that into a 500 auth error with no session.
- **Lifetime:** the cookie's `Max-Age` and the payload's `exp` both come from `identity.expiresAt`, which already includes any `draft.limitLifetime()` cap from the SDK.

### 14.3 `plugins/user-info` (W4.1)
A middleware plugin. It has the `beforeForward` phase, an `onLogin` hook and `handle()`.

- **Secrets:** `user_info_username` and `user_info_password`, the HTTP Basic service credentials. They are sent as `Authorization: Basic base64(user:pass)` over HTTPS only. The header is never logged.
- **Options:**

  | Option | Default | Meaning |
  |---|---|---|
  | `endpoint` | required | `https://` URL template for the groups lookup at login; the only variable is `{sub}` |
  | `groups_path` | `"groups"` | dot path to a JSON array in the response |
  | `on_login_error` | `"fail"` | `"fail"` or `"degrade"` (drops only the backend's groups) |
  | `degrade_ttl_seconds` | 300 | session lifetime when degraded |
  | `profile_endpoint` | `endpoint` | URL template for profile lookups |
  | `profile_fields` | `[]` | allowlist of top-level profile fields to expose |
  | `expose` | `"none"` | `"none"` or `"headers"` |
  | `cache_ttl_seconds` | 300 | profile cache lifetime in KV (provisioned only) |

  `egress` is the origin(s) of `endpoint` and `profile_endpoint`, and `maxFetches` is 2 (W2.R R5: a global ref and a rule ref with different profile options may each fetch once on one request).
- **Manifest:** `identityHeaders: true` (§8): `x-user-*` reach an `upstream` only with `forward_identity: true`.
- **URL templates:** the only variable is `{sub}`, the **verified** subject, URL-encoded; nothing comes from request input. A template containing `{email}` fails `validate()` with a `PluginConfigError` ("lookups are by the verified `{sub}` only", W2.R R1): an IdP may assert an email it has not verified, and selecting the backend record by it would give one user another's groups and profile.
- **`onLogin(ctx, draft, options)`:** fetches `endpoint`, reads `groups_path` and calls `draft.addGroups()`.
  - More than 256 entries at `groups_path` (counted before normalizing) is a failed lookup, `too_many_groups` (W2.R R4).
  - A failure (network, non-2xx, bad JSON, missing path, too many groups) with `"fail"` throws `PluginError(503, "user_info_unavailable")`.
  - With `"degrade"`, it logs a warning and calls `draft.limitLifetime(degrade_ttl_seconds)`. Only the backend's groups are lost: with a `groupsSource: "claim"` provider (Auth0, generic) the claim groups already on the draft are **kept** for the short session; with `"user-info"` (Janrain) the draft is empty, so there are none (W2.R R8).
  - Cache: when `profile_endpoint` equals `endpoint` (and `profile_fields` is non-empty) the login response re-warms the subject's profile entry; otherwise (including a degraded login) any existing entry is deleted, so a fresh login never serves an old profile (W2.R R13).
- **`onLogout(ctx, identity, options)`:** deletes the subject's `profile:<sha256(sub)>` entry from KV (provisioned only). Errors are logged and ignored (W2.R R13).
- **Service username:** a `user_info_username` containing `:` is a misconfiguration: 500 `internal_error`, logged as `username_contains_colon` with no values (W2.R R12).
- **`beforeForward`** (default `when: {authenticated: true}`): with `expose: "headers"`, it adds `x-user-<field>` headers for the allowlisted `profile_fields` (prefix `x-user-`).
- **`handle(ctx, options)`:** a rule handler, e.g. `{ path: "/api/me", tier: "secured", handler: "user-info" }`. It returns JSON: `{sub, email, name, groups}` from the identity, plus the allowlisted profile fields.
- **Profile cache:** profile responses are cached in `ctx.kv` under `sha256(sub)` for `cache_ttl_seconds` on provisioned. On sandbox (no KV) every lookup fetches. The function fetch cache is never used (`cache` stays `pass`). One entry per subject: an entry with another options fingerprint is a miss that is overwritten. The entry is PII at rest for at most `cache_ttl_seconds`, less when the user logs out or logs in again.

### 14.4 Wiring (W2.3)
- **Callback:**
  - The draft's groups come from `groupsSource`.
  - A subscriber `PluginError` with status 503 gives a 503 auth error page and no session; any other subscriber error stays 500.
  - The session is minted from `identity.expiresAt`.
  - `SessionTooLargeError` gives a 500.
  - The 500/503 auth errors after the state was consumed (auth-method negotiation, a login hook, session too large) also clear the login-state cookie (W2.R R14). The 400/401 ones (IdP error, missing code, token exchange rejected, ID token rejected) still set no cookie at all: `test/characterization/**` pins those responses to carry no `Set-Cookie`.
- **Logout (W2.R R7):** `post_logout_redirect_uri` is the validated same-site origin the browser posted from (its `Origin`, else its `Referer`'s origin, already checked against `https://${forwarded_host}` and the request origin), so behind the CDN it is the public host, never just the internal request Host. With neither header usable it falls back to `https://${forwarded_host}/` (non-loopback) or the request origin.
- **Janrain + `user-info` not enabled:** the user simply has no groups, so audience pages return 403 (fail-safe), and an info line (`no_groups_from_user_info`, a hint at a missing or misconfigured user-info plugin) is logged once per login. It is info, not a warning, because a user legitimately having no groups looks the same.
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

## 15. Wave 3: server-side revocation

Sessions stay stateless signed cookies (§14.2). Revocation adds **KV records that veto a session** on every authenticated request. All of it lives in `plugins/oidc-auth`, because only the authenticator can turn a session into "no session" (a middleware hook runs after `authenticate`, and the session cookie and the KV namespace both belong to oidc-auth). A propagation delay of **up to about 60 s** (KV eventual consistency) is accepted (plan D4).

### 15.1 Modes (`revocation_mode` config key, default `auto`; validated at load)

| Mode | Effective behaviour | `ctx.kv` null | KV read error or corrupt record |
|---|---|---|---|
| `auto` | `required` on `provisioned`, `optional` on `sandbox` | | |
| `required` | KV records checked on every authenticated request | `503 {error:"revocation_unavailable"}` | `503 {error:"revocation_unavailable"}` |
| `optional` | KV records checked when KV exists | skipped silently | logged (warn), session accepted |
| `disabled` | no KV reads or writes; admin route and webhook answer 404 | — | — |

- The global cutoff `session_min_iat` (§15.4) applies in **every** mode; it is config, not KV.
- A real sandbox has no KV, so `auto` there means: no KV checks, logout only clears the cookie, and the global cutoff needs a redeploy. A local sandbox with a bound KV store does exercise the checks.
- `required` on a sandbox without KV is allowed but fails every authenticated request with 503: required means required.
- A 503 from `authenticate` follows §4: on `auth: required` rules it is the response; on `auth: optional` rules the kernel logs it and continues anonymously.

### 15.2 Records (`lib/revocation-store.js`, W3.0, done)

The only module that knows key names and record formats. Keys are in the plugin's KV view (kernel prefix `plugin:oidc-auth:`).

| Key | Value | Meaning |
|---|---|---|
| `rev:sid:<sid>` | `{"at": <epoch s>}` | this session is revoked |
| `rev:sub:<hex sha256(sub)>` | `{"revoked_at": <epoch s>}` | every session of this subject with `iat <= revoked_at` is revoked (a per-user epoch) |

- Stored in the oidc-auth KV wrapper `{"value": …, "expires": <epoch ms>}` plus the native `ttl`. An expired wrapper reads as absent.
- **TTL:** `session_ttl_seconds + 120`, because a session is never honoured for longer than `session_ttl_seconds + 60` after its `iat` (§14.2 time bounds).
- The subject is hashed: no PII and no arbitrary bytes in a KV key. `subKey` hashes any non-empty subject, whatever its length, so every verified session is checkable; the 1024-byte bound (`isSubject`, `MAX_SUB_BYTES`) applies only to admin and webhook input.
- **Monotonic epoch:** `revokeSubject` reads the record first and stores `max(existing, min(revokedAt ?? now, now))`, so a stale or replayed request can never re-validate sessions that a newer revocation ended. When the existing epoch already covers the request nothing is written (that record already outlives the sessions it revokes). The admin route passes `revokedAt` = the signed `iat`; the webhook uses now.
- **Errors:** KV errors propagate; a present-but-corrupt record throws `RevocationRecordError`. The caller applies the mode (§15.1).
- **Write rate:** KV allows about one write per second per key. `sid` keys are unique per session; two revocations of one subject within a second may be rejected by the platform (the error propagates).
- API: `isSessionRevoked(kv, sid)`, `subjectRevokedAt(kv, sub)`, `revokeSession(kv, sid, {sessionTtlSeconds})`, `revokeSubject(kv, sub, {sessionTtlSeconds, revokedAt?}) → stored revokedAt`, `isSessionId`, `isSubject`, `sidKey`, `subKey`, `recordTtlSeconds`.

### 15.3 The request check (`lib/revocation.js` `checkRevocation(ctx, session)`, W3.2)

`authenticate()` (wired in W3.0) verifies the cookie (§14.2), then calls `checkRevocation(ctx, session)`. On `{revoked: true}` it **clears the session cookie and returns `null`**, so the kernel challenges as for any missing session (protected: 302 to the IdP; secured: 401). The check, in order:

1. `ctx.config.sessionMinIat` set and `session.iat < sessionMinIat` → revoked, reason `min_iat` (no KV access).
2. Effective mode `disabled` → not revoked.
3. `ctx.kv` null → `required`: throw `PluginError(503, "revocation_unavailable")`; `optional`: not revoked.
4. Read the `sid` record and the `sub` record **in parallel** (exactly two KV reads).
5. From the reads that succeeded: `sid` record present → revoked, reason `sid`. `revoked_at` present and `session.iat <= revoked_at` → revoked, reason `sub`. A proven revocation wins in every mode, even when the other read failed.
6. Otherwise, any read failed (KV error or `RevocationRecordError`), i.e. "can't tell": `required` → `PluginError(503, "revocation_unavailable")`; `optional` → warn and not revoked. The log carries the error class only.
7. A revocation is logged at info as `session revoked` with `{reason}` only (no `sid`, `sub` or cookie values).

Notes:
- **The callback is not checked.** A login after a revocation is allowed: the per-user epoch exists to force a fresh login (and so fresh groups from user-info). The IdP may re-authenticate silently through its own SSO session; to lock a user out, disable them at the IdP.
- **Cost:** 0 KV reads when disabled or without KV, otherwise 2 parallel reads per authenticated request. No per-instance caching (it would add to the delay and Fastly instances are short-lived).
- `effectiveRevocationMode(ctx)` (W3.0) resolves `auto`; a missing `ctx.config.revocationMode` (plugin unit tests) counts as `auto`.

### 15.4 Global cutoff (`session_min_iat` config key, W3.0)

- Absent or empty: no cutoff. Otherwise epoch **seconds**, a non-negative integer, at most 60 s (the session clock skew) in the future at load (a millisecond value or a future date would reject every new session until then: a login loop). Invalid values fail the load.
- Every session with `iat < session_min_iat` is revoked, in every mode and on both profiles. On provisioned it is a config-pipeline change; on sandbox, a redeploy.
- The other "log everyone out" lever stays the emergency key rotation (§14.2, no previous key).

### 15.5 Logout and the admin route (W3.3)

**Logout** (`lib/logout.js`): the POST-only and same-site checks stay first, so a rejected request writes nothing. After `readSession` verifies the cookie, when the effective mode is not `disabled` and `ctx.kv` exists, `revokeSession(sid)` runs **before** `emitLogout`, the cookie clearing and the 303. A failed write is logged (error class only) and never fails the logout: clearing the cookie is still the right answer. Without KV, logout behaves as today. A session that is already revoked writes nothing and `emitLogout` gets `null`: `iat < session_min_iat` (no KV access), or a `rev:sid` record already present (one read, at most one write per `sid`). A failed read is logged (error class only) and the write is still tried.

**`POST <admin_path>`** (option, default `/.auth/admin/revoke`; `null` = not claimed), `lib/admin.js`:

- **Available** only when the profile is `provisioned`, the effective mode is not `disabled`, and the secret `revocation_admin_key` is set (≥ 32 bytes, distinct from the session keys and from `client_secret`, `recaptcha_secret` and `user_info_password` when set, validated at load). Otherwise **404 `{error:"not_found"}`** for every method, before the body is read. Sandbox is always 404: its secrets are embedded in a public repository. Available but `ctx.kv` null → 503 `revocation_unavailable`, checked only after authentication (step 7), so an unauthenticated caller learns nothing about the KV state.
- **Request:**

  ```
  POST /.auth/admin/revoke
  content-type: application/json
  authorization: Gate-Revoke-HMAC-SHA256 <base64url(HMAC-SHA256(revocation_admin_key, raw body bytes)), no padding>

  {"v":1,"aud":"<forwarded_host>","iat":<epoch s>,"jti":"<22–64 base64url chars>","scope":"session","sid":"<sid>","reason":"…"}
  {"v":1,"aud":"<forwarded_host>","iat":<epoch s>,"jti":"<22–64 base64url chars>","scope":"user","sub":"<subject>","reason":"…"}
  ```

- **Checks, in order** (status in brackets):
  1. availability [404];
  2. method POST [405, `Allow: POST`];
  3. media type `application/json` [415 `unsupported_media_type`];
  4. body at most 4096 bytes: a declared `content-length` over the cap is refused unread, a malformed one is 400 `bad_request`, and the stream is read with a hard cap [413 `payload_too_large`];
  5. `authorization` scheme exact and the signature verified over the **exact raw bytes** with `crypto.subtle.verify` (constant time) [401 `unauthorized`];
  6. only then `JSON.parse`; exactly the keys above (`reason` optional, printable ASCII, ≤ 200 chars); `v === 1`; `scope` is `session` (with a valid `sid`) or `user` (with a valid `sub`) [400 `bad_request`];
  7. `aud === ctx.config.forwardedHost` (binds the request to one environment) and `|now − iat| ≤ 300` [401 `unauthorized`];
  8. `ctx.kv` present [503 `revocation_unavailable`];
  9. `jti` single-use marker `admin:jti:<jti>` in KV (TTL 600 s, covering the ±300 s window; best effort under eventual consistency) [409 `replayed`; a KV error on the marker → 503 `kv_write_failed`];
  10. write the record: `revokeSession`, or `revokeSubject` with `revokedAt` = the signed `iat` (clamped to now) [503 `kv_write_failed` on error]. On that error the marker is deleted again (best effort), so the caller can retry the same signed request after ≥ 1 s.
- **Success:** 200 `{"revoked":"session"}` or `{"revoked":"user","revoked_at":<epoch s>}` (the stored epoch), plus `"propagation_seconds":60`.
- **Logs:** outcome, `scope`, `jti` and a sanitized `reason`; never the `sub`, the `sid`, the body or the `authorization` header. Failures log a reason code only.
- **Signing helper** (`lib/admin-signature.js`, W3.3): WebCrypto only, shared by the route and the CLI, so the two can't drift.

### 15.6 IdP webhook skeleton (W3.3)

- Options `webhook_path` and `webhook_adapter` (set together; default unset = no route). Adapters: `janrain` only.
- `lib/webhook.js` defines the adapter interface: `verify(ctx, request) → Promise<Array<{scope: "session", sid} | {scope: "user", sub}>>`, rejecting anything it cannot authenticate. An adapter reads the body itself and **must** cap it (`readBodyCapped` from `lib/admin.js`). The route has the admin route's availability rule (404 otherwise), is POST-only, applies at most 10 events through `revocation-store.js`, and answers 200 `{"applied": n}`. The adapter is found through `ctx.options.webhook_adapter`.
- Open: availability currently also requires `revocation_admin_key` (the admin route's rule). A real adapter should depend on its own secret instead.
- The `janrain` adapter is a **stub** that throws "not implemented" (→ 501 `not_implemented`): Akamai Identity Cloud's webhook delivery format and signature are unverified (`docs/providers/janrain.md`). No secret is declared until they are.

### 15.7 CLI (`scripts/revoke.mjs`, W3.3)

```
REVOCATION_ADMIN_KEY=… node scripts/revoke.mjs --url https://<public host> (--sid <sid> | --sub <subject>) [--reason <text>] [--aud <host>] [--dry-run]
```

The key comes **only** from the environment, never argv, and is never printed. `aud` defaults to the URL's host. `--dry-run` prints the body only. Exit codes: 0 success, 1 HTTP or network error, 2 usage error.

### 15.8 Platform summary

| | provisioned | sandbox |
|---|---|---|
| `auto` means | `required` | `optional` (no KV: nothing to read) |
| Per-request cost | 2 parallel KV reads | 0 |
| Logout | revokes the `sid`, clears cookies | clears cookies |
| `session_min_iat` | config pipeline | redeploy |
| Admin route / webhook | available with `revocation_admin_key` | 404 |

### 15.9 Wave 3 file ownership

| WP | Owns (edit only these) |
|---|---|
| W3.0 (orchestrator, done) | this section; `lib/revocation-store.js` (+ test); stubs of `lib/{revocation,admin,webhook}.js`; `index.js` wiring; `lib/options.js` (`admin_path`, `webhook_path`, `webhook_adapter`); `src/kernel/config.js` (`revocation_mode`, `session_min_iat`, `revocation_admin_key`) + `test/config-revocation.test.js`; YAML/embedded config |
| W3.2 request check | `lib/revocation.js`; `plugins/oidc-auth/test/revocation.test.js` (new); `test/revocation-gate.test.js` (new); existing tests only where provisioned + no-KV authentication now answers 503 (list them) |
| W3.3 routes + CLI | `lib/logout.js`, `lib/admin.js`, `lib/admin-signature.js` (new), `lib/webhook.js`, `scripts/revoke.mjs` (new); tests `logout.test.js` (additions), `admin.test.js`, `webhook.test.js` (new), `test/admin-revoke-gate.test.js`, `test/revoke-cli.test.js` (new) |
| Orchestrator, after W3.2 + W3.3 | `plugins/oidc-auth/README.md`, `CLAUDE.md` |

### 15.10 Review notes (W3.R)

Fixed in W3.F:

- **R3-1** `checkRevocation`: a read that proves a revocation (`sid` record, or a `sub` epoch covering `iat`) wins even when the other read failed, in both modes; only "can't tell" goes to the mode (§15.3 steps 5–6).
- **R3-2** `subKey` hashes any non-empty subject, so a session with a `sub` over 1024 bytes is checked (and revocable) like any other; `isSubject` bounds admin and webhook input only.
- **R3-3** A user revocation stores the signed `iat` (clamped to now, never moving the epoch backwards), so an admin replay that slips past the `jti` marker within the ±300 s window rewrites nothing. Trade-off: a session minted between the signed `iat` and the request's arrival (normally under a second with the CLI) is not covered.
- **R3-4** Logout writes nothing for a session already revoked by `session_min_iat` or an existing `rev:sid` record (one read, at most one write per `sid`) and emits `logout` with `null` for it.
- **R3-5** `session_min_iat` may be at most 60 s in the future at load (was 300 s), so a future cutoff can't cause a long login loop.
- **R3-10** `revocation_admin_key` must also differ from `client_secret`, `recaptcha_secret` and `user_info_password` when set.

Accepted or documented:

- **R3-6** (accepted) The epoch boundary is `iat <= revoked_at` in whole seconds: a login in the revocation second is revoked once (the user logs in again). A POP clock ahead by up to 60 s (the session skew) can mint a session that survives a revocation issued in that window.
- **R3-7** (accepted) A record's TTL uses `session_ttl_seconds` at write time. While a TTL increase rolls out, a record may expire before a longer-lived session it revokes. Keep TTL changes rare.
- **R3-8** (documented) The admin `reason` is logged verbatim: operators must not put personal data in it. A `--sub` on the CLI appears in shell history and `ps`.
- **R3-9** (tracked for the non-sandbox build) Wave 3's guarantees on a provisioned environment depend on the build pin `EXPECTED_PLATFORM_PROFILE = "provisioned"` (`src/build-profile.js`). Without it a ConfigStore outage silently runs the sandbox profile: revocation `optional` with no KV, admin route 404.
- **Remaining replay hardening:** the `jti` marker is a read-then-write under eventual consistency. KV insert-only (add mode) writes would make it atomic per POP, but need a kernel KV-view change; not done. R3-3 already makes a user-scope replay a no-op, and a session-scope replay rewrites the same `rev:sid` record.
