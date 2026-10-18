# oidc-auth (TEMPORARY adapter)

> **Temporary.** This folder is a thin W1.3 adapter that puts the legacy OIDC
> relying-party modules behind the plugin contract. **It is replaced in W1.4**
> by the real `plugins/oidc-auth/` (`lib/`, `providers/generic.js` + `auth0.js`),
> which also deletes the legacy `src/oidc.js`, `src/session.js`, `src/jwt.js`,
> `src/pkce.js` and `src/kv.js` and the boundary allowlist that lets this
> folder import them.

| | |
|---|---|
| Kind | `authenticator` (the policy's `authentication`; legacy policies default to it) |
| Cookies | `__Host-edge_session`, `__Host-edge_login` |
| Secrets | `client_secret`, `session_hmac_key` |
| Routes | `callback_path` (default `/.auth/callback`), `logout_path` (default `/.auth/logout`) |
| Lifecycle | emits `login` (before the session is minted) and `logout` |

## Behaviour (unchanged from the pre-plugin gate)

- **authenticate** → `readSession()` verifies the HMAC-signed
  `__Host-edge_session` cookie and returns `createIdentity({method: "oidc-session", ...})`,
  or `null`.
- **challenge** → on the `protected` tier (`interactive: true`): `startLogin()`,
  a 302 to the IdP's authorize endpoint with PKCE + state + nonce in the
  `__Host-edge_login` cookie. On `secured` (`interactive: false`): `null`, so
  the kernel answers `401 {"error":"unauthorized"}` with `WWW-Authenticate: Bearer`.
- **callback route** → `handleCallback()`: state check, single-use state
  marker (KV only), token exchange, ID token verification. Then it builds an
  `IdentityDraft` from the verified claims and calls
  `ctx.lifecycle.emitLogin(draft)` **before** minting the session. Groups that
  subscribers add with `draft.addGroups()` are minted into the session; a
  subscriber error aborts the login with a 500 authentication error and no
  session. (Nothing subscribes yet. `draft.setAttr()` values are not persisted
  by the legacy session format.)
- **logout route** → `handleLogout()`: POST-only (405 otherwise), same-site
  `Origin`/`Referer` check (403 otherwise), then `ctx.lifecycle.emitLogout(identity|null)`
  (errors logged, not fatal), both cookies cleared, 303 to the IdP's
  `end_session_endpoint` or `/`.

## Options and the `routes` config key

| Option | Default |
|---|---|
| `callback_path` | `/.auth/callback` |
| `logout_path` | `/.auth/logout` |

Both must be exact paths under `/.auth/` and differ. The gate-level `routes`
config key (`{"callback": ..., "logout": ...}`) still decides them:
`src/index.js` (`withAuthRouteOptions`) injects it as
`plugins["oidc-auth"]` base options when oidc-auth is the authenticator
(explicitly, or by the legacy-policy default). Values set in the policy's own
`plugins["oidc-auth"]` / `authentication.options` win. The kernel config loader
stays plugin-agnostic.

## Scalar config read from `ctx.config`

`issuer`, `clientId`, `redirectUri`, `scopes`, `sessionTtlSeconds`,
`forwardedHost` (same-site check), `groupsClaim`. The legacy `OidcConfig` object
is rebuilt per request from these, `ctx.secret()` and a KV bridge.

## Known temporary gaps (fixed by W1.4)

- **Fetches bypass the plugin budget and egress check.** The legacy modules
  call the global `fetch` (discovery, JWKS, token exchange) instead of
  `ctx.fetch`, so login-flow fetches are not counted against the per-execution
  budget and are not egress-checked. The manifest therefore declares no
  `egress`/`maxFetches`.
- **Cookies bypass `ctx.cookies`.** Sessions are read from the raw `Cookie`
  header of `ctx.request` and written as `Set-Cookie` lines on the plugin's own
  responses (allowed: they are this plugin's declared cookies).
- **KV through a bridge.** `ctx.kv` (namespaced `plugin:oidc-auth:`, string
  values) is wrapped to look like the raw store the legacy code expects
  (`get()` → `{text()}`). Cache keys therefore moved from `oidc:*` to
  `plugin:oidc-auth:oidc:*`; old entries simply expire. With no KV the legacy
  behaviour is kept: discovery/JWKS are live-fetched and the single-use state
  marker is skipped (logged), on sandbox **and** on a provisioned env whose KV
  failed to open. §11 says KV-dependent features should fail closed (503) on
  provisioned; W1.4 must decide that for the replay marker.
- **Request ids.** Legacy error pages (`gateError`) compute their own
  `x-auth-request-id` (Fastly trace id, else a fresh UUID) instead of the
  kernel's `ctx.requestId`; header and body stay consistent with each other.
- **Group normalization.** The session keeps the legacy group list (strings,
  duplicates kept); the `Identity` the kernel sees is normalized by
  `createIdentity()` (de-duplicated, empty strings dropped), which is what
  `x-auth-groups` now carries.

## Files

- `index.js` — the manifest and the adapter.
- `test/` — unit tests on `src/sdk/testing.js` and the shared mock OP.
