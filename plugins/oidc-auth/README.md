# oidc-auth

The gate's OpenID Connect relying party, as an **authenticator** plugin
(`docs/architecture/plugins.md`). Authorization-code flow with PKCE (S256),
`state` + `nonce`, RS256 ID token verification, and the gate's own
HMAC-signed session cookie. Legacy policies (no `authentication` key) default
to it.

| | |
|---|---|
| Kind | `authenticator` |
| Cookies | `__Host-edge_session`, `__Host-edge_login` (read and written only through `ctx.cookies`) |
| Secrets | `client_secret`, `session_hmac_key` (through `ctx.secret`) |
| Routes | `callback_path` (default `/.auth/callback`), `logout_path` (default `/.auth/logout`) |
| Egress | the issuer's origin + `extra_egress` |
| `maxFetches` | 4 (callback worst case: discovery + token + jwks + jwks-refresh) |
| Lifecycle | emits `login` (before the session is minted) and `logout` |

## Hooks

- **authenticate**: no session cookie → `null`. Otherwise verify the HMAC and
  the strict session shape (`exp` in the future, `groups` an array) and return
  `createIdentity({method: "oidc-session", sub, email, name, groups, issuedAt, expiresAt})`,
  or `null` when the cookie is invalid. No backend call per request.
- **challenge**: `interactive: true` (protected tier) starts a login: a 302 to
  the IdP's `authorization_endpoint` with `response_type=code`, `client_id`,
  `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge` (S256), plus the
  provider's `authorizeParams`. State, nonce, PKCE verifier and the return
  path go into `__Host-edge_login` (signed, `Max-Age=600`, `SameSite=Lax`).
  `interactive: false` (secured tier) returns `null`, so the kernel answers
  `401 {"error":"unauthorized"}` with `WWW-Authenticate: Bearer`.
- **callback route**:
  1. login-state cookie present and valid, else 400;
  2. returned `state` equals the cookie's (constant time), else 400;
  3. single-use state marker (see KV below): replay → 400;
  4. IdP `error` parameter → 401; no `code` → 400;
  5. token exchange (PKCE verifier, negotiated client authentication, see
     Providers); non-OK or no `id_token` → 401; no acceptable auth method → a
     thrown error (the kernel's generic 500), reason logged;
  6. ID token: `alg` RS256, signature against the JWKS (one forced refetch on
     a `kid` miss), `iss`, `aud`, `azp` (required when `aud` has several values),
     `sub`, `exp`/`nbf`/`iat` (60 s skew), `nonce`, `c_hash`/`at_hash` when
     present; any failure → 400;
  7. build an `IdentityDraft` (groups ONLY from `groups_claim`) and
     `ctx.lifecycle.emitLogin(draft)`; a subscriber error → 500, no session;
  8. mint the session from `draft.toIdentity()` (so groups added by
     subscribers are kept; `attrs` are not persisted), clear the login cookie
     and 302 to the stored return path (same-origin relative only).

  Errors 400/401/500 are a generic `text/plain` page:
  `<status> — authentication error (request-id: <ctx.requestId>)`, with the
  same id in `x-auth-request-id`. The reason is logged, never sent. No cookie
  is written on any error.
- **logout route**: POST only (`405 {"error":"method_not_allowed"}`,
  `Allow: POST`); the `Origin` (or, without it, the `Referer`) must be this
  site or `https://<forwarded_host>` (`403 {"error":"forbidden"}`). Then
  `ctx.lifecycle.emitLogout(identity|null)` (errors logged, not fatal), both
  cookies cleared, and a 303 to the IdP's `end_session_endpoint` with the
  provider's logout params (`client_id`, `post_logout_redirect_uri=<origin>/`,
  plus a fresh random `state` for `janrain`), or to `/` when there is no
  endpoint, discovery fails, or the profile's `endSession` is `"none"` (then
  discovery isn't fetched). The site's sign-out control must be a
  `<form method="post">`.

## Options

| Option | Default | |
|---|---|---|
| `callback_path` | `/.auth/callback` | exact path under `/.auth/` |
| `logout_path` | `/.auth/logout` | exact path under `/.auth/`, differs from `callback_path` |
| `provider` | `generic` | `generic`, `auth0` or `janrain` (see Providers) |
| `token_endpoint_auth_method` | (unset) | pin `client_secret_post` or `client_secret_basic` instead of negotiating; must be in discovery's `token_endpoint_auth_methods_supported` when that is listed |
| `extra_egress` | `[]` | extra https origins the plugin may fetch, e.g. a JWKS host that is not the issuer's |
| `issuer` | (injected) | used **only** for the egress allow-list |

`src/index.js` injects `callback_path`/`logout_path` from the gate's `routes`
config key and `issuer` from the `issuer` config key as `plugins["oidc-auth"]`
base options (route paths set in the policy win; the injected issuer wins).
`egress(options)` can't see `ctx.config`, so this is how the issuer's origin
becomes fetchable. The issuer the plugin actually talks to is always
`ctx.config.issuer`; if the option pointed elsewhere, every IdP fetch would
fail closed with `egress_denied`.

Scalar config read from `ctx.config`: `issuer`, `clientId`, `redirectUri`,
`scopes`, `sessionTtlSeconds`, `groupsClaim`, `forwardedHost`.

## Providers

`providers/` holds what differs between identity providers, nothing else.
`defineProvider()` (`providers/define.js`) checks the shape when the module
loads: every key is required, unknown keys and wrong types throw.

```js
defineProvider({
  name: "generic",
  tokenEndpointAuthMethods: ["client_secret_post", "client_secret_basic"], // ordered preference, non-empty, no repeats
  authorizeParams: {},              // extra /authorize params (core ones are refused)
  groupsSource: "claim",            // "claim" (groups_claim) | "user-info" (login subscribers only)
  endSession: "discovery",          // "discovery" (end_session_endpoint) | "none" (303 to "/")
  logoutParams({ clientId, postLogoutRedirectUri, state }) {
    return { client_id: clientId, post_logout_redirect_uri: postLogoutRedirectUri };
  },
});
```

| Profile | Token auth preference | `authorizeParams` | `groupsSource` | `endSession` | Logout params |
|---|---|---|---|---|---|
| `generic` (default) | post, basic | – | `claim` | `discovery` | `client_id`, `post_logout_redirect_uri` |
| `auth0` | post, basic | – | `claim` | `discovery` | `client_id`, `post_logout_redirect_uri` |
| `janrain` | basic, post | `response_mode=query`, `claims` (ID-token claims) | `user-info` | `discovery` | `client_id`, `post_logout_redirect_uri`, `state` |

`generic` and `auth0` keep the pre-plugin behaviour exactly (secret in the
token request body; `client_id` + `post_logout_redirect_uri` on logout).

**Token endpoint auth negotiation** (`lib/token.js` `negotiateTokenAuthMethod`,
at the callback): the `token_endpoint_auth_method` option, if set, wins, but
must be listed when discovery lists `token_endpoint_auth_methods_supported`;
otherwise the first profile preference that discovery lists; if discovery
omits the field, the first preference. No acceptable method throws (generic
500) and logs the reason with method names only. Discovery validation rejects
a `token_endpoint_auth_methods_supported` that is not an array of strings.
`client_secret_basic` is RFC 6749 §2.3.1: `Authorization: Basic
base64(form-urlencode(id):form-urlencode(secret))`, `client_id` stays in the
body and no secret goes in it.

To add a provider: `providers/<name>.js` with `defineProvider()`, register it
in `providers/index.js`, add tests. Handlers read the profile from settings:
`settingsFor(ctx, options).provider` (e.g. `.groupsSource`, `.endSession`).

### Janrain / Akamai Identity Cloud notes

Grounded in `docs/providers/janrain.md` (desk research; nothing verified
against a live tenant yet). The service is decommissioned 2027-12-31, so the
profile is configuration only.

- **Token auth:** Basic first, because the confidential-client guide says Basic
  is required; post is the fallback (discovery lists both). Pin with
  `token_endpoint_auth_method` once the tenant is checked.
- **`response_mode=query`** is sent explicitly (the documented default for
  `code`), so the `SameSite=Lax` login cookie always comes back.
- **`claims`** requests `email`, `email_verified`, `name`, `given_name`,
  `family_name` in the ID token: Hosted Login scopes only populate userinfo.
  The IdP ignores it when the login policy uses push claims.
- **Groups** are not in Janrain tokens: `groupsSource: "user-info"`, so enable
  the `user-info` plugin; `groups_claim` is unused.
- **Logout** sends `state` (documented as functionally required). Each
  environment's `https://<host>/` must be in the client's
  `postLogoutRedirectURIs`.
- **Unverified:** PKCE together with a confidential client, `kid` always
  present, `email_verified` type, `name` population, and the local-dev
  loopback redirect URI (see `janrain.md` §5).

## Fetches, caching and KV

All fetches go through `ctx.fetch` (budgeted, egress-checked, logged with the
purpose):

| Purpose | When | Fastly cache | KV cache |
|---|---|---|---|
| `discovery` | login start, callback, logout | `{ttl: 3600}` | `oidc:discovery:<issuer>`, 1 h |
| `token` | callback | pass | – |
| `jwks` | callback | `{ttl: 3600}` | `oidc:jwks:<jwks_uri>`, 1 h |
| `jwks-refresh` | callback, once after a `kid` miss | pass | read skipped, written back |

Discovery is memoized per request (`ctx.state`), so a callback fetches it at
most once. It is validated on every use, cache hits included: the issuer must
match config, and the authorization, token and JWKS endpoints must be https
(http only on loopback). A discovered endpoint on an origin outside the egress
list fails the request with the kernel's `500 {"error":"egress_denied"}`.

KV keys live in the kernel's `plugin:oidc-auth:` namespace and keep the
pre-plugin names; values are `{"value": …, "expires": <ms>}` and also carry
the native `ttl`. The discovery/JWKS cache is **best-effort**: a KV read or
write error is logged (without the key) and the request carries on with a live
fetch.

The **single-use state marker** (`oidc:state-used:<state>`, 600 s) depends on
the platform profile:

| | KV present | KV absent |
|---|---|---|
| provisioned | checked and written; a KV error fails closed (500) | **fails closed: `503 {"error":"kv_unavailable"}`** on the callback (login start still works) |
| sandbox | (never: sandbox has no KV) | skipped with a log line (POC reduction: PKCE, the state cookie and the IdP's single-use code remain) |

## Session

The session is the gate's own credential (format v2, `docs/architecture/plugins.md` §14.2;
`lib/session.js`, `lib/signed-cookie.js`):

```
__Host-edge_session=<payload_b64url>.<hmac_b64url>; Path=/; Max-Age=<seconds>; SameSite=Lax; HttpOnly; Secure
payload = {"v":2,"typ":"session","kid":"<8 chars>","sid":"<22 chars>","sub":"…","email":"…","name":"…","groups":["…"],"iat":<s>,"exp":<s>}
hmac    = HMAC-SHA256(payload JSON, session_hmac_key)
```

- `kid`: the first 8 base64url characters of SHA-256 of the signing key (not
  secret). `sid`: 16 random bytes, base64url, minted per login on both
  platform profiles; it becomes `identity.sessionId` (for revocation).
  `email`/`name` are omitted when absent.
- **Verification** tries at most two keys, by HMAC: `session_hmac_key`
  (active), then the optional verify-only `session_hmac_key_previous`. Only
  after a key verifies the signature is the payload parsed, and its `kid`
  must equal that key's id. A `kid` never selects a key. Then the strict
  shape: `v === 2`, `typ === "session"`, well-formed `kid`/`sid`, non-empty
  `sub`, `groups` an array, `exp` in the future. **v1 cookies are rejected**,
  so every user logs in once after the cutover.
- **Typ binding (F19):** the login-state cookie (`__Host-edge_login`) uses the
  same keyring with payload `{"typ":"login","kid",state,nonce,verifier,returnTo}`.
  Each decoder requires its own `typ`, so neither token passes as the other.
- **Lifetime:** `exp = min(now + session_ttl_seconds, identity.expiresAt)`;
  `identity.expiresAt` already carries any `draft.limitLifetime()` cap. The
  cookie `Max-Age` is clamped to `exp - iat`, so cookie and payload expire
  together.
- **Size guard:** an encoded value over 3500 bytes is never set;
  `writeSession` throws `SessionTooLargeError` (exported from `lib/session.js`).

**Rotating `session_hmac_key`** (no mass logout):

1. Generate a new random key (≥ 32 bytes).
2. Set `session_hmac_key_previous` = the current key and `session_hmac_key` =
   the new key, in the same deploy (Cloud Manager secrets bundle / embedded
   config on sandbox). New sessions and login states are signed with the new
   key; existing ones still verify with the previous key.
3. Wait at least `session_ttl_seconds` (sessions) and 10 minutes (login
   state), then remove `session_hmac_key_previous`. Sessions still signed with
   the old key are then rejected and those users log in again.

For an emergency rotation (key compromise), skip step 2's previous key: every
session is invalidated at once. A `session_hmac_key_previous` shorter than 32
bytes is ignored with a warning; one equal to the active key is harmless.

## Security notes

- The session is the gate's own credential, HMAC-SHA256 with
  `session_hmac_key` (see [Session](#session)); the ID token is verified once
  at login, never per request.
- `__Host-` cookies: `Secure`, `Path=/`, no `Domain`, `HttpOnly`,
  `SameSite=Lax` (the kernel's `ctx.cookies` defaults). Both are owned by this
  plugin: the kernel strips them from origin responses and from forwarded
  requests.
- With `groupsSource: "claim"`, groups come only from `groups_claim` (no fallback chain). After changing
  groups/audience config, existing sessions keep their old groups until they
  expire or the user logs in again (the stale-cookie trap in `CLAUDE.md`).
- Error pages are generic; reasons go to the logs with the request id.
- Fetch logs carry purpose, host, status and duration only (no URLs with
  queries, no bodies, no tokens).

## Files

- `index.js`: the manifest.
- `lib/`: `options` (validation, egress), `settings` (per-request config),
  `discovery` (+ the KV JSON cache), `jwt`, `token`, `pkce`, `kv` (expiry
  wrapper), `signed-cookie`, `session`, `state` (login cookie + replay marker),
  `http`, `login`, `callback`, `logout`.
- `providers/`: `define.js` (the profile shape), `generic.js`, `auth0.js`, `janrain.js`, `index.js`.
- `test/`: unit tests on `createTestContext()` (`src/sdk/testing.js`) and the
  shared mock OP; `test/oidc-auth-gate.test.js` (repo root) covers the plugin
  through the real kernel.
