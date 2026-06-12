## Hardening

**1. Normalize the path before classifying it — this is the one real bypass risk.**
`classify()` runs on the raw `url.pathname` (`src/index.js:40`), and glob matching is literal (`src/policy.js:33`). The WHATWG URL parser preserves percent-encoding and duplicate slashes, so:

- `//protected/secret` does not match `/protected/*` (it fails `^/protected/.*$`),
- `/%70rotected/secret` doesn't match it either.

With a fail-closed policy that's harmless (falls to `default_tier: protected`), but the **shipped sample policy includes `{"path":"/*","tier":"public"}`** — so both of those requests classify as *public* and get forwarded verbatim to the EDS origin, which may normalize `//`→`/` or decode `%70` and serve the protected content unauthenticated. Fix in `handleRequest` before classification: `decodeURIComponent` the pathname (return 400 if it throws or contains an encoded `/`/`\`), collapse repeated slashes, then classify the normalized path and forward that same normalized path to origin so the gate and origin agree on what was requested.

**2. The sample policy contradicts the deny-by-default story.**
Because `/*` matches every path, `default_tier: "protected"` is unreachable in the example in `edgeFunctions.yaml:38` / `local.config.json` — the example site is *public by default with protected carve-outs*, while the README advertises deny-by-default. Anyone copying the sample inherits that posture silently. Either drop `/*` from the sample (let the public asset rules + `default_tier` do the work), or add a comment stating that `/*` flips the model. Relatedly, when `policy` JSON fails to parse, `loadConfig` throws and the request 500s — fail-closed, which is good, but worth a test.

**3. Use `__Host-` cookie prefixes.**
`__edge_session` and `__edge_login` already meet the requirements (`Secure`, `Path=/`, no `Domain`), so renaming to `__Host-edge_session` etc. (`src/session.js:9-10`, mirrored in `GATE_COOKIE_NAMES` in `src/origin.js:21`) is free hardening: the browser then guarantees no subdomain or non-secure context can plant/override them.

**4. Drop the groups-claim fallback chain and validate the claim shape.**
`mintSessionCookie` does `claims[config.groupsClaim] || claims.groups || claims.roles || []` (`src/session.js:66`). Two problems: (a) the fallback undermines explicit config — if the configured claim is absent, silently picking up `roles` can grant audience-gated access nobody intended; (b) if the IdP sends groups as a string (some do), the session is minted with a non-array `groups`, `isValidSession` then rejects it on every read, and the user gets an **infinite login loop**. Use only the configured claim, and normalize/validate it to an array of strings at mint time.

**5. Replay protection fails open when KV is unbound.**
If `new KVStore("oidc_cache")` throws, `config.cache` is null (`src/config.js:58`) and the single-use-state check in `handleCallback` (`src/oidc.js:84`) is silently skipped. On real AEM the store should exist, so failing open here mostly hides misconfiguration. For the *callback* specifically I'd fail closed (or at minimum log loudly); for the discovery/JWKS cache, falling through to live fetches is fine.

**6. Enforce config invariants at load.**
`session_hmac_key` ≥ 32 bytes is documented but not enforced — check it in `loadConfig` and throw. Same for `sessionTtlSeconds`: `parseInt` of a malformed value yields `NaN`, which mints a session with `exp: NaN` that never validates → another silent login loop.

**7. Stop echoing internal detail in error responses.**
`errorResponse` reflects `e.message` from token validation and the raw IdP `error` param to the client (`src/oidc.js:99,130`). It's `text/plain` so there's no XSS, but it's free reconnaissance ("azp mismatch", "no JWKS key for kid X"). Return a generic message + the `x-auth-request-id`, and log the detail. While there, add `x-content-type-options: nosniff` to gate-generated responses and a `WWW-Authenticate: Bearer` header on the 401.

**8. Validate the discovery document.**
`getDiscovery` trusts whatever JSON comes back. Per OIDC Discovery, check `discovery.issuer === config.issuer` and that `authorization_endpoint`/`token_endpoint`/`jwks_uri` are `https:` URLs before using them — cheap insurance against a misconfigured or compromised cache/backend, since these values are interpolated into redirects and fetches.

**9. Smaller items.**
- `/.auth/logout` is a CSRF-able GET — any third-party page can force-logout users via an `<img>`. Low impact, but cheap to note in the README or gate behind same-site referer/POST.
- RP-initiated logout omits `id_token_hint` (`src/oidc.js:155`); several providers (Entra ID, Keycloak in some configs) won't honor `end_session` without it. Worth a README note since the id_token isn't persisted.
- `state-used:*` KV markers are never deleted (`src/oidc.js:95`). If the platform KV supports a TTL on put, set one; otherwise note the growth.

## Simplification

**1. One signed-cookie reader instead of two.**
`readSession` and `readStateCookie` (`src/session.js:41-53, 86-98`) are line-for-line identical except for cookie name and validator. A single `readSignedCookie(req, name, validate, config)` removes ~20 duplicated lines and guarantees the two paths can't drift.

**2. One no-store response helper.**
The `surrogate-control: private` + `cache-control: private, no-store` pair is hand-written in six places (`index.js` ×2, `oidc.js` ×4, `origin.js` ×1), and `unauthorizedJson`, `forbidden`, and `errorResponse` are three variants of the same function. A tiny shared `http.js` with `NO_STORE_HEADERS` and one `errorResponse(status, body, type)` collapses all of them — and is where the `nosniff`/`WWW-Authenticate` hardening from above would land once.

**3. Reuse the KV expiry-wrapper logic for the replay marker.**
The `{value, expires}`-wrapped, checked-on-read pattern exists twice: `cachedJson` in `src/jwt.js:118` and inline (with its own `try/catch`) for the state marker in `src/oidc.js:84-96`. Extracting `kvGetFresh(kv, key)` / `kvPutWithTtl(kv, key, value, ttl)` makes the callback's replay block about four lines and keeps one definition of "expired".

**4. Precompile policy regexes.**
`matchGlob` builds a `new RegExp` per rule per request (`src/policy.js:34`). Compiling them once in `loadConfig` (and sorting rules by specificity once) simplifies `classify` to a `find()` and removes per-request regex construction. Minor on a per-request Wasm isolate, but it also means a malformed pattern fails at config load instead of at match time.

If you'd like, I can implement these — the natural first PR is items H1/H2 (path normalization + sample policy) plus the simplifications, since the simplification helpers are where several of the hardening tweaks would live.