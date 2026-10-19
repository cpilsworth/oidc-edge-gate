# CLAUDE.md — oidc-edge-gate

Guidance for working in this repo. Read this before making changes; several
platform behaviours here are non-obvious and cost real time to rediscover.

## What this is

An **OIDC relying-party gate** that fronts an AEM Edge Delivery Services (EDS)
site and validates access on **every request**. It runs as an **AEM Cloud
Service Edge Function** on the **Fastly Compute JavaScript runtime**. Every
request is classified against a three-tier path policy and either forwarded to
the EDS origin, redirected to the IdP to log in, or rejected.

- **IdP:** Auth0 (`dev-37naouno.us.auth0.com`) as a *generic* OIDC provider — **no Adobe IMS integration**.
- **Protected origin:** the EDS delivery host `main--az-poc-ch--hmehta-adobe.aem.live` (`*.aem.live`), NOT the AEM publish tier.
- **Public prod domain (POC):** `bhf.diffa.co.uk`.
- Sibling design reference: `worker-gate-parity-plan.md` (a Cloudflare Worker version this was ported from); `access-control.md` documents the access model.

## The three tiers (src/kernel/policy.js)

- **public** → forwarded to origin before the cookie is even read. No auth.
- **protected** → needs a valid session; HTML clients without one get a 302 to the IdP.
- **secured** → needs a valid session; clients without one get a 401 JSON (for API/XHR that can't follow a 302).
- **default_tier is `protected`** → deny-by-default. Any unmatched path needs a session.
- Matching is **most-specific-first** (longest literal prefix before `*`; exact beats glob). A pattern ending in `/*` also covers its **bare section path**: `/protected/medical/*` matches `/protected/medical` as well as `/protected/medical/` and below, so a section's audience can't be skipped by dropping the trailing slash. This stops at segment boundaries: `/blog/*` covers `/blog`, but not `/blogpost`.
- **reCAPTCHA** (`recaptcha: true` rules; the state-changing methods `POST`, `PUT`, `PATCH`, `DELETE`) requires `success` and, for v3 keys, `score >= recaptcha_min_score`, which is set to `0.5` (Google's recommended starting threshold). Invalid values fail config load. Plugin options can also pin the siteverify `hostname`/`action` (`expected_hostnames`, `expected_action`); bodies over `max_body_bytes` (default 1 MiB) get `413 payload_too_large`.
- **Audience gating:** a rule may carry `audience: [...]`; the session's groups must intersect it (see Groups below).
- Per-rule extensions: `upstream` (proxy to a different origin), `recaptcha: true` (require a verified token on POST/PUT/PATCH/DELETE), `headers` (extra trusted headers forwarded to origin).

## Request flow (src/index.js → src/kernel/pipeline.js)

`src/index.js` is the composition root. Per request it calls `loadGateConfig()` (`src/kernel/config.js`: store **or** embedded config by platform profile, see below), builds the plugin registry from `plugins/index.js` (once per instance), compiles the policy (`src/kernel/policy.js`, memoized per instance by its inputs; warnings logged once) and runs `createPipeline({...}).handle(request)`. Any load error → JSON 500 `internal_error` + `x-auth-request-id` (never cached; the next request retries). The pipeline (spec: `docs/architecture/plugins.md` §4) then runs:
1. **normalize** — `normalizePathname()` (`src/kernel/path.js`): rejects smuggled/encoded separators, resolves `..`, **preserves trailing slash** (important — see EDS notes); a throw → 400 `bad_request`. Inbound `x-auth-*` and plugin-prefixed (`x-recaptcha-*`) headers are stripped, including `_` lookalikes (`x_auth_groups`), plus `x-push-invalidation` and the raw `Cookie` header (captured first for `ctx.cookies`; plugins never see it on `ctx.request`).
2. **routes** — exact match on plugin-claimed `/.auth/*` paths. The `oidc-auth` plugin owns the callback and logout routes (paths from the `routes` config key, injected as `plugins["oidc-auth"]` options). Logout is **POST-only** with a same-site `Origin`/`Referer` check (`405` for other methods, `403` cross-site, `303` on success), so the site's sign-out control must be a `<form method="post">`.
3. **classify** → `{ tier, auth, audience, upstream, headers, secretHeaders, forwardIdentity, handler, middleware }`.
4. **request** middleware (runs before authentication: on a non-public tier a short-circuit with status < 300 is an invariant violation → 500; 3xx/4xx/5xx are allowed) → **authenticate** (`oidc-auth`: signed session cookie → Identity; skipped on public/`auth: none`) → **enforce** (no identity: protected → 302 to the IdP, secured → 401 JSON `Bearer`) → **authorize** (`audience` vs groups; 403 branded error page).
5. **beforeForward** middleware (e.g. `recaptcha`, so reCAPTCHA runs **after** authentication — decision D6) → **handler** (`forward()` in `src/kernel/forward.js`: EDS or `upstream`) → **afterForward** → **finalize** (no-store on every response, gate cookies stripped from origin responses, request id on errors).

## Source map

| File | Role |
|------|------|
| `src/index.js` | Entry point / composition root: config → registry → policy → pipeline; load-failure 500; `routes` + `issuer` → oidc-auth options |
| `src/embedded-config.js` | Build-time config used when stores are absent (sandbox). **Holds the real secret locally; committed with a placeholder** |
| `src/kernel/pipeline.js` | Request lifecycle (normalize … finalize), error semantics, invariants |
| `src/kernel/context.js` | Per-request scope + per-plugin `ctx` (cookies, headers, KV view, secrets, lifecycle) |
| `src/kernel/config.js` | `loadGateConfig` on `detectPlatform`: frozen scalar `config` (no secrets), `secret(key)`, `kv`, `rawPolicy`; built-in defaults; validation |
| `src/kernel/platform/` | Platform profile detection (provisioned vs sandbox), store opening, secret loading |
| `src/kernel/policy.js` | Policy v2 compiler (`compilePolicy`, legacy upgrade), `classify` |
| `src/kernel/forward.js` | `forward` (EDS BYO-CDN, identity/default/rule/secret/plugin headers, upstream proxy) and `errorPage` (branded `/errors/{code}`) |
| `src/kernel/fetch.js` | Per-execution fetch budget, plugin egress check, `CacheOverride` (pass by default) |
| `src/kernel/finalize.js` | Response finalizer: owned-cookie strip, no-store, request id |
| `src/kernel/registry.js` | Plugin registry (names, cookies, header prefixes, routes, egress) |
| `src/kernel/path.js` | Path normalization |
| `src/sdk/index.js` | Plugin SDK (`definePlugin`, `createIdentity`, `PluginError`, …) — the only kernel code plugins import |
| `src/sdk/http.js`, `src/sdk/cookies.js`, `src/sdk/encoding.js` | `errorResponse`/`NO_STORE_HEADERS`/`requestId`; cookie parse/serialize + HMAC; base64url/UTF-8/constant-time |
| `src/sdk/testing.js` | `createTestContext()` for plugin unit tests |
| `plugins/index.js` | Static list of registered plugins |
| `plugins/oidc-auth/` | OIDC relying party (authenticator): `index.js` manifest; `lib/` `login`/`callback`/`logout`, `discovery` (+ KV JSON cache), `jwt` (JWKS + RS256), `token`, `pkce`, `session` (session v2 cookie format), `signed-cookie` (keyring, `kid`, `typ`), `state` (login cookie + single-use marker), `options` (validation, egress), `settings`; `providers/` `define`, `generic`, `auth0`, `janrain` (token auth preference, authorize params, `groupsSource`, logout params). See its README |
| `plugins/recaptcha/` | reCAPTCHA middleware (`beforeForward`, POST/PUT/PATCH/DELETE by default); `lib/siteverify.js` |
| `plugins/user-info/` | Middleware: groups at login from an HTTP backend (`onLogin`, Basic service credentials), allowlisted profile as `x-user-*` headers (`beforeForward`) and the `/api/me` handler (`handle`); `lib/` `options`, `backend`, `profile` (KV cache on provisioned). See its README |
| `config/edgeFunctions.yaml` | AEM edge-function declaration (functions/configs/secrets/kvs) — **provisioned-env config source** |
| `config/cdn.yaml` | CDN routing (`selectAemOrigin`) |
| `config/local.config.json` | Local ConfigStore backing — **dormant** (local dev now uses embedded config) |
| `scripts/check-config-parity.mjs` | Embedded vs YAML config drift check (`KNOWN_DIVERGENCES`) |
| `fastly.toml` | Fastly manifest; `local_server` **intentionally omits the stores** so local mirrors sandbox |
| `.github/workflows/deploy-edge-function.yml` | CI: build + `aio aem edge-functions deploy` on push to main |

## CRITICAL: this is a SANDBOX Cloud Manager program

Program **31359** (`adobe-demo-emea-78`), env **chrisp-dev / 2079124**. On a
**sandbox program the edge-function service stores are NOT provisioned** —
`new ConfigStore/SecretStore/KVStore` **throw** at runtime. The function itself
runs fine; only the stores are missing. This is per the Adobe boilerplate
(github.com/adobe/aem-edge-functions-boilerplate).

Consequences, all already handled in code — **do not "fix" them back**:
- `loadConfig` opens each store defensively (`openStore` → null on throw) and falls back to `src/embedded-config.js`.
- That fallback is only safe for a build that is MEANT to run on sandbox. `src/build-profile.js` exports `EXPECTED_PLATFORM_PROFILE` (`null` today = detection decides). A **provisioned build must set it to `"provisioned"`**, so a ConfigStore that fails to open is a load error (generic 500) instead of a silent downgrade to the embedded sandbox config/secrets; a sandbox build may set `"sandbox"`. A mismatch always fails closed (ADR §11).
- Required config is checked at load on both profiles: `issuer`, `client_id`, `redirect_uri`, `origin_hostname` and `forwarded_host` missing or empty → load error (500).
- KV is null on sandbox → discovery/JWKS caching degrades to live fetch; the OIDC single-use state-replay marker is **skipped** (logged) instead of failing closed (it would 503 every login). A present-but-erroring KV still fails closed. This is a deliberate POC reduction (PKCE + state cookie + IdP single-use code remain). It applies to the **sandbox profile only**: on a **provisioned** platform whose KV did not open, the callback fails closed with `503 {"error":"kv_unavailable"}` (login start still works; ADR §11).

## Platform schema gotchas (edgeFunctions.yaml)

- Top-level key is **`functions`** (not `services`; both accepted, `functions` is current).
- `configs` / `secrets` / `kvs` are siblings of `functions` under `data:`.
- **No `origins:` key** — the config pipeline schema rejects it (top-level *and* nested). Declare no named backends.
- Fixed store names: `config_default`, `secret_default`, `kv_default` (not renameable).
- **fetch() uses dynamic backends** — every `fetch()` passes an **absolute URL and NO `backend` option** (a named backend requires the rejected `origins:` and throws). AEM enables dynamic backends by default.
- **Cloud secrets are one bundled JSON blob** under SecretStore key `secrets` (not per-key). `loadSecrets` tries the blob → per-key (local) → embedded (sandbox).

## Deploy model — config and code are SEPARATE

- **Config pipeline** `edge-function-dev-publish` (id **55493895**) deploys `cdn.yaml` / `edgeFunctions.yaml` — provisions stores + values on non-sandbox envs. It does **NOT** deploy code.
- **Code** (the wasm) deploys separately as **packages**: `aio aem edge-functions deploy oidc-edge-gate`. `aio aem edge-functions packages oidc-edge-gate` lists them; the active one is what runs.
- Cloud Manager **pipeline variables** hold the secrets: `OIDC_CLIENT_SECRET`, `OIDC_SESSION_HMAC_KEY` (see Secrets below for the full key list).
- **On sandbox the config pipeline is moot** (no stores) — the running behaviour comes entirely from the embedded config baked into the deployed wasm.
- **Build profile pin:** before building the wasm for a provisioned (non-sandbox) environment, set `EXPECTED_PLATFORM_PROFILE = "provisioned"` in `src/build-profile.js`. Otherwise a store outage would make that build silently run on the embedded sandbox config. The current POC (sandbox) build leaves it `null`.

## Secret handling — READ BEFORE COMMITTING

`src/embedded-config.js` is **tracked** and committed with a **placeholder**
`client_secret: "REPLACE_WITH_REAL_AUTH0_CLIENT_SECRET"`. Locally it holds the
**real** Auth0 client secret (kept uncommitted). `session_hmac_key` is a
throwaway value and is committed as-is.

**To commit changes to `embedded-config.js`:** swap the real secret for the
placeholder → verify no real secret in the staged content → commit → **restore**
the real secret to the working tree. (Do this via a scratch capture, never echo
the secret.) Never push the real secret. CI injects it from the GitHub secret
`OIDC_CLIENT_SECRET` at build time.

`.aio` is gitignored (holds org/program/env IDs). Pushes to `main` require
explicit authorization each time.

### Secrets (keys)

Provisioned: one JSON bundle under SecretStore key `secrets`. Sandbox:
`EMBEDDED_SECRETS`. Plugins read them only through `ctx.secret(key)`, scoped to
their manifest's `secrets`.

| Key | Required | Used by |
|---|---|---|
| `client_secret` | yes | `oidc-auth` token exchange (post or Basic, per provider) |
| `session_hmac_key` | yes, ≥ 32 bytes | `oidc-auth`: the **active** key, signs + verifies session and login-state cookies |
| `session_hmac_key_previous` | no | `oidc-auth`: **verify-only**, for key rotation (Session v2 below) |
| `user_info_username`, `user_info_password` | with `user-info` | `user-info`: HTTP Basic service credentials for the groups/profile backend |
| `recaptcha_secret` | with a `recaptcha: true` rule | `recaptcha` siteverify |

`config/edgeFunctions.yaml` declares only `client_secret`, `session_hmac_key`
and `recaptcha_secret` so far.

## Groups (authorization)

Where groups come from depends on the `oidc-auth` **provider** (`groupsSource`).
Auth0 and Janrain are **alternative configurations** of the same gate, not
layers of one:

- **Auth0** (`provider: "auth0"` or `"generic"`, `groupsSource: "claim"`): groups come **only** from the id_token claim named by `groups_claim` — no fallback chain.
- **Janrain** (`provider: "janrain"`, `groupsSource: "user-info"`): groups come **only** from the `user-info` plugin's backend lookup **at login**. The draft starts empty and the ID token's claims are ignored (even a claim `groups_claim` names); `groups_claim` is unused. Without `user-info` enabled the user has no groups (audience pages 403; logged as `no_groups_from_user_info`). A backend outage at login is a `503` with no session (`on_login_error: "fail"`), or a short group-less session (`"degrade"`). Setup: `docs/providers/janrain.md` §8.
- Auth0 emits them under a **namespaced** claim (non-namespaced custom claims are stripped): the post-login Action does `api.idToken.setCustomClaim('https://oidc.workers.dev/groups', event.authorization.roles)`. So **`groups_claim = "https://oidc.workers.dev/groups"`** and groups are effectively **Auth0 roles**.
- **Policy `audience` values must equal the group names the source produces:** Auth0 role names (e.g. `medical`, `market-access`), or the user-info backend's group names for Janrain.
- **Group charset:** the SDK's `normalizeGroups` keeps only strings of 1–128 **printable ASCII** characters (0x20–0x7E) with **no comma** and no leading/trailing space; anything else (non-ASCII, control characters, `a,b`, `" admin"`) is silently dropped. Role names like `medical`, `market-access`, `site-readers` are fine. `user-info` also rejects a backend list of more than 256 entries (`too_many_groups`, so `on_login_error` applies).
- **`degrade` keeps claim groups:** user-info's `on_login_error: "degrade"` drops only the backend's groups; with a `"claim"` provider (Auth0) the ID-token groups stay on the short session.
- Groups live in the **signed session cookie** (`__Host-edge_session`) — minted at login, read on every request, forwarded as `x-auth-groups`. There is no separate store.
- **Stale-cookie trap:** the HMAC key is stable across deploys, so a session minted before a config change (e.g. a `groups_claim` fix, a provider switch, a user-info backend change) stays valid with its old/empty groups until it expires (1h TTL) or the user logs out/in. After changing groups/audience config, **a fresh login is required**. The **session v2 cutover** is a one-time forced re-login: v1 cookies are rejected, so every user logs in once after the first v2 deploy.

## Session v2 (plugins/oidc-auth/lib/session.js, ADR §14.2)

- **Format:** `__Host-edge_session=base64url(JSON).base64url(HMAC-SHA256)`, JSON `{v: 2, typ: "session", kid, sid, sub, email?, name?, groups, iat, exp}`. No profile data (user-info's profile is fetched per request / KV-cached, never stored in the cookie).
- `sid`: 16 random bytes (base64url), minted by the callback before the identity is sealed, so `identity.sessionId` equals the cookie's `sid` (on both profiles; for future revocation). `kid`: first 8 base64url chars of SHA-256 of the signing key.
- `typ` binding: the login-state cookie carries `typ: "login"`; neither token passes as the other (F19).
- **Lifetime:** `exp` and `Max-Age` come from `identity.expiresAt`, which includes any `draft.limitLifetime()` cap (user-info `degrade`). **Size guard:** an encoded session over 3500 bytes is never set; the callback answers 500. **Time bounds:** a session with `iat` more than 60 s in the future, or `exp - iat` over `session_ttl_seconds` + 60, is rejected (so lowering `session_ttl_seconds` also ends longer-lived sessions). A non-empty `session_hmac_key_previous` under 32 bytes fails the config load.
- **Key rotation (no mass logout):** set `session_hmac_key_previous` = current key and `session_hmac_key` = new key in one deploy; remove the previous key after `session_ttl_seconds` (+10 min for in-flight logins). Verification tries at most those two keys and requires the payload `kid` to match the verifying key. Emergency rotation: change the key without a previous key (everyone re-logs in). Steps: `plugins/oidc-auth/README.md` "Session".

## EDS specifics

- EDS directory pages are served at the path **with a trailing slash**: `/protected/medical/` → 200, `/protected/medical` → 404. `normalizePathname` preserves the trailing slash so the gate and origin agree.
- Header/footer load as fragments — `/nav`, `/footer`, `/nav.plain.html`, `/footer.plain.html`, `/content/*.plain.html` must be **public** or the page chrome 302s to login.
- `/errors/*` is public; on a 403 the gate fetches the origin's branded `/errors/{code}` page (`originErrorPage`), falling back to JSON.
- `x-forwarded-host` tells EDS the public host for absolute URLs. It is **localhost-aware**: on `localhost` it uses the request host (so local links are localhost), else the configured `forwarded_host`. `redirect_uri` is localhost-aware the same way (and derived identically in `startLogin` + `handleCallback` so the two OIDC legs byte-match).
- BYO-CDN: `x-push-invalidation`, `Surrogate-Control`. Identity/EDS headers are **not** sent to third-party `upstream` targets.

## Caching

The gate sets **no-store on ALL tiers** (`Surrogate-Control: private` + `Cache-Control: private, no-store`, drops `Age`); the function↔origin cache is bypassed via `new CacheOverride("pass")`. **The mode must be the positional first argument:** an init object as the first argument (`new CacheOverride({ ... })`) always means mode `"override"`, so the earlier `CacheOverride({ mode: "pass" })` form did *not* bypass the cache. For a TTL, use `new CacheOverride("override", { ttl })` (discovery/JWKS use this, with a 1 h TTL). After any deploy that changes responses, **purge**: `aio aem edge-functions purge-cache oidc-edge-gate --all`. Query-string cache-busters do **not** bust the outer AEM CDN.

## Commands

```bash
npm test                                          # vitest: test/** + plugins/**/test/** (~1550 tests)
npm run build                                      # js-compute-runtime -> bin/main.wasm
node scripts/check-config-parity.mjs              # embedded vs edgeFunctions.yaml drift (exit 0 = only known divergences)
npm run test:integration                           # build + Viceroy smoke (needs the Fastly CLI)
fastly compute serve --skip-build                 # local dev on http://localhost:7676 (uses embedded config)
aio aem edge-functions build                       # package pkg/oidc-edge-gate.tar.gz
aio aem edge-functions deploy oidc-edge-gate -f    # deploy code (real secret must be in embedded-config.js)
aio aem edge-functions purge-cache oidc-edge-gate --all
aio aem edge-functions tail-logs oidc-edge-gate    # runtime logs (console.* + request logs)
```

Local dev serves the **embedded config** because `fastly.toml`'s `local_server`
omits the stores — so `localhost:7676` faithfully mirrors the sandbox. To
exercise the store-backed path locally instead, re-add the store sections to
`fastly.toml` (see the comment there).

## Testing

Vitest. `test/stubs/` provides in-memory `fastly:*` stubs (config-store,
secret-store, kv-store, cache-override); `test/mock-op.js` is a mock OpenID
Provider; `test/helpers.js` has `reqFor`/`signJwt`/`makeRsaKey`. Tests mock `fetch` and
the stores — they assert URL/headers/status, not the live platform. To simulate
sandbox, mock the store constructors to throw (see
`config-sandbox-embedded.test.js`). `npm run test:integration` builds and runs a
smoke test against a mock OP.

`test/mock-op.js` also has a Janrain mode (`createMockOp({mode: "janrain"})`) and
`test/mock-user-info.js` a mock user-info backend plus `routeFetch` (route
fetches by origin). The end-to-end provider tests `test/janrain-gate.test.js`
and `test/auth0-gate.test.js` run each configuration through `handleRequest`
under **both** platform profiles; for sandbox they `vi.mock` the store
constructors to throw and replace `src/embedded-config.js` with fake values.

## Known open items (as of this writing)

- **`/api` tier divergence:** `embedded-config.js` has `/api/*` as `public` (open swapi.dev proxy — what runs on sandbox); `edgeFunctions.yaml` has it `secured`. Reconcile before a real (non-sandbox) deploy.
- **CI deploy** is wired but blocked: the OAuth Server-to-Server service account needs its Cloud Manager **product profile** granted (deploy fails "Required product profile not found in IMS profile"). Everything up to the deploy step works.
- After config changes affecting authz, existing sessions must re-login (stale-cookie trap above).
- **Accepted sandbox risk (W1.R F2):** `session_hmac_key` and `recaptcha_secret` are committed in `src/embedded-config.js` (and were exposed in an agent transcript during the Wave 1 review). **The GitHub repo is public**, so anyone can mint a valid session cookie (any `sub`/groups) for the deployed **sandbox** gate. Separately, `main` commit `224f827` committed the **real Auth0 `client_secret`** (restored to the placeholder on `feat/gate-platform`); it remains in public history, so that secret must be rotated in Auth0. Accepted for the POC; **before any non-sandbox deploy**: commit placeholders for both, inject them from CI like `client_secret`, add a build guard against placeholders, and rotate both values (new HMAC key; new reCAPTCHA key pair).
- **Janrain tenant facts unverified:** the `janrain` provider and its tests are built from desk research and a mock OP only (`docs/providers/janrain.md` §2/§5); no tenant exists yet. Unverified: Basic vs post at `/token`, PKCE with a confidential client, `claims` parameter vs push claims, `kid` always present, `email_verified` type, post-logout/loopback redirect URIs. Run its §6/§8.4 checklists first; add the `user_info_*` secrets to `edgeFunctions.yaml` before a Janrain deploy.
- **No fetch timeout for user-info:** the kernel's `ctx.fetch` has no timeout, so a slow user-info backend stalls the login callback (and `/api/me`) until the platform's own limits.
- **Deferred review findings:** F19 (session and login-state cookies sharing one HMAC key with no `typ` binding) is fixed by session v2 (`typ`); environment binding and revocation remain for the session-ID/revocation work. F20 (uppercase or `;` path variants are classified differently from what EDS may serve) is suspected only; reject them under audience sections if EDS is found to case-fold paths or strip `;`.
