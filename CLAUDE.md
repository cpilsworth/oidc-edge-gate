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

## The three tiers (src/policy.js)

- **public** → forwarded to origin before the cookie is even read. No auth.
- **protected** → needs a valid session; HTML clients without one get a 302 to the IdP.
- **secured** → needs a valid session; clients without one get a 401 JSON (for API/XHR that can't follow a 302).
- **default_tier is `protected`** → deny-by-default. Any unmatched path needs a session.
- Matching is **most-specific-first** (longest literal prefix before `*`; exact beats glob).
- **Audience gating:** a rule may carry `audience: [...]`; the session's groups must intersect it (see Groups below).
- Per-rule extensions: `upstream` (proxy to a different origin), `recaptcha: true` (require a verified token on POST), `headers` (extra trusted headers forwarded to origin).

## Request flow (src/index.js)

`handleRequest` (wrapped in a top-level try/catch → JSON 500 + correlation id, never an opaque trap):
1. `loadConfig()` — config from stores **or** embedded fallback (see below).
2. `normalizePathname()` — rejects smuggled/encoded separators, resolves `..`, **preserves trailing slash** (important — see EDS notes).
3. Gate-owned routes: `/.auth/callback`, `/.auth/logout`.
4. `classify()` → `{ tier, audience, upstream, headers, recaptcha }`.
5. public → `forwardToOrigin`; protected/secured → `readSession`, then `isAuthorized`, then forward or 403 (branded error page).

## Source map

| File | Role |
|------|------|
| `src/index.js` | Entry point, routing, top-level try/catch, reCAPTCHA gate on POST |
| `src/config.js` | `loadConfig` — store-or-embedded fallback; `loadSecrets` (bundled/per-key/embedded) |
| `src/embedded-config.js` | Build-time config used when stores are absent (sandbox). **Holds the real secret locally; committed with a placeholder** |
| `src/policy.js` | `compilePolicy`, `classify`, `isAuthorized` |
| `src/oidc.js` | `OidcClient`: `startLogin`, `handleCallback`, `handleLogout`; PKCE + state + single-use replay marker |
| `src/jwt.js` | `verifyIdToken`, discovery + JWKS fetch/cache |
| `src/session.js` | Signed session cookies, `mintSessionCookie`, group normalization |
| `src/cookies.js` | Cookie signing/parsing (HMAC) |
| `src/origin.js` | `forwardToOrigin` (EDS BYO-CDN, no-store, upstream proxy), `originErrorPage` |
| `src/recaptcha.js` | Google siteverify for `recaptcha: true` rules on `/form/*` POSTs |
| `src/kv.js` | KV helpers with self-describing expiry (no-op when KV null) |
| `src/http.js` | `errorResponse`, `NO_STORE_HEADERS`, `requestId` |
| `src/path.js`, `src/encoding.js`, `src/pkce.js` | Path normalization, encoding, PKCE |
| `config/edgeFunctions.yaml` | AEM edge-function declaration (functions/configs/secrets/kvs) — **provisioned-env config source** |
| `config/cdn.yaml` | CDN routing (`selectAemOrigin`) |
| `config/local.config.json` | Local ConfigStore backing — **dormant** (local dev now uses embedded config) |
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
- KV is null on sandbox → discovery/JWKS caching degrades to live fetch; the OIDC single-use state-replay marker is **skipped** (logged) instead of failing closed (it would 503 every login). A present-but-erroring KV still fails closed. This is a deliberate POC reduction (PKCE + state cookie + IdP single-use code remain).

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
- Cloud Manager **pipeline variables** hold the secrets: `OIDC_CLIENT_SECRET`, `OIDC_SESSION_HMAC_KEY`.
- **On sandbox the config pipeline is moot** (no stores) — the running behaviour comes entirely from the embedded config baked into the deployed wasm.

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

## Groups (authorization)

- Groups come **only** from the id_token claim named by `groups_claim` — no fallback chain.
- Auth0 emits them under a **namespaced** claim (non-namespaced custom claims are stripped): the post-login Action does `api.idToken.setCustomClaim('https://oidc.workers.dev/groups', event.authorization.roles)`. So **`groups_claim = "https://oidc.workers.dev/groups"`** and groups are effectively **Auth0 roles**.
- **Policy `audience` values must equal Auth0 role names** (e.g. `medical`, `market-access`).
- Groups live in the **signed session cookie** (`__Host-edge_session`) — minted at login, read on every request, forwarded as `x-auth-groups`. There is no separate store.
- **Stale-cookie trap:** the HMAC key is stable across deploys, so a session minted before a config change (e.g. a `groups_claim` fix) stays valid with its old/empty groups until it expires (1h TTL) or the user logs out/in. After changing groups/audience config, **a fresh login is required**.

## EDS specifics

- EDS directory pages are served at the path **with a trailing slash**: `/protected/medical/` → 200, `/protected/medical` → 404. `normalizePathname` preserves the trailing slash so the gate and origin agree.
- Header/footer load as fragments — `/nav`, `/footer`, `/nav.plain.html`, `/footer.plain.html`, `/content/*.plain.html` must be **public** or the page chrome 302s to login.
- `/errors/*` is public; on a 403 the gate fetches the origin's branded `/errors/{code}` page (`originErrorPage`), falling back to JSON.
- `x-forwarded-host` tells EDS the public host for absolute URLs. It is **localhost-aware**: on `localhost` it uses the request host (so local links are localhost), else the configured `forwarded_host`. `redirect_uri` is localhost-aware the same way (and derived identically in `startLogin` + `handleCallback` so the two OIDC legs byte-match).
- BYO-CDN: `x-push-invalidation`, `Surrogate-Control`. Identity/EDS headers are **not** sent to third-party `upstream` targets.

## Caching

The gate sets **no-store on ALL tiers** (`Surrogate-Control: private` + `Cache-Control: private, no-store`, drops `Age`); the function↔origin cache is bypassed via `CacheOverride({ mode: "pass" })`. After any deploy that changes responses, **purge**: `aio aem edge-functions purge-cache oidc-edge-gate --all`. Query-string cache-busters do **not** bust the outer AEM CDN.

## Commands

```bash
npm test                                          # vitest, ~219 tests
npm run build                                      # js-compute-runtime -> bin/main.wasm
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
Provider; `test/helpers.js` has `reqFor`/`seedDiscovery`. Tests mock `fetch` and
the stores — they assert URL/headers/status, not the live platform. To simulate
sandbox, mock the store constructors to throw (see
`config-sandbox-embedded.test.js`). `npm run test:integration` builds and runs a
smoke test against a mock OP.

## Known open items (as of this writing)

- **`/api` tier divergence:** `embedded-config.js` has `/api/*` as `public` (open swapi.dev proxy — what runs on sandbox); `edgeFunctions.yaml` has it `secured`. Reconcile before a real (non-sandbox) deploy.
- **CI deploy** is wired but blocked: the OAuth Server-to-Server service account needs its Cloud Manager **product profile** granted (deploy fails "Required product profile not found in IMS profile"). Everything up to the deploy step works.
- After config changes affecting authz, existing sessions must re-login (stale-cookie trap above).
