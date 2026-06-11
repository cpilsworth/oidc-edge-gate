# oidc-edge-gate parity plan — porting `oidc-worker-gate` to AEM Edge Compute

**Goal:** bring `oidc-edge-gate` (AEM Edge Function on the Fastly Compute JS runtime) up to
the functionality and hardening level of its Cloudflare-Worker sibling `oidc-worker-gate`
(Phase 1 implemented, 59 tests green, opus-reviewed). Same OIDC mechanics, same three-tier
path policy, same JWT/conformance hardening, same observability — adapted to Fastly/AEM
platform primitives.

**Confirmed scope (2026-06-11):** edge-gate fronts an **EDS delivery host** (`*.aem.live`),
matching worker-gate. The full EDS BYO-CDN origin contract therefore ports verbatim. The
current `cdn.yaml` pointing at a publish tier (`publish-pXXXXX-eYYYYY.adobeaemcloud.com`) is
to be re-pointed at the EDS delivery host.

The OIDC/JWT/crypto core is identical Web Crypto on both runtimes, so the *logic* ports
near-verbatim. The work is concentrated in (a) three modules edge-gate is missing or has a
weaker version of, (b) platform-primitive swaps, and (c) a test/conformance layer edge-gate
lacks entirely.

---

## 1. Feature-parity matrix (source = worker-gate, target = edge-gate)

| Capability | worker-gate (source) | edge-gate (today) | Action |
|---|---|---|---|
| Entry / runtime | `export default {fetch}` (workerd) | `addEventListener("fetch")` (Fastly) | keep edge form; rewire routing |
| **Three-tier path policy** (`policy.js`: public/protected/secured, most-specific-match, per-rule `audience`) | ✅ `classify()` + `isAuthorized()` | ❌ single coarse `isAuthorized(session,{require_claim,allow_values})`, **no public tier — every path forces login** | **port `policy.js` + rewire `index.js`** |
| Public tier (forward before touching cookie) | ✅ | ❌ | add |
| Secured tier → 401 JSON for API/XHR | ✅ | ❌ | add |
| **`origin.js` EDS BYO-CDN contract** (Host rewrite, `X-Forwarded-Host`, `X-Push-Invalidation`, `Age` strip, per-tier cache suppression, gate-cookie strip from origin `Set-Cookie`) | ✅ dedicated `origin.js` | ❌ inline `forwardToOrigin`, just sets `x-auth-*` + strips `cookie`; no EDS contract, no cache suppression | **port `origin.js`, adapt to Fastly** |
| **Strip client-supplied `x-auth-*` / `x-push-invalidation` before injecting trusted ones** (Critical auth-bypass fix) | ✅ | ❌ **spoofable once a public tier exists** | **port (security-critical)** |
| JWT: `alg=RS256` enforced | ✅ | ✅ | — |
| JWT: `iss` trailing-slash normalised | ✅ `claims.iss.replace(/\/$/,"")` | ❌ exact compare | port |
| JWT: `aud` match | ✅ | ✅ | — |
| JWT: `azp` check + **multi-valued-`aud`→`azp` required (N4b)** | ✅ | ❌ | port |
| JWT: `sub` required | ✅ | ❌ | port |
| JWT: **`exp` required** (not just "if present") + skew (N5) | ✅ | ❌ *(token with no `exp` passes today)* | **port (security-critical)** |
| JWT: `iat` required + future-`iat` reject | ✅ | ❌ | port |
| JWT: `nbf` skew | ✅ | ✅ | — |
| JWT: nonce (N6) | ✅ | ✅ | — |
| JWT: **`c_hash`/`at_hash` (N11)** | ✅ | ❌ | port |
| JWT: **JWKS refetch-once on `kid` miss (N7)** | ✅ | ❌ | port |
| **State single-use / replay marker (N9)** via KV | ✅ best-effort KV marker | ❌ | port (adapt to Fastly KV) |
| Callback failure semantics | 400 (observable, not re-302) | mixed 400/401 | align to 400 for validation failures |
| `safeReturnTo` open-redirect guard | ✅ robust (URL-resolves, catches `//evil`, `/\evil`) | ⚠️ only blocks `//` | port stronger version |
| `readSession` strict shape validation | ✅ `isValidSession` (sub/iat/exp/groups typed, parse guarded) | ⚠️ loose | port |
| `unsign` input hardening | ✅ type + dot-position guards | ⚠️ minimal | port |
| Groups claim key | ⚠️ hardcoded `https://oidc.workers.dev/groups` | `claims.groups||claims.roles` | **make config-driven** (`groups_claim`) for IMS/Auth0 |
| Request-id correlation header | ✅ `cf-ray`→`x-auth-request-id` | ❌ | port, swap to Fastly trace id |
| **Test suite** | ✅ 59 tests, real workerd, mock-OP, negative matrix | ❌ none | **build node-vitest + Viceroy layer** |
| Hosted OIDF conformance plan | ✅ documented (`conformance-testing.md`) | ❌ | port doc, retarget endpoint |

Cookie names (`__edge_*`) and the `email`/`name` session fields are intentionally **kept**
as-is for edge-gate (don't rename to `__gate_*`); only the `GATE_COOKIE_NAMES` set in the
ported `origin.js` must use the `__edge_*` names.

---

## 2. Platform differences that affect implementation

### 2.0 ✅ RESOLVED — cache integrity vs the edge function

For a security gate the foundational question is whether a cached response can be served
*without* the function's auth decision. Resolved via AEM guidance (edge-functions-caching
docs, 2026-06-11) — there are **two caches**, and the gate controls both (see §2.2 for the
full mechanism):

- **Outer AEM CDN** (in front of the function): a function response is kept out of it with
  **`Surrogate-Control: private`**. Applied to every per-user (protected/secured) and
  gate-generated auth response (login/callback/logout 302s, 401/403/error).
- **Function cache** (function↔origin): bypassed entirely for now with
  `CacheOverride({ mode: "pass" })` on every tier, because EDS can't yet purge it on
  publication (would risk stale content with no eviction path).
- **Browser**: `Cache-Control: private, no-store` on the same per-user/auth responses; `Age`
  dropped so no stale age is implied downstream.

**Consequences (now implemented, not just mandated):**
- Per-user content can never be stored or cross-served by any cache above the function.
- The unauthenticated **302-to-IdP carries `Surrogate-Control: private` + `no-store`**, so a
  fixed-state/nonce login redirect can't be cached and replayed to other users.
- The `cdn.yaml` routing rule keeps the function host-wide (`reqProperty: hostname / equals`).

> Residual: this is verified by header *intent* + Viceroy, but the precise outer-CDN honouring
> of `Surrogate-Control` is an AEM-CDN behaviour — confirm on a real deploy (see §6).

### 2.1 Backends are explicit and allow-listed (vs CF: any URL)

Fastly `fetch()` requires `{ backend }` and the host must be a pre-declared backend.
worker-gate's `fetch(anyUrl)` does not translate.

- **Origin fetch** → `fetch(originUrl, { backend: config.backends.origin })`. The `origin`
  backend's domain must be the EDS delivery host (`*.aem.live`). Declared in `cdn.yaml`
  `origins:` and `fastly.toml` `[local_server.backends]`.
- **IdP fetches** (discovery, JWKS, token exchange) → `{ backend: config.backends.idp }`.
  **Pitfall:** the `jwks_uri` returned by discovery may be a *different host* than the
  issuer. Both the issuer host and the JWKS host must be reachable via the `idp` backend (or
  declare a second backend). Declared in `edgeFunctions.yaml` `origins:` (defence-in-depth
  allow-list). worker-gate had no such constraint — this is net-new config work.

### 2.2 Two caches, two levers — `CacheOverride` (function cache) + `Surrogate-Control` (outer CDN)

**Confirmed against AEM docs (edge-functions-caching) + Viceroy, 2026-06-11.** There are two
caches around the function, controlled by two different mechanisms:

1. **Function cache** — the edge function's own fetch cache, between function and origin.
   Controlled by `CacheOverride` on the origin fetch. worker-gate used CF's
   `new Request(url,{ cf:{ cacheTtl:0 }})`; **there is no Fastly `cf:` object** — the
   replacement is `fetch(req, { backend, cacheOverride: new CacheOverride({ mode: "pass" }) })`
   (note the **object form** `{ mode: "pass" }`, per the AEM docs).
2. **Outer AEM CDN** — sits in *front* of the function. Controlled by **`Surrogate-Control`**
   on the response (Fastly honours it for its own caching and strips it before the browser);
   `Cache-Control` only reaches the browser. `Surrogate-Control: private` stops the outer CDN
   from caching a function response.

**Current implementation decision (the function cache can't be purged on publish yet):**
the AEM function cache *is* purgeable by surrogate key, but EDS has **no hook to purge it on
publication** — a cached entry would go stale with no eviction path. So `origin.js` sets
`CacheOverride({ mode: "pass" })` on **every** tier (don't cache at the function at all for
now); the outer CDN still caches public content via the origin's passed-through
cache/surrogate headers. Per-user content (protected/secured) and all gate-generated auth
responses (login/callback/logout 302s, 401/403/error) additionally carry
`Surrogate-Control: private` + `Cache-Control: private, no-store` (and drop `Age`).

> **Future:** once an out-of-band "observe publish → purge function cache by surrogate key"
> path exists, public tiers can opt back into function caching (drop `pass` for `public`).

### 2.3 KV store API + TTL (verify TTL; fallback ready)

| | worker-gate (CF KV) | edge-gate (Fastly KV) |
|---|---|---|
| handle | `env.OIDC_CACHE` (injected) | `new KVStore("oidc_cache")` (imported inside `jwt.js` today) |
| read | `kv.get(key,"json")` | `(await store.get(key)).text()` then `JSON.parse` |
| write | `kv.put(key,val,{expirationTtl})` | `store.put(key,val)` |
| native TTL | yes (`expirationTtl`) | **verify** |

- edge-gate's cache already uses an **expires-timestamp-in-value** pattern and checks it on
  read, so the discovery/JWKS cache is correct regardless of native TTL.
- The **N9 state-replay marker** needs expiry. If Fastly KV `put` supports a `ttl` option,
  use it; **fallback** = store `{used:true, expires}` in the value and check on read (same
  pattern as the cache), accepting that stale markers self-expire on next read rather than
  by eviction. Either way the marker is *best-effort* (KV is eventually consistent on both
  platforms — same caveat as worker-gate).

### 2.4 Adopt worker-gate's `config.kv` injection (unlocks the test layer)

worker-gate injects KV via `config.kv`; edge-gate imports `KVStore` *inside* `jwt.js`. Make
this an **early step**: load the KV handle in `config.js` (`config.cache`) and pass it down.
After this, every module except `config.js` (and the thin backend-fetch calls) is free of
`fastly:*` imports and runs under plain node-vitest with native Web Crypto — the test layer
falls out of it (see §5).

### 2.5 Misc runtime primitives (verify; all have fallbacks already in worker code)

- **`crypto.randomUUID()`** — used for the request-id fallback. Verify on the js-compute
  version in use; fallback = derive from `getRandomValues`.
- **`Headers.getSetCookie()`** — used in `origin.js` to split multiple `Set-Cookie` lines.
  Verify; worker code already has the `headers.get("set-cookie")` fallback.
- **Request-id source:** swap CF's `cf-ray` for a Fastly trace id (e.g. `Fastly-Trace-Id`
  inbound header, or generate). worker-gate sets `x-auth-request-id` on the origin request.
- **Config/secrets are async on Fastly** (`SecretStore.get()` → Promise; `ConfigStore.get()`
  sync). `loadConfig()` is already async — fine. worker-gate's `loadConfig` is sync; do not
  copy its synchronous shape.

### 2.6 fetch() budget: 32 backend reqs/exec (Fastly/AEM) vs ~1k–50k (CF)

Both designs are already built for this: discovery+JWKS are KV-cached, the session is
validated locally (HMAC, zero backend calls) on the hot path. Callback worst case =
discovery + JWKS (+1 refetch on kid-miss) + token + N9-marker reads ≈ ≤5 — well under 32.
**Implication:** do not add any per-request backend call when porting (e.g. resist any
runtime ACL pull); keep everything hot-path-local. The tighter cap is a reason the
KV-snapshot/local-validation architecture is the right one — preserve it.

---

## 3. Migration plan — phased, file-by-file

Ordering favours testability-first (per §2.4) and lands the security-critical fixes before
the feature expansion.

### Phase A — refactor for injection + test scaffolding (no behaviour change yet)
1. **`config.js`**: load the KV handle once (`config.cache = new KVStore("oidc_cache")`,
   guarded as today), add new config keys: `originHostname`, `forwardedHost`,
   `pushInvalidation`, `groupsClaim`, and the new `policy` shape (`{rules, default_tier}`).
   Add `backends.origin` already exists. Keep secrets async.
2. **`jwt.js`**: take the cache handle from `config` instead of importing `KVStore`; thread
   `config.cache` into `cachedJson`. No logic change.
3. **Test harness scaffolding** (§5): `vitest.config.js` (node env), `fastly:*` import
   aliases/stubs, port `test/helpers.js` + `test/mock-op.js` from worker-gate.

### Phase B — port the three missing/weak modules
4. **`policy.js`** (new file, port verbatim from worker-gate): `classify()` +
   `isAuthorized(session, audience)`. Pure module, no platform deps.
5. **`origin.js`** (new file, port + adapt): EDS BYO-CDN contract. Fastly adaptations:
   - `fetch(originUrl, { backend: config.backends.origin, cacheOverride })` instead of
     `cf:{}`; `CacheOverride("pass")` for protected/secured tiers only.
   - `GATE_COOKIE_NAMES = {"__edge_session","__edge_login"}`.
   - request-id from Fastly trace id, not `cf-ray`.
   - keep `email` in `x-auth-email` if you retain it in the session (worker dropped it;
     edge-gate currently forwards it — decide; recommend keep for parity with edge's
     existing origin contract, harmless).
6. **`index.js`** rewire to the worker's control flow:
   ```
   callback / logout routes →
   classify(path) →
     public  → forwardToOrigin(req, null, "public")
     else read session →
       none    → secured ? 401-json : startLogin
       present → isAuthorized? forwardToOrigin : 403
   ```
   Replace the inline `forwardToOrigin`/`isAuthorized` with the imported ones. Add the
   `unauthorizedJson()` (401) + `forbidden()` (403) helpers.

### Phase C — JWT + session + callback hardening
7. **`jwt.js` `verifyIdToken`**: add iss trailing-slash normalise; `azp` + N4b multi-aud;
   `sub` required; **`exp` required** + skew (N5); `iat` required + future-reject; c_hash/
   at_hash (N11); pass `{code, accessToken}` through from `oidc.js`. Add **N7** refetch-once
   on kid-miss (`getJwks(..., {force:true})` + a `force` param on `cachedJson`).
8. **`oidc.js`**:
   - `handleCallback`: add **N9** single-use state marker via `config.cache` (Fastly KV,
     §2.3 fallback if no native TTL); pass `{code, accessToken: tokens.access_token}` into
     `verifyIdToken`; return **400** on validation failure.
   - `safeReturnTo`: port the robust URL-resolving version (pass `url.origin`).
9. **`session.js`**: port strict `isValidSession`; make the groups claim key config-driven
   (`claims[config.groupsClaim] || claims.groups || claims.roles || []`).
10. **`cookies.js`**: port `unsign` input guards (type + dot-position).

### Phase D — config / deployment (see §4) and tests/conformance (see §5)

---

## 4. Config & deployment changes

**`edgeFunctions.yaml`** — replace coarse policy, add EDS + new keys, add idp+jwks backends:
```yaml
configs:
  issuer: "https://<idp>"               # generic OIDC provider (e.g. Auth0 tenant)
  client_id: "..."
  redirect_uri: "https://<prod-domain>/.auth/callback"
  scopes: "openid profile email"
  session_ttl_seconds: "3600"
  groups_claim: "groups"                # provider's groups claim, NOT workers.dev
  routes: '{"callback":"/.auth/callback","logout":"/.auth/logout"}'
  backends: '{"origin":"origin","idp":"idp"}'
  origin_hostname: "main--<site>--<org>.aem.live"
  forwarded_host: "<prod-domain>"
  push_invalidation: "enabled"
  policy: '{"rules":[
    {"path":"/*","tier":"public"},
    {"path":"/protected/*","tier":"protected"},
    {"path":"/protected/medical/*","tier":"protected","audience":["medical"]},
    {"path":"/api/*","tier":"secured"}
  ],"default_tier":"protected"}'
secrets:
  client_secret: "${{OIDC_CLIENT_SECRET}}"
  session_hmac_key: "${{OIDC_SESSION_HMAC_KEY}}"
origins:
  - name: idp
    domain: <idp-host>
  - name: idp-jwks            # only if jwks_uri host differs from issuer host (§2.1)
    domain: <jwks-host>
```

**`cdn.yaml`** — re-point `origins.origin.domain` from the publish tier to the EDS delivery
host (`main--<site>--<org>.aem.live`); keep the host-wide routing rule.

**`local.config.json`** — mirror the new `policy`/`origin_hostname`/`forwarded_host`/
`push_invalidation`/`groups_claim` keys.

**`fastly.toml`** — point `[local_server.backends.origin]` at the `*.aem.live` host;
`[local_server.backends.idp]` at the IdP; keep KV/Secret/Config local stubs. Add a local
KV stub for the N9 marker namespace if a separate store is used (recommend reuse
`oidc_cache`).

---

## 5. Test & conformance strategy (biggest platform gap)

There is **no Fastly equivalent of `@cloudflare/vitest-pool-workers`** (no first-class pool
that runs tests inside the real Viceroy/Compute runtime). Recommended two-layer approach,
enabled by the §2.4 injection refactor:

**Layer 1 — node-vitest unit/negative-matrix (ports ~verbatim).**
- Pure modules (`policy`, `pkce`, `cookies`, `encoding`, `session`, and `jwt` once KV is
  injected) have zero `fastly:*` imports → run under Node 18+ with native `globalThis.crypto`
  Web Crypto. The worker's `test/helpers.js` (RSA keygen, `signJwt`, `tokenHash`,
  `seedDiscovery`) and `test/mock-op.js` port directly.
- Stub the three `fastly:*` imports (`fastly:kv-store`, `fastly:config-store`,
  `fastly:secret-store`) via vitest `resolve.alias` to in-memory fakes, **or** avoid them
  entirely by testing modules below the `config.js` boundary and injecting a fake
  `config.cache`.
- Reproduce the worker's **negative-case matrix**: invalid sig, `alg=none`, wrong iss/aud,
  expired, missing `exp`, bad nonce, kid mismatch (+ refetch), missing/replayed state, PKCE
  mismatch, `c_hash`/`at_hash`. This is the same matrix that caught edge-gate's current
  `exp`-optional and spoofable-`x-auth-*` holes — it is the point of the exercise.

**Layer 2 — Viceroy integration smoke (`fastly compute serve`).**
- Build the Wasm, run `fastly compute serve` with the mock-OP wired as the `idp` local
  backend and a stub `origin`, drive HTTP from a test script (node `fetch`), assert the full
  302→callback→session→forward round-trip and the three tiers end-to-end. This is the
  closest analog to the worker's in-runtime tests and validates the `fastly:*` glue that
  Layer 1 stubs out.

**Layer 3 — hosted OIDF conformance (platform-agnostic, ports verbatim).**
- `conformance-testing.md` from worker-gate copies over; only the RP endpoint/redirect_uri
  change. Run `oidcc-client-basic-certification-test-plan` (Basic RP) + Config RP against the
  deployed Fastly endpoint.

`package.json`: add `vitest` (+ alias config), keep `@fastly/js-compute`; add
`"test": "vitest run"` and a `"test:integration"` that drives `fastly compute serve`.

---

## 6. Verify-before-asserting checklist (uncertain Fastly facts)

Status legend: ✅ confirmed under Viceroy (`npm run test:integration`, 32 assertions) · ⚠️ still
open (needs a real AEM deploy / production CDN).

| Item | Why it matters | Status |
|---|---|---|
| **CDN cache vs function (§2.0)** | gate bypassability | ✅ model resolved (AEM docs): function cache bypassed (`pass`), outer CDN gated by `Surrogate-Control: private`, browser by `no-store`. ⚠️ outer-CDN *honouring* of `Surrogate-Control` still to confirm on a real deploy (Viceroy has no AEM CDN tier). |
| `Headers.getSetCookie()` on Fastly | split origin `Set-Cookie` | ✅ gate-cookie strip + app-cookie passthrough verified under Viceroy |
| `CacheOverride({mode:"pass"})` object form | function-cache bypass | ✅ compiles + runs under Viceroy on every tier; public stays outer-CDN-cacheable (no `Surrogate-Control`) |
| Named-backend routing + Host rewrite reaching origin | EDS contract | ✅ origin receives `Host: origin.local` + `X-Forwarded-Host` via the `origin` backend |
| `new Response(body, res)` re-init | response rewrite | ✅ exercised on every forwarded response |
| Single-use state replay (sequential) | N9 | ✅ reused callback rejected (≥400) under Viceroy |
| Fastly KV native TTL on `put` | N9 marker expiry | ✅ works via expires-in-value (TTL eviction not relied upon); native TTL still unconfirmed but not required |
| `crypto.randomUUID()` on js-compute build | request-id | ✅ correlation id present on forwarded request |
| `jwks_uri` host == issuer host? | backend allow-list | ⚠️ deployment-specific — declare a second `idp-jwks` origin if they differ |
| True-concurrent replay (CAS) | N9 race | ⚠️ best-effort under eventual consistency (same as the worker); not provable locally |

---

## 7. Risks & notes

- **Security-critical items must land together with the public tier.** The moment a `public`
  tier exists, the missing `x-auth-*` strip (§ matrix) becomes an exploitable identity-spoof
  to origin, and the missing required-`exp` lets a no-exp token through. Do not ship the
  three-tier policy without Phase C.
- **No Adobe IMS integration phase.** This plan deliberately targets a **generic OIDC
  provider** only — groups/audience come from the `groups_claim` in the id_token, full stop.
  There is no IMS-as-OP work, no `/ims/profile/v1` entitlement fetch, and no DA-sourced KV
  ACL on the roadmap here (those were worker-gate's separate Phase 2/3 explorations and are
  explicitly **not** in scope). The objective is worker-gate **Phase 1** parity and nothing
  beyond it. `groups_claim` is just a config knob so the function works against whatever
  provider emits the groups claim.
- **Don't copy worker-gate verbatim where the platform differs**: the `cf:{}` object, the
  synchronous `env` config, and `fetch(anyUrl)` will all silently misbehave or fail to
  compile on Fastly. Every external `fetch` needs a `{backend}`.
- Keep the architecture's KV-snapshot + local-HMAC-validation shape — it is what keeps the
  hot path within the 32-fetch cap and is the reason both siblings can scale.
