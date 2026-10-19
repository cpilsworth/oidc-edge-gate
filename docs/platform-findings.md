# Platform findings (AEM Edge Functions / Fastly Compute)

Measured platform facts that the `oidc-edge-gate` design depends on. Produced
with the throwaway probe in [`tools/platform-probe`](../tools/platform-probe/README.md).
**Status: TEMPLATE — not yet measured.** Replace every `_TBD_` with a
measurement; quote error strings verbatim; never paste the probe token.

## Runs

| # | Date (UTC) | Env type (sandbox / provisioned) | Program kind (EDS / Java-stack) | POP(s) (`pop`) | `FASTLY_SERVICE_VERSION` | `sdk_version` | Config variant (no-origins / with-origins) | Who |
|---|---|---|---|---|---|---|---|---|
| 1 | _TBD_ | sandbox | _TBD_ | _TBD_ | _TBD_ | _TBD_ | no-origins | _TBD_ |
| 2 | _TBD_ | provisioned | _TBD_ | _TBD_ | _TBD_ | _TBD_ | no-origins | _TBD_ |

Context from `GET /__probe/env` (call twice):

| Item | Sandbox | Provisioned |
|---|---|---|
| `requests_seen_by_this_instance` on the 2nd call (>1 ⇒ module state survives across requests) | _TBD_ | _TBD_ |
| `features` that are `false` | _TBD_ | _TBD_ |

---

## 1. Stores per environment type — `GET /__probe/stores`

**Hypothesis (from CLAUDE.md/plan):** On a sandbox program `new ConfigStore("config_default")`,
`new SecretStore("secret_default")` and `new KVStore("kv_default")` all **throw**; the
function itself runs. On a provisioned environment all three construct, and
`probe_marker` is readable from the ConfigStore.

| Store | Measured (sandbox) | Measured (provisioned) |
|---|---|---|
| ConfigStore `config_default`: constructed? error class + message | _TBD_ | _TBD_ |
| `probe_marker` present / value | _TBD_ | _TBD_ |
| SecretStore `secret_default`: constructed? error class + message; absent-key lookup | _TBD_ | _TBD_ |
| KVStore `kv_default`: constructed? error class + message; absent-key lookup | _TBD_ | _TBD_ |
| Derived `profile` | _TBD_ (expect `sandbox`) | _TBD_ (expect `provisioned`) |
| Does the error throw at construction or at first use? | _TBD_ | _TBD_ |

**Design impact:** **W1.5 platform profiles**: the detection rule (which constructor
throws, which error class/message to match) and whether a `partial` profile exists.

## 2. KV read-after-write and propagation — `POST /__probe/kv/write`, `GET /__probe/kv/poll`

**Hypothesis:** KV is eventually consistent (documented). Read-after-write *within the
same execution/POP* is likely visible quickly; other POPs may serve the old value
for a while.

| Metric | Measured (sandbox) | Measured (provisioned) |
|---|---|---|
| `write.ms` (put latency) | n/a if KV absent | _TBD_ |
| `immediate_read.visible` / `ms` | n/a | _TBD_ |
| `same_execution_poll.seen_after_ms` (settle_ms=2000) | n/a | _TBD_ |
| Cross-execution, same POP: `seen_after_ms` | n/a | _TBD_ |
| Cross-POP: writer POP → reader POP, `seen_after_ms` (several samples) | n/a | _TBD_ |
| Worst observed propagation | n/a | _TBD_ |

**Design impact:** **W3.2 revocation SLO**: the propagation delay is the floor for
"how fast does a revoked session stop working everywhere". Also decides whether the
single-use OIDC state marker can rely on KV across POPs (callback may land on a
different POP than login).

## 3. KV write rate limit — `POST /__probe/kv/burst`

**Hypothesis:** 1 write/sec/key (documented). A second write to the same key within
1 s is rejected (error text unknown) or silently dropped/coalesced.

| Metric | Measured (sandbox) | Measured (provisioned) |
|---|---|---|
| `count=3, gap_ms=0`: which writes failed; exact error text | n/a | _TBD_ |
| `final_read` value (which write won?) | n/a | _TBD_ |
| `count=3, gap_ms=1100`: all ok? | n/a | _TBD_ |
| Does a rejected write throw, or resolve silently? | n/a | _TBD_ |

**Design impact:** **W3.2 revocation**: whether a per-user/per-session revocation key
can be written repeatedly (e.g. "revoke all" twice) and whether writers must
debounce or use distinct keys.

## 4. KV latency, sequential vs parallel — `GET /__probe/kv/latency?n=20|100`

**Hypothesis:** KV reads are a network hop (single-digit to tens of ms); parallel
reads (`Promise.all`) overlap, so 2 parallel reads cost ≈ 1 read. Not counted against
the 32 backend-request limit (unverified).

| Metric (ms) | Measured (sandbox) | Measured (provisioned) |
|---|---|---|
| sequential hit p50 / p95 | n/a | _TBD_ |
| sequential miss p50 / p95 | n/a | _TBD_ |
| parallel hit: per-op p50 / p95, `wall_ms` for n | n/a | _TBD_ |
| **parallel pair (hit + miss) p50 / p95** — revocation cost per request | n/a | _TBD_ |
| Any errors at n=100 (per-execution KV op limit?) + text | n/a | _TBD_ |

**Design impact:** **W3.2 revocation SLO** (added latency per protected request for the
2 parallel KV reads) and **W5.2 budgets** (whether KV ops have their own cap).

## 5. Function fetch cache with `CacheOverride` TTL — `GET /__probe/cache`

**Hypothesis:** `new CacheOverride("override", { ttl: 60 })` stores the response in the
function↔origin fetch cache, so the 2nd fetch is a hit; `"pass"` always reaches the
origin. **Open question:** the js-compute types say that when an *object* is the first
constructor argument "the mode defaults to `override`", so the gate's
`new CacheOverride({ mode: "pass" })` (src/origin.js) may NOT be a pass.

Use `url=https://httpbun.com/uuid` (body changes per origin hit).

| Metric | Measured (sandbox) | Measured (provisioned) |
|---|---|---|
| `override_ttl60_1` vs `_2`: same body hash? `ms` each | _TBD_ | _TBD_ |
| cache headers seen (`x-cache`, `age`, `x-served-by`) | _TBD_ | _TBD_ |
| `pass_string_form`: bypassed? | _TBD_ | _TBD_ |
| **`pass_object_form_gate_style`: `constructed_mode`; bypassed?** | _TBD_ | _TBD_ |
| `none_default`: hit or miss? | _TBD_ | _TBD_ |
| Auth0 discovery URL: hit on 2nd override fetch? | _TBD_ | _TBD_ |

**Design impact:** **W5.2 budgets**: whether discovery/JWKS can be cached in the fetch
cache with a TTL (no KV needed on sandbox) and whether cache hits avoid a backend
request. If the object form is not a pass, src/origin.js must switch to
`new CacheOverride("pass")`.

## 6. Backend request limit and its error text — `GET /__probe/budget?n=40`

**Hypothesis:** hard limit of **32 backend requests per execution**; the 33rd `fetch()`
fails with the misleading `Requested backend named '…' does not exist`.

| Metric | Measured (sandbox) | Measured (provisioned) |
|---|---|---|
| `successes` (cache=pass) | _TBD_ | _TBD_ |
| `first_failure.index` (expect 33) | _TBD_ | _TBD_ |
| `first_failure` class + exact message | _TBD_ | _TBD_ |
| `cache=override`: do cache hits count toward the limit? | _TBD_ | _TBD_ |

**Design impact:** **W5.2 budgets**: the per-request fetch budget table (origin fetch +
IdP calls + reCAPTCHA + error-page fetch) and the error-text matcher for a
"budget exhausted" diagnostic.

## 7. Dynamic vs named backends, and `origins:` schema acceptance — `GET /__probe/dynamic-backend`

**Hypothesis:** `fetch(absoluteUrl)` without `backend` works (dynamic backends enabled by
AEM). `backend: "probe_origin"` fails because no `origins:` can be declared: the config
pipeline schema rejects `origins:` (top level and nested).

| Metric | no-origins (sandbox) | no-origins (provisioned) | with-origins (provisioned) |
|---|---|---|---|
| Pipeline accepted the YAML? exact validation error if not | ✓ (baseline) | ✓ (baseline) | _TBD_ |
| `named_backend_probe_origin_exists` | _TBD_ | _TBD_ | _TBD_ |
| `no_backend_option` (www.aem.live): ok/status | _TBD_ | _TBD_ | _TBD_ |
| `named_backend_probe_origin`: ok/status or error text | _TBD_ | _TBD_ | _TBD_ |
| `explicit_dynamic_backend` (`new Backend({...})`): ok/status or error | _TBD_ | _TBD_ | _TBD_ |
| Non-declared host (httpbun.com) `no_backend_option` still ok? | _TBD_ | _TBD_ | _TBD_ |

**Design impact:** **W5.1 origins**: whether the gate can switch to declared, named
origins (defence-in-depth allow-list) or must keep absolute-URL dynamic backends plus an
in-code allowlist.

## 8. Crypto timings — `GET /__probe/crypto?n=100`

**Hypothesis:** HMAC-SHA256 import+verify (session cookie) is well under 1 ms; RS256
verify (id_token at callback) is ~1 ms or less; both negligible against the ~1 s vCPU
termination threshold and the 100 ms average execution target.

| Op (per-op ms p50 / p95, `vcpu_ms` for n ops) | Measured (sandbox) | Measured (provisioned) |
|---|---|---|
| `sanity` (both true?) | _TBD_ | _TBD_ |
| HMAC import (raw, 32-byte key) | _TBD_ | _TBD_ |
| HMAC verify | _TBD_ | _TBD_ |
| HMAC sign | _TBD_ | _TBD_ |
| RS256 import (JWK, 2048-bit) | _TBD_ | _TBD_ |
| RS256 verify | _TBD_ | _TBD_ |
| RS256 import + verify (cold key) | _TBD_ | _TBD_ |

**Design impact:** **W5.2 budgets** (per-request crypto budget, whether to cache imported
`CryptoKey`s in module state, which only helps if `/__probe/env` shows instance reuse).

---

## Summary of decisions

| Work package | Decision driven by this doc | Status |
|---|---|---|
| W1.5 platform profiles | Detection rule from §1 | _TBD_ |
| W3.2 revocation SLO | Propagation (§2), write limit (§3), pair latency (§4) | _TBD_ |
| W5.1 origins | §7 | _TBD_ |
| W5.2 budgets | §5, §6, §8 (and §4 KV caps) | _TBD_ |
