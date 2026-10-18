# platform-probe

A tiny, **throwaway** AEM Edge Function that *measures* the platform facts the
`oidc-edge-gate` design depends on, so `docs/platform-findings.md` records
measurements instead of assumptions. It is a separate function from the gate
and shares no code with `src/`.

What it measures (see [`CLAUDE.md`](../../CLAUDE.md) for the hypotheses):

| Question | Endpoint | Informs |
|---|---|---|
| Are `config_default` / `secret_default` / `kv_default` provisioned? (sandbox vs provisioned) | `GET /__probe/stores` | W1.5 platform profiles |
| KV read-after-write, cross-execution / cross-POP propagation | `POST /__probe/kv/write`, `GET /__probe/kv/read`, `GET /__probe/kv/poll` | W3.2 revocation SLO |
| KV 1 write/sec/key limit | `POST /__probe/kv/burst` | W3.2 |
| KV latency, sequential vs parallel, and the 2-parallel-reads revocation pattern | `GET /__probe/kv/latency` | W3.2, W5.2 |
| Function fetch cache with `CacheOverride` TTL vs `pass` (incl. the gate's object form) | `GET /__probe/cache` | W5.2 (discovery/JWKS caching) |
| 32 backend requests per execution and its error text | `GET /__probe/budget` | W5.2 budgets |
| Dynamic vs named backends; does the pipeline accept `origins:`? | `GET /__probe/dynamic-backend` + the two YAML variants | W5.1 origins |
| Per-op crypto cost (HMAC-SHA256, RS256) in wall time and vCPU | `GET /__probe/crypto` | W5.2 budgets |
| POP, service version, SDK version, sandbox reuse | `GET /__probe/env` | context for every row |
| Teardown helper: delete `probe:` KV keys | `POST /__probe/kv/cleanup` | — |

## Safety

- **Token-gated.** Every route is under `/__probe/` and requires the header
  `x-probe-token`, compared in constant time with a token baked in at build
  time. A missing or wrong token, an unknown path, or a build where the token
  was never injected → plain `404 Not Found` (the probe is not discoverable).
- **The token is never committed.** `src/token.js` holds the placeholder
  `REPLACE_WITH_PROBE_TOKEN`; you inject the real value from an environment
  variable right before building and restore the placeholder afterwards.
- **No secrets.** The probe never reads a real secret: `/__probe/stores` only
  looks up the absent key `probe_absent_key` in the SecretStore and reads only
  `probe_marker` from the ConfigStore. Request headers are never logged or
  echoed. The crypto fixtures in `src/fixtures.js` are throwaway test keys
  (the RSA private key was discarded when they were generated).
- **Bounded side effects.** Fetches go only to an allowlist of public hosts
  (anything else → 400): `www.aem.live`, `httpbun.com`, and
  `dev-37naouno.us.auth0.com` (the gate's IdP; public discovery/JWKS only).
  KV writes only touch keys prefixed `probe:` and always carry a native `ttl`
  (write: 1 h default, burst: 10 min, latency seeds: 24 h).
- **Uncacheable.** All responses carry `cache-control: private, no-store` and
  `surrogate-control: private`.
- **Delete it after use** (see [Teardown](#teardown)).

## Files

```
tools/platform-probe/
├── src/index.js            entry point + all probes (Fastly Compute JS runtime)
├── src/lib.js              pure helpers (token check, allowlist, stats, shaping) — unit-tested
├── src/token.js            build-time token (committed as the placeholder)
├── src/fixtures.js         generated HMAC/RS256 test vectors for /__probe/crypto
├── scripts/inject-token.mjs        inject $PROBE_TOKEN into src/token.js
├── scripts/gen-crypto-fixtures.mjs regenerate src/fixtures.js offline (Node WebCrypto)
├── config/edgeFunctions.no-origins.yaml   function + probe_marker + kvs, no origins:
├── config/edgeFunctions.with-origins.yaml same + origins: [probe_origin]
├── fastly.toml             manifest (name = platform-probe; local_server mirrors sandbox)
└── package.json            build script only; reuses the repo root's @fastly/js-compute
```

Unit tests for `lib.js` live in `test/platform-probe.test.js` (part of `npm test`).

## Before you start: function slots

EDS programs allow up to **3** edge functions per environment; AEM Java-stack
environments allow **1**. Check which kind your target environment is (the
`edgefunctions_edge_delivery` flag in your local `.aio`, or the deploy output).

- **Free slot available:** deploy the probe as a second function named
  `platform-probe` next to `oidc-edge-gate` (the normal path below).
- **Single-slot environment (Java-stack):** you cannot add a second function.
  Either run the probe on an EDS/other environment, or *temporarily* deploy the
  probe package **under the existing function name** (`aio aem edge-functions
  deploy oidc-edge-gate -p pkg/platform-probe.tar.gz`), run it, then redeploy
  the gate (unverified: whether the service accepts a package whose
  `fastly.toml` name differs from the function name; if it rejects it,
  temporarily set `name = "oidc-edge-gate"` in this folder's `fastly.toml`
  before `aio aem edge-functions build`). While the probe occupies the slot, every non-`/__probe/` request
  gets a 404 (fail-closed, nothing leaks), so only do this on a sandbox/dev env.

Run the probe on **both** the sandbox program and a **provisioned**
(non-sandbox) environment when one exists; most rows in the findings table have
a column for each.

## Step 1 — register the function (config pipeline)

The real repo's `config/edgeFunctions.yaml` is **shared by all functions in the
environment**. Do **not** replace it with the probe's YAML; **merge** these
entries into it:

```yaml
data:
  functions:
    - name: oidc-edge-gate
    - name: platform-probe          # ADD

  configs:
    # ...existing gate keys unchanged...
    - key: probe_marker             # ADD
      value: "platform-probe-v1"

  kvs: true                         # already present for the gate
```

Commit and run the config pipeline (`edge-function-dev-publish`). On a sandbox
the stores are not provisioned (that is one of the things being measured), but
the function itself is still registered. The two files under `config/` here are
the stand-alone reference shapes, not files to deploy over the shared one.

No `cdn.yaml` change is needed: call the probe on its debug hostname.

## Step 2 — inject the token, build, package, deploy

Run from `tools/platform-probe` (the repo root must have had `npm install`;
`npm run build` finds `js-compute-runtime` in the root `node_modules`):

```bash
cd tools/platform-probe

# 1. Generate and keep a token in your shell only (never commit it).
export PROBE_TOKEN="$(openssl rand -hex 24)"

# 2. Inject it (one-liner; same pattern as CI's client-secret injection) ...
node -e 'const fs=require("fs"),f="src/token.js",t=process.env.PROBE_TOKEN;if(!t||t.length<16)process.exit(1);const s=fs.readFileSync(f,"utf8");if(!s.includes("\"REPLACE_WITH_PROBE_TOKEN\""))process.exit(2);fs.writeFileSync(f,s.replace("\"REPLACE_WITH_PROBE_TOKEN\"",()=>JSON.stringify(t)))'
#    ... or equivalently: node scripts/inject-token.mjs

# 3. Build + package (runs fastly.toml [scripts].build → bin/main.wasm,
#    then packages pkg/platform-probe.tar.gz).
aio aem edge-functions build

# 4. Restore the placeholder IMMEDIATELY. The token now lives only in bin/main.wasm
#    and pkg/platform-probe.tar.gz (the build runs `fastly compute build
#    --include-source`, so the tarball also carries src/token.js). Both dirs are
#    gitignored; delete them after deploying.
git checkout -- src/token.js
git diff --quiet -- src/token.js && echo "token.js clean"

# 5. Deploy the code package to the function registered in step 1, then drop
#    the token-bearing build outputs.
aio aem edge-functions deploy platform-probe
rm -rf bin pkg
```

The deploy output prints the debug URL. Its pattern is
`https://edgefunction-p<PROGRAM_ID>-e<ENV_ID>-platform-probe.adobeaemcloud.com`
for a Java-stack environment, or
`https://edgefunction-p<PROGRAM_ID>-d<DELIVERY_ID>-platform-probe.adobeaemcloud.com`
for an EDS site. Use your own IDs; this hostname is for debugging only.

Optional local run (needs the Fastly CLI; `fastly.toml` mirrors the sandbox, so
the stores throw locally unless you uncomment the `local_server` stores):
`fastly compute serve` → `http://127.0.0.1:7676/__probe/stores`.

## Step 3 — run the probes

```bash
H="https://edgefunction-p<PROGRAM_ID>-e<ENV_ID>-platform-probe.adobeaemcloud.com"
T="x-probe-token: $PROBE_TOKEN"

# 0. Context (POP, versions, sandbox reuse). Call twice: requests_seen > 1 => instance reuse.
curl -s -H "$T" "$H/__probe/env"

# 1. Stores / platform profile
curl -s -H "$T" "$H/__probe/stores"

# 2. KV read-after-write (same execution), then cross-execution propagation
curl -s -X POST -H "$T" "$H/__probe/kv/write?key=probe:raw-1&settle_ms=2000"
#    copy results.value from the output, then (ideally from ANOTHER network/region too,
#    and compare the "pop" field of each response):
curl -s -H "$T" "$H/__probe/kv/poll?key=probe:raw-1&expect=<VALUE>&max_ms=30000&interval_ms=200"
curl -s -H "$T" "$H/__probe/kv/read?key=probe:raw-1"

# 2b. 1 write/sec/key: back-to-back, then spaced
curl -s -X POST -H "$T" "$H/__probe/kv/burst?key=probe:burst-1&count=3"
curl -s -X POST -H "$T" "$H/__probe/kv/burst?key=probe:burst-2&count=3&gap_ms=1100"

# 3. KV latency: sequential vs parallel vs revocation-style pairs
curl -s -H "$T" "$H/__probe/kv/latency?n=20"
curl -s -H "$T" "$H/__probe/kv/latency?n=100"

# 4. Function fetch cache (httpbun /uuid returns a new body per origin hit, so equal
#    body hashes mean "served from the function cache"). bust=1 (default) makes the
#    first fetch a guaranteed miss. Also try the IdP discovery doc.
curl -s -H "$T" "$H/__probe/cache?url=https://httpbun.com/uuid"
curl -s -H "$T" "$H/__probe/cache?url=https://dev-37naouno.us.auth0.com/.well-known/openid-configuration"

# 5. Backend request budget (expect first_failure.index = 33)
curl -s -H "$T" "$H/__probe/budget?n=40&url=https://www.aem.live/"
curl -s -H "$T" "$H/__probe/budget?n=40&url=https://www.aem.live/&cache=override"   # do cache hits count?

# 6. Dynamic vs named backends (run with BOTH yaml variants, see below)
curl -s -H "$T" "$H/__probe/dynamic-backend?url=https://www.aem.live/"
curl -s -H "$T" "$H/__probe/dynamic-backend?url=https://httpbun.com/get"   # a host NOT in origins:

# 7. Crypto cost
curl -s -H "$T" "$H/__probe/crypto?n=100"
```

Every response is `{ probe, ok, results, notes, elapsed_ms, pop, vcpu_ms }`.
Bad parameters → 400 with the reason; an unexpected exception → 500 with the
error class/message (logged without request data; see
`aio aem edge-functions tail-logs platform-probe`).

### Re-testing `origins:` (W5.1)

`config/edgeFunctions.with-origins.yaml` exists only to re-test whether the
config-pipeline schema **now** accepts an `origins:` block (it was previously
rejected, top-level and nested — see `CLAUDE.md`). Procedure:

1. With the no-origins config deployed, run `/__probe/dynamic-backend` for both
   URLs above and save the output (expected: `no_backend_option` ok,
   `named_backend_probe_origin` fails).
2. Add the `origins:` block from the with-origins file to the shared
   `config/edgeFunctions.yaml` and run the config pipeline. **Record whether the
   pipeline accepts it, and the exact validation error if not.**
3. If accepted, run `/__probe/dynamic-backend` again for both URLs: does the
   named backend work, and is the non-declared host now blocked?

**Warning:** per the AEM docs, declared origins *restrict* fetch() for the
functions in the environment. If the gate runs in the same environment, add its
hosts (EDS origin, Auth0, `www.google.com`, `swapi.dev`, `httpbun.com`; listed
commented-out in the with-origins file) or expect the gate to break. Revert the
block afterwards unless the result says to keep it.

## Recording results

Fill in [`docs/platform-findings.md`](../../docs/platform-findings.md): one
section per question with "Measured (sandbox)" and "Measured (provisioned)"
cells. Paste the relevant numbers (p50/p95, indices, exact error strings), the
`pop`, the date, and the `FASTLY_SERVICE_VERSION` from `/__probe/env`. Keep raw
JSON out of the doc; summarise, and quote error text verbatim. Never paste the
token.

## Teardown

1. Delete the probe's KV keys (they also expire on their own via `ttl`):
   `curl -s -X POST -H "$T" "$H/__probe/kv/cleanup"` (repeat while `results.more` is true).
2. Neutralise the code immediately: rebuild **without** injecting a token and
   redeploy (`aio aem edge-functions build && aio aem edge-functions deploy platform-probe`).
   With the placeholder token every route returns 404.
3. Remove `- name: platform-probe` and `probe_marker` (and any `origins:` test
   block) from `config/edgeFunctions.yaml`, run the config pipeline, and confirm
   with `aio aem edge-functions list` that the function is gone. (The CLI has no
   delete command; the function is declared by the config pipeline.)
4. If you used a single-slot environment, redeploy the gate:
   `aio aem edge-functions deploy oidc-edge-gate -f` from the repo root.
5. Unset the token in your shell: `unset PROBE_TOKEN`.

## Maintenance

- Regenerate crypto fixtures (offline): `node scripts/gen-crypto-fixtures.mjs`.
- Local compile check from the repo root:
  `node_modules/.bin/js-compute-runtime tools/platform-probe/src/index.js tools/platform-probe/bin/main.wasm`
  (`bin/`, `pkg/` and `*.wasm` are gitignored).
