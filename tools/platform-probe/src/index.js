/// <reference types="@fastly/js-compute" />
// platform-probe — a throwaway AEM Edge Function that MEASURES the platform
// facts the oidc-edge-gate design depends on (stores, KV consistency/latency,
// fetch cache, backend budget, named vs dynamic backends, crypto cost).
//
// Every route lives under /__probe/ and requires the build-time `x-probe-token`
// header (constant-time compare). Missing/wrong token, or an un-injected
// placeholder token → opaque 404. Responses are JSON, never cached, and no
// request header is ever logged or echoed. Delete the function after use.
import { ConfigStore } from "fastly:config-store";
import { SecretStore } from "fastly:secret-store";
import { KVStore } from "fastly:kv-store";
import { CacheOverride } from "fastly:cache-override";
import { Backend } from "fastly:backend";
import { env } from "fastly:env";
import { vCpuTime } from "fastly:compute";
import {
  tokenMatches, checkAllowedUrl, isProbeKey, clampInt, summarize, describeError, classifyProfile,
  pickHeaders, probeBody, round, jsonResponse, notFound, b64uToBytes, shortHash,
} from "./lib.js";
import { PROBE_TOKEN } from "./token.js";
import * as FX from "./fixtures.js";

const PREFIX = "/__probe/";
const CACHE_HEADERS = ["x-cache", "x-cache-hits", "age", "x-served-by", "cache-control", "date", "etag", "via"];
const SAFE_ENV = ["FASTLY_POP", "FASTLY_REGION", "FASTLY_HOSTNAME", "FASTLY_SERVICE_VERSION",
  "FASTLY_CACHE_GENERATION", "FASTLY_IS_STAGING", "FASTLY_TRACE_ID"];

/** Module state; survives across requests only if the platform reuses sandboxes. */
const SANDBOX = { firstSeen: 0, requests: 0 };

/** High-resolution clock when available (ms). */
const now = () => (typeof performance !== "undefined" && performance.now ? performance.now() : Date.now());
/** Elapsed ms since `t`, rounded. @param {number} t */
const since = (t) => round(now() - t);
/** vCPU ms consumed so far by this execution (null if unsupported). */
const cpu = () => { try { return vCpuTime(); } catch { return null; } };
/** vCPU ms since `c` (null if unsupported). @param {?number} c */
const cpuSince = (c) => { const c1 = cpu(); return c === null || c1 === null ? null : round(c1 - c); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rand = () => Math.random().toString(36).slice(2, 10);

/** @param {string} name */
function safeEnv(name) {
  try { return env(name) || null; } catch { return null; }
}

class BadRequest extends Error {}

/**
 * Run `fn`, capturing wall time and either its value or a described error.
 * @template T
 * @param {() => Promise<T> | T} fn
 * @returns {Promise<{ok:true, ms:number, value:T} | {ok:false, ms:number, error:object}>}
 */
async function timed(fn) {
  const t = now();
  try {
    const value = await fn();
    return { ok: true, ms: since(t), value };
  } catch (err) {
    return { ok: false, ms: since(t), error: describeError(err) };
  }
}

/** @param {URLSearchParams} p */
function requireUrl(p) {
  const c = checkAllowedUrl(p.get("url"));
  if (!c.ok) throw new BadRequest(c.error);
  return c.url;
}

/** @param {URLSearchParams} p */
function requireKey(p) {
  const key = p.get("key");
  if (!isProbeKey(key)) throw new BadRequest("key must match ^probe:[A-Za-z0-9._:-]{1,200}$");
  return key;
}

function openKv() {
  return new KVStore("kv_default");
}

/** Read a KV key's text, or null when absent. @param {KVStore} kv @param {string} key */
async function kvText(kv, key) {
  const e = await kv.get(key);
  return e ? await e.text() : null;
}

/**
 * Poll `key` until it equals `expect` or `maxMs` passes.
 * @param {KVStore} kv @param {string} key @param {?string} expect
 * @param {number} maxMs @param {number} intervalMs
 */
async function pollKv(kv, key, expect, maxMs, intervalMs) {
  const t0 = now();
  let attempts = 0, consecutiveErrors = 0, lastValue = null, firstError = null;
  while (attempts < 1000) {
    attempts++;
    const r = await timed(() => kvText(kv, key));
    if (r.ok) {
      consecutiveErrors = 0;
      lastValue = r.value;
      if (expect !== null && r.value === expect) {
        return { seen: true, seen_after_ms: since(t0), attempts, last_value: lastValue, first_error: firstError };
      }
    } else {
      firstError ??= { attempt: attempts, ...r.error };
      if (++consecutiveErrors >= 3) break;
    }
    if (since(t0) + intervalMs > maxMs) break;
    await sleep(intervalMs);
  }
  return { seen: false, waited_ms: since(t0), attempts, last_value: lastValue, first_error: firstError };
}

/**
 * Fetch, fully consume the body, and report status/timing/hash/cache headers.
 * @param {string} url @param {object} init
 */
async function fetchReport(url, init) {
  const t = now();
  try {
    const res = await fetch(url, init);
    const buf = await res.arrayBuffer();
    return { ok: true, status: res.status, ms: since(t), bytes: buf.byteLength, body_sha256_16: await shortHash(buf),
      headers: pickHeaders(res.headers, CACHE_HEADERS) };
  } catch (err) {
    return { ok: false, ms: since(t), error: describeError(err) };
  }
}

/**
 * Time `n` sequential runs of `fn`.
 * @param {number} n @param {() => Promise<unknown>} fn
 */
async function measure(n, fn) {
  const samples = [];
  let errors = 0, firstError = null;
  const c0 = cpu();
  for (let i = 0; i < n; i++) {
    const r = await timed(fn);
    samples.push(r.ms);
    if (!r.ok) { errors++; firstError ??= { index: i, ...r.error }; }
  }
  return { ...summarize(samples), errors, first_error: firstError, vcpu_ms: cpuSince(c0) };
}

/* ------------------------------------------------------------------ probes */

/** Open one store and exercise it without reading any foreign key's value. */
async function openAndUse(open, use) {
  const t = now();
  let store;
  try { store = open(); } catch (err) {
    return { constructed: false, construct_ms: since(t), error: describeError(err) };
  }
  const out = { constructed: true, construct_ms: since(t) };
  const r = await timed(() => use(store));
  out.use = r.ok ? { ok: true, ms: r.ms, ...r.value } : { ok: false, ms: r.ms, error: r.error };
  return out;
}

async function probeStores(ctx) {
  const results = {
    config: await openAndUse(() => new ConfigStore("config_default"), (s) => {
      const v = s.get("probe_marker");
      return { probe_marker_present: v !== null, probe_marker_value: v === null ? null : String(v).slice(0, 64) };
    }),
    secret: await openAndUse(() => new SecretStore("secret_default"), async (s) => {
      const e = await s.get("probe_absent_key"); // never reads a real secret
      return { absent_key_lookup: e === null ? "null" : "entry" };
    }),
    kv: await openAndUse(openKv, async (s) => {
      const e = await s.get("probe:stores-check");
      return { absent_key_lookup: e === null ? "null" : "entry" };
    }),
  };
  results.profile = classifyProfile(results);
  ctx.notes.push("profile: provisioned = all three stores construct; sandbox = none do (per CLAUDE.md).");
  return { ok: true, results };
}

async function probeKvWrite(ctx) {
  const key = requireKey(ctx.params);
  const raw = ctx.params.get("value");
  if (raw !== null && !/^[A-Za-z0-9._:-]{1,100}$/.test(raw)) throw new BadRequest("value must match [A-Za-z0-9._:-]{1,100}");
  const value = raw ?? `v-${Date.now()}-${rand()}`;
  const ttl = clampInt(ctx.params.get("ttl"), 3600, 60, 86400);
  const settleMs = clampInt(ctx.params.get("settle_ms"), 0, 0, 5000);
  const kv = openKv();
  const write = await timed(() => kv.put(key, value, { ttl }));
  const read = await timed(() => kvText(kv, key));
  const results = {
    key, value, ttl_s: ttl, written_at_epoch_ms: Date.now(),
    write: { ok: write.ok, ms: write.ms, error: write.ok ? undefined : write.error },
    immediate_read: read.ok ? { ok: true, ms: read.ms, visible: read.value === value, value_seen: read.value }
      : { ok: false, ms: read.ms, error: read.error },
  };
  if (settleMs > 0) results.same_execution_poll = await pollKv(kv, key, value, settleMs, 100);
  ctx.notes.push(`Cross-execution/POP: GET ${PREFIX}kv/poll?key=${key}&expect=${value}&max_ms=30000 (from another POP too).`);
  return { ok: write.ok, results };
}

async function probeKvRead(ctx) {
  const key = requireKey(ctx.params);
  const r = await timed(() => kvText(openKv(), key));
  return { ok: r.ok, results: r.ok ? { key, ms: r.ms, present: r.value !== null, value: r.value } : { key, ms: r.ms, error: r.error } };
}

async function probeKvPoll(ctx) {
  const key = requireKey(ctx.params);
  const expect = ctx.params.get("expect");
  const maxMs = clampInt(ctx.params.get("max_ms"), 10000, 0, 60000);
  const intervalMs = clampInt(ctx.params.get("interval_ms"), 200, 50, 5000);
  const r = await pollKv(openKv(), key, expect, maxMs, intervalMs);
  return { ok: true, results: { key, expect, max_ms: maxMs, interval_ms: intervalMs, ...r } };
}

async function probeKvBurst(ctx) {
  const key = requireKey(ctx.params);
  const count = clampInt(ctx.params.get("count"), 2, 2, 5);
  const gapMs = clampInt(ctx.params.get("gap_ms"), 0, 0, 1500);
  const kv = openKv();
  const base = `b-${Date.now()}-${rand()}`;
  const writes = [];
  for (let i = 0; i < count; i++) {
    if (i > 0 && gapMs) await sleep(gapMs);
    const value = `${base}-${i}`;
    const w = await timed(() => kv.put(key, value, { ttl: 600 }));
    writes.push({ i, value, ok: w.ok, ms: w.ms, error: w.ok ? undefined : w.error });
  }
  const final = await timed(() => kvText(kv, key));
  ctx.notes.push("Documented limit: 1 write/sec/key. A rejected write shows ok:false with the platform error text.");
  return { ok: true, results: { key, count, gap_ms: gapMs, writes, final_read: final.ok ? final.value : final.error } };
}

async function probeKvLatency(ctx) {
  const n = clampInt(ctx.params.get("n"), 20, 1, 100);
  const kv = openKv();
  const [a, b, miss] = ["probe:latency-a", "probe:latency-b", "probe:latency-missing"];
  for (const k of [a, b]) {
    const seeded = await timed(async () => { if ((await kvText(kv, k)) === null) await kv.put(k, `seed-${Date.now()}`, { ttl: 86400 }); });
    if (!seeded.ok) ctx.notes.push(`seeding ${k} failed: ${seeded.error.message}`);
  }

  const sequential = await measure(n, () => kvText(kv, a));
  const sequentialMiss = await measure(n, () => kvText(kv, miss));
  const tp = now();
  const parSamples = await Promise.all(Array.from({ length: n }, () => timed(() => kvText(kv, a))));
  const parallel = { ...summarize(parSamples.map((s) => s.ms)), wall_ms: since(tp), errors: parSamples.filter((s) => !s.ok).length,
    first_error: parSamples.find((s) => !s.ok)?.error ?? null };
  // Revocation pattern: two parallel reads (one hit, one miss) per request.
  const pairs = await measure(n, () => Promise.all([kvText(kv, b), kvText(kv, miss)]));
  ctx.notes.push("pairs = Promise.all([get(hit), get(miss)]) per iteration: the planned per-request revocation cost.");
  return { ok: true, results: { n, sequential_hit: sequential, sequential_miss: sequentialMiss, parallel_hit: parallel, parallel_pair: pairs } };
}

async function probeKvCleanup(ctx) {
  const kv = openKv();
  const listed = await timed(() => kv.list({ prefix: "probe:", limit: 200 }));
  if (!listed.ok) return { ok: false, results: { list_error: listed.error } };
  const keys = listed.value.list.filter(isProbeKey);
  const deleted = [], failed = [];
  for (const k of keys) {
    const d = await timed(() => kv.delete(k));
    (d.ok ? deleted : failed).push(d.ok ? k : { key: k, ...d.error });
  }
  if (listed.value.cursor) ctx.notes.push("More probe: keys remain; call again.");
  ctx.notes.push("Keys also expire on their own (native ttl on every probe write).");
  return { ok: failed.length === 0, results: { deleted, failed, more: Boolean(listed.value.cursor) } };
}

async function probeCache(ctx) {
  const target = requireUrl(ctx.params);
  if (ctx.params.get("bust") !== "0") target.searchParams.set("probe_cb", `${Date.now()}-${rand()}`);
  const u = target.toString();
  /** @type {[string, () => CacheOverride][]} */
  const steps = [
    ["override_ttl60_1", () => new CacheOverride("override", { ttl: 60 })],
    ["override_ttl60_2", () => new CacheOverride("override", { ttl: 60 })],
    ["pass_string_form", () => new CacheOverride("pass")],
    ["pass_object_form_gate_style", () => new CacheOverride({ mode: "pass" })],
    ["none_default", () => new CacheOverride("none")],
  ];
  const results = { url: u, steps: {} };
  for (const [name, make] of steps) {
    let co;
    try { co = make(); } catch (err) { results.steps[name] = { constructed: false, error: describeError(err) }; continue; }
    results.steps[name] = { constructed_mode: co.mode ?? null, constructed_ttl: co.ttl ?? null, ...(await fetchReport(u, { cacheOverride: co })) };
  }
  const h = (k) => results.steps[k]?.body_sha256_16;
  results.interpretation = {
    second_override_served_from_function_cache: h("override_ttl60_1") !== undefined && h("override_ttl60_1") === h("override_ttl60_2"),
    pass_string_bypassed_cache: h("pass_string_form") !== undefined && h("pass_string_form") !== h("override_ttl60_1"),
    pass_object_form_bypassed_cache: h("pass_object_form_gate_style") !== undefined && h("pass_object_form_gate_style") !== h("override_ttl60_1"),
  };
  ctx.notes.push("Body-hash comparisons are only meaningful for a URL whose body changes per origin hit (use https://httpbun.com/uuid).");
  ctx.notes.push("pass_object_form_gate_style mirrors src/origin.js `new CacheOverride({ mode: \"pass\" })`; check constructed_mode.");
  return { ok: true, results };
}

async function probeBudget(ctx) {
  const target = requireUrl(ctx.params);
  const n = clampInt(ctx.params.get("n"), 34, 1, 40);
  const useCache = ctx.params.get("cache") === "override";
  const attempts = [];
  let firstFailure = null, consecutive = 0;
  for (let i = 1; i <= n; i++) {
    const u = new URL(target);
    u.searchParams.set("probe_budget", String(i));
    const co = useCache ? new CacheOverride("override", { ttl: 60 }) : new CacheOverride("pass");
    const r = await fetchReport(u.toString(), { cacheOverride: co });
    attempts.push(r.ok ? { i, ok: true, status: r.status, ms: r.ms } : { i, ok: false, ms: r.ms, error: r.error });
    if (!r.ok) { firstFailure ??= { index: i, ...r.error }; if (++consecutive >= 3) break; } else consecutive = 0;
  }
  ctx.notes.push("index is 1-based: first_failure.index = 33 confirms a 32-request limit.");
  return { ok: true, results: { n, cache: useCache ? "override" : "pass", successes: attempts.filter((a) => a.ok).length,
    first_failure: firstFailure, attempts } };
}

async function probeDynamicBackend(ctx) {
  const target = requireUrl(ctx.params);
  const u = target.toString();
  const host = target.hostname;
  const pass = () => new CacheOverride("pass");
  const results = { url: u };
  const exists = await timed(() => Backend.exists("probe_origin"));
  results.named_backend_probe_origin_exists = exists.ok ? exists.value : { error: exists.error };
  results.no_backend_option = await fetchReport(u, { cacheOverride: pass() });
  results.named_backend_probe_origin = await fetchReport(u, { backend: "probe_origin", cacheOverride: pass() });
  const explicit = await timed(() => new Backend({ target: host, hostOverride: host, sniHostname: host, certificateHostname: host, useSSL: true }));
  results.explicit_dynamic_backend = explicit.ok
    ? { constructed: true, ...(await fetchReport(u, { backend: explicit.value, cacheOverride: pass() })) }
    : { constructed: false, error: explicit.error };
  ctx.notes.push("Deploy once with edgeFunctions.no-origins.yaml and once with edgeFunctions.with-origins.yaml; compare.");
  return { ok: true, results };
}

async function probeCrypto(ctx) {
  const n = clampInt(ctx.params.get("n"), 100, 1, 500);
  const msg = new TextEncoder().encode(FX.MESSAGE);
  const hmacRaw = b64uToBytes(FX.HMAC_KEY_B64U);
  const hmacSig = b64uToBytes(FX.HMAC_SIG_B64U);
  const rsaSig = b64uToBytes(FX.RSA_SIG_B64U);
  const HMAC = { name: "HMAC", hash: "SHA-256" };
  const RSA = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  const importHmac = () => crypto.subtle.importKey("raw", hmacRaw, HMAC, false, ["sign", "verify"]);
  const importRsa = () => crypto.subtle.importKey("jwk", FX.RSA_PUBLIC_JWK, RSA, false, ["verify"]);
  const hk = await importHmac();
  const rk = await importRsa();
  const sanity = {
    hmac_verified: await crypto.subtle.verify("HMAC", hk, hmacSig, msg),
    rsa_verified: await crypto.subtle.verify("RSASSA-PKCS1-v1_5", rk, rsaSig, msg),
  };
  const results = {
    n, sanity,
    hmac_sha256_import_raw: await measure(n, importHmac),
    hmac_sha256_verify: await measure(n, () => crypto.subtle.verify("HMAC", hk, hmacSig, msg)),
    hmac_sha256_sign: await measure(n, () => crypto.subtle.sign("HMAC", hk, msg)),
    rs256_import_jwk: await measure(n, importRsa),
    rs256_verify: await measure(n, () => crypto.subtle.verify("RSASSA-PKCS1-v1_5", rk, rsaSig, msg)),
    rs256_import_plus_verify: await measure(n, async () => crypto.subtle.verify("RSASSA-PKCS1-v1_5", await importRsa(), rsaSig, msg)),
  };
  ctx.notes.push("Executions may be terminated at ~1s of vCPU; compare vcpu_ms per op against the per-request budget.");
  return { ok: sanity.hmac_verified && sanity.rsa_verified, results };
}

async function probeEnv(ctx) {
  const vars = Object.fromEntries(SAFE_ENV.map((k) => [k, safeEnv(k)]));
  const g = /** @type {any} */ (globalThis);
  const results = {
    env: vars,
    sdk_version: g.fastly?.sdkVersion ?? null,
    request_host: ctx.url.host,
    sandbox: { requests_seen_by_this_instance: SANDBOX.requests, first_seen_ms_ago: Date.now() - SANDBOX.firstSeen },
    features: {
      performance_now: typeof performance !== "undefined" && typeof performance.now === "function",
      set_timeout: typeof setTimeout === "function",
      crypto_subtle: typeof crypto !== "undefined" && !!crypto.subtle,
      crypto_random_uuid: typeof crypto !== "undefined" && typeof crypto.randomUUID === "function",
      structured_clone: typeof structuredClone === "function",
      compression_stream: typeof g.CompressionStream === "function",
      vcpu_time: cpu() !== null,
    },
  };
  ctx.notes.push("requests_seen_by_this_instance > 1 means module state (e.g. an in-memory JWKS cache) survives across requests.");
  return { ok: true, results };
}

/** Route table: "METHOD /__probe/<name>" → handler. */
const ROUTES = {
  "GET stores": probeStores,
  "POST kv/write": probeKvWrite,
  "GET kv/read": probeKvRead,
  "GET kv/poll": probeKvPoll,
  "POST kv/burst": probeKvBurst,
  "GET kv/latency": probeKvLatency,
  "POST kv/cleanup": probeKvCleanup,
  "GET cache": probeCache,
  "GET budget": probeBudget,
  "GET dynamic-backend": probeDynamicBackend,
  "GET crypto": probeCrypto,
  "GET env": probeEnv,
};

/**
 * Probe entry point. Exported for completeness; the runtime wires it below.
 * @param {FetchEvent} event
 * @returns {Promise<Response>}
 */
export async function handle(event) {
  SANDBOX.requests++;
  SANDBOX.firstSeen ||= Date.now();
  const req = event.request;
  const url = new URL(req.url);
  if (!url.pathname.startsWith(PREFIX)) return notFound();
  if (!tokenMatches(req.headers.get("x-probe-token"), PROBE_TOKEN)) return notFound();
  const name = url.pathname.slice(PREFIX.length);
  const route = ROUTES[`${req.method} ${name}`];
  if (!route) return notFound();

  const ctx = { url, params: url.searchParams, notes: [] };
  const t0 = now();
  const c0 = cpu();
  const extra = () => ({ pop: safeEnv("FASTLY_POP"), vcpu_ms: cpuSince(c0) });
  try {
    const { ok, results } = await route(ctx);
    return jsonResponse(200, probeBody(name, ok, results, ctx.notes, t0, now(), extra()));
  } catch (err) {
    const error = describeError(err);
    if (err instanceof BadRequest) return jsonResponse(400, probeBody(name, false, { error }, ctx.notes, t0, now(), extra()));
    console.error(`platform-probe ${name} failed: ${error.class}: ${error.message}`);
    return jsonResponse(500, probeBody(name, false, { error }, ctx.notes, t0, now(), extra()));
  }
}

if (typeof addEventListener === "function") {
  addEventListener("fetch", (event) => event.respondWith(handle(event)));
}
