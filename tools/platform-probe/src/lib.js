// Pure helpers for the platform probe. No `fastly:*` imports here, so this
// module is unit-testable under plain node (test/platform-probe.test.js).

/** Headers on every probe response: keep it out of the outer CDN and the browser. */
export const PROBE_HEADERS = Object.freeze({
  "content-type": "application/json; charset=utf-8",
  "cache-control": "private, no-store",
  "surrogate-control": "private",
  "x-content-type-options": "nosniff",
});

/**
 * Public hosts the fetch-based probes may contact. Anything else → 400.
 * - www.aem.live: EDS public site (same delivery platform as the protected origin)
 * - httpbun.com: echo service; /uuid returns a fresh body per origin hit (cache test)
 * - dev-37naouno.us.auth0.com: the gate's IdP (public discovery + JWKS documents)
 */
export const ALLOWED_HOSTS = Object.freeze(["www.aem.live", "httpbun.com", "dev-37naouno.us.auth0.com"]);

// Split so the build-time injection one-liner (which replaces the first literal
// placeholder in token.js) can never rewrite this sentinel.
const PLACEHOLDER = "REPLACE_WITH_" + "PROBE_TOKEN";
const MIN_TOKEN_LENGTH = 16;

/**
 * True when a real token was injected (not the placeholder, long enough).
 * @param {unknown} expected
 * @returns {boolean}
 */
export function isTokenConfigured(expected) {
  return typeof expected === "string" && expected !== PLACEHOLDER && expected.length >= MIN_TOKEN_LENGTH;
}

/**
 * Constant-time token comparison. Loops over the expected token's length
 * regardless of the provided value, folding length mismatch into the result.
 * Fails closed when the expected token is unconfigured.
 * @param {?string} provided  value of the x-probe-token header
 * @param {string} expected   build-time token
 * @returns {boolean}
 */
export function tokenMatches(provided, expected) {
  if (!isTokenConfigured(expected) || typeof provided !== "string") return false;
  const enc = new TextEncoder();
  const a = enc.encode(provided);
  const b = enc.encode(expected);
  let diff = a.length ^ b.length;
  for (let i = 0; i < b.length; i++) diff |= (i < a.length ? a[i] : 0) ^ b[i];
  return diff === 0;
}

/**
 * Validate a user-supplied URL against the allowlist: https, exact host, no
 * credentials, default port.
 * @param {?string} raw
 * @returns {{ ok: true, url: URL } | { ok: false, error: string }}
 */
export function checkAllowedUrl(raw) {
  if (!raw) return { ok: false, error: "missing url parameter" };
  let url;
  try { url = new URL(raw); } catch { return { ok: false, error: "invalid url" }; }
  if (url.protocol !== "https:") return { ok: false, error: "only https is allowed" };
  if (url.username || url.password || url.port) return { ok: false, error: "credentials/port not allowed" };
  if (!ALLOWED_HOSTS.includes(url.hostname)) {
    return { ok: false, error: `host not allowlisted (allowed: ${ALLOWED_HOSTS.join(", ")})` };
  }
  return { ok: true, url };
}

/**
 * KV keys used by the probe must be `probe:`-prefixed and use a safe charset
 * (Fastly forbids `#;?^|\n\r`; we are stricter).
 * @param {?string} key
 * @returns {boolean}
 */
export function isProbeKey(key) {
  return typeof key === "string" && /^probe:[A-Za-z0-9._:-]{1,200}$/.test(key);
}

/**
 * Parse an integer query parameter, clamped to [min, max]; `def` when absent/NaN.
 * @param {?string} raw
 * @param {number} def
 * @param {number} min
 * @param {number} max
 */
export function clampInt(raw, def, min, max) {
  const n = raw == null || raw === "" ? NaN : Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}

/**
 * Nearest-rank percentile of an ascending-sorted array.
 * @param {number[]} sorted
 * @param {number} p  0..100
 */
export function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1];
}

/** Round ms to µs precision (null-safe). @param {?number} x */
export const round = (x) => (x == null ? null : Math.round(x * 1000) / 1000);

/**
 * Summarise latency samples (ms).
 * @param {number[]} samples
 * @returns {{ n:number, min:?number, p50:?number, p95:?number, max:?number, mean:?number, total:number }}
 */
export function summarize(samples) {
  const s = [...samples].sort((x, y) => x - y);
  const total = s.reduce((acc, x) => acc + x, 0);
  return {
    n: s.length,
    min: round(s[0] ?? null),
    p50: round(percentile(s, 50)),
    p95: round(percentile(s, 95)),
    max: round(s.length ? s[s.length - 1] : null),
    mean: round(s.length ? total / s.length : null),
    total: round(total),
  };
}

/**
 * Describe a thrown value without leaking anything but class/name/message.
 * @param {unknown} err
 * @returns {{ class: string, name: string, message: string }}
 */
export function describeError(err) {
  if (err && typeof err === "object") {
    const e = /** @type {any} */ (err);
    return {
      class: (e.constructor && e.constructor.name) || typeof err,
      name: String(e.name ?? ""),
      message: String(e.message ?? e),
    };
  }
  return { class: typeof err, name: "", message: String(err) };
}

/**
 * Derive the "platform profile" from the /__probe/stores result: the input for
 * W1.5 (platform profiles). All three stores open → provisioned; none → sandbox.
 * @param {{ config?: {constructed:boolean}, secret?: {constructed:boolean}, kv?: {constructed:boolean} }} stores
 * @returns {"provisioned" | "sandbox" | "partial"}
 */
export function classifyProfile(stores) {
  const flags = ["config", "secret", "kv"].map((k) => Boolean(stores && stores[k] && stores[k].constructed));
  if (flags.every(Boolean)) return "provisioned";
  if (!flags.some(Boolean)) return "sandbox";
  return "partial";
}

/**
 * Pick a fixed set of (lower-cased) response headers; absent ones are omitted.
 * @param {Headers} headers
 * @param {string[]} names
 */
export function pickHeaders(headers, names) {
  /** @type {Record<string,string>} */
  const out = {};
  for (const n of names) {
    const v = headers.get(n);
    if (v !== null) out[n] = v;
  }
  return out;
}

/**
 * Shape a probe result body.
 * @param {string} probe
 * @param {boolean} ok
 * @param {object} results
 * @param {string[]} notes
 * @param {number} startedAt  ms timestamp from the same clock as `now`
 * @param {number} now
 * @param {object} [extra]    extra top-level fields (pop, vcpu_ms)
 */
export function probeBody(probe, ok, results, notes, startedAt, now, extra = {}) {
  return { probe, ok, results, notes, elapsed_ms: round(now - startedAt), ...extra };
}

/**
 * JSON response with the no-store probe headers.
 * @param {number} status
 * @param {object} body
 */
export function jsonResponse(status, body) {
  return new Response(JSON.stringify(body, null, 2), { status, headers: PROBE_HEADERS });
}

/** Opaque 404 used for unknown paths AND for a missing/wrong token. */
export function notFound() {
  return new Response("Not Found", {
    status: 404,
    headers: { "content-type": "text/plain", "cache-control": "private, no-store", "surrogate-control": "private" },
  });
}

/**
 * base64url → bytes (no padding required).
 * @param {string} s
 * @returns {Uint8Array}
 */
export function b64uToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Hex prefix of SHA-256(bytes): lets the cache probe tell "same body" (served
 * from cache) from "fresh body" without echoing content.
 * @param {ArrayBuffer} buf
 */
export async function shortHash(buf) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return [...d.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
