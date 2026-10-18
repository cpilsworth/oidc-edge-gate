// reCAPTCHA middleware plugin (W1.3; was the inline check in src/index.js).
//
// A request this plugin is attached to (by default: the state-changing methods
// POST, PUT, PATCH and DELETE) must carry a `g-recaptcha-response` form field
// that Google's siteverify accepts, with a v3 score of at least `min_score`
// and, when configured, the expected hostname/action. On success the request
// is forwarded with the body re-attached and the trusted x-recaptcha-* result
// headers added; on failure it ends with 400 {error: "recaptcha_failed"}. A
// body larger than `max_body_bytes` ends with 413 {error: "payload_too_large"}
// before Google is called.
//
// Runs in `beforeForward`, i.e. AFTER authentication (decision D6): on a
// protected rule an anonymous POST is sent to log in first and never costs a
// siteverify call. See README.md.

import { definePlugin, PluginConfigError, PluginError } from "../../src/sdk/index.js";
import {
  extractRecaptchaToken, matchesExpectations, passesRecaptcha, recaptchaResultHeaders, verifyRecaptcha,
} from "./lib/siteverify.js";

const OPTION_KEYS = new Set(["min_score", "expected_hostnames", "expected_action", "max_body_bytes"]);
/** Default cap on the buffered request body (1 MiB). */
export const DEFAULT_MAX_BODY_BYTES = 1048576;
const HOSTNAME_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
// Google: actions may only contain alphanumerics, slashes and underscores.
const ACTION_RE = /^[A-Za-z0-9_/]{1,100}$/;

export default definePlugin({
  name: "recaptcha",
  kind: "middleware",
  description: "Require a verified Google reCAPTCHA token (v2 or v3 with a minimum score) on matching requests.",
  phases: ["beforeForward"],
  trustedHeaderPrefixes: ["x-recaptcha-"],
  egress: ["https://www.google.com"],
  secrets: ["recaptcha_secret"],
  maxFetches: 1,
  defaults: { when: { methods: ["POST", "PUT", "PATCH", "DELETE"] } },

  validate(options) {
    for (const k of Object.keys(options)) {
      if (!OPTION_KEYS.has(k)) throw new PluginConfigError(`unknown option ${JSON.stringify(k)}`);
    }
    const out = {};
    if (options.min_score !== undefined) {
      const n = options.min_score;
      if (typeof n !== "number" || !Number.isFinite(n) || n < 0 || n > 1) {
        throw new PluginConfigError("min_score must be a number between 0.0 and 1.0");
      }
      out.min_score = n;
    }
    if (options.expected_hostnames !== undefined) {
      const h = options.expected_hostnames;
      if (!Array.isArray(h) || h.length === 0 || !h.every((x) => typeof x === "string" && HOSTNAME_RE.test(x))) {
        throw new PluginConfigError("expected_hostnames must be a non-empty array of lowercase hostnames");
      }
      out.expected_hostnames = Object.freeze([...new Set(h)]);
    }
    if (options.expected_action !== undefined) {
      if (typeof options.expected_action !== "string" || !ACTION_RE.test(options.expected_action)) {
        throw new PluginConfigError("expected_action must be a non-empty string of letters, digits, \"_\" and \"/\"");
      }
      out.expected_action = options.expected_action;
    }
    if (options.max_body_bytes !== undefined) {
      const m = options.max_body_bytes;
      if (!Number.isSafeInteger(m) || m <= 0) throw new PluginConfigError("max_body_bytes must be a positive integer");
      out.max_body_bytes = m;
    }
    return out;
  },

  async beforeForward(ctx, options) {
    const secret = ctx.secret("recaptcha_secret");
    if (!secret) {
      // A rule requires reCAPTCHA but no secret is provisioned: fail closed
      // rather than silently letting unverified submissions through.
      ctx.log.error("misconfiguration: recaptcha required but recaptcha_secret is not configured");
      throw new PluginError(500, "internal_error", "recaptcha_secret is not configured");
    }

    // Buffer the body as BYTES (multipart can carry a binary file part that a
    // UTF-8 decode/re-encode would corrupt); decode a lossy text VIEW of the
    // same bytes only to locate the token, which is always plain ASCII.
    // F9: the buffer is capped. A declared Content-Length over the cap is
    // refused up front; the streaming read enforces the same cap, so a missing
    // or lying Content-Length cannot make the gate buffer an unbounded body.
    const req = ctx.request;
    const maxBytes = options.max_body_bytes ?? DEFAULT_MAX_BODY_BYTES;
    const declared = req.headers.get("content-length");
    if (declared !== null && /^\s*\d+\s*$/.test(declared) && Number(declared) > maxBytes) {
      throw new PluginError(413, "payload_too_large", "request body exceeds max_body_bytes (content-length)");
    }
    const bodyBuf = await readBodyCapped(req, maxBytes);
    const token = extractRecaptchaToken(new TextDecoder().decode(bodyBuf), req.headers.get("content-type"));
    const result = await verifyRecaptcha(token, secret, ctx.fetch);
    const minScore = options.min_score ?? ctx.config.recaptchaMinScore ?? null;
    if (!passesRecaptcha(result, minScore)) {
      const codes = result && Array.isArray(result["error-codes"]) ? result["error-codes"].map(String) : [];
      ctx.log.warn("recaptcha failed", { errorCodes: codes, score: result && typeof result.score === "number" ? result.score : undefined });
      throw new PluginError(400, "recaptcha_failed", "recaptcha verification failed");
    }
    // F8: a token minted for another site or another action is not a pass.
    const mismatch = matchesExpectations(result, {
      expectedHostnames: options.expected_hostnames, expectedAction: options.expected_action,
    });
    if (mismatch) {
      ctx.log.warn("recaptcha failed", { reason: mismatch });
      throw new PluginError(400, "recaptcha_failed", `recaptcha verification failed (${mismatch})`);
    }

    // Reading the body consumed the stream: re-attach the buffered bytes.
    const bodyless = req.method === "GET" || req.method === "HEAD";
    ctx.replaceRequest(new Request(req.url, { method: req.method, headers: req.headers, body: bodyless ? undefined : bodyBuf }));
    for (const [name, value] of Object.entries(recaptchaResultHeaders(result))) ctx.forwardHeaders.set(name, value);
  },
});

/**
 * Read a request body into one ArrayBuffer, never holding more than `max`
 * bytes: the read is cancelled and 413 thrown as soon as the running total
 * exceeds it.
 * @param {Request} req
 * @param {number} max
 * @returns {Promise<ArrayBuffer>}
 */
async function readBodyCapped(req, max) {
  if (!req.body) return new ArrayBuffer(0);
  const reader = req.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
    total += chunk.byteLength;
    if (total > max) {
      try { await reader.cancel(); } catch { /* ignore */ }
      throw new PluginError(413, "payload_too_large", "request body exceeds max_body_bytes");
    }
    chunks.push(chunk);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return out.buffer;
}
