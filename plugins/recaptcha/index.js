// reCAPTCHA middleware plugin (W1.3; was the inline check in src/index.js).
//
// A request this plugin is attached to (by default: POST only) must carry a
// `g-recaptcha-response` form field that Google's siteverify accepts, with a v3
// score of at least `min_score`. On success the request is forwarded with the
// body re-attached and the trusted x-recaptcha-* result headers added; on
// failure it ends with 400 {error: "recaptcha_failed"}.
//
// Runs in `beforeForward`, i.e. AFTER authentication (decision D6): on a
// protected rule an anonymous POST is sent to log in first and never costs a
// siteverify call. See README.md.

import { definePlugin, PluginConfigError, PluginError } from "../../src/sdk/index.js";
import { extractRecaptchaToken, passesRecaptcha, recaptchaResultHeaders, verifyRecaptcha } from "./lib/siteverify.js";

const OPTION_KEYS = new Set(["min_score"]);

export default definePlugin({
  name: "recaptcha",
  kind: "middleware",
  description: "Require a verified Google reCAPTCHA token (v2 or v3 with a minimum score) on matching requests.",
  phases: ["beforeForward"],
  trustedHeaderPrefixes: ["x-recaptcha-"],
  egress: ["https://www.google.com"],
  secrets: ["recaptcha_secret"],
  maxFetches: 1,
  defaults: { when: { methods: ["POST"] } },

  validate(options) {
    for (const k of Object.keys(options)) {
      if (!OPTION_KEYS.has(k)) throw new PluginConfigError(`unknown option ${JSON.stringify(k)}`);
    }
    if (options.min_score === undefined) return {};
    const n = options.min_score;
    if (typeof n !== "number" || !Number.isFinite(n) || n < 0 || n > 1) {
      throw new PluginConfigError("min_score must be a number between 0.0 and 1.0");
    }
    return { min_score: n };
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
    const req = ctx.request;
    const bodyBuf = await req.arrayBuffer();
    const token = extractRecaptchaToken(new TextDecoder().decode(bodyBuf), req.headers.get("content-type"));
    const result = await verifyRecaptcha(token, secret, ctx.fetch);
    const minScore = options.min_score ?? ctx.config.recaptchaMinScore ?? null;
    if (!passesRecaptcha(result, minScore)) {
      const codes = result && Array.isArray(result["error-codes"]) ? result["error-codes"].map(String) : [];
      ctx.log.warn("recaptcha failed", { errorCodes: codes, score: result && typeof result.score === "number" ? result.score : undefined });
      throw new PluginError(400, "recaptcha_failed", "recaptcha verification failed");
    }

    // Reading the body consumed the stream: re-attach the buffered bytes.
    const bodyless = req.method === "GET" || req.method === "HEAD";
    ctx.replaceRequest(new Request(req.url, { method: req.method, headers: req.headers, body: bodyless ? undefined : bodyBuf }));
    for (const [name, value] of Object.entries(recaptchaResultHeaders(result))) ctx.forwardHeaders.set(name, value);
  },
});
