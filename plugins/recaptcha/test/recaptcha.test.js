// recaptcha plugin: manifest, options and the beforeForward hook, driven
// through the SDK's createTestContext (no kernel internals).
import { describe, it, expect } from "vitest";
import { PluginError } from "../../../src/sdk/index.js";
import { createTestContext } from "../../../src/sdk/testing.js";
import recaptcha from "../index.js";
import { SITEVERIFY_URL } from "../lib/siteverify.js";

const FORM_CT = "application/x-www-form-urlencoded";

function post(body, headers = { "content-type": FORM_CT }, url = "https://www.example.com/form/x") {
  return new Request(url, { method: "POST", headers, body });
}

function google(result, record = []) {
  return async (input, init) => {
    record.push({ input, init });
    return Response.json(result);
  };
}

function ctxFor(request, { secrets = { recaptcha_secret: "s3cret" }, result = { success: true, score: 0.9 }, config = { recaptchaMinScore: 0.5 }, fetch, options } = {}) {
  return createTestContext({ plugin: recaptcha, request, secrets, config, options, fetch: fetch || google(result) });
}

describe("recaptcha manifest", () => {
  // F7: the default covers every state-changing method (was POST only).
  it("is a beforeForward middleware (D6: after authentication) defaulting to the state-changing methods", () => {
    expect(recaptcha.kind).toBe("middleware");
    expect(recaptcha.phases).toEqual(["beforeForward"]);
    expect(recaptcha.defaults).toEqual({ when: { methods: ["POST", "PUT", "PATCH", "DELETE"] } });
    expect(recaptcha.trustedHeaderPrefixes).toEqual(["x-recaptcha-"]);
    expect(recaptcha.egress).toEqual(["https://www.google.com"]);
    expect(recaptcha.secrets).toEqual(["recaptcha_secret"]);
    expect(recaptcha.maxFetches).toBe(1);
    expect(new URL(SITEVERIFY_URL).origin).toBe("https://www.google.com");
  });

  it("validate: min_score must be a number 0..1; unknown options are rejected", () => {
    expect(recaptcha.validate({})).toEqual({});
    expect(recaptcha.validate({ min_score: 0 })).toEqual({ min_score: 0 });
    expect(recaptcha.validate({ min_score: 1 })).toEqual({ min_score: 1 });
    for (const bad of [-0.1, 1.1, "0.5", NaN, Infinity, null]) {
      expect(() => recaptcha.validate({ min_score: bad }), String(bad)).toThrow(/min_score/);
    }
    expect(() => recaptcha.validate({ min_scor: 0.5 })).toThrow(/unknown option/);
  });

  it("validate (F8): expected_hostnames is a non-empty array of lowercase hostnames; expected_action a string", () => {
    expect(recaptcha.validate({ expected_hostnames: ["www.example.com", "example.com"], expected_action: "submit_form" }))
      .toEqual({ expected_hostnames: ["www.example.com", "example.com"], expected_action: "submit_form" });
    for (const bad of [[], "www.example.com", ["WWW.example.com"], [""], ["a b"], ["https://x.example"], ["x.example:443"], [1]]) {
      expect(() => recaptcha.validate({ expected_hostnames: bad }), JSON.stringify(bad)).toThrow(/expected_hostnames/);
    }
    for (const bad of ["", 1, null, "has space", "x".repeat(101)]) {
      expect(() => recaptcha.validate({ expected_action: bad }), JSON.stringify(bad)).toThrow(/expected_action/);
    }
  });

  it("validate (F9): max_body_bytes is a positive integer", () => {
    expect(recaptcha.validate({ max_body_bytes: 10 })).toEqual({ max_body_bytes: 10 });
    for (const bad of [0, -1, 1.5, "10", NaN, Infinity, null]) {
      expect(() => recaptcha.validate({ max_body_bytes: bad }), String(bad)).toThrow(/max_body_bytes/);
    }
  });
});

describe("recaptcha siteverify expectations (F8)", () => {
  const tok = () => post("g-recaptcha-response=t");
  it("expected_hostnames: a matching hostname (case-insensitive) passes; another or a missing one is 400", async () => {
    const opts = recaptcha.validate({ expected_hostnames: ["www.example.com"] });
    await expect(recaptcha.beforeForward(ctxFor(tok(), { result: { success: true, score: 0.9, hostname: "WWW.example.com" } }), opts)).resolves.toBeUndefined();
    for (const result of [{ success: true, score: 0.9, hostname: "evil.example" }, { success: true, score: 0.9 }]) {
      const ctx = ctxFor(tok(), { result });
      await expect(recaptcha.beforeForward(ctx, opts)).rejects.toMatchObject({ status: 400, code: "recaptcha_failed" });
      expect(ctx.recorded.forwardHeaders.has("x-recaptcha-score")).toBe(false);
      expect(ctx.recorded.logs.some((l) => l.fields && l.fields.reason === "hostname_mismatch")).toBe(true);
      expect(JSON.stringify(ctx.recorded.logs)).not.toContain("evil.example");
    }
  });

  it("expected_action: must equal the siteverify action", async () => {
    const opts = recaptcha.validate({ expected_action: "contact" });
    await expect(recaptcha.beforeForward(ctxFor(tok(), { result: { success: true, score: 0.9, action: "contact" } }), opts)).resolves.toBeUndefined();
    for (const result of [{ success: true, score: 0.9, action: "login" }, { success: true, score: 0.9 }]) {
      await expect(recaptcha.beforeForward(ctxFor(tok(), { result }), opts)).rejects.toMatchObject({ status: 400, code: "recaptcha_failed" });
    }
  });

  it("v2 compatibility: with no expectations configured, a result without score or action still passes", async () => {
    await expect(recaptcha.beforeForward(ctxFor(tok(), { result: { success: true, hostname: "any.example" } }), {})).resolves.toBeUndefined();
  });
});

describe("recaptcha body cap (F9)", () => {
  it("a Content-Length over max_body_bytes is 413 payload_too_large with no siteverify call", async () => {
    const req = post("g-recaptcha-response=t", { "content-type": FORM_CT, "content-length": "2000000" });
    const ctx = ctxFor(req);
    const err = await recaptcha.beforeForward(ctx, {}).catch((e) => e);
    expect(err).toBeInstanceOf(PluginError);
    expect([err.status, err.code]).toEqual([413, "payload_too_large"]);
    expect(ctx.recorded.fetches).toHaveLength(0);
  });

  it("the default cap is 1 MiB", async () => {
    const over = ctxFor(post("g-recaptcha-response=t", { "content-type": FORM_CT, "content-length": String(1048576 + 1) }));
    await expect(recaptcha.beforeForward(over, {})).rejects.toMatchObject({ status: 413, code: "payload_too_large" });
  });

  it("a streamed body with no Content-Length is capped while reading (413, no siteverify)", async () => {
    const chunk = new TextEncoder().encode("g-recaptcha-response=t&pad=" + "x".repeat(64));
    let pulls = 0;
    const stream = new ReadableStream({
      pull(c) { pulls += 1; if (pulls > 1000) c.close(); else c.enqueue(chunk); },
    });
    const req = new Request("https://www.example.com/form/x", { method: "POST", headers: { "content-type": FORM_CT }, body: stream, duplex: "half" });
    expect(req.headers.get("content-length")).toBeNull();
    const ctx = ctxFor(req);
    const err = await recaptcha.beforeForward(ctx, { max_body_bytes: 256 }).catch((e) => e);
    expect([err.status, err.code]).toEqual([413, "payload_too_large"]);
    expect(ctx.recorded.fetches).toHaveLength(0);
    expect(pulls).toBeLessThan(10); // stopped reading early
  });

  it("a lying (too small) Content-Length is still capped by the streaming read", async () => {
    const req = post("g-recaptcha-response=t&pad=" + "x".repeat(500), { "content-type": FORM_CT, "content-length": "10" });
    const ctx = ctxFor(req);
    await expect(recaptcha.beforeForward(ctx, { max_body_bytes: 100 })).rejects.toMatchObject({ status: 413, code: "payload_too_large" });
    expect(ctx.recorded.fetches).toHaveLength(0);
  });

  it("a body exactly at the cap passes", async () => {
    const body = "g-recaptcha-response=t";
    const ctx = ctxFor(post(body));
    await expect(recaptcha.beforeForward(ctx, { max_body_bytes: new TextEncoder().encode(body).length })).resolves.toBeUndefined();
    expect(await ctx.request.text()).toBe(body);
  });

  it("PUT (F7) is verified like POST", async () => {
    const ctx = ctxFor(new Request("https://www.example.com/form/x", { method: "PUT", headers: { "content-type": FORM_CT }, body: "g-recaptcha-response=t" }));
    await expect(recaptcha.beforeForward(ctx, {})).resolves.toBeUndefined();
    expect(ctx.recorded.fetches).toHaveLength(1);
    expect(ctx.request.method).toBe("PUT");
  });
});

describe("recaptcha beforeForward", () => {
  it("valid token: siteverify via ctx.fetch, body re-attached byte-for-byte, x-recaptcha-* forwarded", async () => {
    const body = "name=Ada&g-recaptcha-response=tok-1";
    const calls = [];
    const ctx = ctxFor(post(body), { fetch: google({ success: true, score: 0.9, hostname: "www.example.com", challenge_ts: "2024-01-01T00:00:00Z" }, calls) });
    await expect(recaptcha.beforeForward(ctx, {})).resolves.toBeUndefined();

    expect(ctx.recorded.fetches).toHaveLength(1);
    expect(ctx.recorded.fetches[0].url).toBe(SITEVERIFY_URL);
    expect(ctx.recorded.fetches[0].method).toBe("POST");
    const form = new URLSearchParams(calls[0].init.body);
    expect(form.get("response")).toBe("tok-1");
    expect(form.get("secret")).toBe("s3cret");

    expect(ctx.recorded.replacedRequest).not.toBeNull();
    expect(await ctx.request.text()).toBe(body);
    expect(Object.fromEntries(ctx.recorded.forwardHeaders)).toEqual({
      "x-recaptcha-score": "0.9",
      "x-recaptcha-hostname": "www.example.com",
      "x-recaptcha-challenge-ts": "2024-01-01T00:00:00Z",
    });
  });

  it("multipart: the token is read from its field and a binary body is preserved", async () => {
    const boundary = "B0";
    const enc = new TextEncoder();
    const head = enc.encode(`--${boundary}\r\nContent-Disposition: form-data; name="g-recaptcha-response"\r\n\r\ntok-mp\r\n--${boundary}\r\nContent-Disposition: form-data; name="f"; filename="b"\r\n\r\n`);
    const bin = new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28]);
    const tail = enc.encode(`\r\n--${boundary}--\r\n`);
    const bytes = new Uint8Array([...head, ...bin, ...tail]);
    const calls = [];
    const ctx = ctxFor(post(bytes, { "content-type": `multipart/form-data; boundary=${boundary}` }), { fetch: google({ success: true }, calls) });
    await recaptcha.beforeForward(ctx, {});
    expect(new URLSearchParams(calls[0].init.body).get("response")).toBe("tok-mp");
    expect(new Uint8Array(await ctx.request.arrayBuffer())).toEqual(bytes);
  });

  it("missing token: 400 recaptcha_failed without calling Google", async () => {
    const ctx = ctxFor(post("name=Ada"));
    const err = await recaptcha.beforeForward(ctx, {}).catch((e) => e);
    expect(err).toBeInstanceOf(PluginError);
    expect([err.status, err.code]).toEqual([400, "recaptcha_failed"]);
    expect(ctx.recorded.fetches).toHaveLength(0);
    expect(ctx.recorded.forwardHeaders.has("x-recaptcha-score")).toBe(false);
  });

  it("Google rejects the token: 400 recaptcha_failed, nothing forwarded", async () => {
    const ctx = ctxFor(post("g-recaptcha-response=bad"), { result: { success: false, "error-codes": ["invalid-input-response"] } });
    const err = await recaptcha.beforeForward(ctx, {}).catch((e) => e);
    expect([err.status, err.code]).toEqual([400, "recaptcha_failed"]);
    expect([...ctx.recorded.forwardHeaders]).toEqual([]);
    expect(ctx.recorded.logs.some((l) => l.msg === "recaptcha failed")).toBe(true);
  });

  it("v3 score below ctx.config.recaptchaMinScore fails; at the threshold passes", async () => {
    const low = ctxFor(post("g-recaptcha-response=t"), { result: { success: true, score: 0.49 } });
    await expect(recaptcha.beforeForward(low, {})).rejects.toMatchObject({ status: 400, code: "recaptcha_failed" });
    const ok = ctxFor(post("g-recaptcha-response=t"), { result: { success: true, score: 0.5 } });
    await expect(recaptcha.beforeForward(ok, {})).resolves.toBeUndefined();
  });

  it("options.min_score overrides the gate-wide recaptchaMinScore", async () => {
    const strict = ctxFor(post("g-recaptcha-response=t"), { result: { success: true, score: 0.6 } });
    await expect(recaptcha.beforeForward(strict, { min_score: 0.7 })).rejects.toMatchObject({ code: "recaptcha_failed" });
    const lax = ctxFor(post("g-recaptcha-response=t"), { result: { success: true, score: 0.2 } });
    await expect(recaptcha.beforeForward(lax, { min_score: 0.1 })).resolves.toBeUndefined();
  });

  it("no threshold configured (recaptchaMinScore null): any successful v3 score passes", async () => {
    const ctx = ctxFor(post("g-recaptcha-response=t"), { result: { success: true, score: 0.0 }, config: { recaptchaMinScore: null } });
    await expect(recaptcha.beforeForward(ctx, {})).resolves.toBeUndefined();
  });

  it("missing recaptcha_secret: 500 internal_error, logged as a misconfiguration, body untouched", async () => {
    const ctx = ctxFor(post("g-recaptcha-response=t"), { secrets: {} });
    const err = await recaptcha.beforeForward(ctx, {}).catch((e) => e);
    expect([err.status, err.code]).toEqual([500, "internal_error"]);
    expect(ctx.recorded.logs.find((l) => l.level === "error").msg).toMatch(/^misconfiguration/);
    expect(ctx.recorded.fetches).toHaveLength(0);
    expect(ctx.request.bodyUsed).toBe(false);
  });

  it("siteverify unreachable or non-OK: fails closed with 400", async () => {
    const down = ctxFor(post("g-recaptcha-response=t"), { fetch: async () => { throw new TypeError("fetch failed"); } });
    await expect(recaptcha.beforeForward(down, {})).rejects.toMatchObject({ code: "recaptcha_failed" });
    const err500 = ctxFor(post("g-recaptcha-response=t"), { fetch: async () => new Response("x", { status: 500 }) });
    await expect(recaptcha.beforeForward(err500, {})).rejects.toMatchObject({ code: "recaptcha_failed" });
  });

  it("a fetch-policy violation propagates (never a silent 400)", async () => {
    const ctx = ctxFor(post("g-recaptcha-response=t"), { fetch: async () => { throw new PluginError(503, "budget_exceeded"); } });
    await expect(recaptcha.beforeForward(ctx, {})).rejects.toMatchObject({ status: 503, code: "budget_exceeded" });
  });
});
