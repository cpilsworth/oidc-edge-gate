// The admin revocation route (docs/architecture/plugins.md §15.5): every
// status in the specified order, the signature over raw bytes, the KV writes
// and the log hygiene.
import { describe, it, expect } from "vitest";
import { utf8 } from "../../../src/sdk/encoding.js";
import { signAdminBody } from "../lib/admin-signature.js";
import { handleAdminRevoke, jtiKey } from "../lib/admin.js";
import { subKey } from "../lib/revocation-store.js";
import { settingsFor } from "../lib/settings.js";
import { createTestContext } from "../../../src/sdk/testing.js";
import { CONFIG, OPTIONS, SECRETS, SITE, oidcAuth, routeFor } from "./support.js";

const PATH = "/.auth/admin/revoke";
const ADMIN_KEY = "admin-route-test-key-at-least-32-bytes-long!";
const AUD = CONFIG.forwardedHost;
const SID = "Q2hlY2tTaWQxMjM0NTY3OA";
const SUB = "auth0|secret-subject-4242";
const TTL = CONFIG.sessionTtlSeconds;
const PROVISIONED = { profile: "provisioned" };

let jtiSeq = 0;
const freshJti = () => `jti-${String(++jtiSeq).padStart(4, "0")}-abcdefghijklmnop`;
const nowS = () => Math.floor(Date.now() / 1000);

function sessionBody(over = {}) {
  return { v: 1, aud: AUD, iat: nowS(), jti: freshJti(), scope: "session", sid: SID, ...over };
}
function userBody(over = {}) {
  return { v: 1, aud: AUD, iat: nowS(), jti: freshJti(), scope: "user", sub: SUB, ...over };
}

/**
 * Build a ctx for one admin request. `body` is an object (JSON-encoded), a
 * string or bytes; `sign` signs those exact bytes unless `authorization` is given.
 */
async function adminCtx({
  method = "POST", body = sessionBody(), sign = true, key = ADMIN_KEY, authorization, headers = {},
  contentType = "application/json", platform = PROVISIONED, kv = true, secrets, config = CONFIG, stream,
} = {}) {
  const raw = typeof body === "string" || body instanceof Uint8Array ? body : JSON.stringify(body);
  const h = new Headers(headers);
  if (contentType !== null) h.set("content-type", contentType);
  if (authorization !== undefined) {
    if (authorization !== null) h.set("authorization", authorization);
  } else if (sign) {
    h.set("authorization", await signAdminBody(key, raw));
  }
  const hasBody = method !== "GET" && method !== "HEAD";
  return createTestContext({
    plugin: oidcAuth,
    request: new Request(`${SITE}${PATH}`, { method, headers: h, ...(hasBody ? { body: stream ?? raw, duplex: "half" } : {}) }),
    options: OPTIONS,
    config,
    secrets: secrets ?? { ...SECRETS, revocation_admin_key: ADMIN_KEY },
    kv,
    platform,
  });
}

async function call(opts, deps) {
  const ctx = await adminCtx(opts);
  const res = deps
    ? await handleAdminRevoke(ctx, settingsFor(ctx, OPTIONS), deps)
    : await routeFor(PATH)(ctx, OPTIONS);
  let json = null;
  try { json = await res.clone().json(); } catch { /* not JSON */ }
  return { ctx, res, json };
}

/** Replace ctx.kv with a wrapper whose methods can be overridden. */
function patchKv(ctx, over) {
  const base = ctx.kv;
  Object.defineProperty(ctx, "kv", { value: Object.freeze({ get: (k) => base.get(k), put: (k, v, o) => base.put(k, v, o), delete: (k) => base.delete(k), ...over }) });
  return ctx;
}

const revKeys = (ctx) => (ctx.recorded.kv ? [...ctx.recorded.kv.keys()].filter((k) => k.startsWith("rev:")) : []);

function expectError(r, status, error) {
  expect(r.res.status).toBe(status);
  expect(r.json).toEqual({ error });
  expect(r.res.headers.get("x-auth-request-id")).toBe("test-request-id");
  expect(r.res.headers.get("cache-control")).toBe("private, no-store");
}

/** A request body stream that records whether it was read. */
function trackedStream(bytes) {
  const state = { pulled: 0 };
  const stream = new ReadableStream({
    pull(c) {
      state.pulled += 1;
      c.enqueue(bytes);
      c.close();
    },
  }, { highWaterMark: 0 }); // no eager pull: only a reader pulls
  return { stream, state };
}

describe("1. availability → 404 for every method, before the body is read", () => {
  it.each([
    ["sandbox, even with a key and KV", { platform: { profile: "sandbox" } }],
    ["revocation_mode disabled", { config: { ...CONFIG, revocationMode: "disabled" } }],
    ["no revocation_admin_key", { secrets: SECRETS }],
    ["an empty revocation_admin_key", { secrets: { ...SECRETS, revocation_admin_key: "" } }],
  ])("%s", async (_label, opts) => {
    for (const method of ["POST", "GET", "PUT", "DELETE"]) {
      const r = await call({ method, ...opts });
      expectError(r, 404, "not_found");
      expect(r.ctx.request.bodyUsed).toBe(false);
      expect(revKeys(r.ctx)).toEqual([]);
    }
  });

  it("the body stream is never pulled", async () => {
    const { stream, state } = trackedStream(utf8(JSON.stringify(sessionBody())));
    const r = await call({ platform: { profile: "sandbox" }, stream, authorization: null });
    expectError(r, 404, "not_found");
    expect(state.pulled).toBe(0);
  });

  it("sandbox with explicit revocation_mode required is still 404", async () => {
    const r = await call({ platform: { profile: "sandbox" }, config: { ...CONFIG, revocationMode: "required" } });
    expectError(r, 404, "not_found");
  });

  it("provisioned with revocation_mode optional is available", async () => {
    const r = await call({ config: { ...CONFIG, revocationMode: "optional" } });
    expect(r.res.status).toBe(200);
  });

  it("404 precedes 405 and the KV check", async () => {
    expectError(await call({ method: "GET", platform: { profile: "sandbox" } }), 404, "not_found");
    expectError(await call({ kv: null, secrets: SECRETS }), 404, "not_found");
  });
});

describe("2. method → 405", () => {
  it.each(["GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"])("%s → 405 with Allow: POST", async (method) => {
    const r = await call({ method });
    expect(r.res.status).toBe(405);
    expect(r.res.headers.get("allow")).toBe("POST");
    expect(r.res.headers.get("x-auth-request-id")).toBe("test-request-id");
    if (method !== "HEAD") expect(r.json).toEqual({ error: "method_not_allowed" });
  });

  it("405 precedes 415", async () => {
    const r = await call({ method: "PUT", contentType: "text/plain" });
    expect(r.res.status).toBe(405);
  });
});

describe("3. media type → 415", () => {
  it.each([[null], ["text/plain"], ["application/jsonx"], ["application/x-www-form-urlencoded"], ["multipart/form-data"], ["application/json-patch+json"]])(
    "content-type %s → 415", async (contentType) => {
      expectError(await call({ contentType }), 415, "unsupported_media_type");
    },
  );

  it.each([["application/json; charset=utf-8"], ["Application/JSON"], [" application/json ;charset=UTF-8"]])("content-type %s is accepted", async (contentType) => {
    expect((await call({ contentType })).res.status).toBe(200);
  });

  it("415 precedes 413", async () => {
    expectError(await call({ contentType: "text/plain", body: "x".repeat(5000) }), 415, "unsupported_media_type");
  });
});

describe("4. size → 413", () => {
  it("a declared content-length over 4096 → 413 without reading the body", async () => {
    const { stream, state } = trackedStream(utf8("{}"));
    const r = await call({ stream, headers: { "content-length": "4097" } });
    expectError(r, 413, "payload_too_large");
    expect(state.pulled).toBe(0);
  });

  it("an oversize body without content-length → 413 (capped stream read)", async () => {
    let pulled = 0;
    const stream = new ReadableStream({
      pull(c) {
        pulled += 1;
        if (pulled > 100) { c.close(); return; }
        c.enqueue(new Uint8Array(1024).fill(0x20));
      },
    });
    const r = await call({ stream, authorization: null });
    expectError(r, 413, "payload_too_large");
    expect(pulled).toBeLessThanOrEqual(6); // stops right after passing 4096 bytes
  });

  it("a lying (small) content-length does not lift the cap", async () => {
    const big = JSON.stringify({ ...sessionBody(), reason: "x".repeat(4100) });
    expectError(await call({ body: big, headers: { "content-length": "10" } }), 413, "payload_too_large");
  });

  it("exactly 4096 bytes is accepted by the size check", async () => {
    const base = JSON.stringify(sessionBody());
    const padded = base.slice(0, -1) + " ".repeat(4096 - base.length) + "}";
    expect(utf8(padded).length).toBe(4096);
    expect((await call({ body: padded })).res.status).toBe(200);
  });

  it("a malformed content-length → 400", async () => {
    expectError(await call({ headers: { "content-length": "12abc" } }), 400, "bad_request");
  });

  it("413 precedes 401", async () => {
    expectError(await call({ body: "x".repeat(5000), authorization: "Bearer nope" }), 413, "payload_too_large");
  });
});

describe("5. signature → 401", () => {
  it.each([
    ["no authorization header", null],
    ["another scheme", "Bearer abc"],
    ["lowercase scheme", async (raw) => (await signAdminBody(ADMIN_KEY, raw)).replace("Gate-Revoke-HMAC-SHA256", "gate-revoke-hmac-sha256")],
    ["padded base64url", async (raw) => `${await signAdminBody(ADMIN_KEY, raw)}=`],
    ["a 31-byte tag", async (raw) => (await signAdminBody(ADMIN_KEY, raw)).slice(0, -2)],
    ["a signature with another key", (raw) => signAdminBody("a-different-admin-key-of-32-bytes-or-more!", raw)],
    ["the session HMAC key", (raw) => signAdminBody(SECRETS.session_hmac_key, raw)],
  ])("%s → 401", async (_label, auth) => {
    const body = sessionBody();
    const raw = JSON.stringify(body);
    const authorization = typeof auth === "function" ? await auth(raw) : auth;
    const r = await call({ body: raw, authorization });
    expectError(r, 401, "unauthorized");
    expect(r.res.headers.get("www-authenticate")).toBe("Gate-Revoke-HMAC-SHA256");
    expect(revKeys(r.ctx)).toEqual([]);
  });

  it("the signature covers the exact raw bytes: a whitespace change → 401", async () => {
    const raw = JSON.stringify(sessionBody());
    const authorization = await signAdminBody(ADMIN_KEY, raw);
    expectError(await call({ body: raw.replace('"v":1', '"v": 1'), authorization }), 401, "unauthorized");
    expectError(await call({ body: `${raw}\n`, authorization }), 401, "unauthorized");
    expect((await call({ body: raw, authorization })).res.status).toBe(200);
  });

  it("a pretty-printed body signed as sent is accepted (no canonicalization)", async () => {
    expect((await call({ body: JSON.stringify(sessionBody(), null, 2) })).res.status).toBe(200);
  });

  it("a tampered body → 401", async () => {
    const raw = JSON.stringify(sessionBody());
    const authorization = await signAdminBody(ADMIN_KEY, raw);
    const tampered = raw.replace(SID, "Q2hlY2tTaWQxMjM0NTY3OQ");
    const r = await call({ body: tampered, authorization });
    expectError(r, 401, "unauthorized");
    expect(revKeys(r.ctx)).toEqual([]);
  });

  it("401 precedes 400: a bad signature over bad JSON is 401", async () => {
    expectError(await call({ body: "not json", authorization: "Gate-Revoke-HMAC-SHA256 " + "A".repeat(43) }), 401, "unauthorized");
    expectError(await call({ body: { ...sessionBody(), extra: 1 }, authorization: null }), 401, "unauthorized");
  });

  it("401 precedes the no-KV 503", async () => {
    expectError(await call({ kv: null, authorization: null }), 401, "unauthorized");
  });
});

describe("6. strict JSON shape → 400", () => {
  it.each([
    ["not JSON", "{"],
    ["a JSON array", "[]"],
    ["a JSON string", '"x"'],
    ["null", "null"],
    ["invalid UTF-8", new Uint8Array([0x7b, 0xff, 0x7d])],
    ["an unknown key", () => ({ ...sessionBody(), extra: true })],
    ["both sid and sub", () => ({ ...sessionBody(), sub: SUB })],
    ["user scope with a sid", () => ({ ...userBody(), sid: SID })],
    ["session scope without sid", () => { const b = sessionBody(); delete b.sid; return b; }],
    ["user scope without sub", () => { const b = userBody(); delete b.sub; return b; }],
    ["session scope with a sub instead", () => { const b = sessionBody({ sub: SUB }); delete b.sid; return b; }],
    ["v 2", () => sessionBody({ v: 2 })],
    ["v \"1\"", () => sessionBody({ v: "1" })],
    ["no v", () => { const b = sessionBody(); delete b.v; return b; }],
    ["an unknown scope", () => sessionBody({ scope: "everyone" })],
    ["an invalid sid", () => sessionBody({ sid: "too-short" })],
    ["an empty sub", () => userBody({ sub: "" })],
    ["a sub over 1024 bytes", () => userBody({ sub: "x".repeat(1025) })],
    ["a short jti", () => sessionBody({ jti: "abc" })],
    ["a jti with bad characters", () => sessionBody({ jti: "a".repeat(21) + "!" })],
    ["a 65-char jti", () => sessionBody({ jti: "a".repeat(65) })],
    ["no jti", () => { const b = sessionBody(); delete b.jti; return b; }],
    ["a string iat", () => sessionBody({ iat: String(nowS()) })],
    ["a fractional iat", () => sessionBody({ iat: nowS() + 0.5 })],
    ["a non-string aud", () => sessionBody({ aud: 1 })],
    ["a non-ASCII reason", () => sessionBody({ reason: "café" })],
    ["a reason with a newline", () => sessionBody({ reason: "a\nb" })],
    ["a 201-char reason", () => sessionBody({ reason: "x".repeat(201) })],
    ["a non-string reason", () => sessionBody({ reason: 5 })],
  ])("%s → 400", async (_label, body) => {
    const r = await call({ body: typeof body === "function" ? body() : body });
    expectError(r, 400, "bad_request");
    expect(revKeys(r.ctx)).toEqual([]);
  });

  it("a 200-char reason and an empty reason are accepted", async () => {
    expect((await call({ body: sessionBody({ reason: "x".repeat(200) }) })).res.status).toBe(200);
    expect((await call({ body: sessionBody({ reason: "" }) })).res.status).toBe(200);
  });

  it("400 precedes the aud/iat 401", async () => {
    expectError(await call({ body: sessionBody({ aud: "elsewhere.example", extra: 1 }) }), 400, "bad_request");
  });
});

describe("7. aud and iat → 401", () => {
  it("aud mismatch → 401", async () => {
    const r = await call({ body: sessionBody({ aud: "staging.example.com" }) });
    expectError(r, 401, "unauthorized");
    expect(revKeys(r.ctx)).toEqual([]);
  });

  it("aud is compared exactly (case, port)", async () => {
    expectError(await call({ body: sessionBody({ aud: AUD.toUpperCase() }) }), 401, "unauthorized");
    expectError(await call({ body: sessionBody({ aud: `${AUD}:443` }) }), 401, "unauthorized");
  });

  it("iat skew: ±300 s accepted, ±301 s rejected", async () => {
    const now = 1_800_000_000;
    const deps = { nowMs: () => now * 1000 };
    expect((await call({ body: sessionBody({ iat: now - 300 }) }, deps)).res.status).toBe(200);
    expect((await call({ body: sessionBody({ iat: now + 300 }) }, deps)).res.status).toBe(200);
    expectError(await call({ body: sessionBody({ iat: now - 301 }) }, deps), 401, "unauthorized");
    expectError(await call({ body: sessionBody({ iat: now + 301 }) }, deps), 401, "unauthorized");
  });

  it("aud/iat 401 precedes the no-KV 503", async () => {
    expectError(await call({ kv: null, body: sessionBody({ aud: "x.example" }) }), 401, "unauthorized");
  });
});

describe("8. available but no KV → 503", () => {
  it("a valid request on provisioned without KV → 503 revocation_unavailable", async () => {
    expectError(await call({ kv: null }), 503, "revocation_unavailable");
  });
});

describe("9. single-use jti → 409", () => {
  it("the same signed request twice → 200 then 409; the marker has TTL 600", async () => {
    const raw = JSON.stringify(sessionBody());
    const authorization = await signAdminBody(ADMIN_KEY, raw);
    const ctx1 = await adminCtx({ body: raw, authorization });
    const puts = [];
    patchKv(ctx1, { put: (k, v, o) => { puts.push([k, o]); return ctx1.recorded.kv.set(k, v); } });
    expect((await routeFor(PATH)(ctx1, OPTIONS)).status).toBe(200);
    const jti = JSON.parse(raw).jti;
    expect(puts[0]).toEqual([jtiKey(jti), { ttl: 600 }]);
    expect(jtiKey(jti)).toBe(`admin:jti:${jti}`);

    const ctx2 = await adminCtx({ body: raw, authorization, kv: Object.fromEntries(ctx1.recorded.kv) });
    const res2 = await routeFor(PATH)(ctx2, OPTIONS);
    expect(res2.status).toBe(409);
    expect(await res2.json()).toEqual({ error: "replayed" });
    expect(res2.headers.get("x-auth-request-id")).toBe("test-request-id");
  });

  it("an expired marker no longer blocks", async () => {
    const body = sessionBody();
    const kv = { [jtiKey(body.jti)]: JSON.stringify({ value: { at: 1 }, expires: Date.now() - 1 }) };
    expect((await call({ body, kv })).res.status).toBe(200);
  });

  it("a KV error on the marker → 503 kv_write_failed, nothing written", async () => {
    const ctx = await adminCtx();
    patchKv(ctx, { get: async () => { throw new Error("kv down"); } });
    const res = await routeFor(PATH)(ctx, OPTIONS);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "kv_write_failed" });
    expect(revKeys(ctx)).toEqual([]);
  });
});

describe("10. the record write", () => {
  it("a KV write failure → 503 kv_write_failed; the marker is released so the same request can be retried", async () => {
    const raw = JSON.stringify(sessionBody());
    const authorization = await signAdminBody(ADMIN_KEY, raw);
    const ctx = await adminCtx({ body: raw, authorization });
    patchKv(ctx, {
      put: async (k, v) => {
        if (k.startsWith("rev:")) { const e = new Error(`rate limited ${k}`); e.name = "KvRateLimitError"; throw e; }
        ctx.recorded.kv.set(k, v);
      },
    });
    const res = await routeFor(PATH)(ctx, OPTIONS);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "kv_write_failed" });
    expect(res.headers.get("x-auth-request-id")).toBe("test-request-id");
    expect([...ctx.recorded.kv.keys()]).toEqual([]);
    expect(ctx.recorded.logs).toContainEqual({
      level: "error", msg: "oidc admin revoke rejected",
      fields: { outcome: "rejected", status: 503, reason: "kv_write_failed", error: "KvRateLimitError" },
    });

    const retry = await adminCtx({ body: raw, authorization, kv: Object.fromEntries(ctx.recorded.kv) });
    expect((await routeFor(PATH)(retry, OPTIONS)).status).toBe(200);
  });
});

describe("success", () => {
  it("scope session → 200 {revoked: session, propagation_seconds: 60} and the rev:sid record (TTL ttl+120)", async () => {
    const r = await call({ body: sessionBody({ reason: "stolen laptop" }) });
    expect(r.res.status).toBe(200);
    expect(r.json).toEqual({ revoked: "session", propagation_seconds: 60 });
    expect(r.res.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(r.res.headers.get("cache-control")).toBe("private, no-store");
    expect(r.res.headers.get("x-auth-request-id")).toBe("test-request-id");
    const rec = JSON.parse(r.ctx.recorded.kv.get(`rev:sid:${SID}`));
    expect(rec.value).toEqual({ at: expect.any(Number) });
    expect(rec.expires - Date.now()).toBeGreaterThan((TTL + 120 - 5) * 1000);
  });

  it("scope user → 200 with revoked_at and the hashed rev:sub record", async () => {
    const now = 1_800_000_000;
    const r = await call({ body: userBody({ iat: now }) }, { nowMs: () => now * 1000 });
    expect(r.res.status).toBe(200);
    expect(r.json).toEqual({ revoked: "user", revoked_at: now, propagation_seconds: 60 });
    const key = await subKey(SUB);
    expect(key).toMatch(/^rev:sub:[0-9a-f]{64}$/);
    expect(JSON.parse(r.ctx.recorded.kv.get(key)).value).toEqual({ revoked_at: now });
    expect([...r.ctx.recorded.kv.keys()].some((k) => k.includes(SUB))).toBe(false);
  });

  it("scope user is monotonic: an existing later revoked_at is kept and returned", async () => {
    const now = 1_800_000_000;
    const key = await subKey(SUB);
    const later = now + 100;
    const kv = { [key]: JSON.stringify({ value: { revoked_at: later }, expires: (now + 3600) * 1000 }) };
    const r = await call({ body: userBody({ iat: now }), kv }, { nowMs: () => now * 1000 });
    expect(r.json).toEqual({ revoked: "user", revoked_at: later, propagation_seconds: 60 });
    expect(JSON.parse(r.ctx.recorded.kv.get(key)).value).toEqual({ revoked_at: later });
  });

  it("scope user moves an older epoch forward", async () => {
    const now = 1_800_000_000;
    const key = await subKey(SUB);
    const kv = { [key]: JSON.stringify({ value: { revoked_at: now - 500 }, expires: (now + 3600) * 1000 }) };
    const r = await call({ body: userBody({ iat: now }), kv }, { nowMs: () => now * 1000 });
    expect(r.json.revoked_at).toBe(now);
  });

  it("logs outcome, scope, jti and reason on success", async () => {
    const body = sessionBody({ reason: "offboarding ticket 42" });
    const r = await call({ body });
    expect(r.ctx.recorded.logs).toContainEqual({
      level: "info", msg: "oidc admin revoke",
      fields: { outcome: "revoked", scope: "session", jti: body.jti, reason: "offboarding ticket 42" },
    });
  });
});

describe("log hygiene: never the key, the signature, the body, the sub or the sid", () => {
  it("across successes and every failure class", async () => {
    const logs = [];
    const raws = [];
    const sigs = [];
    const scenarios = [
      { body: sessionBody({ reason: "r" }) },
      { body: userBody() },
      { body: sessionBody(), platform: { profile: "sandbox" } },
      { body: sessionBody(), method: "GET" },
      { body: sessionBody(), contentType: "text/plain" },
      { body: { ...sessionBody(), reason: "x".repeat(4100) } },
      { body: userBody(), authorization: "Gate-Revoke-HMAC-SHA256 " + "B".repeat(43) },
      { body: { ...userBody(), extra: SUB } },
      { body: userBody({ aud: "other.example" }) },
      { body: userBody({ iat: nowS() - 1000 }) },
      { body: userBody(), kv: null },
    ];
    for (const s of scenarios) {
      const raw = JSON.stringify(s.body);
      raws.push(raw);
      if (s.authorization === undefined) sigs.push((await signAdminBody(ADMIN_KEY, raw)).split(" ")[1]);
      const r = await call({ ...s, body: raw });
      logs.push(...r.ctx.recorded.logs);
    }
    // A replay and a KV write failure.
    const raw = JSON.stringify(userBody());
    const authorization = await signAdminBody(ADMIN_KEY, raw);
    const first = await call({ body: raw, authorization });
    logs.push(...first.ctx.recorded.logs);
    const replay = await call({ body: raw, authorization, kv: Object.fromEntries(first.ctx.recorded.kv) });
    expect(replay.res.status).toBe(409);
    logs.push(...replay.ctx.recorded.logs);
    const failing = patchKv(await adminCtx({ body: userBody() }), { put: async () => { throw new Error(`boom ${SUB}`); } });
    expect((await routeFor(PATH)(failing, OPTIONS)).status).toBe(503);
    logs.push(...failing.recorded.logs);

    expect(logs.length).toBeGreaterThan(10);
    const text = JSON.stringify(logs);
    for (const secret of [ADMIN_KEY, SUB, SID, "Gate-Revoke-HMAC-SHA256", ...sigs, ...raws, authorization]) {
      expect(text).not.toContain(secret);
    }
    for (const l of logs.filter((x) => x.msg === "oidc admin revoke rejected")) {
      expect(Object.keys(l.fields).sort()).toEqual(expect.arrayContaining(["outcome", "reason", "status"]));
      expect(Object.keys(l.fields).every((k) => ["outcome", "reason", "status", "error"].includes(k))).toBe(true);
    }
  });
});
