// user-info hooks (onLogin, beforeForward, handle) through createTestContext
// with fake backends: groups at login, fail/degrade per failure kind, profile
// allowlisting, header exposure and sanitization, the KV profile cache per
// platform profile, and log hygiene (no credentials, URLs or bodies).
import { describe, it, expect } from "vitest";
import { PluginError, createIdentity, createIdentityDraft } from "../../../src/sdk/index.js";
import { createTestContext } from "../../../src/sdk/testing.js";
import userInfo from "../index.js";
import { MAX_HEADER_VALUE, headerValue, pickProfile, profileCacheKey, sha256Hex } from "../lib/profile.js";

const USER = "svc-user";
const PASS = "pw-SECRET-1";
const SECRETS = { user_info_username: USER, user_info_password: PASS };
const BASIC = `Basic ${btoa(`${USER}:${PASS}`)}`;
const SUB = "auth0|abc/def?x#y";
const ENC_SUB = encodeURIComponent(SUB);
const BODY_MARKER = "BODY-MARKER-do-not-log";

const options = (extra = {}) => userInfo.validate({ endpoint: "https://users.example.com/v1/users/{sub}", ...extra });

const draftFor = (extra = {}) => createIdentityDraft({ sub: SUB, email: "u@example.com", name: "U Ser", groups: ["site-readers"], ...extra });
const identityFor = (extra = {}) => createIdentity({
  sub: SUB, email: "u@example.com", name: "U Ser", groups: ["site-readers", "medical"], method: "oidc-session",
  issuedAt: 1000, expiresAt: 4600, ...extra,
});

/** A fake backend: a fixed Response factory or a function of the Request. */
function backend(respond) {
  const seen = [];
  const fn = async (input, init) => {
    const req = new Request(input, init);
    seen.push({ url: req.url, authorization: req.headers.get("authorization"), accept: req.headers.get("accept"), method: req.method });
    return typeof respond === "function" ? respond(req) : respond.clone();
  };
  fn.seen = seen;
  return fn;
}

function ctxFor({ opts = options(), identity = null, fetch = backend(Response.json({ groups: [] })), secrets = SECRETS, kv = null, profile = "sandbox", request } = {}) {
  return createTestContext({ plugin: userInfo, options: opts, identity, secrets, kv, fetch, platform: { profile }, request, tier: identity ? "protected" : "public" });
}

/** Everything logged, as one string, must not leak credentials, the URL or the body. */
function expectCleanLogs(ctx) {
  const text = JSON.stringify(ctx.recorded.logs);
  for (const needle of [USER, PASS, BASIC, btoa(`${USER}:${PASS}`), "Basic", BODY_MARKER, ENC_SUB, SUB, "users.example.com/v1", "u@example.com"]) {
    expect(text, `log leaks ${needle}`).not.toContain(needle);
  }
}

const FAILURES = {
  network_error: () => { throw new TypeError(`fetch failed ${BODY_MARKER}`); },
  http_status: () => new Response(BODY_MARKER, { status: 503 }),
  http_status_4xx: () => new Response(BODY_MARKER, { status: 404 }),
  bad_json: () => new Response(`<html>${BODY_MARKER}</html>`, { status: 200 }),
  groups_missing: () => Response.json({ roles: ["medical"], note: BODY_MARKER }),
  groups_not_array: () => Response.json({ groups: "medical", note: BODY_MARKER }),
  groups_object: () => Response.json({ groups: { medical: true }, note: BODY_MARKER }),
  body_not_object: () => Response.json([BODY_MARKER]),
};
const REASON = {
  network_error: "network_error", http_status: "http_status", http_status_4xx: "http_status", bad_json: "bad_json",
  groups_missing: "groups_missing", groups_not_array: "groups_not_array", groups_object: "groups_not_array", body_not_object: "groups_missing",
};

describe("onLogin: groups from the backend", () => {
  it("GETs the expanded endpoint with Basic credentials and adds the groups", async () => {
    const fetch = backend(Response.json({ groups: ["medical", "market-access"] }));
    const ctx = ctxFor({ fetch });
    const draft = draftFor();
    await userInfo.onLogin(ctx, draft, ctx.options);
    expect(draft.groups).toEqual(["site-readers", "medical", "market-access"]);
    expect(draft.lifetimeCap).toBeNull();
    expect(fetch.seen).toEqual([{
      url: `https://users.example.com/v1/users/${ENC_SUB}`, authorization: BASIC, accept: "application/json", method: "GET",
    }]);
    expect(ctx.recorded.fetches[0].opts).toEqual({ purpose: "user-info-groups" }); // cache stays "pass"
    expectCleanLogs(ctx);
  });

  it("reads a nested groups_path and normalizes (drops non-strings, ',' and control characters, duplicates)", async () => {
    const fetch = backend(Response.json({ data: { groups: ["medical", "a,admin", "x\ny", "", 5, null, { g: 1 }, "medical", "ok\u0085", "market-access"] } }));
    const ctx = ctxFor({ fetch, opts: options({ groups_path: "data.groups" }) });
    const draft = draftFor({ groups: [] });
    await userInfo.onLogin(ctx, draft, ctx.options);
    expect(draft.groups).toEqual(["medical", "market-access"]);
  });

  it("an empty array is a success with no groups (not a failure)", async () => {
    const ctx = ctxFor({ fetch: backend(Response.json({ groups: [] })) });
    const draft = draftFor({ groups: [] });
    await userInfo.onLogin(ctx, draft, ctx.options);
    expect(draft.groups).toEqual([]);
    expect(draft.lifetimeCap).toBeNull();
    expect(ctx.recorded.logs).toEqual([]);
  });

  it("R1: {email} templates fail validate(); the lookup is by the verified sub only", async () => {
    expect(() => options({ endpoint: "https://users.example.com/lookup?mail={email}" })).toThrow(/verified \{sub\} only/);
    const fetch = backend(Response.json({ groups: ["g"] }));
    const ctx = ctxFor({ fetch });
    await userInfo.onLogin(ctx, draftFor({ email: "victim@example.com" }), ctx.options);
    expect(fetch.seen[0].url).toBe(`https://users.example.com/v1/users/${ENC_SUB}`);
  });

  describe("on_login_error: \"fail\" (default) → PluginError 503 user_info_unavailable, no groups", () => {
    for (const [kind, respond] of Object.entries(FAILURES)) {
      it(kind, async () => {
        const ctx = ctxFor({ fetch: backend(respond) });
        const draft = draftFor();
        const err = await userInfo.onLogin(ctx, draft, ctx.options).then(() => null, (e) => e);
        expect(err).toBeInstanceOf(PluginError);
        expect(err.status).toBe(503);
        expect(err.code).toBe("user_info_unavailable");
        expect(draft.groups).toEqual(["site-readers"]);
        expect(draft.lifetimeCap).toBeNull();
        const warn = ctx.recorded.logs.find((l) => l.level === "warn");
        expect(warn.fields.reason).toBe(REASON[kind]);
        expect(warn.fields.purpose).toBe("user-info-groups");
        expectCleanLogs(ctx);
      });
    }

    it("bad_url: an {email} template that bypassed validate() is never expanded (no fetch)", async () => {
      const fetch = backend(Response.json({ groups: ["g"] }));
      const opts = Object.freeze({ ...options(), endpoint: "https://users.example.com/lookup?mail={email}" });
      const ctx = ctxFor({ fetch, opts });
      const err = await userInfo.onLogin(ctx, draftFor(), ctx.options).then(() => null, (e) => e);
      expect(err).toMatchObject({ status: 503, code: "user_info_unavailable" });
      expect(fetch.seen).toEqual([]);
      expect(ctx.recorded.logs[0].fields.reason).toBe("bad_url");
    });
  });

  it("W2.R R4: more than 256 backend groups with \"fail\" → 503 user_info_unavailable; exactly 256 is accepted", async () => {
    const tooMany = Array.from({ length: 257 }, (_, i) => `g${i}`);
    const ctx = ctxFor({ fetch: backend(Response.json({ groups: tooMany })) });
    const draft = draftFor();
    const err = await userInfo.onLogin(ctx, draft, ctx.options).then(() => null, (e) => e);
    expect(err).toMatchObject({ status: 503, code: "user_info_unavailable" });
    expect(draft.groups).toEqual(["site-readers"]);
    expect(ctx.recorded.logs[0].fields.reason).toBe("too_many_groups");
    // The cap counts raw entries, before normalizing: 257 entries of junk still fail.
    const junk = ctxFor({ fetch: backend(Response.json({ groups: Array(257).fill(null) })) });
    await expect(userInfo.onLogin(junk, draftFor(), junk.options)).rejects.toMatchObject({ code: "user_info_unavailable" });
    const ok = ctxFor({ fetch: backend(Response.json({ groups: tooMany.slice(0, 256) })) });
    const d2 = draftFor({ groups: [] });
    await userInfo.onLogin(ok, d2, ok.options);
    expect(d2.groups).toHaveLength(256);
  });

  describe("on_login_error: \"degrade\" → warn, lifetime capped at degrade_ttl_seconds, no groups added", () => {
    for (const [kind, respond] of Object.entries(FAILURES)) {
      it(kind, async () => {
        const ctx = ctxFor({ fetch: backend(respond), opts: options({ on_login_error: "degrade", degrade_ttl_seconds: 120 }) });
        const draft = draftFor();
        await userInfo.onLogin(ctx, draft, ctx.options);
        expect(draft.groups).toEqual(["site-readers"]);
        expect(draft.lifetimeCap).toBe(120);
        const identity = draft.toIdentity({ method: "oidc-session", issuedAt: 1000, expiresAt: 4600 });
        expect(identity.expiresAt).toBe(1120);
        expect(ctx.recorded.logs).toHaveLength(1);
        expect(ctx.recorded.logs[0]).toMatchObject({ level: "warn", fields: { reason: REASON[kind], purpose: "user-info-groups", lifetime: 120 } });
        expectCleanLogs(ctx);
      });
    }

    it("bad_url degrades too", async () => {
      const opts = Object.freeze({ ...options({ on_login_error: "degrade" }), endpoint: "https://users.example.com/q?m={email}" });
      const ctx = ctxFor({ opts });
      const draft = draftFor();
      await userInfo.onLogin(ctx, draft, ctx.options);
      expect(draft.lifetimeCap).toBe(300);
    });

    it("W2.R R4: more than 256 backend groups → too_many_groups, degraded (no group added)", async () => {
      const many = Array.from({ length: 257 }, (_, i) => `g${i}`);
      const ctx = ctxFor({ fetch: backend(Response.json({ groups: many })), opts: options({ on_login_error: "degrade" }) });
      const draft = draftFor();
      await userInfo.onLogin(ctx, draft, ctx.options);
      expect(draft.groups).toEqual(["site-readers"]);
      expect(draft.lifetimeCap).toBe(300);
      expect(ctx.recorded.logs[0].fields).toMatchObject({ reason: "too_many_groups", purpose: "user-info-groups" });
    });

    it("W2.R R8: degrade drops only the backend's groups; groups already on the draft (a \"claim\" provider's) are kept", async () => {
      const ctx = ctxFor({ fetch: backend(new Response("down", { status: 503 })), opts: options({ on_login_error: "degrade", degrade_ttl_seconds: 60 }) });
      const draft = createIdentityDraft({ sub: SUB, groups: ["medical", "market-access"] }); // e.g. Auth0 claim groups
      await userInfo.onLogin(ctx, draft, ctx.options);
      const id = draft.toIdentity({ method: "oidc-session", issuedAt: 1000, expiresAt: 4600 });
      expect(id.groups).toEqual(["medical", "market-access"]);
      expect(id.expiresAt).toBe(1060);
    });

    it("a groups array of only unsafe values is still a success (nothing to degrade)", async () => {
      const ctx = ctxFor({ fetch: backend(Response.json({ groups: ["a,b"] })), opts: options({ on_login_error: "degrade" }) });
      const draft = draftFor();
      await userInfo.onLogin(ctx, draft, ctx.options);
      expect(draft.lifetimeCap).toBeNull();
    });
  });

  it("missing credentials → 500 internal_error even with degrade; nothing is fetched", async () => {
    for (const secrets of [{}, { user_info_username: USER }, { user_info_password: PASS }]) {
      const fetch = backend(Response.json({ groups: ["g"] }));
      const ctx = ctxFor({ fetch, secrets, opts: options({ on_login_error: "degrade" }) });
      const draft = draftFor();
      const err = await userInfo.onLogin(ctx, draft, ctx.options).then(() => null, (e) => e);
      expect(err).toMatchObject({ status: 500, code: "internal_error" });
      expect(fetch.seen).toEqual([]);
      expect(draft.lifetimeCap).toBeNull();
      expectCleanLogs(ctx);
    }
  });

  it("a kernel fetch-policy violation (budget) propagates and is never degraded", async () => {
    const ctx = ctxFor({ opts: options({ on_login_error: "degrade" }), fetch: backend(Response.json({ groups: ["g"] })) });
    await ctx.fetch("https://users.example.com/warm-up"); // use up the plugin's two fetches
    await ctx.fetch("https://users.example.com/warm-up");
    const draft = draftFor();
    const err = await userInfo.onLogin(ctx, draft, ctx.options).then(() => null, (e) => e);
    expect(err).toMatchObject({ status: 503, code: "budget_exceeded" });
    expect(draft.lifetimeCap).toBeNull();
  });

  it("same endpoint for profile: warms the KV profile cache on provisioned (allowlisted fields only)", async () => {
    const body = { groups: ["g"], given_name: "Ann", ssn: "123-45-6789", nested: { a: 1 } };
    const ctx = ctxFor({ fetch: backend(Response.json(body)), kv: true, profile: "provisioned", opts: options({ profile_fields: ["given_name", "nested"] }) });
    await userInfo.onLogin(ctx, draftFor(), ctx.options);
    const stored = JSON.parse(ctx.recorded.kv.get(await profileCacheKey(SUB)));
    expect(stored.profile).toEqual({ given_name: "Ann" });
    expect(JSON.stringify(stored)).not.toContain("123-45-6789");
  });

  it("does not warm the cache on sandbox, without profile_fields, or with a separate profile_endpoint", async () => {
    const body = { groups: ["g"], given_name: "Ann" };
    const cases = [
      { kv: true, profile: "sandbox", opts: options({ profile_fields: ["given_name"] }) },
      { kv: true, profile: "provisioned", opts: options() },
      { kv: true, profile: "provisioned", opts: options({ profile_fields: ["given_name"], profile_endpoint: "https://users.example.com/p/{sub}" }) },
    ];
    for (const c of cases) {
      const ctx = ctxFor({ ...c, fetch: backend(Response.json(body)) });
      await userInfo.onLogin(ctx, draftFor(), ctx.options);
      expect(ctx.recorded.kv.size).toBe(0);
    }
  });
});

describe("profile allowlisting", () => {
  it("pickProfile keeps only allowlisted top-level scalars", () => {
    const body = { given_name: "Ann", age: 42, active: false, nan: Number.NaN, obj: { a: 1 }, arr: [1], nul: null, secret: "s" };
    expect(pickProfile(body, ["given_name", "age", "active", "obj", "arr", "nul", "missing", "toString"]))
      .toEqual({ given_name: "Ann", age: 42, active: false });
    expect(() => pickProfile([1], ["a"])).toThrow(/not_an_object/);
    expect(() => pickProfile(null, ["a"])).toThrow();
  });

  it("an own __proto__ key in the backend JSON never becomes a prototype", () => {
    const body = JSON.parse('{"__proto__": {"polluted": true}, "a": "x"}');
    const p = pickProfile(body, ["a"]);
    expect(p).toEqual({ a: "x" });
    expect({}.polluted).toBeUndefined();
  });
});

describe("headerValue (sanitization)", () => {
  it("removes CR/LF and other control characters", () => {
    expect(headerValue("Ann\r\nX-Evil: 1")).toBe("AnnX-Evil: 1");
    expect(headerValue("a\u0000b\tc\u007f\u0085d")).toBe("abcd");
  });

  it("percent-encodes values with non-ASCII or '%' so decodeURIComponent is always exact", () => {
    for (const s of ["José", "50% off", "日本", "plain ascii"]) expect(decodeURIComponent(headerValue(s))).toBe(s);
    expect(headerValue("plain ascii")).toBe("plain ascii");
    expect(headerValue("José")).toBe("Jos%C3%A9");
    expect(headerValue("a\ud800b")).toBe("a%EF%BF%BDb");
  });

  it(`truncates to ${MAX_HEADER_VALUE} characters at a character boundary`, () => {
    expect(headerValue("x".repeat(5000))).toHaveLength(MAX_HEADER_VALUE);
    const enc = headerValue("é".repeat(1000)); // 6 chars each
    expect(enc.length).toBeLessThanOrEqual(MAX_HEADER_VALUE);
    expect(enc.length % 6).toBe(0);
    expect(() => decodeURIComponent(enc)).not.toThrow();
  });

  it("stringifies numbers and booleans", () => {
    expect(headerValue(42)).toBe("42");
    expect(headerValue(false)).toBe("false");
  });
});

describe("beforeForward", () => {
  const profileOpts = (extra = {}) => options({ expose: "headers", profile_fields: ["given_name", "Department", "age", "vip", "address", "tags", "bio", "blank"], ...extra });
  const profileBody = {
    given_name: "Ann\r\nX-Injected: 1", Department: "Cardiología", age: 42, vip: true, address: { city: "x" }, tags: ["a"],
    bio: "y".repeat(3000), blank: "\r\n", ssn: "123-45-6789",
  };

  it("expose: \"headers\" sets sanitized x-user-<field> headers for the allowlisted scalars only", async () => {
    const fetch = backend(Response.json(profileBody));
    const ctx = ctxFor({ fetch, identity: identityFor(), opts: profileOpts() });
    expect(await userInfo.beforeForward(ctx, ctx.options)).toBeUndefined();
    const h = Object.fromEntries(ctx.recorded.forwardHeaders.entries());
    expect(h).toEqual({
      "x-user-given-name": "AnnX-Injected: 1",
      "x-user-department": "Cardiolog%C3%ADa",
      "x-user-age": "42",
      "x-user-vip": "true",
      "x-user-bio": "y".repeat(MAX_HEADER_VALUE),
    });
    expect(fetch.seen).toEqual([{ url: `https://users.example.com/v1/users/${ENC_SUB}`, authorization: BASIC, accept: "application/json", method: "GET" }]);
    expect(ctx.recorded.fetches[0].opts).toEqual({ purpose: "user-info-profile" });
    expectCleanLogs(ctx);
  });

  it("uses profile_endpoint when set", async () => {
    const fetch = backend(Response.json({ given_name: "Ann" }));
    const ctx = ctxFor({ fetch, identity: identityFor(), opts: profileOpts({ profile_endpoint: "https://profiles.example.com/p?id={sub}" }) });
    await userInfo.beforeForward(ctx, ctx.options);
    expect(fetch.seen[0].url).toBe(`https://profiles.example.com/p?id=${ENC_SUB}`);
  });

  it("expose: \"none\" (default), no identity, or no profile_fields → nothing, no fetch", async () => {
    for (const [opts, identity] of [
      [options({ profile_fields: ["given_name"] }), identityFor()],
      [profileOpts(), null],
      [options({ expose: "headers" }), identityFor()],
    ]) {
      const fetch = backend(Response.json(profileBody));
      const ctx = ctxFor({ fetch, identity, opts });
      await userInfo.beforeForward(ctx, ctx.options);
      expect(fetch.seen).toEqual([]);
      expect([...ctx.recorded.forwardHeaders.keys()]).toEqual([]);
    }
  });

  it("a profile failure → PluginError 503 user_info_unavailable, nothing forwarded, logs clean", async () => {
    for (const respond of [FAILURES.network_error, FAILURES.http_status, FAILURES.bad_json, () => Response.json(["x"])]) {
      const ctx = ctxFor({ fetch: backend(respond), identity: identityFor(), opts: profileOpts() });
      const err = await userInfo.beforeForward(ctx, ctx.options).then(() => null, (e) => e);
      expect(err).toMatchObject({ status: 503, code: "user_info_unavailable" });
      expect([...ctx.recorded.forwardHeaders.keys()]).toEqual([]);
      expect(ctx.recorded.logs.some((l) => l.level === "warn" && l.fields.purpose === "user-info-profile")).toBe(true);
      expectCleanLogs(ctx);
    }
  });

  it("missing credentials → 500 internal_error", async () => {
    const ctx = ctxFor({ secrets: {}, identity: identityFor(), opts: profileOpts() });
    await expect(userInfo.beforeForward(ctx, ctx.options)).rejects.toMatchObject({ status: 500, code: "internal_error" });
  });
});

describe("handle", () => {
  const handleOpts = (extra = {}) => options({ profile_fields: ["given_name", "department"], ...extra });

  it("no identity → 401 {error: unauthorized}, no fetch", async () => {
    const fetch = backend(Response.json({}));
    const ctx = ctxFor({ fetch, opts: handleOpts() });
    const res = await userInfo.handle(ctx, ctx.options);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
    expect(fetch.seen).toEqual([]);
  });

  it("returns {sub, email, name, groups, profile} with only the allowlisted profile fields, never cached", async () => {
    const fetch = backend(Response.json({ given_name: "Ann", department: "R&D", ssn: "123-45-6789", groups: ["admin"] }));
    const ctx = ctxFor({ fetch, identity: identityFor(), opts: handleOpts() });
    const res = await userInfo.handle(ctx, ctx.options);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/^application\/json/);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(await res.json()).toEqual({
      sub: SUB, email: "u@example.com", name: "U Ser", groups: ["site-readers", "medical"],
      profile: { given_name: "Ann", department: "R&D" },
    });
  });

  it("no profile_fields → profile {} without a backend call; missing email/name are null", async () => {
    const fetch = backend(Response.json({}));
    const ctx = ctxFor({ fetch, identity: identityFor({ email: undefined, name: undefined }), opts: options() });
    const res = await userInfo.handle(ctx, ctx.options);
    expect(await res.json()).toEqual({ sub: SUB, email: null, name: null, groups: ["site-readers", "medical"], profile: {} });
    expect(fetch.seen).toEqual([]);
  });

  it("a profile failure → PluginError 503", async () => {
    const ctx = ctxFor({ fetch: backend(FAILURES.http_status), identity: identityFor(), opts: handleOpts() });
    await expect(userInfo.handle(ctx, ctx.options)).rejects.toMatchObject({ status: 503, code: "user_info_unavailable" });
    expectCleanLogs(ctx);
  });

  it("beforeForward + handle in one request share one backend call (maxFetches 1)", async () => {
    const fetch = backend(Response.json({ given_name: "Ann", department: "R&D" }));
    const opts = handleOpts({ expose: "headers" });
    const ctx = ctxFor({ fetch, identity: identityFor(), opts });
    await userInfo.beforeForward(ctx, opts);
    const res = await userInfo.handle(ctx, opts);
    expect((await res.json()).profile).toEqual({ given_name: "Ann", department: "R&D" });
    expect(fetch.seen).toHaveLength(1);
  });
});

describe("profile cache (KV)", () => {
  const cacheOpts = (extra = {}) => options({ profile_fields: ["given_name"], cache_ttl_seconds: 600, ...extra });
  const keyFor = async (sub) => `profile:${await sha256Hex(sub)}`;

  it("the key is \"profile:\" + hex SHA-256(sub)", async () => {
    const hex = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(SUB)))]
      .map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(await profileCacheKey(SUB)).toBe(`profile:${hex}`);
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
  });

  it("provisioned miss: fetch, then store the allowlisted profile with cache_ttl_seconds", async () => {
    const fetch = backend(Response.json({ given_name: "Ann", ssn: "123-45-6789" }));
    const ctx = ctxFor({ fetch, identity: identityFor(), opts: cacheOpts(), kv: true, profile: "provisioned" });
    const puts = [];
    const realKv = ctx.kv;
    ctx.kv = { get: (k) => realKv.get(k), put: async (k, v, o) => { puts.push({ k, o }); return realKv.put(k, v, o); }, delete: (k) => realKv.delete(k) };
    const res = await userInfo.handle(ctx, ctx.options);
    expect((await res.json()).profile).toEqual({ given_name: "Ann" });
    expect(fetch.seen).toHaveLength(1);
    expect(puts).toEqual([{ k: await keyFor(SUB), o: { ttl: 600 } }]);
    const stored = ctx.recorded.kv.get(await keyFor(SUB));
    expect(JSON.parse(stored).profile).toEqual({ given_name: "Ann" });
    expect(stored).not.toContain("123-45-6789");
  });

  it("provisioned hit: no backend call", async () => {
    const seed = ctxFor({ fetch: backend(Response.json({ given_name: "Ann" })), identity: identityFor(), opts: cacheOpts(), kv: true, profile: "provisioned" });
    await userInfo.handle(seed, seed.options);
    const fetch = backend(Response.json({ given_name: "CHANGED" }));
    const ctx = ctxFor({ fetch, identity: identityFor(), opts: cacheOpts(), kv: seed.recorded.kv, profile: "provisioned" });
    const res = await userInfo.handle(ctx, ctx.options);
    expect((await res.json()).profile).toEqual({ given_name: "Ann" });
    expect(fetch.seen).toEqual([]);
  });

  it("an entry built for other options (fields/endpoint) or a corrupt entry is a miss", async () => {
    const seed = ctxFor({ fetch: backend(Response.json({ given_name: "Ann", department: "R&D" })), identity: identityFor(), opts: cacheOpts(), kv: true, profile: "provisioned" });
    await userInfo.handle(seed, seed.options);
    const wider = cacheOpts({ profile_fields: ["given_name", "department"] });
    const fetch = backend(Response.json({ given_name: "Ann", department: "R&D" }));
    const ctx = ctxFor({ fetch, identity: identityFor(), opts: wider, kv: seed.recorded.kv, profile: "provisioned" });
    expect((await (await userInfo.handle(ctx, wider)).json()).profile).toEqual({ given_name: "Ann", department: "R&D" });
    expect(fetch.seen).toHaveLength(1);

    for (const corrupt of ["not json", "null", JSON.stringify({ v: 99, profile: {} }), JSON.stringify({ v: 1, fp: "x", profile: [] })]) {
      const kv = new Map([[await keyFor(SUB), corrupt]]);
      const f = backend(Response.json({ given_name: "Live" }));
      const c = ctxFor({ fetch: f, identity: identityFor(), opts: cacheOpts(), kv, profile: "provisioned" });
      expect((await (await userInfo.handle(c, c.options)).json()).profile).toEqual({ given_name: "Live" });
      expect(f.seen).toHaveLength(1);
    }
  });

  it("a KV read error falls back to a live fetch (logged); a write error is logged, not fatal", async () => {
    const fetch = backend(Response.json({ given_name: "Ann" }));
    const ctx = ctxFor({ fetch, identity: identityFor(), opts: cacheOpts(), kv: true, profile: "provisioned" });
    ctx.kv = { get: async () => { throw new Error("kv down"); }, put: async () => { throw new Error("kv down"); }, delete: async () => {} };
    const res = await userInfo.handle(ctx, ctx.options);
    expect(res.status).toBe(200);
    expect((await res.json()).profile).toEqual({ given_name: "Ann" });
    expect(fetch.seen).toHaveLength(1);
    expect(ctx.recorded.logs.map((l) => [l.level, l.fields.reason])).toEqual([["warn", "kv_read_error"], ["warn", "kv_write_error"]]);
    expectCleanLogs(ctx);
  });

  it("sandbox: no KV, every request fetches", async () => {
    for (let i = 0; i < 2; i++) {
      const fetch = backend(Response.json({ given_name: "Ann" }));
      const ctx = ctxFor({ fetch, identity: identityFor(), opts: cacheOpts(), profile: "sandbox" });
      expect(ctx.kv).toBeNull();
      await userInfo.handle(ctx, ctx.options);
      expect(fetch.seen).toHaveLength(1);
    }
  });

  describe("W2.R R13: the cached profile does not outlive the session", () => {
    /** A fake KV that records deletes, over a Map. */
    const fakeKv = (map, { failDelete = false } = {}) => {
      const deletes = [];
      return {
        deletes,
        get: async (k) => (map.has(k) ? map.get(k) : null),
        put: async (k, v) => { map.set(k, v); },
        delete: async (k) => { deletes.push(k); if (failDelete) throw new Error("kv down"); map.delete(k); },
      };
    };

    it("onLogout deletes profile:<sha256(sub)>", async () => {
      const map = new Map([[await keyFor(SUB), "cached"], ["profile:other", "keep"]]);
      const ctx = ctxFor({ opts: cacheOpts(), profile: "provisioned", kv: true });
      ctx.kv = fakeKv(map);
      await userInfo.onLogout(ctx, identityFor(), ctx.options);
      expect(ctx.kv.deletes).toEqual([await keyFor(SUB)]);
      expect([...map.keys()]).toEqual(["profile:other"]);
    });

    it("onLogout with no identity or no KV does nothing; a delete error is logged and ignored", async () => {
      const ctx = ctxFor({ opts: cacheOpts(), profile: "provisioned", kv: true });
      ctx.kv = fakeKv(new Map());
      await userInfo.onLogout(ctx, null, ctx.options);
      expect(ctx.kv.deletes).toEqual([]);
      const noKv = ctxFor({ opts: cacheOpts(), profile: "sandbox" });
      await expect(userInfo.onLogout(noKv, identityFor(), noKv.options)).resolves.toBeUndefined();
      const failing = ctxFor({ opts: cacheOpts(), profile: "provisioned", kv: true });
      failing.kv = fakeKv(new Map(), { failDelete: true });
      await expect(userInfo.onLogout(failing, identityFor(), failing.options)).resolves.toBeUndefined();
      expect(failing.recorded.logs.map((l) => [l.level, l.fields.reason])).toEqual([["warn", "kv_delete_error"]]);
      expectCleanLogs(failing);
    });

    it("login with a separate profile_endpoint drops an old entry, so a fresh login never serves it", async () => {
      const opts = cacheOpts({ profile_endpoint: "https://profiles.example.com/p/{sub}" });
      const map = new Map();
      // An earlier session cached a profile.
      const seed = ctxFor({ fetch: backend(Response.json({ given_name: "Old" })), identity: identityFor(), opts, profile: "provisioned", kv: true });
      seed.kv = fakeKv(map);
      await userInfo.handle(seed, opts);
      expect(map.has(await keyFor(SUB))).toBe(true);
      // Fresh login: the entry is deleted.
      const login = ctxFor({ fetch: backend(Response.json({ groups: ["g"] })), opts, profile: "provisioned", kv: true });
      login.kv = fakeKv(map);
      await userInfo.onLogin(login, draftFor(), opts);
      expect(login.kv.deletes).toEqual([await keyFor(SUB)]);
      expect(map.has(await keyFor(SUB))).toBe(false);
      // The next request fetches the current profile.
      const fetch = backend(Response.json({ given_name: "New" }));
      const after = ctxFor({ fetch, identity: identityFor(), opts, profile: "provisioned", kv: true });
      after.kv = fakeKv(map);
      expect((await (await userInfo.handle(after, opts)).json()).profile).toEqual({ given_name: "New" });
      expect(fetch.seen).toHaveLength(1);
    });

    it("a degraded login drops the entry too; a login that re-warms the same endpoint's entry does not delete it", async () => {
      const opts = cacheOpts({ profile_endpoint: "https://profiles.example.com/p/{sub}", on_login_error: "degrade" });
      const map = new Map([[await keyFor(SUB), "old"]]);
      const ctx = ctxFor({ fetch: backend(new Response("down", { status: 500 })), opts, profile: "provisioned", kv: true });
      ctx.kv = fakeKv(map);
      await userInfo.onLogin(ctx, draftFor(), opts);
      expect(map.size).toBe(0);

      const same = cacheOpts(); // profile_endpoint === endpoint: the login overwrites the entry
      const warm = ctxFor({ fetch: backend(Response.json({ groups: ["g"], given_name: "Ann" })), opts: same, profile: "provisioned", kv: true });
      warm.kv = fakeKv(map);
      await userInfo.onLogin(warm, draftFor(), same);
      expect(warm.kv.deletes).toEqual([]);
      expect(JSON.parse(map.get(await keyFor(SUB))).profile).toEqual({ given_name: "Ann" });
    });
  });

  it("a KV handle on a sandbox platform is never used", async () => {
    const fetch = backend(Response.json({ given_name: "Ann" }));
    const ctx = ctxFor({ fetch, identity: identityFor(), opts: cacheOpts(), kv: true, profile: "sandbox" });
    await userInfo.handle(ctx, ctx.options);
    expect(ctx.recorded.kv.size).toBe(0);
  });
});
