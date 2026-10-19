// W3.2: the per-request revocation check (docs/architecture/plugins.md §15.1,
// §15.3, §15.4). Unit tests over createTestContext, then through
// oidcAuth.authenticate() (cookie clearing, 503 propagation).
import { describe, it, expect, vi } from "vitest";
import { PluginError } from "../../../src/sdk/index.js";
import { createTestContext } from "../../../src/sdk/testing.js";
import { REVOCATION_MODES, checkRevocation, effectiveRevocationMode } from "../lib/revocation.js";
import {
  RevocationRecordError, recordTtlSeconds, revokeSession, revokeSubject, sidKey, subKey,
} from "../lib/revocation-store.js";
import { SESSION_COOKIE, buildSession, encodeSession, newSessionId } from "../lib/session.js";
import { CONFIG, HMAC_KEY, OPTIONS, makeCtx, oidcAuth } from "./support.js";

const TTL = 3600;
const NOW_S = Math.floor(Date.now() / 1000);
const SUB = "user-revocation-test|pii@example.com";
const PROFILES = ["provisioned", "sandbox"];

/** A verified-session shape as readSession returns it. */
function session(overrides = {}) {
  return { sid: newSessionId(), sub: SUB, iat: NOW_S - 100, exp: NOW_S - 100 + TTL, ...overrides };
}

/**
 * A Context for checkRevocation. `kv`: undefined/null = no KV, true/object =
 * createTestContext's in-memory KV, or a custom KV view object.
 */
function ctxFor({ mode, profile = "provisioned", kv = true, minIat } = {}) {
  const config = {};
  if (mode !== undefined) config.revocationMode = mode;
  if (minIat !== undefined) config.sessionMinIat = minIat;
  const custom = kv !== null && typeof kv === "object" && typeof kv.get === "function";
  const ctx = createTestContext({ config, platform: { profile }, kv: custom ? null : kv });
  if (custom) ctx.kv = kv;
  return ctx;
}

/** A KV view that counts reads and delegates to an in-memory map. */
function countingKv(initial = {}) {
  const base = createTestContext({ kv: initial }).kv;
  const gets = [];
  return {
    gets,
    get: (k) => { gets.push(k); return base.get(k); },
    put: (k, v, o) => base.put(k, v, o),
    delete: (k) => base.delete(k),
  };
}

/** A KV view whose reads all fail with `error`. */
function failingKv(error) {
  const gets = [];
  return { gets, get: async (k) => { gets.push(k); throw error; }, put: async () => {}, delete: async () => {} };
}

/**
 * A KV view over an in-memory map whose reads of keys starting with `prefix`
 * ("rev:sid:" or "rev:sub:") fail with `error`; the other read succeeds.
 */
function partlyFailingKv(prefix, error = new Error("kv down")) {
  const kv = countingKv();
  const get = kv.get;
  kv.get = async (k) => {
    if (k.startsWith(prefix)) { kv.gets.push(k); throw error; }
    return get(k);
  };
  return kv;
}

/** Raw wrapper as stored by revocation-store (for corrupt/expired variants). */
const wrap = (value, expires = Date.now() + 60_000) => JSON.stringify({ value, expires });

/** Everything that was logged, as one string (to assert the absence of identifiers). */
const logText = (ctx) => JSON.stringify(ctx.recorded.logs);

async function expectNoIdentifiersLogged(ctx, s) {
  const text = logText(ctx);
  expect(text).not.toContain(s.sid);
  expect(text).not.toContain(SUB);
  expect(text).not.toContain("pii@example.com");
  expect(text).not.toContain((await subKey(SUB)).slice("rev:sub:".length));
  expect(text).not.toContain("rev:");
}

async function expect503(promise) {
  const err = await promise.then(() => null, (e) => e);
  expect(err).toBeInstanceOf(PluginError);
  expect(err.status).toBe(503);
  expect(err.code).toBe("revocation_unavailable");
  return err;
}

describe("effectiveRevocationMode (§15.1)", () => {
  it("exports the four modes", () => {
    expect(REVOCATION_MODES).toEqual(["auto", "required", "optional", "disabled"]);
  });

  it.each([
    ["provisioned", "required"],
    ["sandbox", "optional"],
  ])("auto (and a missing mode) on %s is %s", (profile, expected) => {
    expect(effectiveRevocationMode(ctxFor({ mode: "auto", profile }))).toBe(expected);
    expect(effectiveRevocationMode(ctxFor({ profile }))).toBe(expected);
  });

  for (const profile of PROFILES) {
    it.each(["required", "optional", "disabled"])(`explicit %s is used as-is on ${profile}`, (mode) => {
      expect(effectiveRevocationMode(ctxFor({ mode, profile }))).toBe(mode);
    });
  }

  it("an unknown mode throws, and so does checkRevocation (no silent downgrade)", async () => {
    const ctx = ctxFor({ mode: "sometimes" });
    expect(() => effectiveRevocationMode(ctx)).toThrow(/invalid revocation_mode/);
    await expect(checkRevocation(ctx, session())).rejects.toThrow(/invalid revocation_mode/);
  });
});

describe("step 1: session_min_iat (§15.4)", () => {
  for (const profile of PROFILES) {
    for (const mode of ["auto", "required", "optional", "disabled"]) {
      it(`iat < session_min_iat is revoked (min_iat) with no KV access [${profile}, ${mode}]`, async () => {
        const kv = countingKv();
        const ctx = ctxFor({ mode, profile, kv, minIat: NOW_S - 99 });
        const s = session({ iat: NOW_S - 100 });
        expect(await checkRevocation(ctx, s)).toEqual({ revoked: true, reason: "min_iat" });
        expect(kv.gets).toEqual([]);
        expect(ctx.recorded.logs).toEqual([{ level: "info", msg: "session revoked", fields: { reason: "min_iat" } }]);
      });
    }
  }

  it("applies before the KV checks: required with no KV still answers revoked, not 503", async () => {
    const ctx = ctxFor({ mode: "required", kv: null, minIat: NOW_S });
    expect(await checkRevocation(ctx, session({ iat: NOW_S - 1 }))).toEqual({ revoked: true, reason: "min_iat" });
  });

  it("iat == session_min_iat is NOT revoked; iat > is not either", async () => {
    for (const iat of [NOW_S - 100, NOW_S - 50]) {
      const ctx = ctxFor({ mode: "disabled", minIat: NOW_S - 100 });
      expect(await checkRevocation(ctx, session({ iat }))).toEqual({ revoked: false });
      expect(ctx.recorded.logs).toEqual([]);
    }
  });

  it("an absent (null/undefined) cutoff revokes nothing", async () => {
    for (const minIat of [null, undefined]) {
      const ctx = ctxFor({ mode: "disabled", minIat });
      expect(await checkRevocation(ctx, session({ iat: 0 }))).toEqual({ revoked: false });
    }
  });

  it("a cutoff of 0 revokes nothing with a non-negative iat", async () => {
    const ctx = ctxFor({ mode: "disabled", minIat: 0 });
    expect(await checkRevocation(ctx, session({ iat: 0 }))).toEqual({ revoked: false });
  });
});

describe("step 2: disabled", () => {
  for (const profile of PROFILES) {
    it(`does zero KV reads and accepts even a revoked sid [${profile}]`, async () => {
      const s = session();
      const kv = countingKv();
      await revokeSession(kv, s.sid, { sessionTtlSeconds: TTL });
      await revokeSubject(kv, s.sub, { sessionTtlSeconds: TTL });
      kv.gets.length = 0; // revokeSubject reads before it writes
      const ctx = ctxFor({ mode: "disabled", profile, kv });
      expect(await checkRevocation(ctx, s)).toEqual({ revoked: false });
      expect(kv.gets).toEqual([]);
    });
  }

  it("a failing KV is never touched", async () => {
    const kv = failingKv(new Error("boom"));
    expect(await checkRevocation(ctxFor({ mode: "disabled", kv }), session())).toEqual({ revoked: false });
    expect(kv.gets).toEqual([]);
  });
});

describe("step 3: no KV bound", () => {
  it.each([
    ["required", "provisioned"],
    ["required", "sandbox"],
    ["auto", "provisioned"],
  ])("%s on %s → 503 revocation_unavailable", async (mode, profile) => {
    const ctx = ctxFor({ mode, profile, kv: null });
    const err = await expect503(checkRevocation(ctx, session()));
    expect(err.message).not.toContain(SUB);
  });

  it.each([
    ["optional", "provisioned"],
    ["optional", "sandbox"],
    ["auto", "sandbox"],
  ])("%s on %s → accepted silently", async (mode, profile) => {
    const ctx = ctxFor({ mode, profile, kv: null });
    expect(await checkRevocation(ctx, session())).toEqual({ revoked: false });
    expect(ctx.recorded.logs).toEqual([]);
  });
});

describe("steps 4–5: the KV records", () => {
  for (const mode of ["required", "optional"]) {
    describe(`mode ${mode}`, () => {
      it("no records → not revoked, exactly two reads (the sid key and the sub key)", async () => {
        const s = session();
        const kv = countingKv();
        const ctx = ctxFor({ mode, kv });
        expect(await checkRevocation(ctx, s)).toEqual({ revoked: false });
        expect(kv.gets.sort()).toEqual([sidKey(s.sid), await subKey(s.sub)].sort());
        expect(ctx.recorded.logs).toEqual([]);
      });

      it("a sid record → revoked (sid), logged with the reason only", async () => {
        const s = session();
        const kv = countingKv();
        await revokeSession(kv, s.sid, { sessionTtlSeconds: TTL });
        const ctx = ctxFor({ mode, kv });
        expect(await checkRevocation(ctx, s)).toEqual({ revoked: true, reason: "sid" });
        expect(kv.gets).toHaveLength(2);
        expect(ctx.recorded.logs).toEqual([{ level: "info", msg: "session revoked", fields: { reason: "sid" } }]);
        await expectNoIdentifiersLogged(ctx, s);
      });

      it("another session's sid record does not revoke this one", async () => {
        const kv = countingKv();
        await revokeSession(kv, newSessionId(), { sessionTtlSeconds: TTL });
        expect(await checkRevocation(ctxFor({ mode, kv }), session())).toEqual({ revoked: false });
      });

      it("sub epoch boundary: iat == revoked_at IS revoked, iat < is, iat > is not", async () => {
        const kv = countingKv();
        const revokedAt = await revokeSubject(kv, SUB, { sessionTtlSeconds: TTL, nowMs: (NOW_S - 100) * 1000 });
        expect(revokedAt).toBe(NOW_S - 100);
        for (const [iat, expected] of [
          [NOW_S - 101, { revoked: true, reason: "sub" }],
          [NOW_S - 100, { revoked: true, reason: "sub" }],
          [NOW_S - 99, { revoked: false }],
        ]) {
          const ctx = ctxFor({ mode, kv });
          const s = session({ iat });
          expect(await checkRevocation(ctx, s)).toEqual(expected);
          if (expected.revoked) {
            expect(ctx.recorded.logs).toEqual([{ level: "info", msg: "session revoked", fields: { reason: "sub" } }]);
            await expectNoIdentifiersLogged(ctx, s);
          }
        }
      });

      it("another subject's epoch does not revoke this one", async () => {
        const kv = countingKv();
        await revokeSubject(kv, "someone-else", { sessionTtlSeconds: TTL });
        expect(await checkRevocation(ctxFor({ mode, kv }), session())).toEqual({ revoked: false });
      });

      it("sid wins when both records apply", async () => {
        const s = session();
        const kv = countingKv();
        await revokeSession(kv, s.sid, { sessionTtlSeconds: TTL });
        await revokeSubject(kv, s.sub, { sessionTtlSeconds: TTL });
        expect(await checkRevocation(ctxFor({ mode, kv }), s)).toEqual({ revoked: true, reason: "sid" });
      });

      it("expired records read as absent (even one whose epoch would cover the session)", async () => {
        const s = session();
        const expired = Date.now() - 1;
        const kv = countingKv({
          [sidKey(s.sid)]: wrap({ at: NOW_S }, expired),
          [await subKey(s.sub)]: wrap({ revoked_at: NOW_S }, expired),
        });
        const ctx = ctxFor({ mode, kv });
        expect(await checkRevocation(ctx, s)).toEqual({ revoked: false });
        expect(kv.gets).toHaveLength(2);
        expect(ctx.recorded.logs).toEqual([]);
      });

      it("records written by the store long ago (past their TTL) read as absent", async () => {
        const s = session({ iat: NOW_S - 4000, exp: NOW_S + 100 });
        const kv = countingKv();
        const longAgo = Date.now() - (recordTtlSeconds(TTL) + 1) * 1000;
        await revokeSession(kv, s.sid, { sessionTtlSeconds: TTL, nowMs: longAgo });
        await revokeSubject(kv, s.sub, { sessionTtlSeconds: TTL, nowMs: longAgo });
        expect(await checkRevocation(ctxFor({ mode, kv }), s)).toEqual({ revoked: false });
      });
    });
  }

  it("both reads are issued in parallel: both gets start before either resolves", async () => {
    const s = session();
    const started = [];
    const release = [];
    const kv = {
      get: (k) => new Promise((resolve) => { started.push(k); release.push(() => resolve(null)); }),
      put: async () => {}, delete: async () => {},
    };
    const pending = checkRevocation(ctxFor({ mode: "required", kv }), s);
    // The sub read is preceded by an async SHA-256; wait until both are in flight.
    await vi.waitFor(() => expect(started).toHaveLength(2));
    expect(started.sort()).toEqual([sidKey(s.sid), await subKey(s.sub)].sort());
    for (const r of release) r();
    expect(await pending).toEqual({ revoked: false });
    expect(started).toHaveLength(2);
  });

  it("a sid failure does not leave the sub read's rejection unhandled (both settle)", async () => {
    const unhandled = vi.fn();
    process.on("unhandledRejection", unhandled);
    try {
      const kv = failingKv(new Error("kv down"));
      await expect503(checkRevocation(ctxFor({ mode: "required", kv }), session()));
      await new Promise((r) => setTimeout(r, 10));
      expect(unhandled).not.toHaveBeenCalled();
      expect(kv.gets).toHaveLength(2);
    } finally {
      process.off("unhandledRejection", unhandled);
    }
  });
});

describe("step 4: read failures per mode", () => {
  class FastlyKvError extends Error {
    constructor(message) { super(message); this.name = "FastlyKvError"; }
  }

  /** Cases: [label, build KV for session s, expected logged error class]. */
  const cases = [
    ["KV get throws", () => failingKv(new FastlyKvError("KV lookup of plugin:oidc-auth:rev:sid:… failed")), "FastlyKvError"],
    ["a non-Error is thrown", () => failingKv("plain string with rev:sid:"), "Error"],
    ["corrupt sid record (not JSON)", async (s) => countingKv({ [sidKey(s.sid)]: "{not json" }), "RevocationRecordError"],
    ["sid record with the wrong shape", async (s) => countingKv({ [sidKey(s.sid)]: wrap({ nope: 1 }) }), "RevocationRecordError"],
    ["corrupt sub record", async (s) => countingKv({ [await subKey(s.sub)]: wrap({ revoked_at: "yesterday" }) }), "RevocationRecordError"],
    ["sub record wrapper without expires", async (s) => countingKv({ [await subKey(s.sub)]: JSON.stringify({ value: { revoked_at: 1 } }) }), "RevocationRecordError"],
  ];

  for (const [label, build, errorClass] of cases) {
    it(`${label}: required → 503 revocation_unavailable`, async () => {
      const s = session();
      const kv = await build(s);
      const ctx = ctxFor({ mode: "required", kv });
      const err = await expect503(checkRevocation(ctx, s));
      expect(err.message).toContain(errorClass);
      expect(err.message).not.toContain("rev:");
      expect(kv.gets).toHaveLength(2);
    });

    it(`${label}: optional → warn (error class only), accepted`, async () => {
      const s = session();
      const kv = await build(s);
      const ctx = ctxFor({ mode: "optional", kv });
      expect(await checkRevocation(ctx, s)).toEqual({ revoked: false });
      expect(ctx.recorded.logs).toHaveLength(1);
      expect(ctx.recorded.logs[0].level).toBe("warn");
      expect(ctx.recorded.logs[0].fields).toEqual({ error: errorClass });
      await expectNoIdentifiersLogged(ctx, s);
      expect(logText(ctx)).not.toContain("KV lookup");
    });
  }

  it("auto on provisioned fails closed like required", async () => {
    await expect503(checkRevocation(ctxFor({ profile: "provisioned", kv: failingKv(new Error("x")) }), session()));
  });

  it("auto on a sandbox with a (local) KV that fails behaves like optional", async () => {
    const ctx = ctxFor({ profile: "sandbox", kv: failingKv(new Error("x")) });
    expect(await checkRevocation(ctx, session())).toEqual({ revoked: false });
    expect(ctx.recorded.logs[0].level).toBe("warn");
  });

  describe("a successful read that proves a revocation wins over a failed one (W3.R R3-1)", () => {
    for (const mode of ["required", "optional"]) {
      it(`${mode}: sid record + sub read throws → revoked (sid), not ${mode === "required" ? "503" : "accepted"}`, async () => {
        const s = session();
        const kv = partlyFailingKv("rev:sub:");
        await revokeSession(kv, s.sid, { sessionTtlSeconds: TTL });
        const ctx = ctxFor({ mode, kv });
        expect(await checkRevocation(ctx, s)).toEqual({ revoked: true, reason: "sid" });
        expect(kv.gets).toHaveLength(2);
        expect(ctx.recorded.logs).toEqual([{ level: "info", msg: "session revoked", fields: { reason: "sid" } }]);
      });

      it(`${mode}: sub epoch covering iat + sid read throws → revoked (sub)`, async () => {
        const s = session();
        const kv = partlyFailingKv("rev:sid:");
        await revokeSubject(kv, s.sub, { sessionTtlSeconds: TTL });
        kv.gets.length = 0;
        const ctx = ctxFor({ mode, kv });
        expect(await checkRevocation(ctx, s)).toEqual({ revoked: true, reason: "sub" });
        expect(kv.gets).toHaveLength(2);
        expect(ctx.recorded.logs).toEqual([{ level: "info", msg: "session revoked", fields: { reason: "sub" } }]);
      });

      it(`${mode}: a corrupt sub record does not hide a sid record → revoked (sid)`, async () => {
        const s = session();
        const kv = countingKv({ [await subKey(s.sub)]: "garbage" });
        await revokeSession(kv, s.sid, { sessionTtlSeconds: TTL });
        expect(await checkRevocation(ctxFor({ mode, kv }), s)).toEqual({ revoked: true, reason: "sid" });
      });
    }

    it("a sub epoch that does NOT cover iat + sid read throws: can't tell → per mode", async () => {
      const s = session({ iat: NOW_S - 100 });
      const kv = partlyFailingKv("rev:sid:");
      await revokeSubject(kv, s.sub, { sessionTtlSeconds: TTL, nowMs: (NOW_S - 200) * 1000 });
      await expect503(checkRevocation(ctxFor({ mode: "required", kv }), s));
      const ctx = ctxFor({ mode: "optional", kv });
      expect(await checkRevocation(ctx, s)).toEqual({ revoked: false });
      expect(ctx.recorded.logs.map((l) => [l.level, l.fields])).toEqual([["warn", { error: "Error" }]]);
    });

    it("no sid record + sub read throws: can't tell → per mode", async () => {
      const s = session();
      await expect503(checkRevocation(ctxFor({ mode: "required", kv: partlyFailingKv("rev:sub:") }), s));
      const ctx = ctxFor({ mode: "optional", kv: partlyFailingKv("rev:sub:") });
      expect(await checkRevocation(ctx, s)).toEqual({ revoked: false });
      expect(ctx.recorded.logs[0].level).toBe("warn");
    });
  });

  it("RevocationRecordError is the store's error class (sanity)", () => {
    expect(new RevocationRecordError("x").name).toBe("RevocationRecordError");
  });

  describe("a long sub (> 1024 bytes) is checked normally (W3.R R3-2)", () => {
    const LONG_SUB = "u".repeat(2000);
    for (const mode of ["required", "optional"]) {
      it(`${mode}: no record → not revoked, no warning; revokeSubject → revoked (sub)`, async () => {
        const s = session({ sub: LONG_SUB });
        const kv = countingKv();
        const ctx = ctxFor({ mode, kv });
        expect(await checkRevocation(ctx, s)).toEqual({ revoked: false });
        expect(kv.gets.sort()).toEqual([sidKey(s.sid), await subKey(LONG_SUB)].sort());
        expect(ctx.recorded.logs).toEqual([]);

        await revokeSubject(kv, LONG_SUB, { sessionTtlSeconds: TTL });
        expect(await checkRevocation(ctxFor({ mode, kv }), s)).toEqual({ revoked: true, reason: "sub" });
      });

      it(`${mode}: the sid check still works with a long sub`, async () => {
        const s = session({ sub: LONG_SUB });
        const kv = countingKv();
        await revokeSession(kv, s.sid, { sessionTtlSeconds: TTL });
        expect(await checkRevocation(ctxFor({ mode, kv }), s)).toEqual({ revoked: true, reason: "sid" });
      });
    }
  });

  describe("a malformed sid/sub (impossible for a verified session) is a read failure, not a crash", () => {
    for (const [label, overrides] of [["sid", { sid: "not-a-sid" }], ["sub", { sub: "" }]]) {
      it(`bad ${label}: required → 503; optional → warn TypeError, accepted`, async () => {
        await expect503(checkRevocation(ctxFor({ mode: "required", kv: countingKv() }), session(overrides)));
        const ctx = ctxFor({ mode: "optional", kv: countingKv() });
        expect(await checkRevocation(ctx, session(overrides))).toEqual({ revoked: false });
        expect(ctx.recorded.logs.map((l) => [l.level, l.fields])).toEqual([["warn", { error: "TypeError" }]]);
      });
    }
  });
});

describe("through oidcAuth.authenticate()", () => {
  async function cookieFor(who = {}) {
    const s = buildSession({ sub: SUB, groups: ["medical"], ...who }, TTL);
    return { s, cookie: `${SESSION_COOKIE}=${encodeURIComponent(await encodeSession(s, HMAC_KEY))}` };
  }
  const cleared = (ctx) => ctx.recorded.cookies.some((c) => c.name === SESSION_COOKIE && c.cleared === true);

  it("a live session on provisioned with a KV returns the identity, no cookie written", async () => {
    const { s, cookie } = await cookieFor();
    const ctx = makeCtx("/protected/x", { cookie, kv: true, platform: { profile: "provisioned" } });
    const identity = await oidcAuth.authenticate(ctx, OPTIONS);
    expect(identity).toMatchObject({ sub: SUB, sessionId: s.sid });
    expect(ctx.recorded.cookies).toEqual([]);
  });

  it("a revoked sid returns null and clears __Host-edge_session", async () => {
    const { s, cookie } = await cookieFor();
    const ctx = makeCtx("/protected/x", { cookie, kv: true, platform: { profile: "provisioned" } });
    await revokeSession(ctx.kv, s.sid, { sessionTtlSeconds: TTL });
    expect(await oidcAuth.authenticate(ctx, OPTIONS)).toBeNull();
    expect(cleared(ctx)).toBe(true);
    expect(ctx.recorded.kv.has(sidKey(s.sid))).toBe(true); // check does not delete the record
  });

  it("a per-user epoch returns null and clears the cookie", async () => {
    const { cookie } = await cookieFor();
    const ctx = makeCtx("/protected/x", { cookie, kv: true, platform: { profile: "provisioned" } });
    await revokeSubject(ctx.kv, SUB, { sessionTtlSeconds: TTL, nowMs: Date.now() + 1000 });
    expect(await oidcAuth.authenticate(ctx, OPTIONS)).toBeNull();
    expect(cleared(ctx)).toBe(true);
  });

  it("session_min_iat returns null and clears the cookie on sandbox without KV", async () => {
    const { cookie } = await cookieFor();
    const ctx = makeCtx("/protected/x", { cookie, config: { ...CONFIG, sessionMinIat: NOW_S + 10 } });
    expect(await oidcAuth.authenticate(ctx, OPTIONS)).toBeNull();
    expect(cleared(ctx)).toBe(true);
  });

  it("provisioned (auto → required) without KV: the 503 PluginError propagates, cookie untouched", async () => {
    const { cookie } = await cookieFor();
    const ctx = makeCtx("/protected/x", { cookie, platform: { profile: "provisioned" } });
    await expect503(oidcAuth.authenticate(ctx, OPTIONS));
    expect(ctx.recorded.cookies).toEqual([]);
  });

  it("sandbox (auto → optional) without KV: the session is accepted", async () => {
    const { cookie } = await cookieFor();
    const ctx = makeCtx("/protected/x", { cookie });
    expect(await oidcAuth.authenticate(ctx, OPTIONS)).toMatchObject({ sub: SUB });
  });

  it("no cookie: no revocation check at all (no KV read, no 503)", async () => {
    const ctx = makeCtx("/protected/x", { platform: { profile: "provisioned" } });
    expect(await oidcAuth.authenticate(ctx, OPTIONS)).toBeNull();
  });
});
