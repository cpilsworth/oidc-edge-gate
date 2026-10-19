// W3.0: revocation record store (docs/architecture/plugins.md §15.2).
import { describe, it, expect } from "vitest";
import { createTestContext } from "../../../src/sdk/testing.js";
import {
  MAX_SUB_BYTES, REVOCATION_TTL_MARGIN_SECONDS, RevocationRecordError,
  isSessionId, isSessionRevoked, isSubject, recordTtlSeconds, revokeSession, revokeSubject,
  sidKey, subKey, subjectRevokedAt,
} from "../lib/revocation-store.js";
import { newSessionId } from "../lib/session.js";

const NOW_MS = Date.UTC(2026, 9, 19, 12, 0, 0);
const NOW_S = Math.floor(NOW_MS / 1000);
const TTL = 3600;

/** A KV view (as ctx.kv) whose puts are recorded with their options. */
function kvWithPuts(initial = {}) {
  const ctx = createTestContext({ kv: initial });
  const puts = [];
  const kv = {
    get: (k) => ctx.kv.get(k),
    put: (k, v, o) => { puts.push({ key: k, value: v, opts: o }); return ctx.kv.put(k, v, o); },
    delete: (k) => ctx.kv.delete(k),
  };
  return { kv, puts, store: ctx.recorded.kv };
}

describe("keys", () => {
  it("sidKey is rev:sid:<sid> for a well-formed sid only", () => {
    const sid = newSessionId();
    expect(isSessionId(sid)).toBe(true);
    expect(sidKey(sid)).toBe(`rev:sid:${sid}`);
    for (const bad of ["", "short", `${sid}x`, "a".repeat(21) + "=", "a".repeat(21) + "/", 42, null, undefined]) {
      expect(isSessionId(bad)).toBe(false);
      expect(() => sidKey(bad)).toThrow(TypeError);
    }
  });

  it("subKey is rev:sub:<lowercase hex sha256(sub)>, so no PII or arbitrary bytes reach a KV key", async () => {
    // sha256("abc")
    expect(await subKey("abc")).toBe("rev:sub:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const k = await subKey("user@example.com\r\n../..");
    expect(k).toMatch(/^rev:sub:[0-9a-f]{64}$/);
    expect(k).not.toContain("example");
  });

  it("subKey rejects only empty and non-string subjects", async () => {
    for (const bad of ["", 1, null, undefined, {}]) {
      expect(isSubject(bad)).toBe(false);
      await expect(subKey(bad)).rejects.toThrow(TypeError);
    }
  });

  it("subKey hashes a subject of any length (W3.R R3-2): a session's sub is always checkable", async () => {
    for (const sub of ["x".repeat(MAX_SUB_BYTES + 1), "é".repeat(513), "s".repeat(5000)]) {
      const k = await subKey(sub);
      expect(k).toMatch(/^rev:sub:[0-9a-f]{64}$/);
    }
    expect(await subKey("s".repeat(5000))).not.toBe(await subKey("s".repeat(4999)));
  });

  it("isSubject (the admin/webhook input bound) still caps subjects at MAX_SUB_BYTES (UTF-8)", () => {
    expect(MAX_SUB_BYTES).toBe(1024);
    expect(isSubject("x".repeat(MAX_SUB_BYTES))).toBe(true);
    for (const bad of ["x".repeat(MAX_SUB_BYTES + 1), "é".repeat(513), "s".repeat(5000)]) expect(isSubject(bad)).toBe(false);
  });

  it("records live session_ttl_seconds + 120 s", () => {
    expect(REVOCATION_TTL_MARGIN_SECONDS).toBe(120);
    expect(recordTtlSeconds(3600)).toBe(3720);
    for (const bad of [0, -1, 1.5, NaN, "3600", undefined]) expect(() => recordTtlSeconds(bad)).toThrow(TypeError);
  });
});

describe("session records", () => {
  it("revokeSession writes the wrapped record with the native ttl; isSessionRevoked reads it", async () => {
    const { kv, puts } = kvWithPuts();
    const sid = newSessionId();
    expect(await isSessionRevoked(kv, sid, { nowMs: NOW_MS })).toBe(false);
    await revokeSession(kv, sid, { sessionTtlSeconds: TTL, nowMs: NOW_MS });
    expect(puts).toHaveLength(1);
    expect(puts[0].key).toBe(`rev:sid:${sid}`);
    expect(puts[0].opts).toEqual({ ttl: TTL + 120 });
    expect(JSON.parse(puts[0].value)).toEqual({ value: { at: NOW_S }, expires: NOW_MS + (TTL + 120) * 1000 });
    expect(await isSessionRevoked(kv, sid, { nowMs: NOW_MS })).toBe(true);
    // Another session is unaffected.
    expect(await isSessionRevoked(kv, newSessionId(), { nowMs: NOW_MS })).toBe(false);
  });

  it("an expired record reads as absent (backends that ignore the native ttl)", async () => {
    const { kv } = kvWithPuts();
    const sid = newSessionId();
    await revokeSession(kv, sid, { sessionTtlSeconds: TTL, nowMs: NOW_MS });
    expect(await isSessionRevoked(kv, sid, { nowMs: NOW_MS + (TTL + 120) * 1000 - 1 })).toBe(true);
    expect(await isSessionRevoked(kv, sid, { nowMs: NOW_MS + (TTL + 120) * 1000 })).toBe(false);
  });

  it.each([
    ["not JSON", "{oops"],
    ["no wrapper", JSON.stringify({ at: 1 })],
    ["array", "[]"],
    ["null value", JSON.stringify({ value: null, expires: NOW_MS + 1000 })],
    ["no expires", JSON.stringify({ value: { at: 1 } })],
    ["no at", JSON.stringify({ value: {}, expires: NOW_MS + 1000 })],
    ["string at", JSON.stringify({ value: { at: "1" }, expires: NOW_MS + 1000 })],
  ])("a corrupt record (%s) throws RevocationRecordError (callers decide per mode)", async (_label, raw) => {
    const sid = newSessionId();
    const { kv } = kvWithPuts({ [`rev:sid:${sid}`]: raw });
    await expect(isSessionRevoked(kv, sid, { nowMs: NOW_MS })).rejects.toThrow(RevocationRecordError);
  });

  it("KV errors propagate", async () => {
    const kv = { get: async () => { throw new Error("kv down"); }, put: async () => { throw new Error("kv down"); } };
    await expect(isSessionRevoked(kv, newSessionId())).rejects.toThrow("kv down");
    await expect(revokeSession(kv, newSessionId(), { sessionTtlSeconds: TTL })).rejects.toThrow("kv down");
  });
});

describe("subject records", () => {
  it("revokeSubject stores revoked_at = now (epoch s) under the hashed key; subjectRevokedAt reads it", async () => {
    const { kv, puts } = kvWithPuts();
    expect(await subjectRevokedAt(kv, "user-1", { nowMs: NOW_MS })).toBeNull();
    expect(await revokeSubject(kv, "user-1", { sessionTtlSeconds: TTL, nowMs: NOW_MS })).toBe(NOW_S);
    expect(puts[0].key).toBe(await subKey("user-1"));
    expect(puts[0].opts).toEqual({ ttl: TTL + 120 });
    expect(JSON.parse(puts[0].value)).toEqual({ value: { revoked_at: NOW_S }, expires: NOW_MS + (TTL + 120) * 1000 });
    expect(await subjectRevokedAt(kv, "user-1", { nowMs: NOW_MS })).toBe(NOW_S);
    expect(await subjectRevokedAt(kv, "user-2", { nowMs: NOW_MS })).toBeNull();
  });

  it("the epoch only moves forward: a later revocation advances it, an earlier (stale/replayed) one keeps it", async () => {
    const { kv } = kvWithPuts();
    await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS });
    expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS + 30_000 })).toBe(NOW_S + 30);
    expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS + 10_000 })).toBe(NOW_S + 30);
    expect(await subjectRevokedAt(kv, "u", { nowMs: NOW_MS + 10_000 })).toBe(NOW_S + 30);
  });

  it("an existing epoch that already covers the request is kept without a write", async () => {
    const { kv, puts } = kvWithPuts();
    await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS + 30_000 });
    expect(puts).toHaveLength(1);
    expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS + 30_000 })).toBe(NOW_S + 30);
    expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS + 10_000 })).toBe(NOW_S + 30);
    expect(puts).toHaveLength(1);
  });

  describe("revokedAt (W3.R R3-3)", () => {
    it("a revokedAt in the past is used as the epoch", async () => {
      const { kv, puts } = kvWithPuts();
      expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS, revokedAt: NOW_S - 200 })).toBe(NOW_S - 200);
      expect(JSON.parse(puts[0].value)).toEqual({ value: { revoked_at: NOW_S - 200 }, expires: NOW_MS + (TTL + 120) * 1000 });
      expect(await subjectRevokedAt(kv, "u", { nowMs: NOW_MS })).toBe(NOW_S - 200);
    });

    it("a revokedAt in the future is clamped to now", async () => {
      const { kv } = kvWithPuts();
      expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS, revokedAt: NOW_S + 300 })).toBe(NOW_S);
      expect(await subjectRevokedAt(kv, "u", { nowMs: NOW_MS })).toBe(NOW_S);
    });

    it("never moves the epoch backwards: an earlier revokedAt keeps the stored value, no write", async () => {
      const { kv, puts } = kvWithPuts();
      await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS, revokedAt: NOW_S - 10 });
      expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS + 290_000, revokedAt: NOW_S - 10 })).toBe(NOW_S - 10);
      expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS + 290_000, revokedAt: NOW_S - 50 })).toBe(NOW_S - 10);
      expect(puts).toHaveLength(1);
      expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS + 290_000, revokedAt: NOW_S + 5 })).toBe(NOW_S + 5);
      expect(puts).toHaveLength(2);
    });

    it.each([[-1], [1.5], ["1"], [NaN], [Number.MAX_SAFE_INTEGER + 1]])("rejects a malformed revokedAt (%s) with no KV access", async (bad) => {
      const { kv, puts } = kvWithPuts();
      await expect(revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS, revokedAt: bad })).rejects.toThrow(TypeError);
      expect(puts).toEqual([]);
    });
  });

  it("revokeSubject accepts any non-empty subject, also one over MAX_SUB_BYTES (W3.R R3-2)", async () => {
    const { kv } = kvWithPuts();
    const sub = "s".repeat(5000);
    expect(await revokeSubject(kv, sub, { sessionTtlSeconds: TTL, nowMs: NOW_MS })).toBe(NOW_S);
    expect(await subjectRevokedAt(kv, sub, { nowMs: NOW_MS })).toBe(NOW_S);
    await expect(revokeSubject(kv, "", { sessionTtlSeconds: TTL, nowMs: NOW_MS })).rejects.toThrow(TypeError);
  });

  it("revokeSubject overwrites a corrupt existing record", async () => {
    const key = await subKey("u");
    const { kv } = kvWithPuts({ [key]: "{corrupt" });
    await expect(subjectRevokedAt(kv, "u", { nowMs: NOW_MS })).rejects.toThrow(RevocationRecordError);
    expect(await revokeSubject(kv, "u", { sessionTtlSeconds: TTL, nowMs: NOW_MS })).toBe(NOW_S);
    expect(await subjectRevokedAt(kv, "u", { nowMs: NOW_MS })).toBe(NOW_S);
  });

  it.each([
    ["negative", -1], ["fraction", 1.5], ["string", "1"], ["missing", undefined],
  ])("a record with a bad revoked_at (%s) throws RevocationRecordError", async (_label, v) => {
    const key = await subKey("u");
    const { kv } = kvWithPuts({ [key]: JSON.stringify({ value: { revoked_at: v }, expires: NOW_MS + 1000 }) });
    await expect(subjectRevokedAt(kv, "u", { nowMs: NOW_MS })).rejects.toThrow(RevocationRecordError);
  });

  it("KV read errors during revokeSubject propagate (no blind overwrite)", async () => {
    const kv = { get: async () => { throw new Error("kv down"); }, put: async () => {} };
    await expect(revokeSubject(kv, "u", { sessionTtlSeconds: TTL })).rejects.toThrow("kv down");
  });
});
