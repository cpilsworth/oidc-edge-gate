import { describe, it, expect, beforeEach } from "vitest";
import { kvGetFresh, kvPutWithTtl } from "../src/kv.js";
import { getKvMap, resetStubs } from "./stubs/state.js";

// kv.js wraps every value as `{value, expires}` and checks `expires` on read so
// the gate has one definition of "expired" even when the KV backend doesn't
// honour native TTL eviction. These tests cover the null-kv fallback, the happy
// path, the expired-entry path, and the corrupt-entry catch (line 24) — the
// exact path a poisoned KV would hit.

beforeEach(() => resetStubs());

describe("kvGetFresh", () => {
  it("returns null when kv is null (KV unbound)", async () => {
    await expect(kvGetFresh(null, "any")).resolves.toBeNull();
  });

  it("returns null when the key is absent", async () => {
    const kv = { async get() { return null; }, async put() {} };
    await expect(kvGetFresh(kv, "missing")).resolves.toBeNull();
  });

  it("returns the stored value when unexpired", async () => {
    const kv = { async get() { return { text: async () => JSON.stringify({ value: "v", expires: Date.now() + 1000 }) }; }, async put() {} };
    await expect(kvGetFresh(kv, "k")).resolves.toBe("v");
  });

  it("returns null when the entry has expired", async () => {
    const kv = { async get() { return { text: async () => JSON.stringify({ value: "v", expires: Date.now() - 1 }) }; }, async put() {} };
    await expect(kvGetFresh(kv, "k")).resolves.toBeNull();
  });

  it("returns null for a corrupt cache entry instead of throwing (poisoned KV)", async () => {
    const kv = { async get() { return { text: async () => "not-json{" }; }, async put() {} };
    await expect(kvGetFresh(kv, "k")).resolves.toBeNull();
  });

  it("returns null when the stored wrapper is valid JSON but the wrong shape", async () => {
    const kv = { async get() { return { text: async () => JSON.stringify({ no: "value-or-expires" }) }; }, async put() {} };
    await expect(kvGetFresh(kv, "k")).resolves.toBeNull();
  });
});

describe("kvPutWithTtl", () => {
  it("is a no-op when kv is null (KV unbound)", async () => {
    await expect(kvPutWithTtl(null, "k", "v", 60)).resolves.toBeUndefined();
  });

  it("writes a wrapped entry readable by kvGetFresh", async () => {
    // Use the real KVStore stub so put and get share the same backing map.
    const { KVStore } = await import("fastly:kv-store");
    const kv = new KVStore("kv_default");
    await kvPutWithTtl(kv, "oidc:test:roundtrip", { hello: "world" }, 60);
    await expect(kvGetFresh(kv, "oidc:test:roundtrip")).resolves.toEqual({ hello: "world" });
    // And the entry is stored as the {value, expires} wrapper.
    const raw = JSON.parse(getKvMap("kv_default").get("oidc:test:roundtrip"));
    expect(raw).toHaveProperty("value");
    expect(raw).toHaveProperty("expires");
    expect(raw.expires).toBeGreaterThan(Date.now());
  });
});
