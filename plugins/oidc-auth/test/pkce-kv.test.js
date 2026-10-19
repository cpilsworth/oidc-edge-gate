// PKCE + random state/nonce, and the KV expiry wrapper.
import { describe, it, expect } from "vitest";
import { base64UrlEncode } from "../../../src/sdk/encoding.js";
import { createPkcePair, randomNonce, randomState } from "../lib/pkce.js";
import { kvGetFresh, kvPutWithTtl } from "../lib/kv.js";
import { makeCtx } from "./support.js";

describe("pkce", () => {
  it("creates an S256 verifier/challenge pair (43-char base64url verifier)", async () => {
    const { verifier, challenge, method } = await createPkcePair();
    expect(method).toBe("S256");
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const dg = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    expect(challenge).toBe(base64UrlEncode(dg));
  });

  it("state and nonce are unique 128-bit base64url strings", () => {
    expect(randomState()).not.toBe(randomState());
    expect(randomNonce()).not.toBe(randomNonce());
    expect(randomState()).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });
});

describe("kv expiry wrapper (over ctx.kv string values)", () => {
  const fake = (raw) => ({ async get() { return raw; }, async put() {} });

  it("null kv (no KV): get → null, put → no-op", async () => {
    await expect(kvGetFresh(null, "k")).resolves.toBeNull();
    await expect(kvPutWithTtl(null, "k", "v", 60)).resolves.toBeUndefined();
  });

  it("absent key → null", async () => {
    await expect(kvGetFresh(fake(null), "k")).resolves.toBeNull();
  });

  it("unexpired → value; expired → null", async () => {
    await expect(kvGetFresh(fake(JSON.stringify({ value: "v", expires: Date.now() + 1000 })), "k")).resolves.toBe("v");
    await expect(kvGetFresh(fake(JSON.stringify({ value: "v", expires: Date.now() - 1 })), "k")).resolves.toBeNull();
  });

  it("corrupt or wrongly shaped entry → null instead of throwing (poisoned KV)", async () => {
    await expect(kvGetFresh(fake("not-json{"), "k")).resolves.toBeNull();
    await expect(kvGetFresh(fake(JSON.stringify({ no: "value-or-expires" })), "k")).resolves.toBeNull();
    await expect(kvGetFresh(fake("null"), "k")).resolves.toBeNull();
  });

  it("put writes a {value, expires} wrapper readable by get, through ctx.kv", async () => {
    const ctx = makeCtx("/", { kv: true });
    await kvPutWithTtl(ctx.kv, "oidc:test:roundtrip", { hello: "world" }, 60);
    await expect(kvGetFresh(ctx.kv, "oidc:test:roundtrip")).resolves.toEqual({ hello: "world" });
    const raw = JSON.parse(ctx.recorded.kv.get("oidc:test:roundtrip"));
    expect(raw.value).toEqual({ hello: "world" });
    expect(raw.expires).toBeGreaterThan(Date.now());
  });

  it("put passes the native ttl, and KV errors propagate (callers decide)", async () => {
    const calls = [];
    const kv = { async get() { throw new Error("get boom"); }, async put(k, v, o) { calls.push(o); } };
    await kvPutWithTtl(kv, "k", 1, 600);
    expect(calls).toEqual([{ ttl: 600 }]);
    await expect(kvGetFresh(kv, "k")).rejects.toThrow(/get boom/);
  });
});
