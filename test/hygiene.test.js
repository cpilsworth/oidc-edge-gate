// W0.5 hygiene: the imported-HMAC-key cache in src/sdk/cookies.js.
// (The OIDC parts of this file, best-effort discovery/JWKS caching and the
// cache overrides on IdP fetches, moved to plugins/oidc-auth/test/ in W1.4.)
import { describe, it, expect, afterEach, vi } from "vitest";
import { sign, unsign } from "../src/sdk/cookies.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("HMAC CryptoKey cache (cookies.js)", () => {
  // The cache is module-level, so each test uses its own secret.
  let n = 0;
  const freshSecret = () => `hygiene-secret-${++n}-${"x".repeat(32)}`;

  it("repeated sign/unsign with one secret imports the key once", async () => {
    const spy = vi.spyOn(crypto.subtle, "importKey");
    const secret = freshSecret();
    const t1 = await sign("payload-1", secret);
    const t2 = await sign("payload-2", secret);
    expect(await unsign(t1, secret)).toBe("payload-1");
    expect(await unsign(t2, secret)).toBe("payload-2");
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("concurrent calls share a single import", async () => {
    const spy = vi.spyOn(crypto.subtle, "importKey");
    const secret = freshSecret();
    const tokens = await Promise.all([1, 2, 3, 4].map((i) => sign(`p${i}`, secret)));
    expect(tokens).toHaveLength(4);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("different secrets give different keys (behaviour unchanged)", async () => {
    const a = freshSecret();
    const b = freshSecret();
    const ta = await sign("same", a);
    const tb = await sign("same", b);
    expect(ta).not.toBe(tb);
    expect(await unsign(ta, a)).toBe("same");
    expect(await unsign(ta, b)).toBeNull();
    expect(await unsign(tb, a)).toBeNull();
    expect(await sign("same", a)).toBe(ta); // deterministic HMAC, same cached key
  });

  it("a rejected import is not cached; a later call retries", async () => {
    const real = crypto.subtle.importKey.bind(crypto.subtle);
    const spy = vi.spyOn(crypto.subtle, "importKey")
      .mockImplementationOnce(() => Promise.reject(new Error("import failed")))
      .mockImplementation(real);
    const secret = freshSecret();
    await expect(sign("p", secret)).rejects.toThrow(/import failed/);
    const token = await sign("p", secret);
    expect(await unsign(token, secret)).toBe("p");
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("stays bounded: overflowing the cap clears it and re-imports", async () => {
    const spy = vi.spyOn(crypto.subtle, "importKey");
    const first = freshSecret();
    await sign("p", first);
    for (let i = 0; i < 8; i++) await sign("p", freshSecret());
    const before = spy.mock.calls.length;
    await sign("p", first); // evicted by the clear → imported again
    expect(spy.mock.calls.length).toBe(before + 1);
  });
});
