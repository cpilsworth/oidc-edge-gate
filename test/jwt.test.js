import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { KVStore } from "fastly:kv-store";
import { verifyIdToken } from "../src/jwt.js";
import { createMockOp } from "./mock-op.js";
import { signJwt, seedDiscovery, makeRsaKey } from "./helpers.js";
import { resetStubs } from "./stubs/state.js";

let op, config;
const realFetch = globalThis.fetch;

async function tokenFromMock(opts) {
  return op.mintIdToken(opts);
}

beforeEach(async () => {
  resetStubs();
  op = await createMockOp();
  // edge-gate's jwt.js reads config.cache (KV) and config.backends.idp.
  config = {
    issuer: op.discovery.issuer,
    clientId: "test-client",
    cache: new KVStore("oidc_cache"),
    backends: { origin: "origin", idp: "idp" },
  };
  seedDiscovery(config.issuer, op.discovery, op.jwks);
  // Route the gate's discovery/JWKS fetches to the mock OP.
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
});

afterEach(() => { globalThis.fetch = realFetch; });

describe("verifyIdToken — happy path", () => {
  it("accepts a valid token and returns claims", async () => {
    const t = await tokenFromMock({ nonce: "n1" });
    const claims = await verifyIdToken(t, config, "n1");
    expect(claims.sub).toBe("user-123");
    expect(claims.groups).toEqual(["site-readers"]);
  });
  it("validates at_hash/c_hash when present (N11 positive)", async () => {
    const t = await tokenFromMock({ nonce: "n1", accessToken: "atk", code: "code-1" });
    const claims = await verifyIdToken(t, config, "n1", { accessToken: "atk", code: "code-1" });
    expect(claims.sub).toBe("user-123");
  });
});

describe("verifyIdToken — negative matrix", () => {
  it("N1 invalid signature", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "bad-sig" }), config, "n1"))
      .rejects.toThrow(/signature/);
  });
  it("N2 alg:none", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "alg-none" }), config, "n1"))
      .rejects.toThrow(/alg/);
  });
  it("N3 wrong iss", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "wrong-iss" }), config, "n1"))
      .rejects.toThrow(/iss/);
  });
  it("N3 iss with trailing slash is accepted (Auth0 issuer format)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer + "/", aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    const claims = await verifyIdToken(token, config, "n1");
    expect(claims.sub).toBe("user-123");
  });
  it("N4 wrong aud", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "wrong-aud" }), config, "n1"))
      .rejects.toThrow(/aud/);
  });
  it("N4b multi-aud without azp", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "multi-aud-no-azp" }), config, "n1"))
      .rejects.toThrow(/azp/);
  });
  it("N5 expired", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "expired" }), config, "n1"))
      .rejects.toThrow(/expired/);
  });
  it("N6 nonce mismatch", async () => {
    await expect(verifyIdToken(await tokenFromMock({ nonce: "n1", broken: "bad-nonce" }), config, "n1"))
      .rejects.toThrow(/nonce/);
  });
  it("N11 at_hash mismatch", async () => {
    const t = await tokenFromMock({ nonce: "n1", accessToken: "atk", code: "code-1", broken: "bad-at-hash" });
    await expect(verifyIdToken(t, config, "n1", { accessToken: "atk", code: "code-1" }))
      .rejects.toThrow(/at_hash/);
  });
  it("N11 c_hash mismatch", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1", c_hash: "AAAAAAAAAAAAAAAAAAAAAA" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1", { code: "real-code" }))
      .rejects.toThrow(/c_hash/);
  });
  it("M2 single-aud token with wrong azp is rejected", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1", azp: "other-client" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/azp/);
  });
});

describe("verifyIdToken — I1 exp required and iat cannot be in the future", () => {
  it("I1a rejects a token with exp omitted", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, nonce: "n1" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/expired/);
  });

  it("I1b rejects a token with iat far in the future", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now + 100000, exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/iat/);
  });

  it("I1c rejects a token with sub omitted", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/sub/);
  });

  it("I1d rejects a token with iat omitted", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: op.key.kid, typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        exp: now + 3600, nonce: "n1" },
      op.key.privateKey,
    );
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/iat/);
  });
});

describe("verifyIdToken — N7 kid rotation (refetch JWKS exactly once)", () => {
  // The cache (seeded in beforeEach) holds only the original "test-key-1". A fetch spy
  // counts live /jwks hits to prove the refetch happens EXACTLY once — an implementation
  // that loops would fail the count assertion even though the resolve/reject is correct.
  function spyJwks() {
    let n = 0;
    globalThis.fetch = (input, init) => {
      const r = new Request(input, init);
      if (new URL(r.url).pathname === "/jwks") n++;
      return op.handle(r);
    };
    return () => n;
  }

  it("refetches once and accepts a key present only in the FRESH JWKS", async () => {
    const rotated = await makeRsaKey("key-B");
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: "key-B", typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "user-123", groups: ["site-readers"],
        iat: now, exp: now + 3600, nonce: "n1" },
      rotated.privateKey,
    );
    op.jwks.keys = [op.key.publicJwk, rotated.publicJwk]; // live JWKS rotated; cache still stale
    const count = spyJwks();
    const claims = await verifyIdToken(token, config, "n1");
    expect(claims.sub).toBe("user-123");
    expect(count()).toBe(1); // exactly one forced refetch
  });

  it("refetches once then rejects a kid present NOWHERE", async () => {
    const ghost = await makeRsaKey("ghost-key");
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { alg: "RS256", kid: "ghost-key", typ: "JWT" },
      { iss: config.issuer, aud: "test-client", sub: "x", iat: now, exp: now + 3600, nonce: "n1" },
      ghost.privateKey,
    );
    const count = spyJwks(); // live JWKS unchanged → ghost-key absent everywhere
    await expect(verifyIdToken(token, config, "n1")).rejects.toThrow(/no JWKS key/);
    expect(count()).toBe(1); // refetched exactly once before giving up — not a loop
  });
});
