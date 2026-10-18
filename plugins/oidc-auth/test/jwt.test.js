// ID token verification matrix (ported from the legacy test/jwt.test.js and
// the JWKS parts of test/hygiene.test.js / test/discovery.test.js).
import { describe, it, expect, beforeEach } from "vitest";
import { verifyIdToken } from "../lib/jwt.js";
import { jwksKey } from "../lib/discovery.js";
import { makeRsaKey, signJwt } from "../../../test/helpers.js";
import { CLIENT_ID, ISSUER, makeCtx, newOp } from "./support.js";

let op;
let expectations;
beforeEach(async () => {
  op = await newOp();
  expectations = { issuer: ISSUER, clientId: CLIENT_ID, jwksUri: op.discovery.jwks_uri };
});

const verify = (token, { ctx = makeCtx("/", { op }), nonce = "n1", hashes } = {}) => verifyIdToken(ctx, token, expectations, nonce, hashes);
const mock = (opts) => op.mintIdToken(opts);
const now = () => Math.floor(Date.now() / 1000);
function signed(claims, header = {}) {
  return signJwt({ alg: "RS256", kid: op.key.kid, typ: "JWT", ...header }, claims, op.key.privateKey);
}
const base = () => ({ iss: ISSUER, aud: CLIENT_ID, sub: "user-123", groups: ["site-readers"], iat: now(), exp: now() + 3600, nonce: "n1" });

describe("happy path", () => {
  it("accepts a valid token and returns its claims", async () => {
    const claims = await verify(await mock({ nonce: "n1" }));
    expect(claims.sub).toBe("user-123");
    expect(claims.groups).toEqual(["site-readers"]);
  });

  it("validates at_hash / c_hash when present (N11 positive)", async () => {
    const t = await mock({ nonce: "n1", accessToken: "atk", code: "code-1" });
    expect((await verify(t, { hashes: { accessToken: "atk", code: "code-1" } })).sub).toBe("user-123");
  });

  it("accepts an iss with a trailing slash (Auth0 issuer format)", async () => {
    expect((await verify(await signed({ ...base(), iss: `${ISSUER}/` }))).sub).toBe("user-123");
  });

  it("accepts a token without a typ header (typ is optional)", async () => {
    const h = { alg: "RS256", kid: op.key.kid };
    expect((await verify(await signJwt(h, base(), op.key.privateKey))).sub).toBe("user-123");
  });

  it("accepts a multi-valued aud that includes the client id when azp is the client id", async () => {
    expect((await verify(await signed({ ...base(), aud: [CLIENT_ID, "other"], azp: CLIENT_ID }))).sub).toBe("user-123");
  });
});

describe("negative matrix", () => {
  it.each([
    ["N1 invalid signature", { broken: "bad-sig" }, /signature/],
    ["N2 alg:none", { broken: "alg-none" }, /alg/],
    ["N3 wrong iss", { broken: "wrong-iss" }, /iss/],
    ["N4 wrong aud", { broken: "wrong-aud" }, /aud/],
    ["N4b multi-aud without azp", { broken: "multi-aud-no-azp" }, /azp/],
    ["N5 expired", { broken: "expired" }, /expired/],
    ["N6 nonce mismatch", { broken: "bad-nonce" }, /nonce/],
  ])("%s", async (_label, opts, msg) => {
    await expect(verify(await mock({ nonce: "n1", ...opts }))).rejects.toThrow(msg);
  });

  it("N11 at_hash mismatch", async () => {
    const t = await mock({ nonce: "n1", accessToken: "atk", code: "code-1", broken: "bad-at-hash" });
    await expect(verify(t, { hashes: { accessToken: "atk", code: "code-1" } })).rejects.toThrow(/at_hash/);
  });

  it("N11 c_hash mismatch", async () => {
    await expect(verify(await signed({ ...base(), c_hash: "AAAAAAAAAAAAAAAAAAAAAA" }), { hashes: { code: "real-code" } })).rejects.toThrow(/c_hash/);
  });

  it("M2 single-aud token with a wrong azp", async () => {
    await expect(verify(await signed({ ...base(), azp: "other-client" }))).rejects.toThrow(/azp/);
  });

  it.each([
    ["I1a exp omitted", { exp: undefined }, /expired/],
    ["I1b iat far in the future", { iat: now() + 100000 }, /iat/],
    ["I1c sub omitted", { sub: undefined }, /sub/],
    ["I1d iat omitted", { iat: undefined }, /iat/],
    ["I1e iss omitted (deterministic, not a TypeError)", { iss: undefined }, /iss required/],
    ["nbf in the future (beyond skew)", { nbf: now() + 120 }, /not yet valid/],
  ])("%s", async (_label, patch, msg) => {
    await expect(verify(await signed({ ...base(), ...patch }))).rejects.toThrow(msg);
  });

  it("rejects an unsupported typ", async () => {
    await expect(verify(await signed(base(), { typ: "not-jwt" }))).rejects.toThrow(/typ/);
  });

  it("rejects a malformed JWT", async () => {
    await expect(verify("only.two")).rejects.toThrow(/malformed/);
    await expect(verify("nodots")).rejects.toThrow(/malformed/);
    await expect(verify(undefined)).rejects.toThrow(/malformed/);
  });
});

describe("JWKS fetch, cache and kid rotation (N7)", () => {
  const wrap = (value) => JSON.stringify({ value, expires: Date.now() + 3600_000 });

  it("fetches the JWKS with purpose 'jwks' and cache {ttl: 3600}", async () => {
    const ctx = makeCtx("/", { op });
    await verify(await mock({ nonce: "n1" }), { ctx });
    expect(ctx.recorded.fetches.map((f) => [f.url, f.opts])).toEqual([[op.discovery.jwks_uri, { purpose: "jwks", cache: { ttl: 3600 } }]]);
  });

  it("a cached JWKS needs no fetch", async () => {
    const ctx = makeCtx("/", { kv: { [jwksKey(op.discovery.jwks_uri)]: wrap(op.jwks) }, fetch: () => { throw new Error("no fetch"); } });
    expect((await verify(await mock({ nonce: "n1" }), { ctx })).sub).toBe("user-123");
  });

  it("kid miss: exactly one forced refetch (purpose 'jwks-refresh', default pass, KV bypassed), then accepts the rotated key", async () => {
    const rotated = await makeRsaKey("key-B");
    op.jwks.keys = [op.key.publicJwk, rotated.publicJwk]; // live JWKS rotated; the KV copy is stale
    const ctx = makeCtx("/", { op, kv: { [jwksKey(op.discovery.jwks_uri)]: wrap({ keys: [op.key.publicJwk] }) } });
    const token = await signJwt({ alg: "RS256", kid: "key-B", typ: "JWT" }, base(), rotated.privateKey);
    expect((await verify(token, { ctx })).sub).toBe("user-123");
    expect(ctx.recorded.fetches.map((f) => f.opts)).toEqual([{ purpose: "jwks-refresh" }]);
    // The fresh JWKS is written back to KV.
    expect(JSON.parse(ctx.recorded.kv.get(jwksKey(op.discovery.jwks_uri))).value.keys.map((k) => k.kid)).toEqual([op.key.kid, "key-B"]);
  });

  it("kid miss with no KV: one live 'jwks' fetch, then one 'jwks-refresh'", async () => {
    let n = 0;
    const ctx = makeCtx("/", {
      fetch: (i, init) => (++n === 1 ? Response.json({ keys: [] }) : op.handle(new Request(i, init))),
    });
    expect((await verify(await mock({ nonce: "n1" }), { ctx })).sub).toBe("user-123");
    expect(ctx.recorded.fetches.map((f) => f.opts.purpose)).toEqual(["jwks", "jwks-refresh"]);
    expect(ctx.recorded.fetches[1].opts.cache).toBeUndefined();
  });

  it("refetches once, then rejects a kid present nowhere (no loop)", async () => {
    const ghost = await makeRsaKey("ghost-key");
    const ctx = makeCtx("/", { op });
    const token = await signJwt({ alg: "RS256", kid: "ghost-key", typ: "JWT" }, base(), ghost.privateKey);
    await expect(verify(token, { ctx })).rejects.toThrow(/no JWKS key/);
    expect(ctx.recorded.fetches.map((f) => f.opts.purpose)).toEqual(["jwks", "jwks-refresh"]);
  });

  it("a non-OK JWKS response throws", async () => {
    const ctx = makeCtx("/", { fetch: async () => new Response("down", { status: 500 }) });
    await expect(verify(await mock({ nonce: "n1" }), { ctx })).rejects.toThrow(/jwks fetch failed: 500/);
  });

  it("a throwing KV put still lets JWKS fetch + verification succeed", async () => {
    const ctx = makeCtx("/", { op });
    ctx.kv = { async get() { return null; }, async put() { throw new Error("kv put boom"); }, async delete() {} };
    expect((await verify(await mock({ nonce: "n1" }), { ctx })).sub).toBe("user-123");
    expect(ctx.recorded.logs.map((l) => l.msg)).toEqual(["oidc jwks cache write failed; continuing uncached"]);
  });

  it("a throwing KV get falls back to a live JWKS fetch", async () => {
    const ctx = makeCtx("/", { op });
    ctx.kv = { async get() { throw new Error("kv get boom"); }, async put() {}, async delete() {} };
    expect((await verify(await mock({ nonce: "n1" }), { ctx })).sub).toBe("user-123");
    expect(ctx.recorded.fetches).toHaveLength(1);
  });
});

describe("JWKS key selection (use / alg filtering)", () => {
  it("rejects a key whose use is 'enc' even when the kid matches", async () => {
    op.jwks.keys = [{ ...op.key.publicJwk, use: "enc" }];
    await expect(verify(await mock({ nonce: "n1" }))).rejects.toThrow(/no JWKS key/);
  });

  it("rejects a key whose alg is 'RS512' even when the kid matches", async () => {
    op.jwks.keys = [{ ...op.key.publicJwk, alg: "RS512" }];
    await expect(verify(await mock({ nonce: "n1" }))).rejects.toThrow(/no JWKS key/);
  });

  it("accepts a key with no use/alg annotations (kid + kty checked)", async () => {
    const { kty, n, e, kid } = op.key.publicJwk;
    op.jwks.keys = [{ kty, n, e, kid }];
    expect((await verify(await mock({ nonce: "n1" }))).sub).toBe("user-123");
  });

  it("a JWKS without a keys array is treated as empty", async () => {
    const ctx = makeCtx("/", { fetch: async () => Response.json({}) });
    await expect(verify(await mock({ nonce: "n1" }), { ctx })).rejects.toThrow(/no JWKS key/);
  });
});
