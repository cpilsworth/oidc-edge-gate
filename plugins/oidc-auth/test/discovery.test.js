// Discovery: validation (H8), fetch failures, the per-request memo, the
// best-effort KV cache layer and the fetch purpose/cache options.
import { readFileSync } from "node:fs";
import { describe, it, expect, beforeAll } from "vitest";
import { getDiscovery, discoveryKey, jwksKey } from "../lib/discovery.js";
import { ISSUER, makeCtx, newOp, opFetch } from "./support.js";

const wrap = (value) => JSON.stringify({ value, expires: Date.now() + 3600_000 });
const goodDoc = (issuer) => ({
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`,
  jwks_uri: `${issuer}/jwks`,
  end_session_endpoint: `${issuer}/logout`,
});
const noFetch = () => { throw new Error("unexpected live fetch"); };
const ctxWithCachedDoc = (doc, issuer = ISSUER) => makeCtx("/", { kv: { [discoveryKey(issuer)]: wrap(doc) }, fetch: noFetch });

let op;
beforeAll(async () => { op = await newOp(); });

describe("validation (H8): on every return, cache hits included", () => {
  it("accepts a well-formed https document", async () => {
    expect((await getDiscovery(ctxWithCachedDoc(goodDoc(ISSUER)), ISSUER)).token_endpoint).toBe("https://op.test/token");
  });

  it("accepts an issuer with a trailing slash (Auth0 format)", async () => {
    await expect(getDiscovery(ctxWithCachedDoc({ ...goodDoc(ISSUER), issuer: `${ISSUER}/` }), ISSUER)).resolves.toBeTruthy();
  });

  it.each([
    ["an issuer that does not match config", { issuer: "https://evil.test" }, /issuer/],
    ["a missing issuer", { issuer: undefined }, /issuer/],
    ["a non-secure (http) endpoint on a non-loopback host", { token_endpoint: "http://op.test/token" }, /token_endpoint is not a secure URL/],
    ["a non-URL endpoint", { jwks_uri: "not a url" }, /jwks_uri is not a secure URL/],
    ["a non-string endpoint", { jwks_uri: 12345 }, /jwks_uri is not a secure URL/],
    ["a missing authorization_endpoint", { authorization_endpoint: undefined }, /authorization_endpoint/],
    ["a string token_endpoint_auth_methods_supported", { token_endpoint_auth_methods_supported: "client_secret_basic" }, /token_endpoint_auth_methods_supported is not an array of strings/],
    ["a null token_endpoint_auth_methods_supported", { token_endpoint_auth_methods_supported: null }, /token_endpoint_auth_methods_supported/],
    ["an object token_endpoint_auth_methods_supported", { token_endpoint_auth_methods_supported: { 0: "client_secret_post" } }, /token_endpoint_auth_methods_supported/],
    ["a non-string auth method entry", { token_endpoint_auth_methods_supported: ["client_secret_post", 7] }, /token_endpoint_auth_methods_supported/],
  ])("rejects %s", async (_label, patch, msg) => {
    await expect(getDiscovery(ctxWithCachedDoc({ ...goodDoc(ISSUER), ...patch }), ISSUER)).rejects.toThrow(msg);
  });

  it.each([
    ["absent", undefined],
    ["an empty array", []],
    ["an array of strings (unknown methods included)", ["client_secret_basic", "private_key_jwt"]],
  ])("accepts token_endpoint_auth_methods_supported %s", async (_label, methods) => {
    const d = await getDiscovery(ctxWithCachedDoc({ ...goodDoc(ISSUER), token_endpoint_auth_methods_supported: methods }), ISSUER);
    expect(d.token_endpoint_auth_methods_supported).toEqual(methods);
  });

  it("accepts the synthetic Janrain discovery fixture", async () => {
    const doc = JSON.parse(readFileSync(new URL("../../../test/fixtures/janrain-discovery.json", import.meta.url), "utf8"));
    const d = await getDiscovery(ctxWithCachedDoc(doc, doc.issuer), doc.issuer);
    expect(d.token_endpoint_auth_methods_supported).toEqual(["client_secret_basic", "client_secret_post"]);
  });

  it("rejects a non-object document", async () => {
    await expect(getDiscovery(ctxWithCachedDoc("nope"), ISSUER)).rejects.toThrow(/not an object/);
  });

  it("allows http endpoints on loopback for local dev", async () => {
    const local = "http://127.0.0.1:7681";
    const d = await getDiscovery(ctxWithCachedDoc(goodDoc(local), local), local);
    expect(d.token_endpoint).toBe("http://127.0.0.1:7681/token");
  });
});

describe("live fetch", () => {
  it("fetches through ctx.fetch with purpose 'discovery' and cache {ttl: 3600}", async () => {
    const ctx = makeCtx("/", { op });
    await getDiscovery(ctx, ISSUER);
    expect(ctx.recorded.fetches).toHaveLength(1);
    expect(ctx.recorded.fetches[0]).toMatchObject({ url: `${ISSUER}/.well-known/openid-configuration`, method: "GET" });
    expect(ctx.recorded.fetches[0].opts).toEqual({ purpose: "discovery", cache: { ttl: 3600 } });
  });

  it("a non-OK response throws", async () => {
    const ctx = makeCtx("/", { fetch: async () => new Response("server error", { status: 500 }) });
    await expect(getDiscovery(ctx, ISSUER)).rejects.toThrow(/discovery fetch failed: 500/);
  });

  it("is memoized per request (one fetch however often a request needs it)", async () => {
    const ctx = makeCtx("/", { op });
    const a = await getDiscovery(ctx, ISSUER);
    const b = await getDiscovery(ctx, ISSUER);
    expect(b).toBe(a);
    expect(ctx.recorded.fetches).toHaveLength(1);
  });

  it("a failed fetch is not memoized", async () => {
    let n = 0;
    const ctx = makeCtx("/", { fetch: async (i, init) => (++n === 1 ? new Response("x", { status: 503 }) : op.handle(new Request(i, init))) });
    await expect(getDiscovery(ctx, ISSUER)).rejects.toThrow();
    await expect(getDiscovery(ctx, ISSUER)).resolves.toBeTruthy();
  });

  it("an invalid live document is not memoized or trusted", async () => {
    const ctx = makeCtx("/", { fetch: async () => Response.json({ ...goodDoc(ISSUER), issuer: "https://evil.test" }) });
    await expect(getDiscovery(ctx, ISSUER)).rejects.toThrow(/issuer/);
    await expect(getDiscovery(ctx, ISSUER)).rejects.toThrow(/issuer/);
    expect(ctx.recorded.fetches).toHaveLength(2);
  });
});

describe("KV cache layer (best-effort)", () => {
  it("no KV: every request fetches live", async () => {
    for (let i = 0; i < 2; i += 1) {
      const ctx = makeCtx("/", { op });
      await getDiscovery(ctx, ISSUER);
      expect(ctx.recorded.fetches).toHaveLength(1);
    }
  });

  it("KV present: written after a live fetch, then served from KV (wrapped, 1 h)", async () => {
    const first = makeCtx("/", { op, kv: true });
    await getDiscovery(first, ISSUER);
    expect([...first.recorded.kv.keys()]).toEqual([discoveryKey(ISSUER)]);
    const stored = JSON.parse(first.recorded.kv.get(discoveryKey(ISSUER)));
    expect(stored.value.token_endpoint).toBe(op.discovery.token_endpoint);
    expect(stored.expires - Date.now()).toBeGreaterThan(3500_000);

    const second = makeCtx("/", { kv: first.recorded.kv, fetch: noFetch });
    await expect(getDiscovery(second, ISSUER)).resolves.toMatchObject({ token_endpoint: op.discovery.token_endpoint });
  });

  it("an expired KV entry is refetched", async () => {
    const ctx = makeCtx("/", { op, kv: { [discoveryKey(ISSUER)]: JSON.stringify({ value: goodDoc(ISSUER), expires: Date.now() - 1 }) } });
    await getDiscovery(ctx, ISSUER);
    expect(ctx.recorded.fetches).toHaveLength(1);
  });

  it("a throwing KV get falls back to a live fetch and logs without the key", async () => {
    const ctx = makeCtx("/", { op });
    ctx.kv = { async get() { throw new Error("kv get boom"); }, async put() {}, async delete() {} };
    await expect(getDiscovery(ctx, ISSUER)).resolves.toBeTruthy();
    expect(ctx.recorded.fetches).toHaveLength(1);
    const warns = ctx.recorded.logs.filter((l) => l.level === "warn");
    expect(warns.map((l) => l.msg)).toEqual(["oidc discovery cache read failed; fetching live"]);
    expect(JSON.stringify(ctx.recorded.logs)).not.toContain("oidc:discovery:");
  });

  it("a throwing KV put still returns the document and logs without the key", async () => {
    const ctx = makeCtx("/", { op });
    ctx.kv = { async get() { return null; }, async put() { throw new Error("kv put boom"); }, async delete() {} };
    await expect(getDiscovery(ctx, ISSUER)).resolves.toBeTruthy();
    expect(ctx.recorded.logs.map((l) => l.msg)).toEqual(["oidc discovery cache write failed; continuing uncached"]);
    expect(JSON.stringify(ctx.recorded.logs)).not.toContain("oidc:");
  });

  it("KV keys are the pre-plugin key names (inside the kernel's plugin:oidc-auth: namespace)", () => {
    expect(discoveryKey(ISSUER)).toBe("oidc:discovery:https://op.test");
    expect(jwksKey(`${ISSUER}/jwks`)).toBe("oidc:jwks:https://op.test/jwks");
  });

  it("ctx.fetch routing sanity: the mock OP serves discovery", async () => {
    const res = await opFetch(op)(`${ISSUER}/.well-known/openid-configuration`);
    expect((await res.json()).issuer).toBe(ISSUER);
  });
});
