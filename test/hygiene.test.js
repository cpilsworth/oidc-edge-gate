// W0.5 hygiene: best-effort discovery/JWKS caching, explicit Fastly cache
// overrides on IdP fetches, and the imported-HMAC-key cache.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// Record BOTH constructor arguments so the mode and the init (ttl) can be
// asserted. The shared stub keeps only the first argument.
vi.mock("fastly:cache-override", () => ({
  CacheOverride: class {
    constructor(mode, init) {
      this.mode = mode;
      this.init = init;
    }
  },
}));

import { KVStore } from "fastly:kv-store";
import { getDiscovery, verifyIdToken } from "../src/jwt.js";
import { OidcClient } from "../src/oidc.js";
import { sign, unsign } from "../src/cookies.js";
import { readStateCookie, SESSION_COOKIE } from "../src/session.js";
import { createMockOp } from "./mock-op.js";
import { seedDiscovery, reqFor, getSetCookie, signJwt, makeRsaKey } from "./helpers.js";
import { resetStubs, getKvMap } from "./stubs/state.js";

const realFetch = globalThis.fetch;
let op, config, calls;

/** Route fetches to the mock OP, recording {url, method, init} for each. */
function recordingFetch() {
  calls = [];
  globalThis.fetch = (input, init) => {
    const r = new Request(input, init);
    calls.push({ url: new URL(r.url), method: r.method, init });
    return op.handle(r);
  };
}
const callsTo = (path) => calls.filter((c) => c.url.pathname === path);

/** A KV whose get and/or put throw (optionally only for keys matching `only`). */
function flakyKv({ getThrows = false, putThrows = false, only = /./ } = {}) {
  const kv = new KVStore("kv_default");
  if (getThrows) {
    const get = kv.get.bind(kv);
    kv.get = async (key) => { if (only.test(key)) throw new Error(`kv get boom ${key}`); return get(key); };
  }
  if (putThrows) {
    const put = kv.put.bind(kv);
    kv.put = async (key, ...rest) => { if (only.test(key)) throw new Error(`kv put boom ${key}`); return put(key, ...rest); };
  }
  return kv;
}

function goodToken(kid = op.key.kid, privateKey = op.key.privateKey) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    { alg: "RS256", kid, typ: "JWT" },
    { iss: config.issuer, aud: "test-client", sub: "user-123", iat: now, exp: now + 3600, nonce: "n1" },
    privateKey,
  );
}

beforeEach(async () => {
  resetStubs();
  op = await createMockOp();
  config = {
    issuer: op.discovery.issuer, clientId: "test-client", clientSecret: "test-client-secret",
    redirectUri: "https://www.example.com/.auth/callback",
    scopes: "openid profile email groups", sessionTtlSeconds: 3600,
    sessionKey: "test-hmac-key-at-least-32-bytes-long!!",
    groupsClaim: "groups",
    cache: new KVStore("kv_default"),
    routes: { callback: "/.auth/callback", logout: "/.auth/logout" },
  };
  recordingFetch();
});

afterEach(() => {
  globalThis.fetch = realFetch;
  vi.restoreAllMocks();
});

describe("best-effort discovery/JWKS cache", () => {
  it("a throwing KV put still lets discovery succeed (and logs without the key)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    config.cache = flakyKv({ putThrows: true });
    const d = await getDiscovery(config);
    expect(d.token_endpoint).toBe(op.discovery.token_endpoint);
    expect(callsTo("/.well-known/openid-configuration")).toHaveLength(1);
    expect(warn).toHaveBeenCalled();
    for (const [msg] of warn.mock.calls) expect(String(msg)).not.toContain("oidc:discovery:");
  });

  it("a throwing KV put still lets JWKS fetch + token verification succeed", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    // Discovery cached (readable), JWKS not cached → live fetch, then failing put.
    getKvMap("kv_default").set(`oidc:discovery:${config.issuer}`,
      JSON.stringify({ value: op.discovery, expires: Date.now() + 3600_000 }));
    config.cache = flakyKv({ putThrows: true });
    const claims = await verifyIdToken(await goodToken(), config, "n1");
    expect(claims.sub).toBe("user-123");
    expect(callsTo("/jwks")).toHaveLength(1);
  });

  it("a throwing KV get falls back to a live fetch for discovery and JWKS", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    seedDiscovery(config.issuer, op.discovery, op.jwks); // present, but unreadable
    config.cache = flakyKv({ getThrows: true });
    const claims = await verifyIdToken(await goodToken(), config, "n1");
    expect(claims.sub).toBe("user-123");
    expect(callsTo("/.well-known/openid-configuration")).toHaveLength(1);
    expect(callsTo("/jwks")).toHaveLength(1);
    expect(warn).toHaveBeenCalled();
    for (const [msg] of warn.mock.calls) expect(String(msg)).not.toMatch(/oidc:(discovery|jwks):/);
  });

  it("the single-use state marker stays fail-closed when KV put throws", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    seedDiscovery(config.issuer, op.discovery, op.jwks);
    config.cache = flakyKv({ putThrows: true, only: /^oidc:state-used:/ });
    const oidc = new OidcClient(config);
    const start = await oidc.startLogin(reqFor("/members/x"), new URL("https://www.example.com/members/x"));
    const loginCookie = getSetCookie(start, "__Host-edge_login");
    const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__Host-edge_login=${loginCookie}` }), config);
    const authUrl = new URL(start.headers.get("location"));
    op.issueCode("code-1", { claims: { nonce: saved.nonce }, accessToken: "atk",
      codeChallenge: authUrl.searchParams.get("code_challenge") });
    const cbUrl = new URL("https://www.example.com/.auth/callback");
    cbUrl.searchParams.set("state", saved.state);
    cbUrl.searchParams.set("code", "code-1");
    const cbReq = reqFor(cbUrl.pathname + cbUrl.search, { cookie: `__Host-edge_login=${loginCookie}` });
    await expect(oidc.handleCallback(cbReq, cbUrl)).rejects.toThrow(/kv put boom/);
    expect(callsTo("/token")).toHaveLength(0); // no token exchange, no session
  });
});

describe("Fastly cache overrides on IdP fetches", () => {
  it("discovery and JWKS fetches use override with a 3600s TTL", async () => {
    config.cache = null; // sandbox: no KV, so both are live fetches
    await verifyIdToken(await goodToken(), config, "n1");
    for (const path of ["/.well-known/openid-configuration", "/jwks"]) {
      const [c] = callsTo(path);
      expect(c.init.cacheOverride.mode).toBe("override");
      expect(c.init.cacheOverride.init).toEqual({ ttl: 3600 });
    }
  });

  it("the forced JWKS refetch after a kid miss uses pass", async () => {
    seedDiscovery(config.issuer, op.discovery, op.jwks); // cache holds only the old key
    const rotated = await makeRsaKey("key-B");
    op.jwks.keys = [op.key.publicJwk, rotated.publicJwk];
    const claims = await verifyIdToken(await goodToken("key-B", rotated.privateKey), config, "n1");
    expect(claims.sub).toBe("user-123");
    const jwks = callsTo("/jwks");
    expect(jwks).toHaveLength(1);
    expect(jwks[0].init.cacheOverride.mode).toBe("pass");
  });

  it("the token exchange POST uses pass", async () => {
    seedDiscovery(config.issuer, op.discovery, op.jwks);
    const oidc = new OidcClient(config);
    const start = await oidc.startLogin(reqFor("/members/x"), new URL("https://www.example.com/members/x"));
    const loginCookie = getSetCookie(start, "__Host-edge_login");
    const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__Host-edge_login=${loginCookie}` }), config);
    const authUrl = new URL(start.headers.get("location"));
    op.issueCode("code-1", { claims: { nonce: saved.nonce }, accessToken: "atk",
      codeChallenge: authUrl.searchParams.get("code_challenge") });
    const cbUrl = new URL("https://www.example.com/.auth/callback");
    cbUrl.searchParams.set("state", saved.state);
    cbUrl.searchParams.set("code", "code-1");
    const res = await oidc.handleCallback(
      reqFor(cbUrl.pathname + cbUrl.search, { cookie: `__Host-edge_login=${loginCookie}` }), cbUrl);
    expect(res.status).toBe(302);
    expect(getSetCookie(res, SESSION_COOKIE)).toBeTruthy();
    const [tok] = callsTo("/token");
    expect(tok.method).toBe("POST");
    expect(tok.init.cacheOverride.mode).toBe("pass");
  });
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
