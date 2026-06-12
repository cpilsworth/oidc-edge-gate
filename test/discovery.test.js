import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { KVStore } from "fastly:kv-store";
import { getDiscovery } from "../src/jwt.js";
import { resetStubs, getKvMap } from "./stubs/state.js";

// H8: getDiscovery must validate the document — the issuer must match config and
// the endpoints interpolated into redirects/fetches must be secure URLs — so a
// misconfigured or poisoned cache/backend can't redirect users to an attacker.

const realFetch = globalThis.fetch;
let config;

function seedRawDiscovery(issuer, doc) {
  getKvMap("oidc_cache").set(`discovery:${issuer}`, JSON.stringify({ value: doc, expires: Date.now() + 3600_000 }));
}

function goodDoc(issuer) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    end_session_endpoint: `${issuer}/logout`,
  };
}

beforeEach(() => {
  resetStubs();
  config = { issuer: "https://op.test", cache: new KVStore("oidc_cache"), backends: { idp: "idp" } };
  // No live fetch should be needed — every test pre-seeds the cache.
  globalThis.fetch = () => { throw new Error("unexpected live fetch"); };
});
afterEach(() => { globalThis.fetch = realFetch; });

describe("getDiscovery validation (H8)", () => {
  it("accepts a well-formed https discovery document", async () => {
    seedRawDiscovery(config.issuer, goodDoc(config.issuer));
    const d = await getDiscovery(config);
    expect(d.token_endpoint).toBe("https://op.test/token");
  });

  it("rejects an issuer that does not match config", async () => {
    seedRawDiscovery(config.issuer, { ...goodDoc(config.issuer), issuer: "https://evil.test" });
    await expect(getDiscovery(config)).rejects.toThrow(/issuer/i);
  });

  it("rejects a non-secure (http) endpoint on a non-loopback host", async () => {
    seedRawDiscovery(config.issuer, { ...goodDoc(config.issuer), token_endpoint: "http://op.test/token" });
    await expect(getDiscovery(config)).rejects.toThrow();
  });

  it("rejects a non-URL endpoint", async () => {
    seedRawDiscovery(config.issuer, { ...goodDoc(config.issuer), jwks_uri: "not a url" });
    await expect(getDiscovery(config)).rejects.toThrow();
  });

  it("allows http endpoints on loopback for local dev", async () => {
    const local = "http://127.0.0.1:7681";
    const localConfig = { issuer: local, cache: new KVStore("oidc_cache"), backends: { idp: "idp" } };
    seedRawDiscovery(local, goodDoc(local));
    const d = await getDiscovery(localConfig);
    expect(d.token_endpoint).toBe("http://127.0.0.1:7681/token");
  });
});
