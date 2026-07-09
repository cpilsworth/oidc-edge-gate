import { describe, it, expect, vi, beforeEach } from "vitest";

// config.js's openCache() wraps `new KVStore("kv_default")` in try/catch and
// returns null when KV is unbound (a minimal local run / misconfigured deploy).
// The default in-memory stub never throws, so this file mocks fastly:kv-store
// to throw on construction and asserts loadConfig still succeeds with
// config.cache === null rather than crashing at load (line 77).
vi.mock("fastly:kv-store", () => ({
  KVStore: class {
    constructor() { throw new Error("KV store unbound"); }
  },
}));

import { loadConfig } from "../src/config.js";
import { resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const HMAC_KEY = "test-hmac-key-at-least-32-bytes-long!!";

const VALID = {
  issuer: "https://op.test",
  client_id: "test-client",
  redirect_uri: "https://www.example.com/.auth/callback",
  scopes: "openid profile email",
  session_ttl_seconds: "3600",
  groups_claim: "groups",
  routes: JSON.stringify({ callback: "/.auth/callback", logout: "/.auth/logout" }),
  backends: JSON.stringify({ origin: "origin", idp: "idp" }),
  origin_hostname: "main--mysite--myorg.aem.live",
  forwarded_host: "www.example.com",
  push_invalidation: "enabled",
  policy: JSON.stringify({ rules: [{ path: "/", tier: "public" }], default_tier: "protected" }),
};

beforeEach(() => {
  resetStubs();
  seedSecrets({ client_secret: "test-client-secret", session_hmac_key: HMAC_KEY });
});

describe("loadConfig with KV unbound (openCache fallback)", () => {
  it("still loads successfully with config.cache === null when KVStore throws", async () => {
    seedConfig(VALID);
    const config = await loadConfig();
    expect(config.cache).toBeNull();
    // The rest of the config is still fully populated.
    expect(config.issuer).toBe("https://op.test");
    expect(config.policy.default_tier).toBe("protected");
  });
});
