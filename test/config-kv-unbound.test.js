import { describe, it, expect, vi, beforeEach } from "vitest";

// The platform layer opens `new KVStore("kv_default")` defensively and yields
// a null handle when KV is unbound (a minimal local run / misconfigured deploy).
// The default in-memory stub never throws, so this file mocks fastly:kv-store
// to throw on construction and asserts the loader still succeeds with
// kv === null (plus a warning) rather than crashing at load.
vi.mock("fastly:kv-store", () => ({
  KVStore: class {
    constructor() { throw new Error("KV store unbound"); }
  },
}));

import { loadGateConfig } from "../src/kernel/config.js";
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
  origin_hostname: "main--mysite--myorg.aem.live",
  forwarded_host: "www.example.com",
  push_invalidation: "enabled",
  policy: JSON.stringify({ rules: [{ path: "/", tier: "public" }], default_tier: "protected" }),
};

beforeEach(() => {
  resetStubs();
  seedSecrets({ client_secret: "test-client-secret", session_hmac_key: HMAC_KEY });
});

describe("loadGateConfig with KV unbound", () => {
  it("still loads successfully with kv === null when KVStore throws", async () => {
    seedConfig(VALID);
    const { kv, config, rawPolicy, platform, warnings } = await loadGateConfig();
    expect(kv).toBeNull();
    expect(platform.has("kv")).toBe(false);
    expect(warnings.some((w) => /KVStore/.test(w))).toBe(true);
    // The rest of the config is still fully populated.
    expect(config.issuer).toBe("https://op.test");
    expect(rawPolicy.default_tier).toBe("protected");
  });
});
