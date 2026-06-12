import { describe, it, expect, beforeEach } from "vitest";
import { loadConfig } from "../src/config.js";
import { resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const HMAC_KEY = "test-hmac-key-at-least-32-bytes-long!!";

// A minimal valid ConfigStore bag; individual tests override one field to prove
// the load-time invariant.
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

describe("loadConfig fail-closed invariants", () => {
  it("loads a valid configuration", async () => {
    seedConfig(VALID);
    const config = await loadConfig();
    expect(config.issuer).toBe("https://op.test");
    expect(config.policy.default_tier).toBe("protected");
  });

  it("fails closed when the policy JSON is malformed (H2)", async () => {
    seedConfig({ ...VALID, policy: "{not valid json" });
    await expect(loadConfig()).rejects.toThrow();
  });
});
