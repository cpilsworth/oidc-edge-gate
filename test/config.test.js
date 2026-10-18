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

  it("H6 rejects a session_hmac_key shorter than 32 bytes", async () => {
    seedConfig(VALID);
    seedSecrets({ client_secret: "test-client-secret", session_hmac_key: "too-short" });
    await expect(loadConfig()).rejects.toThrow(/hmac/i);
  });

  it("H6 accepts a session_hmac_key of exactly 32 bytes", async () => {
    seedConfig(VALID);
    seedSecrets({ client_secret: "test-client-secret", session_hmac_key: "x".repeat(32) });
    await expect(loadConfig()).resolves.toBeTruthy();
  });

  it("parses recaptcha_min_score", async () => {
    seedConfig({ ...VALID, recaptcha_min_score: "0.5" });
    expect((await loadConfig()).recaptchaMinScore).toBe(0.5);
  });

  it.each(["1.5", "-0.1", "abc", "0.5abc", "NaN", "Infinity"])("rejects an invalid recaptcha_min_score %j (fail closed)", async (value) => {
    seedConfig({ ...VALID, recaptcha_min_score: value });
    await expect(loadConfig()).rejects.toThrow(/recaptcha_min_score/);
  });

  it("H6 rejects a non-numeric session_ttl_seconds", async () => {
    seedConfig({ ...VALID, session_ttl_seconds: "not-a-number" });
    await expect(loadConfig()).rejects.toThrow(/ttl/i);
  });

  it("H6 rejects a non-positive session_ttl_seconds", async () => {
    seedConfig({ ...VALID, session_ttl_seconds: "0" });
    await expect(loadConfig()).rejects.toThrow(/ttl/i);
  });
});
