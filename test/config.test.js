import { describe, it, expect, beforeEach } from "vitest";
import { loadGateConfig as loadConfig, BUILT_IN_DEFAULTS } from "../src/kernel/config.js";
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
    const { config, rawPolicy, platform } = await loadConfig();
    expect(platform.profile).toBe("provisioned");
    expect(config.issuer).toBe("https://op.test");
    expect(rawPolicy.default_tier).toBe("protected");
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

  it("W2.R R9 rejects a session_hmac_key_previous shorter than 32 bytes (fail closed at load)", async () => {
    seedConfig(VALID);
    seedSecrets({ client_secret: "test-client-secret", session_hmac_key: "x".repeat(32), session_hmac_key_previous: "too-short" });
    await expect(loadConfig()).rejects.toThrow(/session_hmac_key_previous must be at least 32 bytes/);
    // The message never carries the value.
    await expect(loadConfig()).rejects.not.toThrow(/too-short/);
  });

  it("W2.R R9 accepts a 32-byte session_hmac_key_previous, and an absent or empty one", async () => {
    seedConfig(VALID);
    seedSecrets({ client_secret: "test-client-secret", session_hmac_key: "x".repeat(32), session_hmac_key_previous: "y".repeat(32) });
    expect((await loadConfig()).secret("session_hmac_key_previous")).toBe("y".repeat(32));
    for (const extra of [{ session_hmac_key_previous: "" }, {}]) {
      resetStubs();
      seedConfig(VALID);
      seedSecrets({ client_secret: "test-client-secret", session_hmac_key: "x".repeat(32), ...extra });
      const loaded = await loadConfig();
      expect(loaded.secret("session_hmac_key")).toBe("x".repeat(32));
    }
  });

  it("parses recaptcha_min_score", async () => {
    seedConfig({ ...VALID, recaptcha_min_score: "0.5" });
    expect((await loadConfig()).config.recaptchaMinScore).toBe(0.5);
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

describe("loadGateConfig shape (W1.3)", () => {
  it("config is frozen scalars without secrets; secret() looks up the loaded secrets", async () => {
    seedConfig(VALID);
    const { config, secret, kv } = await loadConfig();
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.routes)).toBe(true);
    expect(Object.keys(config).sort()).toEqual([
      "clientId", "forwardedHost", "groupsClaim", "issuer", "originHostname", "pushInvalidation",
      "recaptchaMinScore", "redirectUri", "routes", "scopes", "sessionTtlSeconds",
    ]);
    expect(JSON.stringify(config)).not.toContain("test-client-secret");
    expect(JSON.stringify(config)).not.toContain(HMAC_KEY);
    expect(secret("client_secret")).toBe("test-client-secret");
    expect(secret("nope")).toBeUndefined();
    expect(kv).not.toBeNull();
  });

  it("built-in defaults apply on provisioned (no embedded fallback), incl. recaptcha_min_score 0.5", async () => {
    // F13: the required keys must now be seeded (they have no default); every
    // other key still falls back to the built-in default, never the embedded value.
    const required = { issuer: "https://op.test", client_id: "store-client", redirect_uri: "https://store.example/.auth/callback", origin_hostname: "o.example", forwarded_host: "store.example" };
    seedConfig(required);
    const { config, rawPolicy } = await loadConfig();
    expect(config.recaptchaMinScore).toBe(0.5);
    expect(config.scopes).toBe("openid profile email");
    expect(config.sessionTtlSeconds).toBe(3600);
    expect(config.groupsClaim).toBe("groups");
    expect(config.routes).toEqual({ callback: "/.auth/callback", logout: "/.auth/logout" });
    expect(rawPolicy).toEqual(JSON.parse(BUILT_IN_DEFAULTS.policy));
    // §11: the embedded (sandbox) values never leak into a provisioned load.
    // (Was: forwardedHost/clientId null; those keys are required since F13, so
    // the leak check now uses keys that still have defaults.)
    expect(config.forwardedHost).toBe("store.example");
    expect(config.clientId).toBe("store-client");
    expect(config.pushInvalidation).toBe(false);       // embedded value is "enabled"
    expect(config.groupsClaim).not.toMatch(/^https:/); // embedded value is a namespaced claim
  });

  // F13: required config is checked at load, on both profiles.
  it.each(["issuer", "client_id", "redirect_uri", "origin_hostname", "forwarded_host"])("fails closed when required config %s is missing", async (key) => {
    const bag = { ...VALID };
    delete bag[key];
    seedConfig(bag);
    await expect(loadConfig()).rejects.toThrow(`Missing config: ${key}`);
  });

  it.each(["issuer", "client_id", "redirect_uri", "origin_hostname", "forwarded_host"])("fails closed when required config %s is empty", async (key) => {
    seedConfig({ ...VALID, [key]: "" });
    await expect(loadConfig()).rejects.toThrow(`Missing config: ${key}`);
    resetStubs();
    seedSecrets({ client_secret: "test-client-secret", session_hmac_key: HMAC_KEY });
    seedConfig({ ...VALID, [key]: "   " });
    await expect(loadConfig()).rejects.toThrow(`Missing config: ${key}`);
  });

  it.each(["issuer", "client_id", "redirect_uri", "origin_hostname", "forwarded_host"])("sandbox profile: fails closed when embedded %s is missing", async (key) => {
    const throwing = class { constructor() { throw new Error("not provisioned"); } };
    const embeddedConfigs = { ...VALID, platform_profile: "sandbox" };
    delete embeddedConfigs[key];
    await expect(loadConfig({
      stores: { ConfigStore: throwing, SecretStore: throwing, KVStore: throwing },
      embeddedConfigs,
      embeddedSecrets: { client_secret: "fake-embedded", session_hmac_key: HMAC_KEY },
    })).rejects.toThrow(`Missing config: ${key}`);
  });

  it("an explicitly empty recaptcha_min_score means no threshold", async () => {
    seedConfig({ ...VALID, recaptcha_min_score: "" });
    expect((await loadConfig()).config.recaptchaMinScore).toBeNull();
  });

  it("a secrets JSON bundle is used when present", async () => {
    resetStubs();
    seedConfig(VALID);
    seedSecrets({ secrets: JSON.stringify({ client_secret: "bundled", session_hmac_key: HMAC_KEY }) });
    expect((await loadConfig()).secret("client_secret")).toBe("bundled");
  });

  it("fails closed when a required secret is missing (no embedded fallback on provisioned)", async () => {
    resetStubs();
    seedConfig(VALID);
    seedSecrets({ session_hmac_key: HMAC_KEY });
    await expect(loadConfig()).rejects.toThrow(/client_secret/);
  });

  it("a declared platform_profile must match the detected one", async () => {
    seedConfig({ ...VALID, platform_profile: "provisioned" });
    await expect(loadConfig()).resolves.toBeTruthy();
    seedConfig({ ...VALID, platform_profile: "sandbox" });
    await expect(loadConfig()).rejects.toThrow(/platform_profile mismatch/);
  });

  it("rejects a routes value that is not a JSON object of paths", async () => {
    seedConfig({ ...VALID, routes: "{nope" });
    await expect(loadConfig()).rejects.toThrow(/routes/);
    seedConfig({ ...VALID, routes: JSON.stringify({ callback: "relative" }) });
    await expect(loadConfig()).rejects.toThrow(/routes.callback/);
  });

  it("error messages never echo the malformed JSON", async () => {
    seedConfig({ ...VALID, policy: "{\"x-secret\": \"leak-me\"" });
    await expect(loadConfig()).rejects.toThrow(/^policy is not valid JSON$/);
  });
});

describe("SECRET_KEYS (per-key SecretStore fallback)", () => {
  it("includes every secret a registered plugin declares", async () => {
    const { SECRET_KEYS } = await import("../src/kernel/config.js");
    const { default: plugins } = await import("../plugins/index.js");
    for (const p of plugins) for (const k of p.secrets) expect(SECRET_KEYS).toContain(k);
    expect(SECRET_KEYS).toContain("session_hmac_key_previous");
  });
});
