import { describe, it, expect, vi, beforeEach } from "vitest";

// Simulates a Cloud Manager SANDBOX program, where the edge-function service
// stores are NOT provisioned: constructing a ConfigStore/SecretStore throws
// ("No ConfigStore named 'config_default' exists"). loadConfig must fall back to
// the build-time embedded values (src/embedded-config.js) instead of letting the
// throw bubble into an opaque 500 on every request.
vi.mock("fastly:config-store", () => ({
  ConfigStore: class {
    constructor() { throw new Error("No ConfigStore named 'config_default' exists"); }
  },
}));
vi.mock("fastly:secret-store", () => ({
  SecretStore: class {
    constructor() { throw new Error("No SecretStore named 'secret_default' exists"); }
  },
}));
vi.mock("fastly:kv-store", () => ({
  KVStore: class {
    constructor() { throw new Error("No KVStore named 'kv_default' exists"); }
  },
}));

import { loadConfig } from "../src/config.js";
import { EMBEDDED_CONFIGS, EMBEDDED_SECRETS } from "../src/embedded-config.js";
import { resetStubs } from "./stubs/state.js";

beforeEach(() => {
  resetStubs();
});

describe("loadConfig on a sandbox program (stores unprovisioned)", () => {
  it("falls back to embedded config + secrets instead of throwing", async () => {
    const config = await loadConfig();
    expect(config.issuer).toBe(EMBEDDED_CONFIGS.issuer.replace(/\/$/, ""));
    expect(config.clientId).toBe(EMBEDDED_CONFIGS.client_id);
    expect(config.redirectUri).toBe(EMBEDDED_CONFIGS.redirect_uri);
    expect(config.originHostname).toBe(EMBEDDED_CONFIGS.origin_hostname);
    expect(config.clientSecret).toBe(EMBEDDED_SECRETS.client_secret);
    expect(config.sessionKey).toBe(EMBEDDED_SECRETS.session_hmac_key);
    expect(config.policy.default_tier).toBe("protected");
    // KV also unprovisioned on sandbox -> cache is null, not a crash.
    expect(config.cache).toBeNull();
  });

  it("embedded session_hmac_key satisfies the >=32-byte invariant", () => {
    expect(new TextEncoder().encode(EMBEDDED_SECRETS.session_hmac_key).length).toBeGreaterThanOrEqual(32);
  });
});
