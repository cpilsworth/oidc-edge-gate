import { describe, it, expect, vi, beforeEach } from "vitest";

// Simulates a Cloud Manager SANDBOX program, where the edge-function service
// stores are NOT provisioned: constructing a ConfigStore/SecretStore throws
// ("No ConfigStore named 'config_default' exists"). The loader must use
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

import { loadGateConfig } from "../src/kernel/config.js";
import { EMBEDDED_CONFIGS, EMBEDDED_SECRETS } from "../src/embedded-config.js";
import { resetStubs } from "./stubs/state.js";

beforeEach(() => {
  resetStubs();
});

describe("loadGateConfig on a sandbox program (stores unprovisioned)", () => {
  it("uses embedded config + secrets instead of throwing", async () => {
    const { platform, config, secret, rawPolicy, kv, warnings } = await loadGateConfig();
    expect(platform.profile).toBe("sandbox");
    expect(config.issuer).toBe(EMBEDDED_CONFIGS.issuer.replace(/\/$/, ""));
    expect(config.clientId).toBe(EMBEDDED_CONFIGS.client_id);
    expect(config.redirectUri).toBe(EMBEDDED_CONFIGS.redirect_uri);
    expect(config.originHostname).toBe(EMBEDDED_CONFIGS.origin_hostname);
    expect(secret("client_secret")).toBe(EMBEDDED_SECRETS.client_secret);
    expect(secret("session_hmac_key")).toBe(EMBEDDED_SECRETS.session_hmac_key);
    expect(rawPolicy.default_tier).toBe("protected");
    // The embedded config declares the sandbox profile, so there is no "not declared" warning.
    expect(warnings).toEqual([]);
    // KV also unprovisioned on sandbox -> null, not a crash.
    expect(kv).toBeNull();
  });

  it("embedded session_hmac_key satisfies the >=32-byte invariant", () => {
    expect(new TextEncoder().encode(EMBEDDED_SECRETS.session_hmac_key).length).toBeGreaterThanOrEqual(32);
  });
});
