import { describe, it, expect } from "vitest";
import { detectPlatform } from "../../src/kernel/platform/index.js";
import { describeEachProfile, makeProfileStores } from "../helpers/profiles.js";

// All secrets here are fakes owned by this test file.
const FAKE_SECRETS = { client_secret: "fake-client-secret", session_hmac_key: "fake-hmac-key-0123456789abcdef0123" };
const SECRET_KEYS = ["client_secret", "session_hmac_key", "recaptcha_secret"];
const EMBEDDED_CONFIGS = { issuer: "https://embedded.test", forwarded_host: "debug.example", platform_profile: "sandbox" };
const EMBEDDED_SECRETS = { client_secret: "fake-embedded-secret", session_hmac_key: "fake-embedded-hmac-0123456789abcdef" };
const OPTS = { embeddedConfigs: EMBEDDED_CONFIGS, embeddedSecrets: EMBEDDED_SECRETS, secretKeys: SECRET_KEYS };

const provisioned = (data = {}) =>
  makeProfileStores("provisioned", {
    config: { platform_profile: "provisioned", issuer: "https://store.test" },
    secrets: { secrets: JSON.stringify(FAKE_SECRETS) },
    ...data,
  });
const sandbox = () => makeProfileStores("sandbox");

describe("detectPlatform: provisioned", () => {
  it("detects provisioned when ConfigStore opens and exposes all stores", async () => {
    const det = detectPlatform(provisioned(), OPTS);
    expect(det.platform.profile).toBe("provisioned");
    expect(det.stores.config).not.toBeNull();
    expect(det.stores.secret).not.toBeNull();
    expect(det.stores.kv).not.toBeNull();
    expect(det.cfg("issuer")).toBe("https://store.test");
    expect(det.warnings).toEqual([]);
    expect(Object.isFrozen(det.platform)).toBe(true);
  });

  it("throws when the SecretStore cannot be opened (fails closed)", () => {
    const stores = { ...provisioned(), SecretStore: makeProfileStores("sandbox").SecretStore };
    expect(() => detectPlatform(stores, OPTS)).toThrow(/SecretStore "secret_default" failed to open/);
  });

  it("without KV: has('kv') false, warning recorded, still provisioned", () => {
    const det = detectPlatform(provisioned({ kv: false }), OPTS);
    expect(det.platform.profile).toBe("provisioned");
    expect(det.platform.has("kv")).toBe(false);
    expect(det.stores.kv).toBeNull();
    expect(det.warnings.some((w) => /KVStore "kv_default" unavailable \(Error\)/.test(w))).toBe(true);
  });

  it("config has NO embedded fallback (embedded-only key -> null)", () => {
    const det = detectPlatform(provisioned(), OPTS);
    expect(EMBEDDED_CONFIGS.forwarded_host).toBeDefined();
    expect(det.cfg("forwarded_host")).toBeNull();
    expect(det.cfg("nope")).toBeNull();
  });

  it("loadSecrets reads the JSON bundle", async () => {
    const det = detectPlatform(provisioned(), OPTS);
    const s = await det.loadSecrets();
    expect(s).toEqual(FAKE_SECRETS);
  });

  it("loadSecrets falls back to per-key lookup when no bundle is present", async () => {
    const det = detectPlatform(provisioned({ secrets: { client_secret: "fake-a", session_hmac_key: "fake-b", unrelated: "x" } }), OPTS);
    expect(await det.loadSecrets()).toEqual({ client_secret: "fake-a", session_hmac_key: "fake-b" });
  });

  it("loadSecrets never falls back to embedded secrets", async () => {
    const det = detectPlatform(provisioned({ secrets: {} }), OPTS);
    expect(await det.loadSecrets()).toEqual({});
  });

  it("malformed bundle throws without echoing its contents", async () => {
    const det = detectPlatform(provisioned({ secrets: { secrets: "{not json SUPERSECRET", client_secret: "fake-a" } }), OPTS);
    const err = await det.loadSecrets().catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toMatch(/not valid JSON/);
    expect(err.message).not.toContain("SUPERSECRET");
  });

  it.each([
    ["array", "[\"a\"]"],
    ["null", "null"],
    ["string", "\"x\""],
    ["non-string value", "{\"client_secret\":42}"],
  ])("bundle that is not an object of strings (%s) throws", async (_n, raw) => {
    const det = detectPlatform(provisioned({ secrets: { secrets: raw } }), OPTS);
    await expect(det.loadSecrets()).rejects.toThrow(/must be a JSON object of strings/);
  });
});

describe("detectPlatform: sandbox", () => {
  it("detects sandbox when ConfigStore throws; config + secrets from embedded objects", async () => {
    const det = detectPlatform(sandbox(), OPTS);
    expect(det.platform.profile).toBe("sandbox");
    expect(det.stores).toEqual({ config: null, secret: null, kv: null });
    expect(det.cfg("issuer")).toBe(EMBEDDED_CONFIGS.issuer);
    expect(det.cfg("missing")).toBeNull();
    expect(det.cfg("toString")).toBeNull(); // no prototype leakage
    const s = await det.loadSecrets();
    expect(s).toEqual(EMBEDDED_SECRETS);
    expect(s).not.toBe(EMBEDDED_SECRETS); // shallow copy
    s.client_secret = "mutated";
    expect(EMBEDDED_SECRETS.client_secret).toBe("fake-embedded-secret");
    expect(det.warnings).toEqual([]);
  });

  it("does not open the SecretStore even if one would open", () => {
    let opened = false;
    const stores = { ...sandbox(), SecretStore: class { constructor() { opened = true; } } };
    const det = detectPlatform(stores, OPTS);
    expect(opened).toBe(false);
    expect(det.platform.has("secret-store")).toBe(false);
  });

  it("uses a KV store when one is bound (local dev)", () => {
    const stores = { ...sandbox(), KVStore: makeProfileStores("provisioned").KVStore };
    const det = detectPlatform(stores, OPTS);
    expect(det.platform.profile).toBe("sandbox");
    expect(det.platform.has("kv")).toBe(true);
    expect(det.stores.kv).not.toBeNull();
  });

  it("missing opts -> empty config and secrets", async () => {
    const det = detectPlatform(sandbox());
    expect(det.cfg("issuer")).toBeNull();
    expect(await det.loadSecrets()).toEqual({});
  });
});

describe("detectPlatform: declared platform_profile", () => {
  it("matching declaration passes (both profiles)", () => {
    expect(detectPlatform(provisioned(), OPTS).platform.profile).toBe("provisioned");
    expect(detectPlatform(sandbox(), OPTS).platform.profile).toBe("sandbox");
  });

  it("mismatch throws", () => {
    expect(() => detectPlatform(provisioned({ config: { platform_profile: "sandbox" } }), OPTS))
      .toThrow("platform_profile mismatch: declared sandbox, detected provisioned");
    expect(() => detectPlatform(sandbox(), { ...OPTS, embeddedConfigs: { platform_profile: "provisioned" } }))
      .toThrow("platform_profile mismatch: declared provisioned, detected sandbox");
  });

  it("absent declaration is allowed with a warning", () => {
    const p = detectPlatform(provisioned({ config: {} }), OPTS);
    expect(p.warnings).toContain('platform_profile not declared; detected "provisioned"');
    const s = detectPlatform(sandbox(), { ...OPTS, embeddedConfigs: {} });
    expect(s.warnings).toContain('platform_profile not declared; detected "sandbox"');
  });
});

// F5: the build pin (src/build-profile.js) turns a silent downgrade into a load error.
describe("detectPlatform: build pin (expectedProfile)", () => {
  it("a build pinned to provisioned throws when the ConfigStore throws (no silent sandbox downgrade)", () => {
    expect(() => detectPlatform(sandbox(), { ...OPTS, expectedProfile: "provisioned" }))
      .toThrow(/platform profile mismatch: build expects provisioned, detected sandbox \(ConfigStore "config_default": Error\)/);
  });
  it("a build pinned to sandbox throws when the stores are present", () => {
    expect(() => detectPlatform(provisioned(), { ...OPTS, expectedProfile: "sandbox" }))
      .toThrow("platform profile mismatch: build expects sandbox, detected provisioned");
  });
  it("a matching pin passes on both profiles", () => {
    expect(detectPlatform(provisioned(), { ...OPTS, expectedProfile: "provisioned" }).platform.profile).toBe("provisioned");
    expect(detectPlatform(sandbox(), { ...OPTS, expectedProfile: "sandbox" }).platform.profile).toBe("sandbox");
  });
  it("null / absent pin keeps detection-only behaviour", () => {
    expect(detectPlatform(sandbox(), { ...OPTS, expectedProfile: null }).platform.profile).toBe("sandbox");
    expect(detectPlatform(sandbox(), OPTS).platform.profile).toBe("sandbox");
  });
  it("an unknown pin value is rejected", () => {
    expect(() => detectPlatform(provisioned(), { ...OPTS, expectedProfile: "prod" })).toThrow(/expected platform profile/);
  });
  it("the pin error never echoes embedded secrets", () => {
    let msg = "";
    try { detectPlatform(sandbox(), { ...OPTS, expectedProfile: "provisioned" }); } catch (e) { msg = String(e && e.message); }
    expect(msg).not.toContain(EMBEDDED_SECRETS.client_secret);
  });
});

describe("detectPlatform: has() capability matrix", () => {
  const cases = [
    ["provisioned", () => provisioned(), { "config-store": true, "secret-store": true, kv: true }],
    ["provisioned, no KV", () => provisioned({ kv: false }), { "config-store": true, "secret-store": true, kv: false }],
    ["sandbox", () => sandbox(), { "config-store": false, "secret-store": false, kv: false }],
  ];
  it.each(cases)("%s", (_name, mk, expected) => {
    const { platform } = detectPlatform(mk(), OPTS);
    for (const [cap, v] of Object.entries(expected)) expect(platform.has(cap)).toBe(v);
    expect(platform.has("unknown")).toBe(false);
    expect(platform.has("toString")).toBe(false);
    expect(platform.has(undefined)).toBe(false);
  });
});

// Self-test for test/helpers/profiles.js.
const seen = [];
describeEachProfile("describeEachProfile helper", (profile, makeStores) => {
  it("passes the profile name and matching fake stores", async () => {
    seen.push(profile);
    const stores = makeStores({ config: { platform_profile: profile }, secrets: { session_hmac_key: "fake-k" }, kv: { a: "1" } });
    const det = detectPlatform(stores, { embeddedConfigs: { platform_profile: profile }, secretKeys: ["session_hmac_key"] });
    expect(det.platform.profile).toBe(profile);
    if (profile === "provisioned") {
      expect(await det.loadSecrets()).toEqual({ session_hmac_key: "fake-k" });
      expect(await (await det.stores.kv.get("a")).text()).toBe("1");
      expect(() => new stores.ConfigStore("other")).toThrow();
      expect(detectPlatform(makeStores({ kv: false })).platform.has("kv")).toBe(false);
    } else {
      expect(() => new stores.ConfigStore("config_default")).toThrow();
      expect(() => new stores.KVStore("kv_default")).toThrow();
    }
  });
});

describe("describeEachProfile covered both profiles", () => {
  it("ran for provisioned and sandbox", () => {
    expect([...seen].sort()).toEqual(["provisioned", "sandbox"]);
  });
});
