// W3.0: revocation config keys (docs/architecture/plugins.md §15.1, §15.4, §15.5).
//   revocation_mode       auto | required | optional | disabled (default auto)
//   session_min_iat       global cutoff, epoch seconds (default none)
//   revocation_admin_key  optional secret, ≥ 32 bytes, distinct from the session keys
//                         and from every other secret that is set
import { describe, it, expect, beforeEach } from "vitest";
import {
  loadGateConfig as loadConfig, BUILT_IN_DEFAULTS, REVOCATION_MODES, SECRET_KEYS, SESSION_MIN_IAT_MAX_FUTURE_SECONDS,
} from "../src/kernel/config.js";
import { resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const HMAC_KEY = "test-hmac-key-at-least-32-bytes-long!!";
const ADMIN_KEY = "test-admin-revocation-key-32-bytes-long!";
const NOW_MS = Date.UTC(2026, 9, 19, 12, 0, 0);
const NOW_S = Math.floor(NOW_MS / 1000);

const VALID = {
  issuer: "https://op.test",
  client_id: "test-client",
  redirect_uri: "https://www.example.com/.auth/callback",
  origin_hostname: "main--mysite--myorg.aem.live",
  forwarded_host: "www.example.com",
};

const load = () => loadConfig({ now: () => NOW_MS });

beforeEach(() => {
  resetStubs();
  seedSecrets({ client_secret: "test-client-secret", session_hmac_key: HMAC_KEY });
});

describe("revocation_mode", () => {
  it("defaults to auto", async () => {
    seedConfig(VALID);
    expect(BUILT_IN_DEFAULTS.revocation_mode).toBe("auto");
    expect((await load()).config.revocationMode).toBe("auto");
  });

  it.each(REVOCATION_MODES)("accepts %j", async (mode) => {
    seedConfig({ ...VALID, revocation_mode: mode });
    expect((await load()).config.revocationMode).toBe(mode);
  });

  it("an empty value takes the default", async () => {
    seedConfig({ ...VALID, revocation_mode: "" });
    expect((await load()).config.revocationMode).toBe("auto");
  });

  it.each(["Required", "off", "true", " required"])("rejects %j (fail closed)", async (mode) => {
    seedConfig({ ...VALID, revocation_mode: mode });
    await expect(load()).rejects.toThrow(/revocation_mode must be one of auto, required, optional, disabled/);
  });
});

describe("session_min_iat", () => {
  it("defaults to no cutoff (null)", async () => {
    seedConfig(VALID);
    expect((await load()).config.sessionMinIat).toBeNull();
    seedConfig({ ...VALID, session_min_iat: "" });
    expect((await load()).config.sessionMinIat).toBeNull();
  });

  it("parses epoch seconds, including now and up to 60 s ahead (the session clock skew)", async () => {
    expect(SESSION_MIN_IAT_MAX_FUTURE_SECONDS).toBe(60);
    for (const v of [0, 1_700_000_000, NOW_S, NOW_S + 60]) {
      seedConfig({ ...VALID, session_min_iat: String(v) });
      expect((await load()).config.sessionMinIat).toBe(v);
    }
  });

  it.each(["-1", "1.5", "abc", "1e9", "0x10", "1_700_000_000", "１２３"])("rejects %j", async (v) => {
    seedConfig({ ...VALID, session_min_iat: v });
    await expect(load()).rejects.toThrow(/session_min_iat must be a non-negative integer/);
  });

  it("rejects a value more than 60 s in the future, e.g. milliseconds by mistake (a login loop; W3.R R3-5)", async () => {
    for (const v of [NOW_S + 61, NOW_S + 300, NOW_MS]) {
      seedConfig({ ...VALID, session_min_iat: String(v) });
      await expect(load()).rejects.toThrow(/session_min_iat must not be in the future/);
    }
  });
});

describe("revocation_admin_key", () => {
  it("is a known secret key (manifest-declared), optional at load", async () => {
    expect(SECRET_KEYS).toContain("revocation_admin_key");
    seedConfig(VALID);
    expect((await load()).secret("revocation_admin_key")).toBeUndefined();
  });

  it("loads a ≥ 32-byte key that differs from the session keys", async () => {
    seedConfig(VALID);
    seedSecrets({ client_secret: "s", session_hmac_key: HMAC_KEY, revocation_admin_key: ADMIN_KEY });
    expect((await load()).secret("revocation_admin_key")).toBe(ADMIN_KEY);
  });

  it("an empty key means no key", async () => {
    seedConfig(VALID);
    seedSecrets({ client_secret: "s", session_hmac_key: HMAC_KEY, revocation_admin_key: "" });
    await expect(load()).resolves.toBeTruthy();
  });

  it("rejects a key shorter than 32 bytes without echoing it", async () => {
    seedConfig(VALID);
    seedSecrets({ client_secret: "s", session_hmac_key: HMAC_KEY, revocation_admin_key: "short-admin-key" });
    await expect(load()).rejects.toThrow(/revocation_admin_key must be at least 32 bytes/);
    await expect(load()).rejects.not.toThrow(/short-admin-key/);
  });

  it("rejects a key equal to the active or previous session key (key separation)", async () => {
    seedConfig(VALID);
    seedSecrets({ client_secret: "s", session_hmac_key: HMAC_KEY, revocation_admin_key: HMAC_KEY });
    await expect(load()).rejects.toThrow(/revocation_admin_key must differ from the session HMAC keys/);
    const previous = "previous-session-hmac-key-32-bytes!!";
    seedSecrets({ client_secret: "s", session_hmac_key: HMAC_KEY, session_hmac_key_previous: previous, revocation_admin_key: previous });
    await expect(load()).rejects.toThrow(/must differ/);
  });

  it.each(["client_secret", "recaptcha_secret", "user_info_password"])(
    "rejects a key equal to %s without echoing it (W3.R R3-10)", async (other) => {
      seedConfig(VALID);
      const shared = "shared-secret-value-at-least-32-bytes!!";
      seedSecrets({ client_secret: "s", session_hmac_key: HMAC_KEY, [other]: shared, revocation_admin_key: shared });
      const err = await load().then(() => null, (e) => e);
      expect(err).toBeInstanceOf(Error);
      expect(err.message).toBe(`revocation_admin_key must differ from ${other}`);
      expect(err.message).not.toContain(shared);
    },
  );

  it("loads when those secrets are set and different, or absent/empty", async () => {
    seedConfig(VALID);
    seedSecrets({
      client_secret: "client-secret", session_hmac_key: HMAC_KEY, recaptcha_secret: "recaptcha-secret",
      user_info_password: "user-info-password", revocation_admin_key: ADMIN_KEY,
    });
    expect((await load()).secret("revocation_admin_key")).toBe(ADMIN_KEY);
    seedSecrets({ client_secret: "s", session_hmac_key: HMAC_KEY, recaptcha_secret: "", user_info_password: "", revocation_admin_key: ADMIN_KEY });
    expect((await load()).secret("revocation_admin_key")).toBe(ADMIN_KEY);
  });
});
