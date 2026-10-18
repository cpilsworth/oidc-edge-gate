// Platform profile detection (W1.5). Spec: docs/architecture/plugins.md §11.
//
// Two profiles:
//   provisioned  ConfigStore("config_default") opens. Config, secrets and KV come
//                ONLY from the service stores; there is no embedded fallback.
//   sandbox      ConfigStore construction throws (sandbox Cloud Manager programs
//                do not provision the stores). Config and secrets come from the
//                build-time embedded values passed in by the caller.
//
// The store constructors are INJECTED (no `fastly:*` imports here) so this module
// is platform-agnostic, unit-testable with fakes, and bundles for js-compute.
// Nothing in this file may log or embed secret values: error messages carry only
// store names and error class names.

/** @typedef {import("../types.js").PlatformDetection} PlatformDetection */

export const PROFILES = Object.freeze(["provisioned", "sandbox"]);
export const CAPABILITIES = Object.freeze(["config-store", "secret-store", "kv"]);

export const CONFIG_STORE_NAME = "config_default";
export const SECRET_STORE_NAME = "secret_default";
export const KV_STORE_NAME = "kv_default";
/** SecretStore key holding the cloud secrets bundle (one JSON object of strings). */
export const SECRETS_BUNDLE_KEY = "secrets";
/** Config key that declares the expected profile. */
export const PROFILE_CONFIG_KEY = "platform_profile";

/**
 * Detect the platform profile and open the stores it implies.
 *
 * @param {{ConfigStore: Function, SecretStore: Function, KVStore: Function}} stores
 *        store constructors (the `fastly:*` ones in production, fakes in tests)
 * @param {{embeddedConfigs?: Object, embeddedSecrets?: Object<string,string>, secretKeys?: string[]}} [opts]
 *        embedded values (used ONLY on sandbox) and the per-key secret names
 *        tried on provisioned when no bundle is present.
 * @returns {PlatformDetection}
 * @throws {Error} provisioned without a SecretStore; platform_profile mismatch
 */
export function detectPlatform(stores, opts = {}) {
  const { ConfigStore, SecretStore, KVStore } = stores || {};
  const embeddedConfigs = opts.embeddedConfigs || {};
  const embeddedSecrets = opts.embeddedSecrets || {};
  const secretKeys = Array.isArray(opts.secretKeys) ? [...opts.secretKeys] : [];
  const warnings = [];

  const config = tryOpen(ConfigStore, CONFIG_STORE_NAME);
  const profile = config.handle ? "provisioned" : "sandbox";

  let secret = null;
  let kv = null;
  let cfg;
  let loadSecrets;

  if (profile === "provisioned") {
    const s = tryOpen(SecretStore, SECRET_STORE_NAME);
    if (!s.handle) {
      throw new Error(
        `provisioned platform: SecretStore "${SECRET_STORE_NAME}" failed to open (${s.errorName})`,
      );
    }
    secret = s.handle;

    const k = tryOpen(KVStore, KV_STORE_NAME);
    kv = k.handle;
    if (!kv) warnings.push(`provisioned platform: KVStore "${KV_STORE_NAME}" unavailable (${k.errorName}); KV features fail closed`);

    const configHandle = config.handle;
    cfg = (key) => {
      const v = configHandle.get(key);
      return v === undefined ? null : v;
    };
    const secretHandle = secret;
    loadSecrets = () => loadProvisionedSecrets(secretHandle, secretKeys);
  } else {
    // Local dev may bind a KV store even when Config/Secret stores are absent.
    kv = tryOpen(KVStore, KV_STORE_NAME).handle;
    cfg = (key) => (Object.hasOwn(embeddedConfigs, key) ? embeddedConfigs[key] ?? null : null);
    loadSecrets = async () => ({ ...embeddedSecrets });
  }

  const declared = cfg(PROFILE_CONFIG_KEY);
  if (declared == null) {
    warnings.push(`${PROFILE_CONFIG_KEY} not declared; detected "${profile}"`);
  } else if (declared !== profile) {
    throw new Error(`platform_profile mismatch: declared ${declared}, detected ${profile}`);
  }

  const caps = {
    "config-store": config.handle != null,
    "secret-store": secret != null,
    kv: kv != null,
  };
  const platform = Object.freeze({
    profile,
    has: (cap) => Object.hasOwn(caps, cap) && caps[cap] === true,
  });

  return {
    platform,
    stores: { config: config.handle, secret, kv },
    cfg,
    loadSecrets,
    warnings,
  };
}

/** Construct a store; never throws. errorName is the error's class/name only. */
function tryOpen(Ctor, name) {
  if (typeof Ctor !== "function") return { handle: null, errorName: "not available" };
  try {
    const handle = new Ctor(name);
    return { handle: handle ?? null, errorName: handle ? null : "null handle" };
  } catch (err) {
    return { handle: null, errorName: (err && err.name) || "Error" };
  }
}

/**
 * Provisioned secrets: the JSON bundle under key "secrets" (must be an object of
 * strings), else per-key. A present-but-invalid bundle throws (fail closed).
 * Errors never include the bundle text (JSON.parse messages can echo input).
 */
async function loadProvisionedSecrets(store, secretKeys) {
  const entry = await store.get(SECRETS_BUNDLE_KEY);
  if (entry != null) {
    let parsed;
    try {
      parsed = JSON.parse(entry.plaintext());
    } catch {
      throw new Error(`SecretStore "${SECRET_STORE_NAME}": "${SECRETS_BUNDLE_KEY}" bundle is not valid JSON`);
    }
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed) ||
      !Object.values(parsed).every((v) => typeof v === "string")
    ) {
      throw new Error(`SecretStore "${SECRET_STORE_NAME}": "${SECRETS_BUNDLE_KEY}" bundle must be a JSON object of strings`);
    }
    return { ...parsed };
  }

  const out = {};
  for (const key of secretKeys) {
    const e = await store.get(key);
    if (e != null) out[key] = e.plaintext();
  }
  return out;
}
