// Vitest helper: run a suite under both platform profiles (docs/architecture/plugins.md §11).
import { describe } from "vitest";

export const PROFILE_NAMES = Object.freeze(["provisioned", "sandbox"]);

const STORE_NAMES = Object.freeze({
  ConfigStore: "config_default",
  SecretStore: "secret_default",
  KVStore: "kv_default",
});

function unprovisioned(kind) {
  return class {
    constructor(name) {
      throw new Error(`No ${kind} named '${name}' exists`);
    }
  };
}

/**
 * Build fake store constructors for one profile.
 *
 * - sandbox: every constructor throws, like an unprovisioned sandbox program
 *   (config/secrets then come from the `embeddedConfigs`/`embeddedSecrets` you
 *   pass to detectPlatform; `config`/`secrets`/`kv` here are ignored).
 * - provisioned: constructors open only the fixed store names and serve the
 *   given data. `kv: false` makes the KV constructor throw (unbound); `kv` may be
 *   an object of initial string values. All instances of one makeStores() call
 *   share the same backing data, so writes are visible across `new KVStore()`.
 *
 * @param {"provisioned"|"sandbox"} profile
 * @param {{config?: Object<string,string>, secrets?: Object<string,string>, kv?: boolean|Object<string,string>}} [data]
 * @returns {{ConfigStore: Function, SecretStore: Function, KVStore: Function}}
 */
export function makeProfileStores(profile, { config = {}, secrets = {}, kv = true } = {}) {
  if (profile === "sandbox") {
    return {
      ConfigStore: unprovisioned("ConfigStore"),
      SecretStore: unprovisioned("SecretStore"),
      KVStore: unprovisioned("KVStore"),
    };
  }
  if (profile !== "provisioned") throw new Error(`unknown profile: ${profile}`);

  const checkName = (kind, name) => {
    if (name !== STORE_NAMES[kind]) throw new Error(`No ${kind} named '${name}' exists`);
  };
  const configBag = { ...config };
  const secretBag = { ...secrets };
  const kvMap = new Map(kv && typeof kv === "object" ? Object.entries(kv) : []);

  class ConfigStore {
    constructor(name) { checkName("ConfigStore", name); }
    get(key) { return Object.hasOwn(configBag, key) ? configBag[key] : null; }
  }
  class SecretStore {
    constructor(name) { checkName("SecretStore", name); }
    async get(key) {
      if (!Object.hasOwn(secretBag, key)) return null;
      const v = secretBag[key];
      return { plaintext: () => v };
    }
  }
  const KVStore = kv === false
    ? unprovisioned("KVStore")
    : class KVStore {
      constructor(name) { checkName("KVStore", name); }
      async get(key) {
        if (!kvMap.has(key)) return null;
        const v = kvMap.get(key);
        return { text: async () => v };
      }
      async put(key, value) { kvMap.set(key, value); }
      async delete(key) { kvMap.delete(key); }
    };
  return { ConfigStore, SecretStore, KVStore };
}

/**
 * Run `fn` once per platform profile, each inside
 * `describe(`${title} [${profile}]`)`.
 *
 * @param {string} title
 * @param {(profile: "provisioned"|"sandbox", makeStores: (data?: {config?: Object, secrets?: Object, kv?: boolean|Object}) => {ConfigStore: Function, SecretStore: Function, KVStore: Function}) => void} fn
 *
 * @example
 * import { describeEachProfile } from "../helpers/profiles.js";
 * import { detectPlatform } from "../../src/kernel/platform/index.js";
 *
 * describeEachProfile("issuer lookup", (profile, makeStores) => {
 *   it("resolves issuer", () => {
 *     const stores = makeStores({ config: { issuer: "https://op.test" }, secrets: { k: "fake" } });
 *     const det = detectPlatform(stores, { embeddedConfigs: { issuer: "https://op.test" } });
 *     expect(det.platform.profile).toBe(profile);
 *     expect(det.cfg("issuer")).toBe("https://op.test");
 *   });
 * });
 */
export function describeEachProfile(title, fn) {
  for (const profile of PROFILE_NAMES) {
    describe(`${title} [${profile}]`, () => {
      fn(profile, (data) => makeProfileStores(profile, data));
    });
  }
}
