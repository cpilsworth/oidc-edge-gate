// Shared, module-level backing state for the in-memory fastly:* stubs.
//
// loadConfig() constructs its OWN `new ConfigStore("config_default")`,
// `new SecretStore("secret_default")` and `new KVStore("kv_default")` internally;
// tests never inject those instances. So the data a test seeds must live here,
// keyed by namespace, and every `new XStore(name)` reads/writes through it.
// Otherwise the handle loadConfig opens would see none of the seeded state.

/** namespace -> { key: stringValue }  (ConfigStore) */
export const configState = new Map();
/** namespace -> { key: stringValue }  (SecretStore plaintext) */
export const secretState = new Map();
/** namespace -> Map<key, stringValue>  (KVStore) */
export const kvState = new Map();

export function getConfigBag(namespace) {
  let b = configState.get(namespace);
  if (!b) { b = {}; configState.set(namespace, b); }
  return b;
}

export function getSecretBag(namespace) {
  let b = secretState.get(namespace);
  if (!b) { b = {}; secretState.set(namespace, b); }
  return b;
}

export function getKvMap(namespace) {
  let b = kvState.get(namespace);
  if (!b) { b = new Map(); kvState.set(namespace, b); }
  return b;
}

/** Wipe all stub backing state between tests. */
export function resetStubs() {
  configState.clear();
  secretState.clear();
  kvState.clear();
}

/** Seed ConfigStore("config_default") values (one object). */
export function seedConfig(values, namespace = "config_default") {
  Object.assign(getConfigBag(namespace), values);
}

/** Seed SecretStore("secret_default") plaintext values. */
export function seedSecrets(values, namespace = "secret_default") {
  Object.assign(getSecretBag(namespace), values);
}
