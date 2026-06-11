// In-memory stand-in for `fastly:kv-store`.
// Backs both the discovery/JWKS cache (src/jwt.js) and the N9 state-replay
// marker (src/oidc.js). `.get(key)` is async → null or an entry whose async
// `.text()` yields the stored string; `.put(key, value)` stores it.
import { getKvMap } from "./state.js";

export class KVStore {
  constructor(namespace) {
    this.map = getKvMap(namespace);
  }
  async get(key) {
    if (!this.map.has(key)) return null;
    const value = this.map.get(key);
    return { text: async () => value };
  }
  async put(key, value) {
    this.map.set(key, value);
  }
  async delete(key) {
    this.map.delete(key);
  }
}
