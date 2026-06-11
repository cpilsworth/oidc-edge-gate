// In-memory stand-in for `fastly:secret-store`.
// `.get(key)` is async and resolves to null or an entry exposing `.plaintext()`,
// matching the js-compute SecretStore contract used by src/config.js.
import { getSecretBag } from "./state.js";

export class SecretStore {
  constructor(namespace) {
    this.bag = getSecretBag(namespace);
  }
  async get(key) {
    const v = this.bag[key];
    if (v === undefined) return null;
    return { plaintext: () => v };
  }
}
