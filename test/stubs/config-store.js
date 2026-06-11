// In-memory stand-in for `fastly:config-store`.
// `.get(key)` is synchronous and returns a string or null, matching the
// js-compute ConfigStore contract used by src/config.js.
import { getConfigBag } from "./state.js";

export class ConfigStore {
  constructor(namespace) {
    this.bag = getConfigBag(namespace);
  }
  get(key) {
    const v = this.bag[key];
    return v === undefined ? null : v;
  }
}
