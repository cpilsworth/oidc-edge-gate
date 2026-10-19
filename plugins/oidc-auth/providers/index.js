// Registered provider profiles (the `provider` plugin option). See ./define.js
// for the profile shape. W2 adds janrain here.

import generic from "./generic.js";
import auth0 from "./auth0.js";

export const DEFAULT_PROVIDER = "generic";

export const PROVIDERS = Object.freeze({
  [generic.name]: generic,
  [auth0.name]: auth0,
});

/**
 * @param {string} name
 * @returns {import("./define.js").ProviderProfile}
 */
export function getProvider(name) {
  const p = Object.prototype.hasOwnProperty.call(PROVIDERS, name) ? PROVIDERS[name] : undefined;
  if (!p) throw new TypeError(`unknown oidc-auth provider ${JSON.stringify(name)}`);
  return p;
}
