// Server-side revocation check, run inside authenticate() on every request
// that carries a verified session (docs/architecture/plugins.md §15).
//
// OWNER: W3.2. This file is a W3.0 stub: the mode resolution below is part of
// the contract; checkRevocation() still accepts every session.

/** Values of the `revocation_mode` config key. */
export const REVOCATION_MODES = Object.freeze(["auto", "required", "optional", "disabled"]);

/**
 * The effective mode for this request (§15.1): `auto` is `required` on the
 * provisioned profile and `optional` on sandbox; anything else is used as-is.
 * A missing ctx.config.revocationMode (plugin unit tests) means `auto`.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @returns {"required"|"optional"|"disabled"}
 */
export function effectiveRevocationMode(ctx) {
  const mode = ctx.config.revocationMode ?? "auto";
  if (mode === "auto") return ctx.platform.profile === "provisioned" ? "required" : "optional";
  if (mode === "required" || mode === "optional" || mode === "disabled") return mode;
  throw new Error(`oidc-auth: invalid revocation_mode ${JSON.stringify(String(mode))}`);
}

/**
 * @typedef {Object} RevocationVerdict
 * @property {boolean} revoked
 * @property {"min_iat"|"sid"|"sub"} [reason]  set when revoked
 */

/**
 * Decide whether a verified session has been revoked (§15.3).
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {{sid: string, sub: string, iat: number, exp: number}} session  a verified session (session.js)
 * @returns {Promise<RevocationVerdict>}
 * @throws {import("../../../src/sdk/index.js").PluginError} 503 revocation_unavailable (mode required, KV missing or failing)
 */
// eslint-disable-next-line no-unused-vars
export async function checkRevocation(ctx, session) {
  return { revoked: false };
}
