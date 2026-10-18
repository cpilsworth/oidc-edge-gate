// Login state: the transient signed `__Host-edge_login` cookie that carries
// state / nonce / PKCE verifier / return path across the round trip to the
// IdP, and the single-use state-replay marker checked at the callback.
//
// Cookie: __Host-edge_login=<token>; Path=/; Max-Age=600; SameSite=Lax; HttpOnly; Secure
// (Lax so it rides along on the IdP's top-level GET redirect back to us).

import { PluginError } from "../../../src/sdk/index.js";
import { kvGetFresh, kvPutWithTtl } from "./kv.js";
import { decodeSigned, encodeSigned, isRecord } from "./signed-cookie.js";

export const LOGIN_COOKIE = "__Host-edge_login";
export const LOGIN_STATE_TTL_SECONDS = 600;
export const STATE_USED_TTL_SECONDS = 600;

/** KV key of the single-use marker (inside the plugin's KV namespace). */
export const stateUsedKey = (state) => `oidc:state-used:${state}`;

/** @param {unknown} s */
export function isValidLoginState(s) {
  if (!isRecord(s)) return false;
  for (const k of ["state", "nonce", "verifier", "returnTo"]) {
    if (typeof s[k] !== "string" || !s[k]) return false;
  }
  return true;
}

/** Verify a login-state token; null when invalid. Never throws. */
export function decodeLoginState(token, key) {
  return decodeSigned(token, key, isValidLoginState);
}

/**
 * Set the login-state cookie.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {{state: string, nonce: string, verifier: string, returnTo: string}} loginState
 * @param {string} key
 */
export async function writeLoginState(ctx, { state, nonce, verifier, returnTo }, key) {
  const token = await encodeSigned({ state, nonce, verifier, returnTo }, key);
  ctx.cookies.set(LOGIN_COOKIE, token, { maxAge: LOGIN_STATE_TTL_SECONDS, sameSite: "Lax" });
}

/** Read and verify the request's login-state cookie. */
export function readLoginState(ctx, key) {
  return decodeLoginState(ctx.cookies.get(LOGIN_COOKIE), key);
}

/** Expire the login-state cookie. */
export function clearLoginState(ctx) {
  ctx.cookies.clear(LOGIN_COOKIE);
}

/**
 * Burn a validated `state` so a captured callback URL cannot be replayed (N9).
 * Returns false when the state was already used.
 *
 * Per platform profile (docs/architecture/plugins.md §11):
 *   - KV present: check, then write the marker. KV errors propagate (fail
 *     closed; the request ends 500). KV is eventually consistent, so this stops
 *     practical replays, not a perfectly timed race. A later token-exchange
 *     failure still burns the state (the user starts over), the safe direction.
 *   - provisioned, no KV: fail closed, PluginError(503, "kv_unavailable").
 *     A provisioned env without its KV is misconfigured.
 *   - sandbox, no KV: skip with a log line (sandbox programs have no KV; failing
 *     closed would break every login). Deliberate POC reduction: PKCE binds the
 *     code to the verifier in the signed state cookie, the state cookie + match
 *     blocks CSRF, and the IdP rejects reuse of a single-use authorization code.
 *
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} state
 * @returns {Promise<boolean>}
 */
export async function consumeState(ctx, state) {
  if (!ctx.kv) {
    if (ctx.platform.profile === "provisioned") {
      throw new PluginError(503, "kv_unavailable", "oidc callback: KV is not available on a provisioned platform; refusing the login (single-use state marker)");
    }
    ctx.log.warn("oidc callback: KV unavailable (sandbox); skipping the single-use state marker (POC)");
    return true;
  }
  const key = stateUsedKey(state);
  if (await kvGetFresh(ctx.kv, key)) return false;
  await kvPutWithTtl(ctx.kv, key, true, STATE_USED_TTL_SECONDS);
  return true;
}
