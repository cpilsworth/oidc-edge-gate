// The logout route. POST-only from this site:
//   - any other method          → 405 {"error":"method_not_allowed"}, Allow: POST
//   - cross-site Origin/Referer → 403 {"error":"forbidden"}
//   - otherwise: with a verified session, revoke its sid in KV when the
//     effective revocation mode is not `disabled` and KV exists (§15.5; a
//     failed write is logged with the error class only and never changes the
//     response; no KV write for an absent/invalid session, a rejected request
//     or a session already revoked by session_min_iat or a sid record), then
//     emit the logout lifecycle event with the identity (null when there is no
//     live session; errors logged, not fatal),
//     clear the session AND login-state cookies (a half-finished login can't be
//     resumed), and 303 to the IdP's end_session_endpoint with the provider's
//     logout params (given a fresh random `state` each time; profiles that
//     don't need it ignore it; post_logout_redirect_uri is the validated
//     same-site origin the browser posted from, i.e. the public host behind
//     the CDN, never just the internal request Host), or to "/" when there is
//     none, discovery fails,
//     or the profile's endSession is "none" (then discovery isn't fetched).
// A GET (link, <img>, prefetch) must never end a session, so the site's
// sign-out control is a <form method="post">.

import { errorResponse } from "../../../src/sdk/http.js";
import { getDiscovery } from "./discovery.js";
import { isSameSiteRequest, postLogoutRedirectUri, redirect } from "./http.js";
import { randomState } from "./pkce.js";
import { effectiveRevocationMode } from "./revocation.js";
import { isSessionRevoked, revokeSession } from "./revocation-store.js";
import { clearSession, readSession, sessionToIdentity } from "./session.js";
import { requireSecret } from "./settings.js";
import { clearLoginState } from "./state.js";

/**
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {import("./settings.js").OidcSettings} s
 * @returns {Promise<Response>}
 */
export async function handleLogout(ctx, s) {
  const id = ctx.requestId;
  const url = ctx.url;
  if (ctx.request.method !== "POST") {
    return errorResponse(405, { error: "method_not_allowed" }, { headers: { allow: "POST", "x-auth-request-id": id } });
  }
  if (!isSameSiteRequest(ctx.request, url, s.forwardedHost)) {
    ctx.log.error("oidc logout rejected: Origin/Referer is not this site");
    return errorResponse(403, { error: "forbidden" }, { headers: { "x-auth-request-id": id } });
  }

  try {
    const session = await readSession(ctx, requireSecret(ctx, "session_hmac_key"), s.sessionTtlSeconds);
    // Before emitLogout, the cookie clearing and the 303; never throws.
    const live = session ? await revokeOnLogout(ctx, s, session) : false;
    // An already-revoked session is no identity: hooks see a logout without one.
    await ctx.lifecycle.emitLogout(live ? sessionToIdentity(session) : null);
  } catch (e) {
    ctx.log.error("oidc logout hook failed", { error: (e && e.name) || "Error" });
  }

  let discovery = {};
  if (s.provider.endSession === "discovery") {
    try {
      discovery = await getDiscovery(ctx, s.issuer);
    } catch {
      /* no RP-initiated logout; still end the local session */
    }
  }

  clearSession(ctx);
  clearLoginState(ctx);

  if (discovery.end_session_endpoint) {
    const logout = new URL(discovery.end_session_endpoint);
    // 128-bit WebCrypto random, base64url (the same generator as the login state).
    const state = randomState();
    const params = s.provider.logoutParams({ clientId: s.clientId, postLogoutRedirectUri: postLogoutRedirectUri(ctx.request, s, url), state });
    for (const [k, v] of Object.entries(params)) logout.searchParams.set(k, v);
    return redirect(303, logout.toString());
  }
  return redirect(303, "/");
}

/**
 * Server-side revocation of the session being logged out (§15.5). Best
 * effort: clearing the cookie is the answer either way, so a failure (an
 * invalid mode, a KV error) is logged with the error class only and swallowed.
 *
 * An already-revoked session writes nothing (W3.R R3-4), so a stolen revoked
 * cookie can't drive KV writes: one read and at most one write per sid.
 *   - iat below the session_min_iat cutoff: revoked by config, no KV access;
 *   - a rev:sid record already present: no write;
 *   - that read fails: logged (error class only), the write is still tried.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {import("./settings.js").OidcSettings} s
 * @param {{sid: string, iat: number}} session  a verified session
 * @returns {Promise<boolean>}  false when the session was already revoked (by either rule)
 */
async function revokeOnLogout(ctx, s, session) {
  const minIat = ctx.config.sessionMinIat;
  if (typeof minIat === "number" && session.iat < minIat) return false;
  try {
    if (effectiveRevocationMode(ctx) === "disabled" || !ctx.kv) return true;
  } catch (e) {
    ctx.log.error("oidc logout revocation failed", { error: (e && e.name) || "Error" });
    return true;
  }
  try {
    if (await isSessionRevoked(ctx.kv, session.sid)) return false;
  } catch (e) {
    ctx.log.error("oidc logout revocation check failed", { error: (e && e.name) || "Error" });
  }
  try {
    await revokeSession(ctx.kv, session.sid, { sessionTtlSeconds: s.sessionTtlSeconds });
  } catch (e) {
    ctx.log.error("oidc logout revocation failed", { error: (e && e.name) || "Error" });
  }
  return true;
}
