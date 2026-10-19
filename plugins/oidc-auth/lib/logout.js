// The logout route. POST-only from this site:
//   - any other method          → 405 {"error":"method_not_allowed"}, Allow: POST
//   - cross-site Origin/Referer → 403 {"error":"forbidden"}
//   - otherwise: emit the logout lifecycle event (errors logged, not fatal),
//     clear the session AND login-state cookies (a half-finished login can't be
//     resumed), and 303 to the IdP's end_session_endpoint with the provider's
//     logout params (given a fresh random `state` each time; profiles that
//     don't need it ignore it), or to "/" when there is none, discovery fails,
//     or the profile's endSession is "none" (then discovery isn't fetched).
// A GET (link, <img>, prefetch) must never end a session, so the site's
// sign-out control is a <form method="post">.

import { errorResponse } from "../../../src/sdk/http.js";
import { getDiscovery } from "./discovery.js";
import { isSameSiteRequest, redirect } from "./http.js";
import { randomState } from "./pkce.js";
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
    const session = await readSession(ctx, requireSecret(ctx, "session_hmac_key"));
    await ctx.lifecycle.emitLogout(session ? sessionToIdentity(session) : null);
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
    const params = s.provider.logoutParams({ clientId: s.clientId, postLogoutRedirectUri: `${url.origin}/`, state });
    for (const [k, v] of Object.entries(params)) logout.searchParams.set(k, v);
    return redirect(303, logout.toString());
  }
  return redirect(303, "/");
}
