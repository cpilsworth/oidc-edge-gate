// The OIDC callback route: validate the returned state against the signed
// login-state cookie, burn it (single-use marker), exchange the code (PKCE),
// verify the ID token, run the login lifecycle, mint the session and send the
// browser back to where it started.
//
// Client-visible outcomes (pinned by test/characterization/**):
//   400  no/invalid login-state cookie, state mismatch, replayed state,
//        missing code, ID token rejected
//   401  IdP error parameter, token exchange rejected, no id_token
//   500  a login lifecycle subscriber failed (fail closed, no session)
//   503  {"error":"kv_unavailable"}: provisioned platform without KV (§11)
//   302  success: Location = stored return path, session set, login cookie cleared
// 4xx/500 auth errors are a generic text/plain page with the request id; the
// reason is only logged. Nothing is written to cookies before success.

import { PluginError, createIdentityDraft } from "../../../src/sdk/index.js";
import { timingSafeEqual } from "../../../src/sdk/encoding.js";
import { getDiscovery } from "./discovery.js";
import { authError, effectiveRedirectUri, redirect, safeReturnTo } from "./http.js";
import { verifyIdToken } from "./jwt.js";
import { buildSession, writeSession } from "./session.js";
import { requireSecret } from "./settings.js";
import { clearLoginState, consumeState, readLoginState } from "./state.js";
import { exchangeCode } from "./token.js";

const str = (v) => (typeof v === "string" ? v : undefined);

/**
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {import("./settings.js").OidcSettings} s
 * @returns {Promise<Response>}
 */
export async function handleCallback(ctx, s) {
  const url = ctx.url;
  const sessionKey = requireSecret(ctx, "session_hmac_key");

  const saved = await readLoginState(ctx, sessionKey);
  if (!saved) return authError(ctx, 400, "login session expired or state cookie missing");

  const returnedState = url.searchParams.get("state") || "";
  if (!await timingSafeEqual(returnedState, saved.state)) {
    return authError(ctx, 400, "state mismatch, possible CSRF");
  }

  // Single-use state (N9); per-profile KV behaviour lives in consumeState.
  if (!await consumeState(ctx, saved.state)) {
    return authError(ctx, 400, "state already used, possible replay");
  }

  const idpError = url.searchParams.get("error");
  if (idpError) return authError(ctx, 401, `authorization failed: ${idpError}`);

  const code = url.searchParams.get("code");
  if (!code) return authError(ctx, 400, "missing authorization code");

  // --- token exchange (PKCE) ---
  const discovery = await getDiscovery(ctx, s.issuer);
  const tokenRes = await exchangeCode(ctx, discovery.token_endpoint, {
    method: s.provider.tokenEndpointAuthMethod,
    clientId: s.clientId,
    clientSecret: requireSecret(ctx, "client_secret"),
    code,
    // Must byte-match the redirect_uri sent to /authorize.
    redirectUri: effectiveRedirectUri(s, url),
    verifier: saved.verifier,
  });
  if (!tokenRes.ok) return authError(ctx, 401, `token exchange failed: ${tokenRes.status}`);
  const tokens = await tokenRes.json();
  if (!tokens || !tokens.id_token) return authError(ctx, 401, "no id_token in token response");

  let claims;
  try {
    claims = await verifyIdToken(ctx, tokens.id_token, {
      issuer: s.issuer, clientId: s.clientId, jwksUri: discovery.jwks_uri,
    }, saved.nonce, { code, accessToken: tokens.access_token });
  } catch (e) {
    if (e instanceof PluginError) throw e; // kernel fetch-policy errors (budget/egress) keep their code
    return authError(ctx, 400, `ID token validation failed: ${(e && e.message) || e}`);
  }

  // --- login lifecycle: subscribers (onLogin) see the verified identity
  // before the session exists and may add groups/attrs; an error aborts. ---
  const draft = createIdentityDraft({
    sub: claims.sub,
    email: str(claims.email),
    name: str(claims.name),
    // Groups come ONLY from the configured claim (no fallback chain).
    groups: claims[s.groupsClaim],
    claims,
  });
  try {
    await ctx.lifecycle.emitLogin(draft);
  } catch (e) {
    // (A subscriber's fetch-policy violation is still reported by the kernel,
    // which replaces this response with budget_exceeded/egress_denied.)
    return authError(ctx, 500, `login aborted by a login hook: ${(e && e.name) || "Error"}: ${(e && e.message) || ""}`);
  }

  // --- mint the session from the sealed draft ---
  const now = Math.floor(Date.now() / 1000);
  const identity = draft.toIdentity({ method: "oidc-session", issuedAt: now, expiresAt: now + s.sessionTtlSeconds });
  await writeSession(ctx, buildSession(identity, s.sessionTtlSeconds, now), sessionKey, s.sessionTtlSeconds);
  clearLoginState(ctx);
  return redirect(302, safeReturnTo(saved.returnTo, url.origin));
}
