// The OIDC callback route: validate the returned state against the signed
// login-state cookie, burn it (single-use marker), exchange the code (PKCE),
// verify the ID token, run the login lifecycle, mint the session and send the
// browser back to where it started. Spec: docs/architecture/plugins.md §14.4.
//
// Client-visible outcomes (the 400/401/302 rows are pinned by test/characterization/**):
//   400  no/invalid login-state cookie, state mismatch, replayed state,
//        missing code, ID token rejected
//   401  IdP error parameter, token exchange rejected, no id_token
//   500  no acceptable token endpoint auth method (negotiation, before the
//        token exchange); a login subscriber failed with anything but a
//        503 PluginError; the session would exceed the cookie size guard
//   503  a login subscriber threw PluginError(503) (e.g. user-info's
//        user_info_unavailable): the backend is down, the login is aborted
//   302  success: Location = stored return path, session set, login cookie cleared
// The 400/401/500/503 rows above are a generic text/plain auth error page with
// the request id; the reason is only logged (fixed codes, never claims or
// IdP/backend text). No session is ever written before success. The 500/503
// rows (after the state was consumed) also clear the login-state cookie
// (W2.R R14); the 400/401 rows set no cookie at all (pinned by
// test/characterization/**).
// Raised to the kernel instead (JSON {"error": code} + x-auth-request-id):
//   503  kv_unavailable: provisioned platform without KV (§11), before any fetch
//   500  egress_denied / 503 budget_exceeded: a kernel fetch-policy violation,
//        here or in a login subscriber (never remapped by this route)
//   500  internal_error: discovery fetch/validation failed, a secret is missing
//
// Groups (provider groupsSource, §14.1): "claim" seeds the draft from the
// `groups_claim` ID-token claim; "user-info" seeds it EMPTY (token claims are
// ignored even if present) and only login subscribers (plugins/user-info) add
// groups. The session id (sid) is minted before the identity, so
// identity.sessionId and the cookie's sid are the same value, and the session
// lifetime comes from identity.expiresAt (which carries draft.limitLifetime()).

import { PluginError, createIdentityDraft } from "../../../src/sdk/index.js";
import { timingSafeEqual } from "../../../src/sdk/encoding.js";
import { getDiscovery } from "./discovery.js";
import { authError, effectiveRedirectUri, redirect, safeReturnTo } from "./http.js";
import { idTokenFailureReason, verifyIdToken } from "./jwt.js";
import { SessionTooLargeError, buildSession, newSessionId, writeSession } from "./session.js";
import { requireSecret } from "./settings.js";
import { clearLoginState, consumeState, readLoginState } from "./state.js";
import { exchangeCode } from "./token.js";

const str = (v) => (typeof v === "string" ? v : undefined);

// F16: the IdP `error` parameter is attacker-controllable (anyone can hit the
// callback URL); only a plain OAuth error-code shape is ever logged.
const IDP_ERROR_RE = /^[a-z_]{1,64}$/;
/** @param {string} v */
export const safeIdpError = (v) => (IDP_ERROR_RE.test(v) ? v : "invalid");

/** Fixed reason code logged when a "user-info" provider login ends with no groups. */
export const NO_GROUPS_FROM_USER_INFO = "no_groups_from_user_info";

// A subscriber error's class/code may only reach a log line in a plain shape.
const NAME_RE = /^[A-Za-z0-9_]{1,64}$/;
const errorName = (e) => (e && typeof e.name === "string" && NAME_RE.test(e.name) ? e.name : "Error");
const errorCode = (e) => (e && typeof e.code === "string" && NAME_RE.test(e.code) ? e.code : "unknown");

/**
 * An auth error after the state was consumed that the user can only recover
 * from by starting over: the login-state cookie is cleared too (W2.R R14), so
 * a burnt state is not left in the browser for its remaining 10 minutes.
 * ctx.cookies writes are applied by the finalizer to whatever response this
 * request ends with, so the auth error page carries the clear.
 * The 400/401 outcomes (IdP error, missing code, token exchange rejected,
 * ID token rejected) keep the cookie untouched: test/characterization/**
 * pins those responses to carry no Set-Cookie at all.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {number} status
 * @param {string} detail  log-only
 */
function abortLogin(ctx, status, detail) {
  clearLoginState(ctx);
  return authError(ctx, status, detail);
}

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
  // State is validated AND consumed before anything is fetched or exchanged.
  if (!await consumeState(ctx, saved.state)) {
    return authError(ctx, 400, "state already used, possible replay");
  }

  const idpError = url.searchParams.get("error");
  if (idpError) return authError(ctx, 401, `authorization failed: ${safeIdpError(idpError)}`);

  const code = url.searchParams.get("code");
  if (!code) return authError(ctx, 400, "missing authorization code");

  // --- token exchange (PKCE) ---
  const discovery = await getDiscovery(ctx, s.issuer);
  // Negotiate client authentication right after discovery, before anything
  // else can fail late: a misconfiguration is a 500, never a token request.
  let authMethod;
  try {
    authMethod = s.tokenEndpointAuthMethod(discovery); // logs the method names on failure
  } catch {
    return abortLogin(ctx, 500, "token endpoint auth method negotiation failed");
  }
  const tokenRes = await exchangeCode(ctx, discovery.token_endpoint, {
    method: authMethod,
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
    // F16: a fixed reason code only (iss_mismatch, expired, kid_unknown, …), never e.message.
    return authError(ctx, 400, `ID token validation failed: ${idTokenFailureReason(e)}`);
  }

  // --- login lifecycle: subscribers (onLogin) see the verified identity
  // before the session exists and may add groups/attrs; an error aborts. ---
  const groupsFromUserInfo = s.provider.groupsSource === "user-info";
  const draft = createIdentityDraft({
    sub: claims.sub,
    // F17: an email the IdP explicitly marks unverified is not an identity
    // attribute the origin should trust (x-auth-email). Only an explicit
    // `false` drops it; an absent claim keeps today's behaviour.
    email: claims.email_verified === false ? undefined : str(claims.email),
    name: str(claims.name),
    // groupsSource "claim": ONLY the configured claim (no fallback chain).
    // "user-info": none from the token, even if it carries a groups claim.
    groups: groupsFromUserInfo ? [] : claims[s.groupsClaim],
    claims,
  });
  try {
    await ctx.lifecycle.emitLogin(draft);
  } catch (e) {
    // A kernel fetch-policy violation (budget/egress) keeps the kernel's own
    // code: rethrown, never turned into an auth error page.
    if (e && e.fatal === true) throw e;
    // The message may carry IdP/token/backend-derived text: log the class/code only.
    if (e instanceof PluginError && e.status === 503) {
      return abortLogin(ctx, 503, `login aborted by a login hook: ${errorCode(e)}`);
    }
    return abortLogin(ctx, 500, `login aborted by a login hook: ${errorName(e)}`);
  }
  if (groupsFromUserInfo && draft.groups.length === 0 && draft.lifetimeCap === null) {
    // Not an error (the user may simply have no groups; audience pages then
    // 403), but also what a missing or misconfigured user-info plugin looks like.
    ctx.log.info("oidc login without groups", { reason: NO_GROUPS_FROM_USER_INFO });
  }

  // --- mint the session from the sealed draft ---
  const now = Math.floor(Date.now() / 1000);
  const identity = draft.toIdentity({
    method: "oidc-session", sessionId: newSessionId(), issuedAt: now, expiresAt: now + s.sessionTtlSeconds,
  });
  // identity.expiresAt already carries any draft.limitLifetime() cap.
  const ttl = identity.expiresAt - now;
  try {
    await writeSession(ctx, buildSession(identity, ttl, now), sessionKey, ttl);
  } catch (e) {
    if (e instanceof SessionTooLargeError) return abortLogin(ctx, 500, "session too large");
    throw e;
  }
  clearLoginState(ctx);
  return redirect(302, safeReturnTo(saved.returnTo, url.origin));
}
