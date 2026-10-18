// Login start (the authenticator's interactive challenge): mint state, nonce
// and a PKCE pair, stash them with the return path in the signed login-state
// cookie, and 302 the browser to the IdP's authorization endpoint.

import { getDiscovery } from "./discovery.js";
import { effectiveRedirectUri, redirect } from "./http.js";
import { createPkcePair, randomNonce, randomState } from "./pkce.js";
import { requireSecret } from "./settings.js";
import { writeLoginState } from "./state.js";

/**
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {import("./settings.js").OidcSettings} s
 * @returns {Promise<Response>}
 */
export async function startLogin(ctx, s) {
  const discovery = await getDiscovery(ctx, s.issuer);
  const state = randomState();
  const nonce = randomNonce();
  const pkce = await createPkcePair();
  const url = ctx.url; // the normalized request URL

  const authorize = new URL(discovery.authorization_endpoint);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", s.clientId);
  authorize.searchParams.set("redirect_uri", effectiveRedirectUri(s, url));
  authorize.searchParams.set("scope", s.scopes);
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("nonce", nonce);
  authorize.searchParams.set("code_challenge", pkce.challenge);
  authorize.searchParams.set("code_challenge_method", pkce.method);
  for (const [k, v] of Object.entries(s.provider.authorizeParams)) authorize.searchParams.set(k, v);

  await writeLoginState(ctx, {
    state, nonce, verifier: pkce.verifier, returnTo: url.pathname + url.search,
  }, requireSecret(ctx, "session_hmac_key"));

  // Never cacheable: it carries a per-user state/nonce (the finalizer also
  // applies no-store to every response).
  return redirect(302, authorize.toString());
}
