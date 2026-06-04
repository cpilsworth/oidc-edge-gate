import { getDiscovery, verifyIdToken } from "./jwt.js";
import { createPkcePair, randomNonce, randomState } from "./pkce.js";
import {
  clearSessionCookie,
  clearStateCookie,
  mintSessionCookie,
  mintStateCookie,
  readStateCookie,
} from "./session.js";
import { timingSafeEqual } from "./encoding.js";

/**
 * OpenID Connect relying party. Drives the authorization-code-with-PKCE flow
 * against the configured OpenID Provider and converts a successful login into
 * a gate session cookie.
 */
export class OidcClient {
  constructor(config) {
    this.config = config;
  }

  /**
   * No valid session: kick off the auth-code flow. We stash state, nonce, PKCE
   * verifier and the originally-requested URL in a short-lived signed cookie,
   * then 302 the browser to the IdP's authorization endpoint.
   * @param {URL} url the originally requested URL
   */
  async startLogin(req, url) {
    const discovery = await getDiscovery(this.config);
    const state = randomState();
    const nonce = randomNonce();
    const pkce = await createPkcePair();

    const authorize = new URL(discovery.authorization_endpoint);
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("client_id", this.config.clientId);
    authorize.searchParams.set("redirect_uri", this.config.redirectUri);
    authorize.searchParams.set("scope", this.config.scopes);
    authorize.searchParams.set("state", state);
    authorize.searchParams.set("nonce", nonce);
    authorize.searchParams.set("code_challenge", pkce.challenge);
    authorize.searchParams.set("code_challenge_method", pkce.method);

    const stateCookie = await mintStateCookie(
      { state, nonce, verifier: pkce.verifier, returnTo: url.pathname + url.search },
      this.config,
    );

    return new Response(null, {
      status: 302,
      headers: { location: authorize.toString(), "set-cookie": stateCookie },
    });
  }

  /**
   * Handle the IdP redirect back to redirect_uri: validate state, exchange the
   * code for tokens, verify the ID token, mint a session, and bounce the user
   * back to where they started.
   */
  async handleCallback(req, url) {
    const saved = await readStateCookie(req, this.config);
    if (!saved) return errorResponse(400, "Login session expired — please retry.");

    const returnedState = url.searchParams.get("state") || "";
    if (!timingSafeEqual(returnedState, saved.state)) {
      return errorResponse(400, "State mismatch — possible CSRF.");
    }

    const idpError = url.searchParams.get("error");
    if (idpError) return errorResponse(401, `Authorization failed: ${idpError}`);

    const code = url.searchParams.get("code");
    if (!code) return errorResponse(400, "Missing authorization code.");

    // --- token exchange ---
    const discovery = await getDiscovery(this.config);
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code_verifier: saved.verifier,
    });
    const tokenRes = await fetch(discovery.token_endpoint, {
      method: "POST",
      backend: this.config.backends.idp,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!tokenRes.ok) return errorResponse(401, `Token exchange failed: ${tokenRes.status}`);

    const tokens = await tokenRes.json();
    if (!tokens.id_token) return errorResponse(401, "No id_token in token response.");

    let claims;
    try {
      claims = await verifyIdToken(tokens.id_token, this.config, saved.nonce);
    } catch (e) {
      return errorResponse(401, `ID token validation failed: ${e.message}`);
    }

    // --- mint session, drop the transient state cookie, redirect home ---
    const sessionCookie = await mintSessionCookie(claims, this.config);
    const headers = new Headers({ location: safeReturnTo(saved.returnTo) });
    headers.append("set-cookie", sessionCookie);
    headers.append("set-cookie", clearStateCookie());
    return new Response(null, { status: 302, headers });
  }

  /**
   * Clear the local session and, if the provider supports it, perform
   * RP-initiated logout.
   */
  async handleLogout(req, url) {
    const discovery = await getDiscovery(this.config).catch(() => ({}));
    const headers = new Headers();
    headers.append("set-cookie", clearSessionCookie());

    if (discovery.end_session_endpoint) {
      const logout = new URL(discovery.end_session_endpoint);
      logout.searchParams.set("client_id", this.config.clientId);
      logout.searchParams.set("post_logout_redirect_uri", `${url.origin}/`);
      headers.set("location", logout.toString());
      return new Response(null, { status: 302, headers });
    }

    headers.set("location", "/");
    return new Response(null, { status: 302, headers });
  }
}

// Only allow same-origin relative redirects to avoid open-redirect abuse.
function safeReturnTo(returnTo) {
  if (typeof returnTo === "string" && returnTo.startsWith("/") && !returnTo.startsWith("//")) {
    return returnTo;
  }
  return "/";
}

function errorResponse(status, message) {
  return new Response(`${status} — ${message}\n`, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}
