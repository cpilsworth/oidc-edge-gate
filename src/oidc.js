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
      headers: {
        location: authorize.toString(),
        "set-cookie": stateCookie,
        // Never let a cache store an auth-initiation 302 — it carries a fixed
        // state/nonce that must not be replayed to other users (plan §2.0).
        // Surrogate-Control stops the outer AEM CDN; Cache-Control the browser.
        "surrogate-control": "private",
        "cache-control": "private, no-store",
      },
    });
  }

  /**
   * Handle the IdP redirect back to redirect_uri: validate state (incl. single-use
   * replay protection), exchange the code for tokens, verify the ID token, mint a
   * session, and bounce the user back to where they started. Validation failures
   * return 400 (not a re-302) so rejection is observable.
   */
  async handleCallback(req, url) {
    const saved = await readStateCookie(req, this.config);
    if (!saved) return errorResponse(400, "Login session expired — please retry.");

    const returnedState = url.searchParams.get("state") || "";
    if (!timingSafeEqual(returnedState, saved.state)) {
      return errorResponse(400, "State mismatch — possible CSRF.");
    }

    // Single-use state: reject a replayed callback (N9). Best-effort via KV — KV is
    // eventually consistent, so this stops practical replays, not a perfectly-timed
    // race. The marker carries its own expiry and is checked on read, so it works
    // whether or not the KV backend supports native TTL eviction. Marked consumed
    // once the state validates; a later token-exchange failure still burns the state
    // (user re-initiates login), which is the safe direction.
    if (this.config.cache) {
      const usedKey = `state-used:${saved.state}`;
      const existing = await this.config.cache.get(usedKey);
      if (existing) {
        try {
          const w = JSON.parse(await existing.text());
          if (w.expires > Date.now()) return errorResponse(400, "State already used — possible replay.");
        } catch {
          return errorResponse(400, "State already used — possible replay.");
        }
      }
      await this.config.cache.put(usedKey, JSON.stringify({ expires: Date.now() + 600_000 }));
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
      claims = await verifyIdToken(tokens.id_token, this.config, saved.nonce,
        { code, accessToken: tokens.access_token });
    } catch (e) {
      return errorResponse(400, `ID token validation failed: ${e.message}`);
    }

    // --- mint session, drop the transient state cookie, redirect home ---
    const sessionCookie = await mintSessionCookie(claims, this.config);
    const headers = new Headers({ location: safeReturnTo(saved.returnTo, url.origin) });
    headers.append("set-cookie", sessionCookie);
    headers.append("set-cookie", clearStateCookie());
    // The callback response carries the session Set-Cookie — must never be cached.
    headers.set("surrogate-control", "private");
    headers.set("cache-control", "private, no-store");
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
    headers.set("surrogate-control", "private"); // response clears the session cookie
    headers.set("cache-control", "private, no-store");

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
// Resolving against the origin catches `//evil.com` and `/\evil.com` too.
function safeReturnTo(returnTo, origin) {
  if (typeof returnTo !== "string" || !returnTo.startsWith("/")) return "/";
  try {
    const resolved = new URL(returnTo, origin);
    if (resolved.origin !== origin) return "/";
    return resolved.pathname + resolved.search;
  } catch {
    return "/";
  }
}

function errorResponse(status, message) {
  return new Response(`${status} — ${message}\n`, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "surrogate-control": "private",
      "cache-control": "private, no-store",
    },
  });
}
