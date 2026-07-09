import { getDiscovery, verifyIdToken } from "./jwt.js";
import { createPkcePair, randomNonce, randomState } from "./pkce.js";
import {
  clearSessionCookie,
  clearStateCookie,
  mintSessionCookie,
  mintStateCookie,
  readStateCookie,
} from "./session.js";import { timingSafeEqual } from "./encoding.js";
import { NO_STORE_HEADERS, errorResponse, requestId } from "./http.js";
import { kvGetFresh, kvPutWithTtl } from "./kv.js";

const STATE_USED_TTL_SECONDS = 600;

/**
 * Generic client-facing error. The internal `detail` is logged (with the request
 * id) but never echoed to the client, so error responses can't be used for
 * reconnaissance ("azp mismatch", "no JWKS key for kid X", raw IdP error params).
 */
function gateError(status, detail, request) {
  const id = requestId(request);
  console.error(`[oidc] ${detail} (request-id: ${id})`);
  return errorResponse(status, `${status} — authentication error (request-id: ${id})\n`, {
    headers: { "x-auth-request-id": id },
  });
}

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
    authorize.searchParams.set("redirect_uri", effectiveRedirectUri(this.config, url));
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
        ...NO_STORE_HEADERS,
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
    if (!saved) return gateError(400, "login session expired or state cookie missing", req);

    const returnedState = url.searchParams.get("state") || "";
    if (!await timingSafeEqual(returnedState, saved.state)) {
      return gateError(400, "state mismatch — possible CSRF", req);
    }

    // Single-use state: reject a replayed callback (N9). The replay marker is the
    // gate's own defence against a captured callback URL being submitted twice.
    // KV is eventually consistent, so this stops practical replays, not a
    // perfectly-timed race. The marker carries its own expiry and is checked on
    // read, so it works whether or not the KV backend supports native TTL
    // eviction. Marked consumed once the state validates; a later token-exchange
    // failure still burns the state (user re-initiates login), the safe direction.
    //
    // SANDBOX POC: sandbox programs don't provision KV, so config.cache is null.
    // We cannot fail closed (that would 503 every login), so we skip the gate's
    // marker and rely on the remaining defences: PKCE binds the code to the
    // verifier in the signed state cookie, the state cookie + match blocks CSRF,
    // and the IdP rejects reuse of a single-use authorization code at exchange.
    // This is a deliberate, POC-only reduction — on a provisioned env cache is
    // non-null and full replay protection is restored with no behaviour change.
    // A present-but-erroring KV still propagates (real misconfig, fail closed).
    if (!this.config.cache) {
      console.warn(`oidc callback [${requestId(req)}]: KV unavailable (sandbox) — skipping single-use state marker (POC)`);
    } else {
      const usedKey = `oidc:state-used:${saved.state}`;
      if (await kvGetFresh(this.config.cache, usedKey)) {
        return gateError(400, "state already used — possible replay", req);
      }
      await kvPutWithTtl(this.config.cache, usedKey, true, STATE_USED_TTL_SECONDS);
    }

    const idpError = url.searchParams.get("error");
    if (idpError) return gateError(401, `authorization failed: ${idpError}`, req);

    const code = url.searchParams.get("code");
    if (!code) return gateError(400, "missing authorization code", req);

    // --- token exchange ---
    const discovery = await getDiscovery(this.config);
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      // Must byte-match the redirect_uri sent to /authorize (OIDC). Both derive
      // from the request host, so local + deployed each stay self-consistent.
      redirect_uri: effectiveRedirectUri(this.config, url),
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code_verifier: saved.verifier,
    });
    // No `backend` option — dynamic backend from the absolute URL (see src/jwt.js getDiscovery).
    const tokenRes = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!tokenRes.ok) return gateError(401, `token exchange failed: ${tokenRes.status}`, req);

    const tokens = await tokenRes.json();
    if (!tokens.id_token) return gateError(401, "no id_token in token response", req);

    let claims;
    try {
      claims = await verifyIdToken(tokens.id_token, this.config, saved.nonce,
        { code, accessToken: tokens.access_token });
    } catch (e) {
      return gateError(400, `ID token validation failed: ${e.message}`, req);
    }

    // --- mint session, drop the transient state cookie, redirect home ---
    const sessionCookie = await mintSessionCookie(claims, this.config);
    const headers = new Headers({ location: safeReturnTo(saved.returnTo, url.origin) });
    headers.append("set-cookie", sessionCookie);
    headers.append("set-cookie", clearStateCookie());
    // The callback response carries the session Set-Cookie — must never be cached.
    for (const [k, v] of Object.entries(NO_STORE_HEADERS)) headers.set(k, v);
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
    // Also drop any lingering login-state cookie so a half-finished login can't
    // be resumed after an explicit logout.
    headers.append("set-cookie", clearStateCookie());
    // response clears the session cookie — must never be cached.
    for (const [k, v] of Object.entries(NO_STORE_HEADERS)) headers.set(k, v);

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
/**
 * The OIDC callback URI. In a real deployment this is the configured redirect_uri;
 * when served locally (`fastly compute serve`) derive it from the request origin so
 * login round-trips through localhost instead of the deployed host. startLogin and
 * handleCallback both call this with their request URL, so the value byte-matches
 * across the two legs (OIDC requires that). NOTE: the local URI
 * (http://localhost:<port>/.auth/callback) must also be registered as an allowed
 * callback with the IdP for a local login to complete.
 */
function effectiveRedirectUri(config, url) {
  const h = url.hostname;
  if (h === "localhost" || h === "127.0.0.1" || h === "::1") {
    return `${url.origin}${config.routes.callback}`;
  }
  return config.redirectUri;
}

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

