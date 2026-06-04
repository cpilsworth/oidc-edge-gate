import { parseCookies, serializeCookie, sign, unsign } from "./cookies.js";

// The session is the gate's *own* credential, minted once after a successful
// OIDC login and validated cheaply (HMAC, no backend call) on every subsequent
// request. We deliberately do NOT re-verify the IdP's JWT per request — that
// would hammer the JWKS endpoint and blow the 32-fetch budget. Instead we trust
// our HMAC signature and the embedded `exp`.

export const SESSION_COOKIE = "__edge_session";
const STATE_COOKIE = "__edge_login";

/**
 * Read + verify the session cookie. Returns the session object, or null if
 * absent, tampered, or expired.
 * @param {Request} req
 * @param {import("./config.js").Config} config
 */
export async function readSession(req, config) {
  const token = parseCookies(req.headers.get("cookie"))[SESSION_COOKIE];
  if (!token) return null;

  const payload = await unsign(token, config.sessionKey);
  if (!payload) return null;

  try {
    const session = JSON.parse(payload);
    if (typeof session.exp !== "number" || session.exp * 1000 <= Date.now()) return null;
    return session;
  } catch {
    return null;
  }
}

/**
 * Build a Set-Cookie header carrying a freshly-minted session derived from the
 * validated ID token claims.
 */
export async function mintSessionCookie(claims, config) {
  const now = Math.floor(Date.now() / 1000);
  const session = {
    sub: claims.sub,
    email: claims.email,
    name: claims.name,
    groups: claims.groups || claims.roles || [],
    iat: now,
    exp: now + config.sessionTtlSeconds,
  };
  const token = await sign(JSON.stringify(session), config.sessionKey);
  return serializeCookie(SESSION_COOKIE, token, { maxAge: config.sessionTtlSeconds });
}

export function clearSessionCookie() {
  return serializeCookie(SESSION_COOKIE, "", { maxAge: 0 });
}

// --- transient login state (state / nonce / pkce verifier / return path) -----

export async function mintStateCookie(state, config) {
  const token = await sign(JSON.stringify(state), config.sessionKey);
  // Short-lived; only needs to survive the round trip to the IdP and back.
  return serializeCookie(STATE_COOKIE, token, { maxAge: 600, sameSite: "Lax" });
}

export async function readStateCookie(req, config) {
  const token = parseCookies(req.headers.get("cookie"))[STATE_COOKIE];
  if (!token) return null;
  const payload = await unsign(token, config.sessionKey);
  if (!payload) return null;
  try {
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

export function clearStateCookie() {
  return serializeCookie(STATE_COOKIE, "", { maxAge: 0 });
}
