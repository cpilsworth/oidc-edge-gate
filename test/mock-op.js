// In-test OpenID Provider + stub EDS origin. Serves discovery + JWKS, exchanges
// codes for tokens, and mints id_tokens — including, per the `broken` flag,
// deliberately invalid ones. Install `handle` as globalThis.fetch so the gate's
// discovery/JWKS/token AND origin fetches hit it. Dispatch is by hostname: the
// issuer host serves the OIDC endpoints; the EDS origin host serves "origin-body".
import { makeRsaKey, signJwt, tokenHash, b64urlJson, b64url } from "./helpers.js";

export async function createMockOp({
  issuer = "https://op.test",
  clientId = "test-client",
  originHostname = "main--mysite--myorg.aem.live",
} = {}) {
  const key = await makeRsaKey();
  const discovery = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    end_session_endpoint: `${issuer}/logout`,
  };
  const jwks = { keys: [key.publicJwk] };

  // code -> { claims override, codeChallenge, accessToken, broken }
  const codes = new Map();

  /** Register a code the token endpoint will accept; returns the code string. */
  function issueCode(code, { claims = {}, codeChallenge, accessToken = "access-token-xyz" } = {}) {
    codes.set(code, { claims, codeChallenge, accessToken });
    return code;
  }

  /** Build an id_token. `broken` mutates header/claims/signature to exercise N-cases. */
  async function mintIdToken({ nonce, claims = {}, accessToken, code, broken } = {}) {
    const now = Math.floor(Date.now() / 1000);
    let header = { alg: "RS256", kid: key.kid, typ: "JWT" };
    let body = {
      iss: issuer, aud: clientId, sub: "user-123", email: "u@example.com",
      groups: ["site-readers"], iat: now, exp: now + 3600, nonce, ...claims,
    };
    if (accessToken) body.at_hash = await tokenHash(accessToken);
    if (code) body.c_hash = await tokenHash(code);

    let signKey = key.privateKey;
    switch (broken) {
      case "alg-none": {
        const h = b64urlJson({ ...header, alg: "none" });
        const p = b64urlJson(body);
        return `${h}.${p}.`;
      }
      case "bad-sig": {
        const other = await makeRsaKey("rogue"); signKey = other.privateKey; break;
      }
      case "wrong-iss":  body.iss = "https://evil.test"; break;
      case "wrong-aud":  body.aud = "someone-else"; break;
      case "multi-aud-no-azp": body.aud = [clientId, "other"]; delete body.azp; break;
      case "expired":    body.exp = now - 7200; break;   // well past the 60s skew window
      case "bad-nonce":  body.nonce = "not-the-login-nonce"; break;
      case "bad-at-hash": body.at_hash = "AAAAAAAAAAAAAAAAAAAAAA"; break;
      // N7 (kid rotation) is exercised in jwt.test.js with signJwt + a custom kid,
      // not via a broken-mode here, so the refetch-count spy can assert "exactly once".
    }
    return signJwt(header, body, signKey);
  }

  async function handle(request) {
    const url = new URL(request.url);
    // --- stub EDS origin: anything on the origin host ---
    if (url.hostname === originHostname) {
      return new Response("origin-body", { status: 200, headers: { "content-type": "text/html" } });
    }
    // --- OIDC provider endpoints (issuer host) ---
    if (url.pathname === "/.well-known/openid-configuration")
      return Response.json(discovery);
    if (url.pathname === "/jwks") return Response.json(jwks);
    if (url.pathname === "/token" && request.method === "POST") {
      const form = new URLSearchParams(await request.text());
      // Synchronous get+delete (no await between) — this is what makes the N9
      // concurrent-duplicate test deterministic: only one caller sees the code.
      const rec = codes.get(form.get("code"));
      if (!rec) return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
      codes.delete(form.get("code")); // authorization codes are one-time credentials
      // PKCE check: S256(code_verifier) must equal the registered challenge.
      if (rec.codeChallenge) {
        const v = form.get("code_verifier") || "";
        const dg = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)));
        const challenge = b64url(dg);
        if (challenge !== rec.codeChallenge)
          return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
      }
      const id_token = await mintIdToken({
        nonce: rec.claims.nonce, claims: rec.claims, accessToken: rec.accessToken,
        code: form.get("code"), broken: rec.broken,
      });
      return Response.json({ access_token: rec.accessToken, id_token, token_type: "Bearer" });
    }
    return new Response("not found", { status: 404 });
  }

  return { discovery, jwks, key, issueCode, mintIdToken, handle, codes, originHostname,
    setBrokenForCode(code, broken) { codes.get(code).broken = broken; } };
}
