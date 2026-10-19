// In-test OpenID Provider + stub EDS origin. Serves discovery + JWKS, exchanges
// codes for tokens, and mints id_tokens — including, per the `broken` flag,
// deliberately invalid ones. Install `handle` as globalThis.fetch so the gate's
// discovery/JWKS/token AND origin fetches hit it. Dispatch is by hostname: the
// issuer host serves the OIDC endpoints; the EDS origin host serves "origin-body".
import { makeRsaKey, signJwt, tokenHash, b64urlJson, b64url } from "./helpers.js";

// `mode: "janrain"` switches to a Janrain / Akamai Identity Cloud Hosted Login
// model (see createJanrainOp below and docs/providers/janrain.md). Without
// `mode` (or with `mode: "default"`) the behaviour is the original mock OP,
// unchanged; many suites (including characterization) depend on it.
export async function createMockOp(opts = {}) {
  const mode = opts?.mode ?? "default";
  if (mode === "janrain") return createJanrainOp(opts);
  if (mode !== "default") throw new Error(`createMockOp: unknown mode ${JSON.stringify(mode)}`);
  return createDefaultOp(opts);
}

async function createDefaultOp({
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

// ---------------------------------------------------------------------------
// Janrain / Akamai Identity Cloud Hosted Login mode.
//
// Modelled on docs/providers/janrain.md (desk research, not verified-live) and
// test/fixtures/janrain-discovery.json:
//   - path-based issuer `https://v1.api.{region}.janrain.com/{customerId}/login`;
//     endpoints `{issuer}/authorize|token|jwk|end_session`, userinfo at
//     `{customer base}/profiles/oidc/userinfo` (NOT under /login)        [row 2]
//   - RS256 only; JWKS keys are RSA/sig/RS256; unannounced key rotation [rows 9-11]
//   - confidential client authenticates at /token with ONE method; Basic is
//     form-urlencoded per RFC 6749 §2.3.1                                [row 7]
//   - PKCE S256 only                                                     [row 6]
//   - scopes never populate the ID token; the `claims` parameter does    [row 18]
//   - no groups in tokens (they come from the user-info backend)         [§4]
//   - opaque access token, accepted (Bearer) by the userinfo endpoint    [rows 21, 24]
//   - `aud` may be an array, `azp` is always the client id               [row 13]
//   - end_session needs client_id + post_logout_redirect_uri + state     [row 22]
// ---------------------------------------------------------------------------

const JANRAIN_DEFAULT_ISSUER = "https://v1.api.us.janrain.com/00000000-0000-0000-0000-000000000000/login";
const JANRAIN_DEFAULT_USER = Object.freeze({
  sub: "3c388dd9-0000-4000-8000-000000000001",
  email: "u@example.com",
  email_verified: true,
  given_name: "Uma",
  family_name: "User",
  preferred_username: "uuser",
  groups: ["site-readers"],
});
// Fixture fields that are not endpoint URLs (copied so the shape matches).
const JANRAIN_STATIC_DISCOVERY = Object.freeze({
  request_parameter_supported: false,
  request_uri_parameter_supported: false,
  response_modes_supported: ["query", "fragment", "form_post"],
  response_types_supported: ["code", "id_token", "token", "none", "code id_token", "code token", "id_token token", "code id_token token"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  grant_types_supported: ["authorization_code", "client_credentials", "implicit", "password", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
  acr_values_supported: ["0", "urn:akamai-ic:nist:800-63-3:aal:1", "urn:akamai-ic:nist:800-63-3:aal:2"],
  scopes_supported: ["openid", "profile", "email", "address", "phone", "offline_access"],
  claims_parameter_supported: true,
  claims_supported: ["sub", "iss", "auth_time", "given_name", "address", "family_name", "middle_name", "preferred_username", "gender", "birthdate", "updated_at", "phone_number", "phone_number_verified", "email", "email_verified", "sid"],
  claim_types_supported: ["normal", "aggregated"],
  code_challenge_methods_supported: ["S256"],
});
const SCOPE_CLAIMS = Object.freeze({
  email: ["email", "email_verified"],
  profile: ["name", "given_name", "family_name", "middle_name", "preferred_username", "gender", "birthdate", "updated_at"],
  phone: ["phone_number", "phone_number_verified"],
  address: ["address"],
});
const CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"];

function jsonError(status, error, description, headers = {}) {
  const body = { error };
  if (description) body.error_description = description;
  return Response.json(body, { status, headers: { "cache-control": "no-store", ...headers } });
}

/** RFC 6749 §2.3.1 / application/x-www-form-urlencoded decoding. Throws on malformed input. */
function formDecode(s) {
  return decodeURIComponent(s.replace(/\+/g, " "));
}

/** Decode `Authorization: Basic …` per RFC 6749 §2.3.1. Returns {clientId, clientSecret} or null. */
export function decodeClientBasic(header) {
  const m = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(header || "");
  if (!m) return null;
  let raw;
  try { raw = atob(m[1]); } catch { return null; }
  const i = raw.indexOf(":");
  if (i < 0) return null;
  try { return { clientId: formDecode(raw.slice(0, i)), clientSecret: formDecode(raw.slice(i + 1)) }; } catch { return null; }
}

async function s256(verifier) {
  const dg = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  return b64url(dg);
}

function randomToken(bytes = 24) {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function customerBase(issuer) {
  return issuer.endsWith("/login") ? issuer.slice(0, -"/login".length) : issuer.replace(/\/+$/, "");
}

async function createJanrainOp({
  issuer = JANRAIN_DEFAULT_ISSUER,
  clientId = "janrain-client",
  clientSecret = "janrain-client-secret",
  originHostname = "main--mysite--myorg.aem.live",
  // Endpoint URL overrides, e.g. { token_endpoint: "https://…" }.
  endpoints = {},
  // What discovery advertises (null → field omitted).
  tokenEndpointAuthMethods = ["client_secret_basic", "client_secret_post"],
  // What /token actually enforces: one of client_secret_basic|client_secret_post|none.
  clientAuthMethod = "client_secret_basic",
  // false → no end_session_endpoint in discovery and the route 404s.
  endSession = true,
  // Allowed post_logout_redirect_uri values (null → any absolute URL).
  postLogoutRedirectUris = null,
  // Allowed redirect_uri values at /authorize (null → any absolute URL), exact match.
  redirectUris = null,
  // /authorize: require a PKCE challenge (S256 is always the only accepted method).
  requirePkce = true,
  // /authorize: if set, `response_mode` must equal this (use "absent" to require it omitted).
  expectResponseMode = undefined,
  // The user /authorize logs in (claims available to `claims` echo and userinfo).
  user = JANRAIN_DEFAULT_USER,
  // true → put the user's groups into the ID token (Janrain normally doesn't).
  groupsInIdToken = false,
  // Admin-side push claims: always in the ID token, and the `claims` parameter is then ignored.
  pushClaims = null,
  // "client" → aud: clientId; "array" → aud: [clientId]; "client+redirect" → [clientId, redirect_uri].
  audience = "client",
  // false → ID token header carries no kid (documented as optional with a single key).
  includeKid = true,
  idTokenTtl = 3600,
} = {}) {
  if (!CLIENT_AUTH_METHODS.includes(clientAuthMethod))
    throw new Error(`createMockOp(janrain): unknown clientAuthMethod ${clientAuthMethod}`);
  const iss = issuer.replace(/\/+$/, "");
  const base = customerBase(iss);
  const discovery = {
    issuer: iss,
    authorization_endpoint: `${iss}/authorize`,
    token_endpoint: `${iss}/token`,
    introspection_endpoint: `${iss}/token/introspect`,
    revocation_endpoint: `${iss}/token/revoke`,
    userinfo_endpoint: `${base}/profiles/oidc/userinfo`,
    end_session_endpoint: `${iss}/end_session`,
    jwks_uri: `${iss}/jwk`,
    ...JANRAIN_STATIC_DISCOVERY,
    token_endpoint_auth_methods_supported: tokenEndpointAuthMethods,
    ...endpoints,
  };
  if (!endSession) delete discovery.end_session_endpoint;
  if (tokenEndpointAuthMethods == null) delete discovery.token_endpoint_auth_methods_supported;
  // Copy so the caller's array is not shared with the discovery document.
  if (discovery.token_endpoint_auth_methods_supported)
    discovery.token_endpoint_auth_methods_supported = [...discovery.token_endpoint_auth_methods_supported];

  // --- signing keys (RS256 only) ---
  let keySeq = 1;
  const keys = [await makeRsaKey(`janrain-key-${keySeq}`)]; // every key ever minted
  const published = new Set([keys[0].kid]);
  let current = keys[0];
  const jwksDoc = () => ({ keys: keys.filter((k) => published.has(k.kid)).map((k) => ({ ...k.publicJwk })) });

  /** Mint a new signing key; later ID tokens use it. `keepOld: false` unpublishes all older keys. */
  async function rotateKey({ keepOld = true, kid } = {}) {
    const k = await makeRsaKey(kid || `janrain-key-${++keySeq}`);
    keys.push(k);
    if (!keepOld) published.clear();
    published.add(k.kid);
    current = k;
    return k;
  }
  /** Remove a kid from the published JWKS (it stays usable for minting via mintIdToken({ key })). */
  function unpublishKey(kid) { published.delete(kid); }

  // --- state ---
  let currentUser = { ...user };
  const codes = new Map();          // code -> record
  const accessTokens = new Map();   // opaque AT -> { sub, scope, userClaims }
  const requests = { authorize: [], token: [], userinfo: [], endSession: [], discovery: [], jwks: [] };

  /** Register a code the token endpoint accepts (same shape as default mode, plus Janrain fields). */
  function issueCode(code, {
    claims = {}, codeChallenge, accessToken, nonce, redirectUri, requestedClaims, scope = "openid", sub, userClaims,
  } = {}) {
    codes.set(code, {
      claims, codeChallenge, accessToken, nonce: nonce ?? claims.nonce, redirectUri, requestedClaims, scope,
      userClaims: userClaims ?? { ...currentUser, ...(sub ? { sub } : {}) },
    });
    return code;
  }

  /** Claims the ID token carries for a code record (before `claims` overrides). */
  function idTokenUserClaims(rec) {
    const u = rec.userClaims || {};
    const out = {};
    if (pushClaims) {
      for (const name of pushClaims) if (u[name] !== undefined) out[name] = u[name];
    } else if (rec.requestedClaims?.id_token && typeof rec.requestedClaims.id_token === "object") {
      for (const name of Object.keys(rec.requestedClaims.id_token)) {
        if (name === "groups") continue; // not a Janrain claim (not in claims_supported)
        if (u[name] !== undefined) out[name] = u[name];
      }
    }
    if (groupsInIdToken && u.groups !== undefined) out.groups = u.groups;
    return out;
  }

  /**
   * Build an RS256 ID token. `broken` mirrors default mode plus "no-kid";
   * `key` signs with a specific key record (defaults to the current key).
   */
  async function mintIdToken({ nonce, claims = {}, accessToken, broken, key: signWith, userClaims, redirectUri } = {}) {
    const now = Math.floor(Date.now() / 1000);
    const k = signWith || current;
    let header = { alg: "RS256", typ: "JWT" };
    if (includeKid && broken !== "no-kid") header = { alg: "RS256", kid: k.kid, typ: "JWT" };
    const aud = audience === "array" ? [clientId]
      : audience === "client+redirect" ? [clientId, redirectUri || "https://www.example.com/.auth/callback"]
        : clientId;
    const body = {
      iss, aud, azp: clientId, sub: (userClaims && userClaims.sub) || currentUser.sub,
      iat: now, auth_time: now, exp: now + idTokenTtl, jti: randomToken(12), sid: "janrain-sid-1",
      ...(nonce !== undefined ? { nonce } : {}),
      ...claims,
    };
    if (accessToken) body.at_hash = await tokenHash(accessToken);
    let signKey = k.privateKey;
    switch (broken) {
      case "alg-none": return `${b64urlJson({ ...header, alg: "none" })}.${b64urlJson(body)}.`;
      case "bad-sig": signKey = (await makeRsaKey("rogue")).privateKey; break;
      case "wrong-iss": body.iss = "https://evil.test"; break;
      case "wrong-aud": body.aud = "someone-else"; break;
      case "multi-aud-no-azp": body.aud = [clientId, "other"]; delete body.azp; break;
      case "expired": body.exp = now - 7200; break;
      case "bad-nonce": body.nonce = "not-the-login-nonce"; break;
      case "bad-at-hash": body.at_hash = "AAAAAAAAAAAAAAAAAAAAAA"; break;
    }
    return signJwt(header, body, signKey);
  }

  const urlOf = (u) => `${u.origin}${u.pathname}`;
  const is = (u, endpoint) => endpoint && urlOf(u) === endpoint.split("?")[0];

  function handleAuthorize(url) {
    const q = Object.fromEntries(url.searchParams);
    const rec = {
      query: q, client_id: q.client_id, redirect_uri: q.redirect_uri, response_type: q.response_type,
      response_mode: q.response_mode, scope: q.scope, state: q.state, nonce: q.nonce,
      code_challenge: q.code_challenge, code_challenge_method: q.code_challenge_method,
      claims: undefined, claimsRaw: q.claims, hasClientSecret: url.searchParams.has("client_secret"),
      error: null, code: null,
    };
    requests.authorize.push(rec);
    const fail = (error, description, redirect = true) => {
      rec.error = error;
      if (!redirect) return jsonError(400, error, description);
      const to = new URL(q.redirect_uri);
      to.searchParams.set("error", error);
      if (description) to.searchParams.set("error_description", description);
      if (q.state !== undefined) to.searchParams.set("state", q.state);
      return new Response(null, { status: 302, headers: { location: to.toString() } });
    };
    // Errors that must not redirect (unknown client / bad redirect_uri).
    if (q.client_id !== clientId) return fail("invalid_client", "unknown client_id", false);
    let redirectOk = false;
    try { redirectOk = !!q.redirect_uri && /^https?:$/.test(new URL(q.redirect_uri).protocol); } catch { /* invalid */ }
    if (!redirectOk || (redirectUris && !redirectUris.includes(q.redirect_uri)))
      return fail("invalid_request", "redirect_uri not registered", false);
    if (q.response_type !== "code") return fail("unsupported_response_type", "only code is modelled");
    if (!(q.scope || "").split(/\s+/).includes("openid")) return fail("invalid_scope", "openid is required");
    if (q.response_mode !== undefined && !JANRAIN_STATIC_DISCOVERY.response_modes_supported.includes(q.response_mode))
      return fail("invalid_request", "unsupported response_mode");
    if (expectResponseMode !== undefined) {
      const want = expectResponseMode === "absent" ? undefined : expectResponseMode;
      if (q.response_mode !== want) return fail("invalid_request", `response_mode must be ${expectResponseMode}`);
    }
    if (q.code_challenge !== undefined || q.code_challenge_method !== undefined) {
      if (q.code_challenge_method !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
      if (!q.code_challenge) return fail("invalid_request", "code_challenge missing");
    } else if (requirePkce) {
      return fail("invalid_request", "PKCE (S256) is required");
    }
    if (q.claims !== undefined) {
      try { rec.claims = JSON.parse(q.claims); } catch { return fail("invalid_request", "claims is not JSON"); }
      if (!rec.claims || typeof rec.claims !== "object" || Array.isArray(rec.claims))
        return fail("invalid_request", "claims must be a JSON object");
    }
    const code = `jr-code-${randomToken(12)}`;
    rec.code = code;
    issueCode(code, {
      nonce: q.nonce, codeChallenge: q.code_challenge, redirectUri: q.redirect_uri,
      requestedClaims: rec.claims, scope: q.scope,
    });
    if (q.response_mode === "form_post") {
      const esc = (s) => String(s).replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);
      const fields = { code, ...(q.state !== undefined ? { state: q.state } : {}) };
      const inputs = Object.entries(fields).map(([n, v]) => `<input type="hidden" name="${n}" value="${esc(v)}">`).join("");
      return new Response(`<form method="post" action="${esc(q.redirect_uri)}">${inputs}</form>`,
        { status: 200, headers: { "content-type": "text/html" } });
    }
    const to = new URL(q.redirect_uri);
    to.searchParams.set("code", code);
    if (q.state !== undefined) to.searchParams.set("state", q.state);
    return new Response(null, { status: 302, headers: { location: to.toString() } });
  }

  async function handleToken(request) {
    const contentType = request.headers.get("content-type") || "";
    const form = new URLSearchParams(await request.text());
    const basic = request.headers.get("authorization");
    const bodyFields = {};
    for (const [k, v] of form) if (k !== "client_secret" && k !== "code_verifier") bodyFields[k] = v;
    const rec = {
      authMethod: null, clientId: null, contentType, body: bodyFields,
      hasClientSecretInBody: form.has("client_secret"), hasAuthorizationHeader: basic !== null,
      hasCodeVerifier: form.has("code_verifier"), status: null, error: null,
    };
    requests.token.push(rec);
    const fail = (status, error, description, headers) => {
      rec.status = status; rec.error = error;
      return jsonError(status, error, description, headers);
    };
    const invalidClient = (d) => fail(401, "invalid_client", d,
      clientAuthMethod === "client_secret_basic" ? { "www-authenticate": 'Basic realm="janrain"' } : {});

    // Which client authentication did the caller use?
    const usedBasic = basic !== null;
    const usedPost = form.has("client_secret");
    rec.authMethod = usedBasic && usedPost ? "multiple" : usedBasic ? "client_secret_basic" : usedPost ? "client_secret_post" : "none";
    if (rec.authMethod === "multiple") return invalidClient("more than one client authentication method");
    if (rec.authMethod !== clientAuthMethod)
      return invalidClient(`client must authenticate with ${clientAuthMethod}, got ${rec.authMethod}`);
    if (usedBasic) {
      const cred = decodeClientBasic(basic);
      if (!cred) return invalidClient("malformed Basic credentials");
      rec.clientId = cred.clientId;
      if (cred.clientId !== clientId || cred.clientSecret !== clientSecret) return invalidClient("bad client credentials");
      if (form.has("client_id") && form.get("client_id") !== clientId) return invalidClient("client_id mismatch");
    } else {
      rec.clientId = form.get("client_id");
      if (rec.clientId !== clientId) return invalidClient("unknown client_id");
      if (usedPost && form.get("client_secret") !== clientSecret) return invalidClient("bad client credentials");
    }

    if (form.get("grant_type") !== "authorization_code") return fail(400, "unsupported_grant_type");
    const code = form.get("code");
    const c = codes.get(code); // synchronous get+delete, as in default mode
    if (!c) return fail(400, "invalid_grant", "unknown or used code");
    codes.delete(code);
    if (c.redirectUri && form.get("redirect_uri") !== c.redirectUri) return fail(400, "invalid_grant", "redirect_uri mismatch");
    if (c.codeChallenge) {
      const v = form.get("code_verifier");
      if (!v) return fail(400, "invalid_grant", "code_verifier missing");
      if ((await s256(v)) !== c.codeChallenge) return fail(400, "invalid_grant", "PKCE verification failed");
    }
    const accessToken = c.accessToken || `jr-at-${randomToken(24)}`; // opaque: no dots, not a JWT
    accessTokens.set(accessToken, { sub: c.userClaims.sub, scope: c.scope, userClaims: c.userClaims });
    const id_token = await mintIdToken({
      nonce: c.nonce, claims: { ...idTokenUserClaims(c), ...c.claims }, accessToken, broken: c.broken,
      userClaims: c.userClaims, redirectUri: c.redirectUri,
    });
    rec.status = 200;
    return Response.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, id_token, scope: c.scope },
      { headers: { "cache-control": "no-store" } });
  }

  function handleUserinfo(request) {
    const auth = request.headers.get("authorization") || "";
    const m = /^Bearer\s+(\S+)\s*$/i.exec(auth);
    const rec = { method: request.method, hasBearer: !!m, status: null, error: null };
    requests.userinfo.push(rec);
    const fail = (error) => {
      rec.status = 401; rec.error = error;
      return jsonError(401, error, undefined, { "www-authenticate": `Bearer error="${error}"` });
    };
    if (!m) return fail("invalid_request");
    const at = accessTokens.get(m[1]);
    if (!at) return fail("invalid_token");
    const scopes = (at.scope || "").split(/\s+/);
    const out = { sub: at.sub, global_sub: `capture-v1://janrain.test/entity/${at.sub}` };
    for (const s of scopes) for (const name of SCOPE_CLAIMS[s] || [])
      if (at.userClaims[name] !== undefined) out[name] = at.userClaims[name];
    rec.status = 200;
    return Response.json(out);
  }

  function handleEndSession(url) {
    const q = Object.fromEntries(url.searchParams);
    const rec = {
      query: q, client_id: q.client_id, post_logout_redirect_uri: q.post_logout_redirect_uri, state: q.state,
      logout_hint: q.logout_hint, id_token_hint: q.id_token_hint, status: null, error: null,
    };
    requests.endSession.push(rec);
    const fail = (d) => { rec.status = 400; rec.error = "invalid_request"; return jsonError(400, "invalid_request", d); };
    if (q.client_id !== clientId) return fail("client_id missing or unknown");
    if (!q.post_logout_redirect_uri) return fail("post_logout_redirect_uri missing");
    let to;
    try { to = new URL(q.post_logout_redirect_uri); } catch { return fail("post_logout_redirect_uri invalid"); }
    if (postLogoutRedirectUris && !postLogoutRedirectUris.includes(q.post_logout_redirect_uri))
      return fail("post_logout_redirect_uri not registered");
    if (!q.state) return fail("state missing");
    to.searchParams.set("state", q.state);
    rec.status = 302;
    return new Response(null, { status: 302, headers: { location: to.toString() } });
  }

  async function handle(request) {
    const url = new URL(request.url);
    if (url.hostname === originHostname)
      return new Response("origin-body", { status: 200, headers: { "content-type": "text/html" } });
    if (urlOf(url) === `${iss}/.well-known/openid-configuration`) {
      requests.discovery.push({ method: request.method });
      return Response.json(discovery);
    }
    if (is(url, discovery.jwks_uri)) { requests.jwks.push({ method: request.method }); return Response.json(jwksDoc()); }
    if (is(url, discovery.authorization_endpoint) && request.method === "GET") return handleAuthorize(url);
    if (is(url, discovery.token_endpoint)) {
      if (request.method !== "POST") return jsonError(405, "invalid_request", "POST required");
      return handleToken(request);
    }
    if (is(url, discovery.userinfo_endpoint) && (request.method === "GET" || request.method === "POST")) return handleUserinfo(request);
    if (endSession && is(url, discovery.end_session_endpoint) && request.method === "GET") return handleEndSession(url);
    return new Response("not found", { status: 404 });
  }

  function reset() {
    codes.clear(); accessTokens.clear();
    for (const k of Object.keys(requests)) requests[k].length = 0;
  }

  return {
    mode: "janrain", issuer: iss, clientId, clientSecret, clientAuthMethod, originHostname, discovery,
    get jwks() { return jwksDoc(); },
    get key() { return current; },
    keys, rotateKey, unpublishKey,
    get user() { return currentUser; },
    setUser(u) { currentUser = { ...u }; },
    issueCode, mintIdToken, handle, codes, accessTokens, requests, reset,
    setBrokenForCode(code, broken) { codes.get(code).broken = broken; },
    lastAuthorize: () => requests.authorize.at(-1),
    lastToken: () => requests.token.at(-1),
    lastEndSession: () => requests.endSession.at(-1),
  };
}
