// W2.2: unit tests for the shared test mocks — the mock OP (default mode and
// Janrain mode, test/mock-op.js) and the mock user-info backend + fetch router
// (test/mock-user-info.js). docs/architecture/plugins.md §14, docs/providers/janrain.md.
import { describe, it, expect, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { createMockOp, decodeClientBasic } from "./mock-op.js";
import { createMockUserInfo, routeFetch, basicAuth, USER_INFO_FAILURES } from "./mock-user-info.js";
import { b64url, tokenHash } from "./helpers.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/janrain-discovery.json", import.meta.url), "utf8"));

function decodeJwt(jwt) {
  const [h, p, s] = jwt.split(".");
  const dec = (x) => JSON.parse(Buffer.from(x, "base64url").toString("utf8"));
  return { header: dec(h), payload: dec(p), signature: s };
}

async function verifyJwt(jwt, jwks) {
  const { header } = decodeJwt(jwt);
  const jwk = header.kid ? jwks.keys.find((k) => k.kid === header.kid) : jwks.keys[0];
  if (!jwk) return false;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const [h, p, s] = jwt.split(".");
  return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, Buffer.from(s, "base64url"), new TextEncoder().encode(`${h}.${p}`));
}

async function pkcePair() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const dg = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  return { verifier, challenge: b64url(dg) };
}

const formEncode = (s) => encodeURIComponent(s).replace(/%20/g, "+");
const clientBasic = (id, secret) => `Basic ${btoa(`${formEncode(id)}:${formEncode(secret)}`)}`;
const CALLBACK = "https://www.example.com/.auth/callback";

// ---------------------------------------------------------------------------
describe("createMockOp default mode (regression: unchanged)", () => {
  let op;
  beforeEach(async () => { op = await createMockOp({ issuer: "https://op.test", clientId: "test-client" }); });

  it("discovery has exactly the original keys and URLs", async () => {
    const res = await op.handle(new Request("https://op.test/.well-known/openid-configuration"));
    expect(await res.json()).toEqual({
      issuer: "https://op.test",
      authorization_endpoint: "https://op.test/authorize",
      token_endpoint: "https://op.test/token",
      jwks_uri: "https://op.test/jwks",
      end_session_endpoint: "https://op.test/logout",
    });
  });

  it("returns the original API surface and one JWKS key", async () => {
    expect(Object.keys(op).sort()).toEqual(
      ["codes", "discovery", "handle", "issueCode", "jwks", "key", "mintIdToken", "originHostname", "setBrokenForCode"].sort());
    expect(op.jwks.keys).toHaveLength(1);
    expect(op.jwks.keys[0].kid).toBe("test-key-1");
    expect(op.originHostname).toBe("main--mysite--myorg.aem.live");
    expect(op.mode).toBeUndefined();
  });

  it("token response shape and id_token claims are unchanged", async () => {
    const { verifier, challenge } = await pkcePair();
    op.issueCode("c1", { claims: { nonce: "n1" }, codeChallenge: challenge });
    const res = await op.handle(new Request("https://op.test/token", {
      method: "POST", body: new URLSearchParams({ code: "c1", code_verifier: verifier, client_secret: "anything" }),
    }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(["access_token", "id_token", "token_type"]);
    expect(body.access_token).toBe("access-token-xyz");
    expect(body.token_type).toBe("Bearer");
    const { header, payload } = decodeJwt(body.id_token);
    expect(header).toEqual({ alg: "RS256", kid: "test-key-1", typ: "JWT" });
    expect(Object.keys(payload).sort()).toEqual(
      ["at_hash", "aud", "c_hash", "email", "exp", "groups", "iat", "iss", "nonce", "sub"]);
    expect(payload).toMatchObject({ iss: "https://op.test", aud: "test-client", sub: "user-123", email: "u@example.com", groups: ["site-readers"], nonce: "n1" });
    expect(payload.at_hash).toBe(await tokenHash("access-token-xyz"));
    expect(await verifyJwt(body.id_token, op.jwks)).toBe(true);
  });

  it("codes are one-time, PKCE mismatches are invalid_grant, unknown paths 404, origin host serves origin-body", async () => {
    op.issueCode("c2", { codeChallenge: "nope" });
    const bad = await op.handle(new Request("https://op.test/token", { method: "POST", body: "code=c2&code_verifier=x" }));
    expect(bad.status).toBe(400);
    expect(await bad.json()).toEqual({ error: "invalid_grant" });
    const again = await op.handle(new Request("https://op.test/token", { method: "POST", body: "code=c2" }));
    expect(again.status).toBe(400);
    expect((await op.handle(new Request("https://op.test/nope"))).status).toBe(404);
    const o = await op.handle(new Request("https://main--mysite--myorg.aem.live/x"));
    expect(await o.text()).toBe("origin-body");
  });

  it("explicit mode: 'default' is the same as no mode; unknown modes throw", async () => {
    const d = await createMockOp({ mode: "default" });
    expect(d.discovery.jwks_uri).toBe("https://op.test/jwks");
    await expect(createMockOp({ mode: "okta" })).rejects.toThrow(/unknown mode/);
  });
});

// ---------------------------------------------------------------------------
describe("createMockOp janrain mode", () => {
  let op;
  const ISS = fixture.issuer;
  beforeEach(async () => { op = await createMockOp({ mode: "janrain" }); });

  async function authorize(params = {}) {
    const { verifier, challenge } = await pkcePair();
    const q = new URLSearchParams({
      client_id: op.clientId, redirect_uri: CALLBACK, response_type: "code", scope: "openid email profile",
      state: "st-1", nonce: "n-1", code_challenge: challenge, code_challenge_method: "S256", ...params,
    });
    for (const [k, v] of Object.entries(params)) if (v === undefined) q.delete(k);
    const res = await op.handle(new Request(`${op.discovery.authorization_endpoint}?${q}`));
    const loc = res.headers.get("location");
    return { res, verifier, code: loc ? new URL(loc).searchParams.get("code") : null, location: loc };
  }

  function token(fields, { basic, headers = {} } = {}) {
    const h = { "content-type": "application/x-www-form-urlencoded", ...headers };
    if (basic) h.authorization = basic;
    return op.handle(new Request(op.discovery.token_endpoint, { method: "POST", headers: h, body: new URLSearchParams(fields) }));
  }

  async function loginTokens(authParams, tokenOverrides = {}) {
    const a = await authorize(authParams);
    const res = await token({ grant_type: "authorization_code", code: a.code, redirect_uri: CALLBACK, code_verifier: a.verifier, ...tokenOverrides },
      { basic: clientBasic(op.clientId, op.clientSecret) });
    return { a, res, body: await res.json() };
  }

  describe("discovery", () => {
    it("matches the fixture shape (same keys, same non-URL values, fixture URLs by default)", async () => {
      const res = await op.handle(new Request(`${ISS}/.well-known/openid-configuration`));
      expect(res.status).toBe(200);
      const doc = await res.json();
      const { _comment, ...want } = fixture;
      expect(Object.keys(doc).sort()).toEqual(Object.keys(want).sort());
      expect(doc).toEqual(want);
      expect(doc.userinfo_endpoint).toMatch(/\/profiles\/oidc\/userinfo$/);
      expect(doc.userinfo_endpoint).not.toContain("/login/");
    });

    it("issuer, endpoints and token auth methods are configurable; end_session can be switched off", async () => {
      const o = await createMockOp({
        mode: "janrain", issuer: "https://login.example.com/login",
        endpoints: { token_endpoint: "https://tok.example.com/t" },
        tokenEndpointAuthMethods: ["client_secret_post"], endSession: false,
      });
      expect(o.discovery.issuer).toBe("https://login.example.com/login");
      expect(o.discovery.authorization_endpoint).toBe("https://login.example.com/login/authorize");
      expect(o.discovery.userinfo_endpoint).toBe("https://login.example.com/profiles/oidc/userinfo");
      expect(o.discovery.token_endpoint).toBe("https://tok.example.com/t");
      expect(o.discovery.token_endpoint_auth_methods_supported).toEqual(["client_secret_post"]);
      expect(o.discovery).not.toHaveProperty("end_session_endpoint");
      const res = await o.handle(new Request("https://login.example.com/login/end_session?client_id=x&post_logout_redirect_uri=https://a.test/&state=s"));
      expect(res.status).toBe(404);
      const none = await createMockOp({ mode: "janrain", tokenEndpointAuthMethods: null });
      expect(none.discovery).not.toHaveProperty("token_endpoint_auth_methods_supported");
    });

    it("JWKS publishes only RSA sig RS256 keys", async () => {
      const res = await op.handle(new Request(fixture.jwks_uri));
      const jwks = await res.json();
      expect(jwks.keys).toHaveLength(1);
      for (const k of jwks.keys) {
        expect(k).toMatchObject({ kty: "RSA", use: "sig", alg: "RS256", e: "AQAB" });
        expect(k).not.toHaveProperty("d");
      }
    });
  });

  describe("authorize", () => {
    it("records the query (response_mode, claims, S256) and redirects with code + state", async () => {
      const claims = { id_token: { email: null, given_name: null } };
      const a = await authorize({ response_mode: "query", claims: JSON.stringify(claims) });
      expect(a.res.status).toBe(302);
      const loc = new URL(a.location);
      expect(`${loc.origin}${loc.pathname}`).toBe(CALLBACK);
      expect(loc.searchParams.get("state")).toBe("st-1");
      const rec = op.lastAuthorize();
      expect(rec).toMatchObject({ response_mode: "query", code_challenge_method: "S256", claims, client_id: op.clientId, error: null, code: a.code });
      expect(rec.query.scope).toBe("openid email profile");
      expect(rec.hasClientSecret).toBe(false);
    });

    it("rejects plain / missing PKCE and an unexpected response_mode", async () => {
      expect(new URL((await authorize({ code_challenge_method: "plain" })).location).searchParams.get("error")).toBe("invalid_request");
      expect(new URL((await authorize({ code_challenge: undefined, code_challenge_method: undefined })).location).searchParams.get("error")).toBe("invalid_request");
      const strict = await createMockOp({ mode: "janrain", expectResponseMode: "query" });
      op = strict;
      expect(new URL((await authorize()).location).searchParams.get("error")).toBe("invalid_request");
      expect((await authorize({ response_mode: "query" })).code).toBeTruthy();
      const absent = await createMockOp({ mode: "janrain", expectResponseMode: "absent" });
      op = absent;
      expect((await authorize()).code).toBeTruthy();
      expect(new URL((await authorize({ response_mode: "query" })).location).searchParams.get("error")).toBe("invalid_request");
    });

    it("unknown client or unregistered redirect_uri is a 400, not a redirect", async () => {
      expect((await authorize({ client_id: "other" })).res.status).toBe(400);
      const o = await createMockOp({ mode: "janrain", redirectUris: ["https://a.test/cb"] });
      op = o;
      expect((await authorize()).res.status).toBe(400);
      expect(op.lastAuthorize().error).toBe("invalid_request");
    });

    it("form_post response_mode returns an auto-post form", async () => {
      const { res } = await authorize({ response_mode: "form_post" });
      expect(res.status).toBe(200);
      expect(await res.text()).toMatch(/<form method="post" action="https:\/\/www\.example\.com\/\.auth\/callback">.*name="code".*name="state" value="st-1"/);
    });
  });

  describe("token endpoint", () => {
    it("client_secret_basic (default) succeeds; form-urlencoded credentials are decoded per RFC 6749 §2.3.1", async () => {
      const o = await createMockOp({ mode: "janrain", clientId: "id with:colon&+", clientSecret: "s3cr%t +/:x" });
      op = o;
      const { res, body } = await loginTokens();
      expect(res.status).toBe(200);
      expect(body.token_type).toBe("Bearer");
      const rec = op.lastToken();
      expect(rec).toMatchObject({ authMethod: "client_secret_basic", clientId: "id with:colon&+", status: 200, hasClientSecretInBody: false, hasCodeVerifier: true });
      expect(rec.body).not.toHaveProperty("client_secret");
      expect(rec.body).not.toHaveProperty("code_verifier");
      expect(rec.body.grant_type).toBe("authorization_code");
      expect(JSON.stringify(op.requests)).not.toContain("s3cr%t");
      // Raw (non-encoded) Basic of the same credentials decodes differently → rejected.
      const a = await authorize();
      const raw = await token({ grant_type: "authorization_code", code: a.code, redirect_uri: CALLBACK, code_verifier: a.verifier },
        { basic: `Basic ${btoa("id with:colon&+:s3cr%t +/:x")}` });
      expect(raw.status).toBe(401);
    });

    it("decodeClientBasic decodes + as space and percent-escapes", () => {
      expect(decodeClientBasic(clientBasic("a b", "c:d%"))).toEqual({ clientId: "a b", clientSecret: "c:d%" });
      expect(decodeClientBasic("Bearer x")).toBeNull();
      expect(decodeClientBasic(`Basic ${btoa("nocolon")}`)).toBeNull();
    });

    it("wrong method is 401 invalid_client (post when basic is enforced, and vice versa)", async () => {
      const a = await authorize();
      const res = await token({ grant_type: "authorization_code", code: a.code, redirect_uri: CALLBACK, code_verifier: a.verifier, client_id: op.clientId, client_secret: op.clientSecret });
      expect(res.status).toBe(401);
      expect(await res.json()).toMatchObject({ error: "invalid_client" });
      expect(res.headers.get("www-authenticate")).toMatch(/^Basic/);
      expect(op.lastToken()).toMatchObject({ authMethod: "client_secret_post", status: 401, error: "invalid_client", hasClientSecretInBody: true });
      expect(op.lastToken().body).not.toHaveProperty("client_secret");
      // the code was not consumed by the rejected call
      expect(op.codes.has(a.code)).toBe(true);

      const p = await createMockOp({ mode: "janrain", clientAuthMethod: "client_secret_post" });
      op = p;
      const b = await authorize();
      const viaBasic = await token({ grant_type: "authorization_code", code: b.code, redirect_uri: CALLBACK, code_verifier: b.verifier },
        { basic: clientBasic(op.clientId, op.clientSecret) });
      expect(viaBasic.status).toBe(401);
      expect(await viaBasic.json()).toMatchObject({ error: "invalid_client" });
      const viaPost = await token({ grant_type: "authorization_code", code: b.code, redirect_uri: CALLBACK, code_verifier: b.verifier, client_id: op.clientId, client_secret: op.clientSecret });
      expect(viaPost.status).toBe(200);
      expect(op.lastToken()).toMatchObject({ authMethod: "client_secret_post", clientId: op.clientId, status: 200 });
    });

    it("bad secret, both methods at once, and no auth are all invalid_client", async () => {
      const a = await authorize();
      const f = { grant_type: "authorization_code", code: a.code, redirect_uri: CALLBACK, code_verifier: a.verifier };
      expect((await token(f, { basic: clientBasic(op.clientId, "wrong") })).status).toBe(401);
      expect((await token({ ...f, client_secret: op.clientSecret }, { basic: clientBasic(op.clientId, op.clientSecret) })).status).toBe(401);
      expect(op.lastToken().authMethod).toBe("multiple");
      expect((await token({ ...f, client_id: op.clientId })).status).toBe(401);
      expect(op.lastToken().authMethod).toBe("none");
    });

    it("verifies PKCE and binds redirect_uri; codes are single-use", async () => {
      const a = await authorize();
      const basic = clientBasic(op.clientId, op.clientSecret);
      const f = { grant_type: "authorization_code", code: a.code, redirect_uri: CALLBACK };
      const wrong = await token({ ...f, code_verifier: "not-the-verifier" }, { basic });
      expect(wrong.status).toBe(400);
      expect(await wrong.json()).toMatchObject({ error: "invalid_grant" });
      const b = await authorize();
      expect((await token({ ...f, code: b.code }, { basic })).status).toBe(400); // missing verifier
      const c = await authorize();
      expect((await token({ ...f, code: c.code, code_verifier: c.verifier, redirect_uri: "https://evil.test/cb" }, { basic })).status).toBe(400);
      const d = await authorize();
      expect((await token({ ...f, code: d.code, code_verifier: d.verifier }, { basic })).status).toBe(200);
      expect((await token({ ...f, code: d.code, code_verifier: d.verifier }, { basic })).status).toBe(400);
      expect((await token({ ...f, grant_type: "password" }, { basic })).status).toBe(400);
    });

    it("returns an opaque access token and an RS256 id_token without groups or scope claims", async () => {
      const { body } = await loginTokens();
      expect(Object.keys(body).sort()).toEqual(["access_token", "expires_in", "id_token", "scope", "token_type"]);
      expect(body.access_token.split(".")).toHaveLength(1); // not a JWT
      const { header, payload } = decodeJwt(body.id_token);
      expect(header.alg).toBe("RS256");
      expect(header.kid).toBe(op.key.kid);
      expect(payload).toMatchObject({ iss: fixture.issuer, aud: op.clientId, azp: op.clientId, sub: op.user.sub, nonce: "n-1", sid: expect.any(String) });
      expect(payload.at_hash).toBe(await tokenHash(body.access_token));
      expect(payload).not.toHaveProperty("groups");
      expect(payload).not.toHaveProperty("email"); // scopes never populate the ID token
      expect(payload).not.toHaveProperty("c_hash");
      expect(await verifyJwt(body.id_token, op.jwks)).toBe(true);
    });

    it("echoes requested `claims` into the id_token (never groups); push claims override the parameter", async () => {
      const claims = JSON.stringify({ id_token: { email: null, email_verified: null, given_name: null, name: null, groups: null } });
      const { payload } = decodeJwt((await loginTokens({ claims })).body.id_token);
      expect(payload).toMatchObject({ email: "u@example.com", email_verified: true, given_name: "Uma" });
      expect(payload).not.toHaveProperty("name"); // no mapped attribute on the user
      expect(payload).not.toHaveProperty("groups");
      expect(payload).not.toHaveProperty("family_name");

      op = await createMockOp({ mode: "janrain", pushClaims: ["family_name"], groupsInIdToken: true, audience: "client+redirect" });
      const p2 = decodeJwt((await loginTokens({ claims })).body.id_token).payload;
      expect(p2.family_name).toBe("User");
      expect(p2).not.toHaveProperty("email");
      expect(p2.groups).toEqual(["site-readers"]);
      expect(p2.aud).toEqual([op.clientId, CALLBACK]);
      expect(p2.azp).toBe(op.clientId);
    });

    it("issueCode/setBrokenForCode work like default mode", async () => {
      op.issueCode("k1", { claims: { nonce: "n", groups: ["x"] } });
      op.setBrokenForCode("k1", "no-kid");
      const res = await token({ grant_type: "authorization_code", code: "k1" }, { basic: clientBasic(op.clientId, op.clientSecret) });
      const { header, payload } = decodeJwt((await res.json()).id_token);
      expect(header).not.toHaveProperty("kid");
      expect(payload).toMatchObject({ nonce: "n", groups: ["x"] });
    });
  });

  describe("key rotation", () => {
    it("rotateKey adds a new kid used by later tokens; the old key can stay published or be dropped", async () => {
      const t1 = (await loginTokens()).body.id_token;
      const oldKid = op.key.kid;
      const k2 = await op.rotateKey();
      expect(k2.kid).not.toBe(oldKid);
      const t2 = (await loginTokens()).body.id_token;
      expect(decodeJwt(t2).header.kid).toBe(k2.kid);
      expect(op.jwks.keys.map((k) => k.kid)).toEqual([oldKid, k2.kid]);
      expect(await verifyJwt(t1, op.jwks)).toBe(true);
      expect(await verifyJwt(t2, op.jwks)).toBe(true);

      const k3 = await op.rotateKey({ keepOld: false, kid: "k3" });
      const served = await (await op.handle(new Request(op.discovery.jwks_uri))).json();
      expect(served.keys.map((k) => k.kid)).toEqual(["k3"]);
      expect(served.keys.every((k) => k.kty === "RSA" && k.use === "sig" && k.alg === "RS256")).toBe(true);
      expect(decodeJwt((await loginTokens()).body.id_token).header.kid).toBe(k3.kid);
      expect(await verifyJwt(t1, op.jwks)).toBe(false);
    });
  });

  describe("userinfo", () => {
    it("requires the Bearer access token and returns scoped claims (no groups)", async () => {
      const { body } = await loginTokens({ scope: "openid email" });
      const ep = op.discovery.userinfo_endpoint;
      expect((await op.handle(new Request(ep))).status).toBe(401);
      const bad = await op.handle(new Request(ep, { headers: { authorization: "Bearer nope" } }));
      expect(bad.status).toBe(401);
      expect(bad.headers.get("www-authenticate")).toMatch(/invalid_token/);
      const ok = await op.handle(new Request(ep, { headers: { authorization: `Bearer ${body.access_token}` } }));
      expect(ok.status).toBe(200);
      const info = await ok.json();
      expect(info).toMatchObject({ sub: op.user.sub, email: "u@example.com", email_verified: true });
      expect(info).not.toHaveProperty("given_name");
      expect(info).not.toHaveProperty("groups");
      expect(op.requests.userinfo.map((r) => r.status)).toEqual([401, 401, 200]);
      expect(op.requests.userinfo[0].hasBearer).toBe(false);
    });
  });

  describe("end_session", () => {
    const ep = () => op.discovery.end_session_endpoint;
    it("requires client_id, post_logout_redirect_uri and state, and records them", async () => {
      const ok = await op.handle(new Request(`${ep()}?client_id=${op.clientId}&post_logout_redirect_uri=${encodeURIComponent("https://www.example.com/")}&state=s1`));
      expect(ok.status).toBe(302);
      expect(ok.headers.get("location")).toBe("https://www.example.com/?state=s1");
      expect(op.lastEndSession()).toMatchObject({ client_id: op.clientId, post_logout_redirect_uri: "https://www.example.com/", state: "s1", status: 302 });
      for (const q of [
        `post_logout_redirect_uri=https://www.example.com/&state=s1`,
        `client_id=${op.clientId}&state=s1`,
        `client_id=${op.clientId}&post_logout_redirect_uri=https://www.example.com/`,
        `client_id=other&post_logout_redirect_uri=https://www.example.com/&state=s1`,
      ]) {
        const r = await op.handle(new Request(`${ep()}?${q}`));
        expect(r.status, q).toBe(400);
        expect(await r.json()).toMatchObject({ error: "invalid_request" });
      }
      expect(op.requests.endSession).toHaveLength(5);
    });

    it("enforces registered postLogoutRedirectUris when configured", async () => {
      op = await createMockOp({ mode: "janrain", postLogoutRedirectUris: ["https://www.example.com/"] });
      expect((await op.handle(new Request(`${ep()}?client_id=${op.clientId}&post_logout_redirect_uri=https://evil.test/&state=s`))).status).toBe(400);
      expect((await op.handle(new Request(`${ep()}?client_id=${op.clientId}&post_logout_redirect_uri=https://www.example.com/&state=s`))).status).toBe(302);
    });
  });

  it("reset() clears codes, tokens and recorded requests", async () => {
    await loginTokens();
    op.reset();
    expect(op.requests.authorize).toHaveLength(0);
    expect(op.requests.token).toHaveLength(0);
    expect(op.accessTokens.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
describe("createMockUserInfo", () => {
  const ORIGIN = "https://userinfo.test";
  let ui;
  const auth = basicAuth("svc-user", "svc-pass");
  const get = (path, headers = { authorization: auth }, init = {}) => ui.handle(new Request(`${ORIGIN}${path}`, { headers, ...init }));
  beforeEach(() => {
    ui = createMockUserInfo({
      users: {
        "3c388dd9-0000-4000-8000-000000000001": { groups: ["medical", "market-access"], profile: { email: "u@example.com", name: "Uma User" } },
        "a/b c": { groups: [], profile: {} },
      },
    });
  });

  it("serves groups for a known sub (URL-decoded) and the profile path", async () => {
    const res = await get("/users/3c388dd9-0000-4000-8000-000000000001");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ sub: "3c388dd9-0000-4000-8000-000000000001", email: "u@example.com", name: "Uma User", groups: ["medical", "market-access"] });
    expect((await get(`/users/${encodeURIComponent("a/b c")}`)).status).toBe(200);
    const prof = await get("/profiles/3c388dd9-0000-4000-8000-000000000001");
    expect(prof.status).toBe(200);
    expect((await prof.json()).name).toBe("Uma User");
    expect(ui.requests.map((r) => r.kind)).toEqual(["groups", "groups", "profile"]);
    expect(ui.requests[1].sub).toBe("a/b c");
    expect(ui.endpoint).toBe("https://userinfo.test/users/{sub}");
  });

  it("requires valid Basic credentials; records presence/validity, never the password", async () => {
    expect((await get("/users/x", {})).status).toBe(401);
    expect((await get("/users/x", { authorization: basicAuth("svc-user", "nope") })).status).toBe(401);
    expect((await get("/users/x", { authorization: "Bearer svc-pass" })).status).toBe(401);
    expect(ui.requests.map((r) => [r.authPresent, r.authValid])).toEqual([[false, false], [true, false], [true, false]]);
    expect(ui.requests[0]).toMatchObject({ method: "GET", path: "/users/x", status: 401 });
    expect(JSON.stringify(ui.requests)).not.toContain("svc-pass");
    expect(JSON.stringify(ui.requests)).not.toContain(btoa("svc-user:svc-pass"));
  });

  it("unknown user → 404; unknown path → 404; non-GET → 405", async () => {
    expect((await get("/users/nobody")).status).toBe(404);
    expect((await get("/elsewhere")).status).toBe(404);
    expect((await get("/users/x", { authorization: auth }, { method: "POST", body: "" })).status).toBe(405);
  });

  it("nested groupsPath, {email} templates and a custom profile path", async () => {
    ui = createMockUserInfo({
      origin: "https://ui2.test/", username: "u", password: "p:with:colons", groupsPath: "data.roles",
      path: "/v1/lookup/{email}", profilePath: "/v1/profile/{sub}",
      users: { s1: { groups: ["g1"], profile: { email: "e@x.test" } } },
    });
    const h = { authorization: basicAuth("u", "p:with:colons") };
    const r = await ui.handle(new Request(`https://ui2.test/v1/lookup/${encodeURIComponent("e@x.test")}`, { headers: h }));
    expect(await r.json()).toEqual({ sub: "s1", email: "e@x.test", data: { roles: ["g1"] } });
    const p = await ui.handle(new Request("https://ui2.test/v1/profile/s1", { headers: h }));
    expect(p.status).toBe(200);
  });

  describe("failure modes", () => {
    const SUB = "/users/3c388dd9-0000-4000-8000-000000000001";
    it("status-500 and arbitrary status", async () => {
      ui.fail("status-500");
      expect((await get(SUB)).status).toBe(500);
      ui.fail({ status: 503 });
      expect((await get(SUB)).status).toBe(503);
    });
    it("malformed-json", async () => {
      ui.fail("malformed-json");
      const res = await get(SUB);
      expect(res.status).toBe(200);
      await expect(res.json()).rejects.toThrow();
    });
    it("missing-groups / groups-not-array / groups-non-string / groups-comma", async () => {
      ui.fail("missing-groups");
      expect(await (await get(SUB)).json()).not.toHaveProperty("groups");
      ui.fail("groups-not-array");
      expect(typeof (await (await get(SUB)).json()).groups).toBe("string");
      ui.fail("groups-non-string");
      expect((await (await get(SUB)).json()).groups.some((g) => typeof g !== "string")).toBe(true);
      ui.fail("groups-comma");
      expect((await (await get(SUB)).json()).groups.some((g) => typeof g === "string" && g.includes(","))).toBe(true);
    });
    it("missing-groups removes a nested path", async () => {
      ui = createMockUserInfo({ groupsPath: "a.b", users: { s: { groups: ["g"] } } });
      ui.fail("missing-groups");
      expect(await (await get("/users/s")).json()).toEqual({ sub: "s", a: {} });
    });
    it("network-error throws like fetch", async () => {
      ui.fail("network-error");
      await expect(get(SUB)).rejects.toThrow(TypeError);
      expect(ui.requests[0]).toMatchObject({ status: "network-error", failure: "network-error" });
    });
    it("times limits a failure; failures are not consumed by unauthenticated calls; clearFailure resets", async () => {
      ui.fail("status-500", { times: 1 });
      expect((await get(SUB, {})).status).toBe(401);
      expect((await get(SUB)).status).toBe(500);
      expect((await get(SUB)).status).toBe(200);
      ui.fail("status-500");
      ui.clearFailure();
      expect((await get(SUB)).status).toBe(200);
      expect(() => ui.fail("bogus")).toThrow();
      expect(USER_INFO_FAILURES).toContain("groups-comma");
    });
    it("delay slows the response and honours an abort signal", async () => {
      ui.setDelay(60);
      const t0 = Date.now();
      expect((await get(SUB)).status).toBe(200);
      expect(Date.now() - t0).toBeGreaterThanOrEqual(50);
      const ac = new AbortController();
      const p = get(SUB, { authorization: auth }, { signal: ac.signal });
      setTimeout(() => ac.abort(), 5);
      await expect(p).rejects.toThrow();
      const slow = createMockUserInfo({ delayMs: 30, users: { s: { groups: [] } } });
      ui = slow;
      const t1 = Date.now();
      await get("/users/s");
      expect(Date.now() - t1).toBeGreaterThanOrEqual(25);
    });
  });

  it("setUser/removeUser/reset", async () => {
    ui.setUser("new", { groups: ["g"] });
    expect((await get("/users/new")).status).toBe(200);
    ui.removeUser("new");
    expect((await get("/users/new")).status).toBe(404);
    ui.fail("status-500");
    ui.setDelay(1000);
    ui.reset();
    expect(ui.requests).toHaveLength(0);
    expect((await get("/users/a%2Fb%20c")).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
describe("routeFetch", () => {
  it("dispatches OP, user-info, origin host and siteverify by origin; records calls", async () => {
    const op = await createMockOp({ mode: "janrain" });
    const ui = createMockUserInfo({ users: { s: { groups: ["g"] } } });
    const siteverify = async () => Response.json({ success: true, score: 0.9 });
    const f = routeFetch({
      [new URL(op.issuer).origin]: op,
      [ui.origin]: ui,
      [op.originHostname]: op,
      "https://www.google.com": siteverify,
    });
    expect((await f(`${op.issuer}/.well-known/openid-configuration`)).status).toBe(200);
    expect((await f(`${ui.origin}/users/s`, { headers: { authorization: basicAuth("svc-user", "svc-pass") } })).status).toBe(200);
    expect(await (await f(`https://${op.originHostname}/page`)).text()).toBe("origin-body");
    expect((await (await f(new Request("https://www.google.com/recaptcha/api/siteverify", { method: "POST", body: "x" }))).json()).success).toBe(true);
    expect(f.calls.map((c) => c.routed)).toEqual([true, true, true, true]);
    expect(f.calls[3].method).toBe("POST");
  });

  it("unrouted origins reject, or go to the fallback", async () => {
    const f = routeFetch({ "https://a.test": () => new Response("a") });
    await expect(f("https://b.test/x")).rejects.toThrow(/no mock for https:\/\/b\.test/);
    expect(f.calls[0].routed).toBe(false);
    const g = routeFetch({}, () => new Response("fb", { status: 418 }));
    expect((await g("https://b.test/")).status).toBe(418);
    expect(() => routeFetch({ "https://a.test": {} })).toThrow(/handle/);
  });

  it("can be installed as globalThis.fetch with the default-mode OP", async () => {
    const op = await createMockOp();
    const real = globalThis.fetch;
    globalThis.fetch = routeFetch({ "https://op.test": op });
    try {
      expect((await (await fetch("https://op.test/.well-known/openid-configuration")).json()).issuer).toBe("https://op.test");
    } finally { globalThis.fetch = real; }
  });
});
