// The callback route (ported from the legacy test/oidc.test.js handleCallback
// cases, the adapter's lifecycle tests and the hygiene fail-closed marker test),
// plus the per-profile KV behaviour (ADR §11) and the kernel fetch policy
// (egress, budget, cache modes).
import { describe, it, expect, beforeEach, vi } from "vitest";

// Spy on newSessionId (the real implementation) so a test can tell which
// minted id ended up in the cookie and how many were minted per login.
vi.mock("../lib/session.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, newSessionId: vi.fn(actual.newSessionId) };
});

import { PluginError, createIdentityDraft, isIdentity } from "../../../src/sdk/index.js";
import { makeRsaKey, signJwt } from "../../../test/helpers.js";
import { describeEachProfile } from "../../../test/helpers/profiles.js";
import { NO_GROUPS_FROM_USER_INFO } from "../lib/callback.js";
import { buildSession, decodeSession, newSessionId } from "../lib/session.js";
import { keyId } from "../lib/signed-cookie.js";
import { stateUsedKey } from "../lib/state.js";
import {
  CLIENT_ID, HMAC_KEY, ISSUER, OPTIONS, SECRETS, SITE, callbackRoute, makeCtx, newOp, oidcAuth, runCallback, setCookieValue, startLogin,
} from "./support.js";

let op;
beforeEach(async () => { op = await newOp(); });

const SESSION = "__Host-edge_session";
const LOGIN = "__Host-edge_login";
const sessionOf = (ctx) => setCookieValue(ctx, SESSION);
const tokenCalls = (ctx) => ctx.recorded.fetches.filter((f) => f.opts.purpose === "token");

async function expectAuthError(res, status) {
  expect(res.status).toBe(status);
  expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
  expect(res.headers.get("x-auth-request-id")).toBe("test-request-id"); // ctx.requestId, not a fresh id
  expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  expect(await res.text()).toBe(`${status} — authentication error (request-id: test-request-id)\n`);
}

describe("success", () => {
  it("P2 mints a session, clears the login cookie (in that order) and 302s back to the return path", async () => {
    const start = await startLogin(op, "/members/x?q=1");
    const { ctx, res } = await runCallback(op, start, { groups: ["medical"] });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/members/x?q=1");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(ctx.recorded.cookies.map((c) => c.name)).toEqual([SESSION, LOGIN]);
    expect(ctx.recorded.cookies[0].attrs).toEqual({ maxAge: 3600 });
    expect(ctx.recorded.cookies[1]).toEqual({ name: LOGIN, cleared: true });
    const session = await decodeSession(sessionOf(ctx), HMAC_KEY);
    expect(session).toMatchObject({ v: 2, typ: "session", kid: await keyId(HMAC_KEY), sub: "user-123", email: "u@example.com", groups: ["medical"] });
    expect(session.sid).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(session.exp - session.iat).toBe(3600);
  });

  it("every login mints a fresh session id", async () => {
    const a = await runCallback(op, await startLogin(op));
    const b = await runCallback(op, await startLogin(op));
    const [sa, sb] = await Promise.all([decodeSession(sessionOf(a.ctx), HMAC_KEY), decodeSession(sessionOf(b.ctx), HMAC_KEY)]);
    expect(sa.sid).not.toBe(sb.sid);
  });

  it("key rotation mid-login: a login started under the old key completes; the session uses the new key", async () => {
    const OLD_KEY = "old-plugin-test-hmac-key-at-least-32-bytes";
    const start = await startLogin(op, "/x", { secrets: { ...SECRETS, session_hmac_key: OLD_KEY } });
    const rotated = { ...SECRETS, session_hmac_key_previous: OLD_KEY };
    const { ctx, res } = await runCallback(op, start, { ctxOpts: { secrets: rotated } });
    expect(res.status).toBe(302);
    const session = await decodeSession(sessionOf(ctx), HMAC_KEY);
    expect(session.kid).toBe(await keyId(HMAC_KEY));
    // Without the previous key the in-flight login state no longer verifies.
    const start2 = await startLogin(op, "/x", { secrets: { ...SECRETS, session_hmac_key: OLD_KEY } });
    await expectAuthError((await runCallback(op, start2)).res, 400);
  });

  it("a session cookie presented as the login-state cookie → 400 (typ binding, F19)", async () => {
    const { ctx } = await runCallback(op, await startLogin(op));
    const asLogin = makeCtx("/.auth/callback?code=c&state=s", { op, cookie: `${LOGIN}=${encodeURIComponent(sessionOf(ctx))}` });
    await expectAuthError(await callbackRoute()(asLogin, OPTIONS), 400);
    expect(asLogin.recorded.fetches).toEqual([]);
  });

  it("the minted session authenticates on the next request", async () => {
    const { ctx } = await runCallback(op, await startLogin(op), { groups: ["a", "b"] });
    const identity = await oidcAuth.authenticate(makeCtx("/protected/x", { cookie: `${SESSION}=${sessionOf(ctx)}` }), OPTIONS);
    expect(isIdentity(identity)).toBe(true);
    expect(identity.groups).toEqual(["a", "b"]);
    expect(identity.sessionId).toBe((await decodeSession(sessionOf(ctx), HMAC_KEY)).sid);
  });

  it("token exchange: client_secret_post form POST with code, verifier, client id/secret and redirect_uri (purpose token, pass)", async () => {
    const seen = [];
    const start = await startLogin(op);
    const { ctx, res } = await runCallback(op, start, {
      ctxOpts: { fetch: async (input, init) => { const r = new Request(input, init); if (r.method === "POST") seen.push(await r.clone().text()); return op.handle(r); } },
    });
    expect(res.status).toBe(302);
    const [tok] = tokenCalls(ctx);
    expect(tok).toMatchObject({ url: `${ISSUER}/token`, method: "POST" });
    expect(tok.opts).toEqual({ purpose: "token" }); // default cache mode: pass
    expect(tok.init.headers).toEqual({ "content-type": "application/x-www-form-urlencoded" });
    const form = new URLSearchParams(seen[0]);
    expect([...form.keys()]).toEqual(["grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"]);
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("redirect_uri")).toBe(`${SITE}/.auth/callback`);
    expect(form.get("client_id")).toBe(CLIENT_ID);
    expect(form.get("client_secret")).toBe("test-client-secret");
    expect(form.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("groups come only from the configured groups claim (no fallback to roles)", async () => {
    const config = { ...makeCtx("/").config, groupsClaim: "https://claims/groups" };
    const start = await startLogin(op, "/x", { config });
    const { ctx } = await runCallback(op, start, {
      claims: { groups: ["plain"], roles: ["admin"], "https://claims/groups": ["ns", 5, "ns", ""] }, ctxOpts: { config },
    });
    expect((await decodeSession(sessionOf(ctx), HMAC_KEY)).groups).toEqual(["ns"]);
  });

  // F17: an explicitly unverified email is dropped from the identity.
  it("email_verified: false drops the email; true or absent keeps it", async () => {
    const unverified = await runCallback(op, await startLogin(op), { claims: { email: "victim@example.com", email_verified: false } });
    const s1 = await decodeSession(sessionOf(unverified.ctx), HMAC_KEY);
    expect(s1.sub).toBe("user-123");
    expect(s1.email).toBeFalsy();
    expect(JSON.stringify(s1)).not.toContain("victim@example.com");
    for (const claims of [{ email: "v@example.com", email_verified: true }, { email: "v@example.com" }, { email: "v@example.com", email_verified: "false" }]) {
      const { ctx } = await runCallback(op, await startLogin(op), { claims });
      expect((await decodeSession(sessionOf(ctx), HMAC_KEY)).email).toBe("v@example.com");
    }
  });

  it("F17 a group containing a comma is dropped (x-auth-groups is comma-joined)", async () => {
    const { ctx } = await runCallback(op, await startLogin(op), { groups: ["medical", "readers,admin"] });
    expect((await decodeSession(sessionOf(ctx), HMAC_KEY)).groups).toEqual(["medical"]);
  });

  it("H4 a single-string groups claim becomes a one-element list (no login loop)", async () => {
    const { ctx } = await runCallback(op, await startLogin(op), { claims: { groups: "site-readers" } });
    expect((await decodeSession(sessionOf(ctx), HMAC_KEY)).groups).toEqual(["site-readers"]);
  });

  it("N13 a protocol-relative return path is sanitized to '/' (no open redirect)", async () => {
    const { res } = await runCallback(op, await startLogin(op, "//evil.com"));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/");
  });

  it("local dev: the callback's redirect_uri is request-derived, matching the login leg", async () => {
    const options = oidcAuth.validate({ issuer: ISSUER });
    const start = await startLogin(op, "http://localhost:7676/x");
    const seen = [];
    op.issueCode("local-code", { claims: { nonce: start.params.get("nonce") }, codeChallenge: start.params.get("code_challenge") });
    const ctx = makeCtx(`http://localhost:7676/.auth/callback?code=local-code&state=${encodeURIComponent(start.params.get("state"))}`, {
      cookie: start.loginCookie,
      fetch: async (i, init) => { const r = new Request(i, init); if (r.method === "POST") seen.push(await r.clone().text()); return op.handle(r); },
    });
    const res = await callbackRoute(options)(ctx, options);
    expect(res.status).toBe(302);
    expect(new URLSearchParams(seen[0]).get("redirect_uri")).toBe("http://localhost:7676/.auth/callback");
    expect(start.params.get("redirect_uri")).toBe("http://localhost:7676/.auth/callback");
  });
});

describe("rejections: generic error page, request id, no cookies written", () => {
  it("no login-state cookie → 400, nothing fetched", async () => {
    const ctx = makeCtx("/.auth/callback?code=c&state=s", { op });
    await expectAuthError(await callbackRoute()(ctx, OPTIONS), 400);
    expect(ctx.recorded.fetches).toEqual([]);
    expect(ctx.recorded.cookies).toEqual([]);
  });

  it("forged (unsigned) login-state cookie → 400", async () => {
    const ctx = makeCtx("/.auth/callback?code=c&state=s", { op, cookie: `${LOGIN}=forged.value` });
    await expectAuthError(await callbackRoute()(ctx, OPTIONS), 400);
  });

  it("N8 state mismatch → 400, logged reason not leaked", async () => {
    const { ctx, res } = await runCallback(op, await startLogin(op), { state: "WRONG" });
    await expectAuthError(res, 400);
    expect(ctx.recorded.cookies).toEqual([]);
    expect(ctx.recorded.fetches).toEqual([]);
    expect(ctx.recorded.logs.find((l) => l.level === "error").fields).toEqual({ status: 400, detail: "state mismatch, possible CSRF" });
  });

  it("N12/H7 IdP error parameter → 401, not reflected to the client", async () => {
    const { ctx, res } = await runCallback(op, await startLogin(op), { errorParam: "this_is_internal_detail" });
    expect(res.status).toBe(401);
    expect(await res.text()).not.toContain("this_is_internal_detail");
    expect(ctx.recorded.cookies).toEqual([]);
  });

  // F16: attacker-controlled IdP text never reaches the logs verbatim.
  it("a crafted IdP error parameter is logged as \"invalid\", never verbatim", async () => {
    const crafted = "access_denied\r\n{\"level\":\"info\",\"forged\":true} <script>EVIL-MARKER</script>";
    const { ctx, res } = await runCallback(op, await startLogin(op), { errorParam: crafted });
    expect(res.status).toBe(401);
    const logs = JSON.stringify(ctx.recorded.logs);
    expect(logs).not.toContain("EVIL-MARKER");
    expect(logs).not.toContain("forged");
    expect(ctx.recorded.logs.find((l) => l.level === "error").fields).toEqual({ status: 401, detail: "authorization failed: invalid" });
  });

  it("a plain OAuth error code from the IdP is logged as-is", async () => {
    const { ctx } = await runCallback(op, await startLogin(op), { errorParam: "access_denied" });
    expect(ctx.recorded.logs.find((l) => l.level === "error").fields.detail).toBe("authorization failed: access_denied");
  });

  it.each([
    ["malformed", "%%%EVIL-MARKER%%%.%%%.%%%"],
    ["malformed", "only.EVIL-MARKER"],
    ["kid_unknown", `${Buffer.from(JSON.stringify({ alg: "RS256", kid: "EVIL-MARKER\r\nfake log line" })).toString("base64url")}.${Buffer.from("{}").toString("base64url")}.c2ln`],
    ["unsupported_alg", `${Buffer.from(JSON.stringify({ alg: "EVIL-MARKER" })).toString("base64url")}.${Buffer.from("{}").toString("base64url")}.c2ln`],
  ])("an ID token rejected as %s is logged as that fixed reason code, never verbatim", async (reason, idToken) => {
    const start = await startLogin(op);
    const { ctx, res } = await runCallback(op, start, {
      ctxOpts: { fetch: async (i, init) => { const r = new Request(i, init); return r.method === "POST" ? Response.json({ id_token: idToken, access_token: "x" }) : op.handle(r); } },
    });
    await expectAuthError(res, 400);
    expect(ctx.recorded.logs.find((l) => l.level === "error").fields).toEqual({ status: 400, detail: `ID token validation failed: ${reason}` });
    expect(JSON.stringify(ctx.recorded.logs)).not.toContain("EVIL-MARKER");
  });

  it("missing code → 400", async () => {
    await expectAuthError((await runCallback(op, await startLogin(op), { dropCode: true })).res, 400);
  });

  it("N10 wrong PKCE verifier → the OP rejects the code, 401, no session", async () => {
    const { ctx, res } = await runCallback(op, await startLogin(op), { wrongPkce: true });
    await expectAuthError(res, 401);
    expect(sessionOf(ctx)).toBeNull();
  });

  it("a code the IdP does not know → 401", async () => {
    await expectAuthError((await runCallback(op, await startLogin(op), { code: "unknown", register: false })).res, 401);
  });

  it("a token response without an id_token → 401", async () => {
    const start = await startLogin(op);
    const { res } = await runCallback(op, start, {
      ctxOpts: { fetch: async (i, init) => { const r = new Request(i, init); return r.method === "POST" ? Response.json({ access_token: "x" }) : op.handle(r); } },
    });
    await expectAuthError(res, 401);
  });

  it.each(["bad-sig", "alg-none", "wrong-aud", "bad-nonce", "expired"])("ID token rejected (%s) → 400, no session", async (broken) => {
    const { ctx, res } = await runCallback(op, await startLogin(op), { broken });
    await expectAuthError(res, 400);
    expect(ctx.recorded.cookies).toEqual([]);
  });

  it("a discovery failure at the callback throws (the kernel answers 500 internal_error)", async () => {
    const start = await startLogin(op);
    await expect(runCallback(op, start, { ctxOpts: { fetch: async () => new Response("down", { status: 503 }) } })).rejects.toThrow(/discovery fetch failed/);
  });

  it("missing client_secret → throws (500), no session", async () => {
    const start = await startLogin(op);
    await expect(runCallback(op, start, { ctxOpts: { secrets: { session_hmac_key: HMAC_KEY } } })).rejects.toThrow(/client_secret/);
  });
});

describe("login lifecycle", () => {
  it("emits login with the verified draft BEFORE minting; groups added by subscribers land in the session", async () => {
    const start = await startLogin(op);
    op.issueCode("lc", { claims: { nonce: start.params.get("nonce"), groups: ["idp-group"] }, codeChallenge: start.params.get("code_challenge") });
    const seen = [];
    let ctx = null;
    ctx = makeCtx(`/.auth/callback?code=lc&state=${encodeURIComponent(start.params.get("state"))}`, {
      op,
      cookie: start.loginCookie,
      lifecycle: {
        emitLogin: async (draft) => {
          seen.push({ sub: draft.sub, email: draft.email, groups: [...draft.groups], claimsSub: draft.claims.sub, cookiesSoFar: ctx.recorded.cookies.length });
          draft.addGroups(["from-hook", "idp-group"]);
          draft.setAttr("tier", "gold");
        },
      },
    });
    const res = await callbackRoute()(ctx, OPTIONS);
    expect(res.status).toBe(302);
    expect(ctx.recorded.lifecycle.map((e) => e.event)).toEqual(["login"]);
    expect(seen).toEqual([{ sub: "user-123", email: "u@example.com", groups: ["idp-group"], claimsSub: "user-123", cookiesSoFar: 0 }]);
    // attrs are not persisted (the session wire format has no attrs); groups are.
    expect(await decodeSession(sessionOf(ctx), HMAC_KEY)).toMatchObject({ groups: ["idp-group", "from-hook"] });
  });

  it("a failing login subscriber aborts the login (fail closed): 500 auth error, no cookies", async () => {
    const { ctx, res } = await runCallback(op, await startLogin(op), {
      ctxOpts: { lifecycle: { emitLogin: async () => { throw new Error("user-info backend down"); } } },
    });
    await expectAuthError(res, 500);
    expect(ctx.recorded.cookies).toEqual([]);
  });

  it("the draft is sealed after minting (a late addGroups throws)", async () => {
    let held;
    await runCallback(op, await startLogin(op), { ctxOpts: { lifecycle: { emitLogin: async (d) => { held = d; } } } });
    expect(() => held.addGroups(["late"])).toThrow(/sealed/);
  });
});

describe("single-use state marker (N9)", () => {
  it("KV present: a replayed callback (same cookie + state) → 400 before any token exchange", async () => {
    const start = await startLogin(op);
    const first = await runCallback(op, start, { ctxOpts: { kv: true } });
    expect(first.res.status).toBe(302);
    expect([...first.ctx.recorded.kv.keys()]).toContain(stateUsedKey(start.params.get("state")));
    const marker = JSON.parse(first.ctx.recorded.kv.get(stateUsedKey(start.params.get("state"))));
    expect(marker.value).toBe(true);

    const second = await runCallback(op, start, { register: false, code: first.code, ctxOpts: { kv: first.ctx.recorded.kv } });
    await expectAuthError(second.res, 400);
    expect(tokenCalls(second.ctx)).toEqual([]);
    expect(sessionOf(second.ctx)).toBeNull();
  });

  it("an expired marker does not block", async () => {
    const start = await startLogin(op);
    const kv = new Map([[stateUsedKey(start.params.get("state")), JSON.stringify({ value: true, expires: Date.now() - 1 })]]);
    expect((await runCallback(op, start, { ctxOpts: { kv } })).res.status).toBe(302);
  });

  it("concurrent duplicate callbacks mint at most one session (the IdP's single-use code)", async () => {
    const start = await startLogin(op);
    op.issueCode("dup", { claims: { nonce: start.params.get("nonce") }, codeChallenge: start.params.get("code_challenge") });
    const results = await Promise.all([1, 2].map(() => runCallback(op, start, { code: "dup", register: false })));
    expect(results.filter((r) => sessionOf(r.ctx)).length).toBeLessThanOrEqual(1);
  });
});

describeEachProfile("KV behaviour per platform profile (ADR §11)", (profile) => {
  const platform = { profile };

  it("KV present: the marker is written and the login completes", async () => {
    const { ctx, res } = await runCallback(op, await startLogin(op), { ctxOpts: { kv: true, platform } });
    expect(res.status).toBe(302);
    expect([...ctx.recorded.kv.keys()].some((k) => k.startsWith("oidc:state-used:"))).toBe(true);
  });

  it("KV present but erroring: fails closed (throws → 500), no token exchange, no session", async () => {
    const start = await startLogin(op);
    const u = `/.auth/callback?code=c&state=${encodeURIComponent(start.params.get("state"))}`;
    const ctx = makeCtx(u, { op, cookie: start.loginCookie, platform });
    ctx.kv = { async get() { return null; }, async put() { throw new Error("kv put boom"); }, async delete() {} };
    await expect(callbackRoute()(ctx, OPTIONS)).rejects.toThrow(/kv put boom/);
    expect(tokenCalls(ctx)).toEqual([]);
    expect(ctx.recorded.cookies).toEqual([]);
  });

  if (profile === "provisioned") {
    it("no KV: fails closed with PluginError(503, kv_unavailable) before the token exchange", async () => {
      const start = await startLogin(op);
      let err;
      try {
        await runCallback(op, start, { ctxOpts: { platform } });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(PluginError);
      expect(err).toMatchObject({ status: 503, code: "kv_unavailable" });
    });

    it("no KV: nothing was fetched or written before the 503", async () => {
      const start = await startLogin(op);
      const u = `/.auth/callback?code=c&state=${encodeURIComponent(start.params.get("state"))}`;
      const ctx = makeCtx(u, { op, cookie: start.loginCookie, platform });
      await expect(callbackRoute()(ctx, OPTIONS)).rejects.toMatchObject({ code: "kv_unavailable" });
      expect(ctx.recorded.fetches).toEqual([]);
      expect(ctx.recorded.cookies).toEqual([]);
    });

    it("no KV: a bad state still gets the 400 (the 503 only guards a validated state)", async () => {
      const { res } = await runCallback(op, await startLogin(op), { state: "WRONG", ctxOpts: { platform } });
      expect(res.status).toBe(400);
    });

    it("no KV: login START still works (only the callback needs the marker)", async () => {
      const { res } = await startLogin(op, "/x", { platform });
      expect(res.status).toBe(302);
    });
  } else {
    it("no KV: the marker is skipped with a log line and the login completes", async () => {
      const { ctx, res } = await runCallback(op, await startLogin(op), { ctxOpts: { platform } });
      expect(res.status).toBe(302);
      expect(sessionOf(ctx)).toBeTruthy();
      expect(ctx.recorded.logs).toContainEqual(expect.objectContaining({ level: "warn", msg: expect.stringMatching(/KV unavailable \(sandbox\).*single-use state marker/) }));
    });

    it("no KV: a replay is stopped by the IdP's single-use code instead → 401", async () => {
      const start = await startLogin(op);
      const first = await runCallback(op, start, { ctxOpts: { platform } });
      expect(first.res.status).toBe(302);
      const replay = await runCallback(op, start, { register: false, code: first.code, ctxOpts: { platform } });
      await expectAuthError(replay.res, 401);
    });
  }
});

describe("kernel fetch policy (ctx.fetch)", () => {
  it("worst case (no KV cache + kid rotation) uses exactly 4 fetches: discovery, token, jwks, jwks-refresh", async () => {
    const start = await startLogin(op);
    const rotated = await makeRsaKey("key-B");
    // The OP signs with key-B; the first JWKS fetch still serves only the old key.
    let jwksCalls = 0;
    const fetch = async (input, init) => {
      const r = new Request(input, init);
      const u = new URL(r.url);
      if (u.pathname === "/jwks") return Response.json({ keys: ++jwksCalls === 1 ? [op.key.publicJwk] : [op.key.publicJwk, rotated.publicJwk] });
      if (u.pathname === "/token") {
        const now = Math.floor(Date.now() / 1000);
        const idToken = await signJwt({ alg: "RS256", kid: "key-B", typ: "JWT" },
          { iss: ISSUER, aud: CLIENT_ID, sub: "user-123", iat: now, exp: now + 60, nonce: start.params.get("nonce") }, rotated.privateKey);
        return Response.json({ id_token: idToken });
      }
      return op.handle(r);
    };
    const { ctx, res } = await runCallback(op, start, { register: false, ctxOpts: { fetch } });
    expect(res.status).toBe(302);
    expect(ctx.recorded.fetches.map((f) => [f.opts.purpose, f.opts.cache])).toEqual([
      ["discovery", { ttl: 3600 }], ["token", undefined], ["jwks", { ttl: 3600 }], ["jwks-refresh", undefined],
    ]);
    expect(ctx.recorded.fetches.length).toBeLessThanOrEqual(oidcAuth.maxFetches);
  });

  it("with discovery and JWKS in KV, the callback makes a single fetch (the token exchange)", async () => {
    const warm = await runCallback(op, await startLogin(op), { ctxOpts: { kv: true } });
    const start = await startLogin(op, "/x", { kv: warm.ctx.recorded.kv });
    const { ctx, res } = await runCallback(op, start, { ctxOpts: { kv: warm.ctx.recorded.kv } });
    expect(res.status).toBe(302);
    expect(ctx.recorded.fetches.map((f) => f.opts.purpose)).toEqual(["token"]);
  });

  it("a discovered token endpoint on a non-allowed origin → egress_denied (propagates; never fetched)", async () => {
    const doc = { ...op.discovery, token_endpoint: "https://evil.test/token" };
    const fetch = async (input, init) => {
      const r = new Request(input, init);
      if (new URL(r.url).pathname === "/.well-known/openid-configuration") return Response.json(doc);
      return op.handle(r);
    };
    const start = await startLogin(op, "/x", { fetch });
    let err;
    try {
      await runCallback(op, start, { ctxOpts: { fetch } });
    } catch (e) {
      err = e;
    }
    expect(err).toMatchObject({ status: 500, code: "egress_denied" });
  });

  it("a discovered jwks_uri on a non-allowed origin → egress_denied (not swallowed as a 400)", async () => {
    const doc = { ...op.discovery, jwks_uri: "https://keys.elsewhere.test/jwks" };
    const fetch = async (input, init) => {
      const r = new Request(input, init);
      const u = new URL(r.url);
      if (u.pathname === "/.well-known/openid-configuration") return Response.json(doc);
      if (u.host === "keys.elsewhere.test") return Response.json(op.jwks);
      return op.handle(r);
    };
    const start = await startLogin(op, "/x", { fetch });
    await expect(runCallback(op, start, { ctxOpts: { fetch } })).rejects.toMatchObject({ code: "egress_denied" });

    // …and allowed once the origin is listed in extra_egress.
    const options = oidcAuth.validate({ issuer: ISSUER, extra_egress: ["https://keys.elsewhere.test"] });
    const start2 = await startLogin(op, "/x", { fetch, options });
    const { res } = await runCallback(op, start2, { ctxOpts: { fetch, options } });
    expect(res.status).toBe(302);
  });
});

// --- W2.3 wiring (docs/architecture/plugins.md §14.4) -------------------------

const JANRAIN = oidcAuth.validate({ callback_path: "/.auth/callback", logout_path: "/.auth/logout", issuer: ISSUER, provider: "janrain" });
const janrainCallback = (start, opts = {}) => runCallback(op, start, { ...opts, ctxOpts: { options: JANRAIN, ...(opts.ctxOpts || {}) } });
const startJanrain = (path = "/x", ctxOpts = {}) => startLogin(op, path, { options: JANRAIN, ...ctxOpts });
const infoLogs = (ctx) => ctx.recorded.logs.filter((l) => l.level === "info");

describe("groups source (provider groupsSource)", () => {
  it("user-info: the draft starts with NO groups; an ID-token groups claim is ignored", async () => {
    const seen = [];
    const { ctx, res } = await janrainCallback(await startJanrain(), {
      groups: ["idp-admin"],
      claims: { "https://claims/groups": ["ns-admin"] },
      ctxOpts: { lifecycle: { emitLogin: async (d) => { seen.push([...d.groups]); d.addGroups(["medical"]); } } },
    });
    expect(res.status).toBe(302);
    expect(seen).toEqual([[]]);
    expect((await decodeSession(sessionOf(ctx), HMAC_KEY)).groups).toEqual(["medical"]);
    expect(infoLogs(ctx)).toEqual([]);
  });

  it("user-info: ignored even when groups_claim names a claim the token carries", async () => {
    const config = { ...makeCtx("/").config, groupsClaim: "https://claims/groups" };
    const { ctx } = await janrainCallback(await startJanrain("/x", { config }), {
      claims: { "https://claims/groups": ["ns-admin"] }, ctxOpts: { config },
    });
    expect((await decodeSession(sessionOf(ctx), HMAC_KEY)).groups).toEqual([]);
  });

  it("user-info: no groups after the login event (no subscriber) → an info line with the fixed reason code only", async () => {
    const { ctx, res } = await janrainCallback(await startJanrain(), { groups: ["idp-admin"], claims: { email: "who@example.com" } });
    expect(res.status).toBe(302);
    expect((await decodeSession(sessionOf(ctx), HMAC_KEY)).groups).toEqual([]);
    expect(infoLogs(ctx)).toEqual([{ level: "info", msg: "oidc login without groups", fields: { reason: NO_GROUPS_FROM_USER_INFO } }]);
    expect(NO_GROUPS_FROM_USER_INFO).toBe("no_groups_from_user_info");
    const logs = JSON.stringify(ctx.recorded.logs);
    for (const needle of ["idp-admin", "who@example.com", "user-123"]) expect(logs).not.toContain(needle);
  });

  it("user-info: no groups but a lifetime cap (degraded login) → no extra info line", async () => {
    const { ctx } = await janrainCallback(await startJanrain(), {
      ctxOpts: { lifecycle: { emitLogin: async (d) => { d.limitLifetime(120); } } },
    });
    expect(infoLogs(ctx)).toEqual([]);
  });

  it("claim (generic): groups still come from groups_claim, and an empty list logs nothing", async () => {
    const a = await runCallback(op, await startLogin(op), { groups: ["medical"] });
    expect((await decodeSession(sessionOf(a.ctx), HMAC_KEY)).groups).toEqual(["medical"]);
    const b = await runCallback(op, await startLogin(op), { groups: [] });
    expect((await decodeSession(sessionOf(b.ctx), HMAC_KEY)).groups).toEqual([]);
    expect(infoLogs(b.ctx)).toEqual([]);
  });
});

describe("login subscriber errors", () => {
  const failingWith = (err) => ({ ctxOpts: { lifecycle: { emitLogin: async () => { throw err; } } } });

  it("PluginError(503) → 503 generic auth error, no cookies, the code logged (never the message)", async () => {
    const { ctx, res } = await janrainCallback(await startJanrain(),
      failingWith(new PluginError(503, "user_info_unavailable", "backend SECRET-DETAIL")));
    await expectAuthError(res, 503);
    expect(ctx.recorded.cookies).toEqual([]);
    expect(ctx.recorded.logs.find((l) => l.level === "error").fields).toEqual({ status: 503, detail: "login aborted by a login hook: user_info_unavailable" });
    expect(JSON.stringify(ctx.recorded.logs)).not.toContain("SECRET-DETAIL");
  });

  it.each([
    ["a PluginError other than 503", new PluginError(502, "bad_gateway", "x"), "PluginError"],
    ["a PluginError(500)", new PluginError(500, "internal_error"), "PluginError"],
    ["a plain Error", new Error("boom SECRET-DETAIL"), "Error"],
    ["a TypeError", new TypeError("x"), "TypeError"],
  ])("%s → 500, no cookies", async (_label, err, name) => {
    const { ctx, res } = await janrainCallback(await startJanrain(), failingWith(err));
    await expectAuthError(res, 500);
    expect(ctx.recorded.cookies).toEqual([]);
    expect(ctx.recorded.logs.find((l) => l.level === "error").fields).toEqual({ status: 500, detail: `login aborted by a login hook: ${name}` });
    expect(JSON.stringify(ctx.recorded.logs)).not.toContain("SECRET-DETAIL");
  });

  it("a kernel fetch-policy error (fatal) keeps the kernel's own code: rethrown, never an auth page", async () => {
    const budget = Object.assign(new PluginError(503, "budget_exceeded", "x"), { fatal: true });
    const egress = Object.assign(new PluginError(500, "egress_denied", "x"), { fatal: true });
    for (const err of [budget, egress]) {
      const start = await startJanrain();
      await expect(janrainCallback(start, failingWith(err))).rejects.toBe(err);
    }
  });
});

describe("token endpoint auth negotiation", () => {
  const discoveryWith = (methods) => async (input, init) => {
    const r = new Request(input, init);
    if (new URL(r.url).pathname === "/.well-known/openid-configuration") {
      return Response.json({ ...op.discovery, token_endpoint_auth_methods_supported: methods });
    }
    return op.handle(r);
  };

  it("no acceptable method → 500 auth error after discovery, before the token request; state already consumed", async () => {
    const fetch = discoveryWith(["private_key_jwt"]);
    const start = await startJanrain("/x", { fetch });
    const { ctx, res } = await janrainCallback(start, { ctxOpts: { fetch, kv: true } });
    await expectAuthError(res, 500);
    expect(ctx.recorded.fetches.map((f) => f.opts.purpose)).toEqual(["discovery"]);
    expect(ctx.recorded.cookies).toEqual([]);
    expect([...ctx.recorded.kv.keys()]).toContain(stateUsedKey(start.params.get("state")));
    expect(ctx.recorded.logs.filter((l) => l.level === "error").map((l) => l.fields.detail)).toEqual([
      "no token endpoint auth method in common: provider prefers [client_secret_basic, client_secret_post], discovery supports [private_key_jwt]",
      "token endpoint auth method negotiation failed",
    ]);
  });

  it("a pinned method discovery does not list → 500 auth error, no token request", async () => {
    const options = oidcAuth.validate({ issuer: ISSUER, provider: "janrain", token_endpoint_auth_method: "client_secret_post" });
    const fetch = discoveryWith(["client_secret_basic"]);
    const start = await startLogin(op, "/x", { options, fetch });
    const { ctx, res } = await runCallback(op, start, { ctxOpts: { options, fetch } });
    await expectAuthError(res, 500);
    expect(tokenCalls(ctx)).toEqual([]);
  });

  it("a replayed state is still rejected (400) before discovery, even when negotiation would fail", async () => {
    const fetch = discoveryWith(["private_key_jwt"]);
    const start = await startJanrain("/x", { fetch });
    const first = await janrainCallback(start, { ctxOpts: { fetch, kv: true } });
    const second = await janrainCallback(start, { register: false, code: first.code, ctxOpts: { fetch, kv: first.ctx.recorded.kv } });
    await expectAuthError(second.res, 400);
    expect(second.ctx.recorded.fetches).toEqual([]);
  });

  it("janrain against a discovery listing both methods uses client_secret_basic (no secret in the body)", async () => {
    const seen = [];
    const fetch = async (input, init) => {
      const r = new Request(input, init);
      if (r.method === "POST") seen.push({ body: await r.clone().text(), authorization: r.headers.get("authorization") });
      return discoveryWith(["client_secret_basic", "client_secret_post"])(r);
    };
    const { res } = await janrainCallback(await startJanrain("/x", { fetch }), { ctxOpts: { fetch } });
    expect(res.status).toBe(302);
    expect(seen[0].authorization).toMatch(/^Basic /);
    expect(new URLSearchParams(seen[0].body).has("client_secret")).toBe(false);
  });
});

describe("session id minted before the identity", () => {
  beforeEach(() => { newSessionId.mockClear(); });

  it("one sid per login, minted by the callback; the cookie's sid is that value and identity.sessionId matches", async () => {
    const { ctx, res } = await runCallback(op, await startLogin(op));
    expect(res.status).toBe(302);
    expect(newSessionId).toHaveBeenCalledTimes(1); // the callback mints exactly one, before toIdentity
    const minted = newSessionId.mock.results[0].value;
    const session = await decodeSession(sessionOf(ctx), HMAC_KEY);
    expect(session.sid).toBe(minted);
    const identity = await oidcAuth.authenticate(makeCtx("/protected/x", { cookie: `${SESSION}=${sessionOf(ctx)}` }), OPTIONS);
    expect(identity.sessionId).toBe(minted);
  });

  it("buildSession uses identity.sessionId when present and mints one only when absent", () => {
    const draft = createIdentityDraft({ sub: "u", groups: [] });
    const sid = "AAAAAAAAAAAAAAAAAAAAAA";
    const identity = draft.toIdentity({ method: "oidc-session", sessionId: sid, issuedAt: 1_000, expiresAt: 4_600 });
    expect(identity.sessionId).toBe(sid);
    expect(buildSession(identity, 3600, 1_000).sid).toBe(sid);
    const anonymous = createIdentityDraft({ sub: "u" }).toIdentity({ method: "oidc-session", issuedAt: 1_000, expiresAt: 4_600 });
    const a = buildSession(anonymous, 3600, 1_000).sid;
    expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(buildSession(anonymous, 3600, 1_000).sid).not.toBe(a); // minted per call when absent
  });

  it("buildSession rejects a malformed sessionId (it would never verify)", () => {
    expect(() => buildSession({ sub: "u", groups: [], sessionId: "short" }, 60)).toThrow(TypeError);
  });
});

describe("session lifetime", () => {
  it("a subscriber's limitLifetime cap sets both the payload exp and the cookie Max-Age", async () => {
    const { ctx, res } = await janrainCallback(await startJanrain(), {
      ctxOpts: { lifecycle: { emitLogin: async (d) => { d.limitLifetime(120); } } },
    });
    expect(res.status).toBe(302);
    const session = await decodeSession(sessionOf(ctx), HMAC_KEY);
    expect(session.exp - session.iat).toBe(120);
    expect(ctx.recorded.cookies.find((c) => c.name === SESSION).attrs).toEqual({ maxAge: 120 });
  });

  it("several caps: the smallest wins; without a cap the configured TTL applies", async () => {
    const capped = await janrainCallback(await startJanrain(), {
      ctxOpts: { lifecycle: { emitLogin: async (d) => { d.limitLifetime(600); d.limitLifetime(90); d.limitLifetime(300); } } },
    });
    expect(capped.ctx.recorded.cookies.find((c) => c.name === SESSION).attrs).toEqual({ maxAge: 90 });
    const plain = await janrainCallback(await startJanrain());
    expect(plain.ctx.recorded.cookies.find((c) => c.name === SESSION).attrs).toEqual({ maxAge: 3600 });
  });

  it("a cap longer than session_ttl_seconds does not extend the session", async () => {
    const { ctx } = await janrainCallback(await startJanrain(), {
      ctxOpts: { lifecycle: { emitLogin: async (d) => { d.limitLifetime(86_400); } } },
    });
    const session = await decodeSession(sessionOf(ctx), HMAC_KEY);
    expect(session.exp - session.iat).toBe(3600);
  });
});

describe("session size guard", () => {
  it("a session over the cookie size limit → 500 auth error, no session cookie, login cookie untouched", async () => {
    const huge = Array.from({ length: 200 }, (_, i) => `group-with-a-rather-long-name-${i}`);
    const { ctx, res } = await janrainCallback(await startJanrain(), {
      ctxOpts: { lifecycle: { emitLogin: async (d) => { d.addGroups(huge); } } },
    });
    await expectAuthError(res, 500);
    expect(ctx.recorded.cookies).toEqual([]); // neither set nor cleared, as on every other error
    expect(ctx.recorded.logs.find((l) => l.level === "error").fields).toEqual({ status: 500, detail: "session too large" });
  });

  it("a large but fitting group list still logs in", async () => {
    const many = Array.from({ length: 40 }, (_, i) => `g${i}`);
    const { ctx, res } = await janrainCallback(await startJanrain(), {
      ctxOpts: { lifecycle: { emitLogin: async (d) => { d.addGroups(many); } } },
    });
    expect(res.status).toBe(302);
    expect((await decodeSession(sessionOf(ctx), HMAC_KEY)).groups).toHaveLength(40);
  });
});
