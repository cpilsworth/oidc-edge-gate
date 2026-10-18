// The callback route (ported from the legacy test/oidc.test.js handleCallback
// cases, the adapter's lifecycle tests and the hygiene fail-closed marker test),
// plus the per-profile KV behaviour (ADR §11) and the kernel fetch policy
// (egress, budget, cache modes).
import { describe, it, expect, beforeEach } from "vitest";
import { PluginError, isIdentity } from "../../../src/sdk/index.js";
import { makeRsaKey, signJwt } from "../../../test/helpers.js";
import { describeEachProfile } from "../../../test/helpers/profiles.js";
import { decodeSession } from "../lib/session.js";
import { stateUsedKey } from "../lib/state.js";
import {
  CLIENT_ID, HMAC_KEY, ISSUER, OPTIONS, SITE, callbackRoute, makeCtx, newOp, oidcAuth, runCallback, setCookieValue, startLogin,
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
    expect(session).toMatchObject({ sub: "user-123", email: "u@example.com", groups: ["medical"] });
    expect(session.exp - session.iat).toBe(3600);
  });

  it("the minted session authenticates on the next request", async () => {
    const { ctx } = await runCallback(op, await startLogin(op), { groups: ["a", "b"] });
    const identity = await oidcAuth.authenticate(makeCtx("/protected/x", { cookie: `${SESSION}=${sessionOf(ctx)}` }), OPTIONS);
    expect(isIdentity(identity)).toBe(true);
    expect(identity.groups).toEqual(["a", "b"]);
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
