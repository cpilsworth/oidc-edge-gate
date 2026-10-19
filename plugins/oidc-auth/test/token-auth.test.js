// Token endpoint client authentication (docs/architecture/plugins.md §14.1):
// the negotiation matrix (provider preference × discovery's
// token_endpoint_auth_methods_supported × the token_endpoint_auth_method pin),
// the option validation, and the method the callback actually uses.
import { describe, it, expect, beforeEach } from "vitest";
import { PluginConfigError } from "../../../src/sdk/index.js";
import generic from "../providers/generic.js";
import auth0 from "../providers/auth0.js";
import janrain from "../providers/janrain.js";
import { negotiateTokenAuthMethod } from "../lib/token.js";
import { settingsFor } from "../lib/settings.js";
import { CLIENT_ID, ISSUER, SECRETS, SITE, callbackRoute, makeCtx, newOp, oidcAuth, runCallback, startLogin } from "./support.js";

const POST = "client_secret_post";
const BASIC = "client_secret_basic";
const POST_FIRST = { tokenEndpointAuthMethods: [POST, BASIC] };
const BASIC_FIRST = { tokenEndpointAuthMethods: [BASIC, POST] };
const POST_ONLY = { tokenEndpointAuthMethods: [POST] };
const BASIC_ONLY = { tokenEndpointAuthMethods: [BASIC] };
const doc = (supported) => (supported === undefined ? {} : { token_endpoint_auth_methods_supported: supported });

describe("negotiateTokenAuthMethod: the matrix", () => {
  // [label, provider, discovery list (undefined = field absent), pin, expected method | Error regex]
  const NO_OVERLAP = /no token endpoint auth method in common/;
  const PIN_UNSUPPORTED = /\(pinned\) is not in discovery/;
  it.each([
    // discovery field absent → the pin, else the first preference
    ["post-first, field absent", POST_FIRST, undefined, null, POST],
    ["basic-first, field absent", BASIC_FIRST, undefined, null, BASIC],
    ["basic-only, field absent", BASIC_ONLY, undefined, null, BASIC],
    ["post-first, field absent, pinned basic", POST_FIRST, undefined, BASIC, BASIC],
    ["post-only, field absent, pinned basic (a pin is an operator override)", POST_ONLY, undefined, BASIC, BASIC],
    // both listed → the first preference
    ["post-first, both listed (basic first in discovery)", POST_FIRST, [BASIC, POST], null, POST],
    ["basic-first, both listed (post first in discovery)", BASIC_FIRST, [POST, BASIC], null, BASIC],
    // one listed → the first preference discovery lists
    ["post-first, only basic listed", POST_FIRST, [BASIC], null, BASIC],
    ["basic-first, only post listed", BASIC_FIRST, [POST], null, POST],
    ["post-first, listed with unknown extras", POST_FIRST, ["private_key_jwt", BASIC, "tls_client_auth"], null, BASIC],
    // no overlap → error
    ["post-only, only basic listed", POST_ONLY, [BASIC], null, NO_OVERLAP],
    ["basic-only, only post listed", BASIC_ONLY, [POST], null, NO_OVERLAP],
    ["post-first, only private_key_jwt listed", POST_FIRST, ["private_key_jwt"], null, NO_OVERLAP],
    ["post-first, an empty list", POST_FIRST, [], null, NO_OVERLAP],
    // a pin must be listed when discovery lists methods
    ["pinned post, both listed", BASIC_FIRST, [BASIC, POST], POST, POST],
    ["pinned basic, both listed", POST_FIRST, [POST, BASIC], BASIC, BASIC],
    ["pinned post, only basic listed", POST_FIRST, [BASIC], POST, PIN_UNSUPPORTED],
    ["pinned basic, only post listed", BASIC_FIRST, [POST], BASIC, PIN_UNSUPPORTED],
    ["pinned basic, an empty list", BASIC_FIRST, [], BASIC, PIN_UNSUPPORTED],
  ])("%s", (_label, provider, supported, pin, expected) => {
    if (expected instanceof RegExp) {
      expect(() => negotiateTokenAuthMethod(provider, doc(supported), pin)).toThrow(expected);
    } else {
      expect(negotiateTokenAuthMethod(provider, doc(supported), pin)).toBe(expected);
    }
  });

  it("the pin defaults to none", () => {
    expect(negotiateTokenAuthMethod(BASIC_FIRST, doc([POST, BASIC]))).toBe(BASIC);
  });

  it("the error names methods only; IdP-supplied junk is not echoed", () => {
    let err;
    try {
      negotiateTokenAuthMethod(POST_ONLY, doc(["private_key_jwt", "<script>alert(1)</script>", "x".repeat(200)]));
    } catch (e) { err = e; }
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe("no token endpoint auth method in common: provider prefers [client_secret_post], discovery supports [private_key_jwt, ?, ?]");
  });

  it("generic and auth0 negotiate post against Auth0's discovery list (today's behaviour); janrain negotiates basic", () => {
    const auth0Doc = doc([BASIC, POST, "private_key_jwt"]); // what Auth0 advertises
    expect(negotiateTokenAuthMethod(generic, auth0Doc)).toBe(POST);
    expect(negotiateTokenAuthMethod(auth0, auth0Doc)).toBe(POST);
    expect(negotiateTokenAuthMethod(generic, {})).toBe(POST);
    expect(negotiateTokenAuthMethod(janrain, doc([BASIC, POST]))).toBe(BASIC);
    expect(negotiateTokenAuthMethod(janrain, {})).toBe(BASIC);
  });
});

describe("token_endpoint_auth_method option", () => {
  it.each([POST, BASIC])("accepts %s and keeps it through re-normalization", (m) => {
    const once = oidcAuth.validate({ issuer: ISSUER, token_endpoint_auth_method: m });
    expect(once.token_endpoint_auth_method).toBe(m);
    expect(oidcAuth.validate(once)).toEqual(once);
  });

  it("unset (or null) leaves the key out, so the normalized options keep their pre-W2 shape", () => {
    expect("token_endpoint_auth_method" in oidcAuth.validate({})).toBe(false);
    expect("token_endpoint_auth_method" in oidcAuth.validate({ token_endpoint_auth_method: null })).toBe(false);
  });

  it.each([["none"], ["private_key_jwt"], ["CLIENT_SECRET_POST"], [""], [1], [true], [[POST]]])("rejects %j", (v) => {
    expect(() => oidcAuth.validate({ token_endpoint_auth_method: v })).toThrow(PluginConfigError);
    expect(() => oidcAuth.validate({ token_endpoint_auth_method: v })).toThrow(/token_endpoint_auth_method must be one of/);
  });

  it("settings negotiation logs the reason (method names only) and rethrows", () => {
    const options = oidcAuth.validate({ issuer: ISSUER, token_endpoint_auth_method: BASIC });
    const ctx = makeCtx("/", { options });
    const s = settingsFor(ctx, options);
    expect(() => s.tokenEndpointAuthMethod(doc([POST]))).toThrow(/pinned/);
    expect(ctx.recorded.logs).toEqual([{
      level: "error",
      msg: "oidc token endpoint auth method negotiation failed",
      fields: { provider: "generic", detail: "token endpoint auth method client_secret_basic (pinned) is not in discovery's token_endpoint_auth_methods_supported [client_secret_post]" },
    }]);
  });
});

describe("the callback uses the negotiated method", () => {
  let op;
  beforeEach(async () => { op = await newOp(); });

  /** ctx.fetch through the mock OP, with extra discovery fields. */
  const withDiscovery = (extra) => (input, init) => {
    const req = new Request(input, init);
    if (new URL(req.url).pathname === "/.well-known/openid-configuration") return Response.json({ ...op.discovery, ...extra });
    return op.handle(req);
  };

  async function login({ provider, pin, extra }) {
    const options = oidcAuth.validate({ issuer: ISSUER, provider, ...(pin ? { token_endpoint_auth_method: pin } : {}) });
    const fetch = withDiscovery(extra);
    const start = await startLogin(op, "/x", { options, fetch });
    const { ctx, res } = await runCallback(op, start, { ctxOpts: { options, fetch } });
    const token = ctx.recorded.fetches.find((f) => f.opts.purpose === "token");
    return { ctx, res, token, form: token && new URLSearchParams(token.init.body) };
  }

  it("janrain (discovery lists basic + post): HTTP Basic, client_id in the body, no client_secret in the body", async () => {
    const { res, token, form } = await login({ provider: "janrain", extra: { token_endpoint_auth_methods_supported: [BASIC, POST] } });
    expect(res.status).toBe(302);
    expect(token.init.headers.authorization).toBe(`Basic ${btoa(`${CLIENT_ID}:${SECRETS.client_secret}`)}`);
    expect(form.has("client_secret")).toBe(false);
    // RFC 6749 §2.3.1/§4.1.3: the client authenticates once (the header); client_id in
    // the body only identifies it and matches the Basic user (as in Akamai's example).
    expect(form.get("client_id")).toBe(CLIENT_ID);
    expect([...form.keys()]).toEqual(["grant_type", "code", "redirect_uri", "client_id", "code_verifier"]);
  });

  it("janrain with discovery omitting the field: still Basic (first preference)", async () => {
    const { token } = await login({ provider: "janrain", extra: {} });
    expect(token.init.headers.authorization).toMatch(/^Basic /);
  });

  it("janrain when the tenant only lists post: falls back to post", async () => {
    const { res, token, form } = await login({ provider: "janrain", extra: { token_endpoint_auth_methods_supported: [POST] } });
    expect(res.status).toBe(302);
    expect(token.init.headers.authorization).toBeUndefined();
    expect(form.get("client_secret")).toBe(SECRETS.client_secret);
  });

  it("janrain pinned to post via the option", async () => {
    const { token, form } = await login({ provider: "janrain", pin: POST, extra: { token_endpoint_auth_methods_supported: [BASIC, POST] } });
    expect(token.init.headers.authorization).toBeUndefined();
    expect(form.get("client_secret")).toBe(SECRETS.client_secret);
  });

  it("generic (discovery lists both, basic first): post, byte-identical to today", async () => {
    const { token, form } = await login({ provider: "generic", extra: { token_endpoint_auth_methods_supported: [BASIC, POST] } });
    expect(token.init.headers).toEqual({ "content-type": "application/x-www-form-urlencoded" });
    expect([...form.keys()]).toEqual(["grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"]);
  });

  it("no overlap: the callback throws (the kernel answers a generic 500) before any token request, logging method names only", async () => {
    const options = oidcAuth.validate({ issuer: ISSUER, provider: "generic" });
    const fetch = withDiscovery({ token_endpoint_auth_methods_supported: ["private_key_jwt"] });
    const start = await startLogin(op, "/x", { options, fetch });
    op.issueCode("code-x", { claims: { nonce: start.params.get("nonce") }, codeChallenge: start.params.get("code_challenge") });
    const ctx = makeCtx(`${SITE}/.auth/callback?state=${start.params.get("state")}&code=code-x`, { options, fetch, cookie: start.loginCookie });
    await expect(callbackRoute(options)(ctx, options)).rejects.toThrow(/no token endpoint auth method in common/);
    expect(ctx.recorded.fetches.map((f) => f.opts.purpose)).toEqual(["discovery"]);
    expect(ctx.recorded.cookies).toEqual([]);
    expect(ctx.recorded.logs).toContainEqual({
      level: "error",
      msg: "oidc token endpoint auth method negotiation failed",
      fields: { provider: "generic", detail: "no token endpoint auth method in common: provider prefers [client_secret_post, client_secret_basic], discovery supports [private_key_jwt]" },
    });
  });
});
