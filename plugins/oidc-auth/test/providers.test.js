// Provider profiles (docs/architecture/plugins.md §14.1): the shape check,
// the registered profiles (generic/auth0 pinned to today's behaviour, janrain
// grounded in docs/providers/janrain.md) and the token request encoding.
import { describe, it, expect, beforeEach } from "vitest";
import {
  CORE_AUTHORIZE_PARAMS, END_SESSION_MODES, GROUPS_SOURCES, TOKEN_ENDPOINT_AUTH_METHODS, defineProvider,
} from "../providers/define.js";
import { DEFAULT_PROVIDER, PROVIDERS, getProvider } from "../providers/index.js";
import generic from "../providers/generic.js";
import auth0 from "../providers/auth0.js";
import janrain, { JANRAIN_ID_TOKEN_CLAIMS } from "../providers/janrain.js";
import { buildTokenRequest } from "../lib/token.js";
import { settingsFor } from "../lib/settings.js";
import { ISSUER, OPTIONS, makeCtx, newOp, oidcAuth, runCallback, startLogin } from "./support.js";

const LOGOUT_INPUT = Object.freeze({ clientId: "c", postLogoutRedirectUri: "https://s.test/", state: "st" });

describe("registered profiles", () => {
  it("generic is the default; generic, auth0 and janrain are registered", () => {
    expect(DEFAULT_PROVIDER).toBe("generic");
    expect(Object.keys(PROVIDERS)).toEqual(["generic", "auth0", "janrain"]);
    expect(getProvider("auth0")).toBe(auth0);
    expect(getProvider("janrain")).toBe(janrain);
    expect(() => getProvider("okta")).toThrow(/unknown oidc-auth provider/);
    expect(() => getProvider("toString")).toThrow(/unknown oidc-auth provider/);
    expect(settingsFor(makeCtx("/"), OPTIONS).provider).toBe(generic);
  });

  it.each([generic, auth0])("$name keeps today's behaviour: post first, no extra authorize params, groups claim, discovery logout with client_id + post_logout_redirect_uri (no state)", (p) => {
    expect(Object.isFrozen(p) && Object.isFrozen(p.tokenEndpointAuthMethods) && Object.isFrozen(p.authorizeParams)).toBe(true);
    expect(p.tokenEndpointAuthMethods).toEqual(["client_secret_post", "client_secret_basic"]);
    expect(p.authorizeParams).toEqual({});
    expect(p.groupsSource).toBe("claim");
    expect(p.endSession).toBe("discovery");
    expect(p.logoutParams(LOGOUT_INPUT)).toEqual({ client_id: "c", post_logout_redirect_uri: "https://s.test/" });
    expect("tokenEndpointAuthMethod" in p).toBe(false);
  });

  it("janrain: Basic first, response_mode=query + an ID-token claims request, groups from user-info, discovery logout with state", () => {
    expect(Object.isFrozen(janrain)).toBe(true);
    expect(janrain.tokenEndpointAuthMethods).toEqual(["client_secret_basic", "client_secret_post"]);
    expect(janrain.authorizeParams).toEqual({ response_mode: "query", claims: JSON.stringify(JANRAIN_ID_TOKEN_CLAIMS) });
    expect(JSON.parse(janrain.authorizeParams.claims)).toEqual({
      id_token: { email: null, email_verified: null, name: null, given_name: null, family_name: null },
    });
    expect(janrain.groupsSource).toBe("user-info");
    expect(janrain.endSession).toBe("discovery");
    expect(janrain.logoutParams(LOGOUT_INPUT)).toEqual({ client_id: "c", post_logout_redirect_uri: "https://s.test/", state: "st" });
  });

  it("settingsFor exposes the profile (W2.3 reads s.provider.groupsSource) and the pin", () => {
    const s = settingsFor(makeCtx("/"), oidcAuth.validate({ issuer: ISSUER, provider: "janrain" }));
    expect(s.provider).toBe(janrain);
    expect(s.provider.groupsSource).toBe("user-info");
    expect(s.tokenEndpointAuthMethodPin).toBeNull();
    const pinned = settingsFor(makeCtx("/"), oidcAuth.validate({ issuer: ISSUER, provider: "janrain", token_endpoint_auth_method: "client_secret_post" }));
    expect(pinned.tokenEndpointAuthMethodPin).toBe("client_secret_post");
    expect(pinned.tokenEndpointAuthMethod({})).toBe("client_secret_post");
  });

  it("the enum lists are the documented ones", () => {
    expect(TOKEN_ENDPOINT_AUTH_METHODS).toEqual(["client_secret_post", "client_secret_basic"]);
    expect(GROUPS_SOURCES).toEqual(["claim", "user-info"]);
    expect(END_SESSION_MODES).toEqual(["discovery", "none"]);
  });
});

describe("defineProvider (shape check at module load)", () => {
  const ok = Object.freeze({
    name: "x",
    tokenEndpointAuthMethods: ["client_secret_basic"],
    authorizeParams: { prompt: "login" },
    groupsSource: "claim",
    endSession: "none",
    logoutParams: () => ({}),
  });
  const without = (k) => { const { [k]: _, ...rest } = ok; return rest; };

  it("accepts and freezes a well-formed profile (copies the list and params)", () => {
    const methods = ["client_secret_basic", "client_secret_post"];
    const p = defineProvider({ ...ok, tokenEndpointAuthMethods: methods });
    expect(Object.isFrozen(p) && Object.isFrozen(p.authorizeParams) && Object.isFrozen(p.tokenEndpointAuthMethods)).toBe(true);
    methods.push("x");
    expect(p.tokenEndpointAuthMethods).toEqual(["client_secret_basic", "client_secret_post"]);
  });

  it.each([
    ["a non-object", null, /must be an object/],
    ["an array", [], /must be an object/],
    ["an unknown key", { ...ok, extra: 1 }, /unknown key "extra"/],
    ["the replaced singular tokenEndpointAuthMethod", { ...ok, tokenEndpointAuthMethod: "client_secret_post" }, /unknown key "tokenEndpointAuthMethod"/],
    ["a non-lowercase name", { ...ok, name: "Bad Name" }, /name/],
    ["a non-string name", { ...ok, name: 5 }, /name/],
    ...["name", "tokenEndpointAuthMethods", "authorizeParams", "groupsSource", "endSession", "logoutParams"]
      .map((k) => [`a missing ${k}`, without(k), new RegExp(`missing key "${k}"`)]),
    ["a string instead of a method list", { ...ok, tokenEndpointAuthMethods: "client_secret_post" }, /non-empty array/],
    ["an empty method list", { ...ok, tokenEndpointAuthMethods: [] }, /non-empty array/],
    ["an unsupported method", { ...ok, tokenEndpointAuthMethods: ["none"] }, /entries must be one of/],
    ["private_key_jwt", { ...ok, tokenEndpointAuthMethods: ["client_secret_post", "private_key_jwt"] }, /entries must be one of/],
    ["a non-string method", { ...ok, tokenEndpointAuthMethods: [1] }, /entries must be one of/],
    ["a duplicated method", { ...ok, tokenEndpointAuthMethods: ["client_secret_post", "client_secret_post"] }, /must not repeat/],
    ["null authorizeParams", { ...ok, authorizeParams: null }, /authorizeParams must be an object/],
    ["array authorizeParams", { ...ok, authorizeParams: [] }, /authorizeParams must be an object/],
    ["a core authorize param", { ...ok, authorizeParams: { state: "x" } }, /core parameter "state"/],
    ["a non-string authorize param", { ...ok, authorizeParams: { prompt: 1 } }, /must be a string/],
    ["an unknown groupsSource", { ...ok, groupsSource: "userinfo" }, /groupsSource/],
    ["a non-string groupsSource", { ...ok, groupsSource: true }, /groupsSource/],
    ["an unknown endSession", { ...ok, endSession: "global" }, /endSession/],
    ["a boolean endSession", { ...ok, endSession: false }, /endSession/],
    ["a non-function logoutParams", { ...ok, logoutParams: {} }, /logoutParams must be a function/],
    ["logoutParams returning null", { ...ok, logoutParams: () => null }, /object of string values/],
    ["logoutParams returning an array", { ...ok, logoutParams: () => [] }, /object of string values/],
    ["logoutParams returning a non-string value", { ...ok, logoutParams: () => ({ a: 1 }) }, /object of string values/],
  ])("rejects %s", (_label, profile, msg) => {
    expect(() => defineProvider(profile)).toThrow(TypeError);
    expect(() => defineProvider(profile)).toThrow(msg);
  });

  it("core authorize params are the ones the login code sets", () => {
    expect(CORE_AUTHORIZE_PARAMS).toEqual(["response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"]);
  });
});

describe("token endpoint client authentication", () => {
  const base = { clientId: "id:with space", clientSecret: "s3cr/t+&", code: "c", redirectUri: "https://s.test/cb", verifier: "v" };

  it("client_secret_post: secret in the body, no Authorization header (legacy order)", () => {
    const { headers, body } = buildTokenRequest({ ...base, method: "client_secret_post" });
    expect(headers).toEqual({ "content-type": "application/x-www-form-urlencoded" });
    const form = new URLSearchParams(body);
    expect([...form.keys()]).toEqual(["grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"]);
    expect(form.get("client_secret")).toBe("s3cr/t+&");
  });

  it("client_secret_basic: RFC 6749 §2.3.1 header (form-urlencoded id:secret), no secret in the body", () => {
    const { headers, body } = buildTokenRequest({ ...base, method: "client_secret_basic" });
    expect(headers.authorization).toBe(`Basic ${btoa("id%3Awith+space:s3cr%2Ft%2B%26")}`);
    const form = new URLSearchParams(body);
    expect(form.has("client_secret")).toBe(false);
    expect(form.get("client_id")).toBe("id:with space");
    expect([...form.keys()]).toEqual(["grant_type", "code", "redirect_uri", "client_id", "code_verifier"]);
  });

  it("an unknown method throws", () => {
    expect(() => buildTokenRequest({ ...base, method: "private_key_jwt" })).toThrow(/unsupported/);
  });
});

describe("provider: auth0 end to end", () => {
  let op;
  beforeEach(async () => { op = await newOp(); });

  it("same authorize URL shape, token request and logout params as generic", async () => {
    const options = oidcAuth.validate({ issuer: ISSUER, provider: "auth0" });
    const start = await startLogin(op, "/x", { options });
    expect([...start.params.keys()]).toEqual(["response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"]);
    const { ctx, res } = await runCallback(op, start, { ctxOpts: { options } });
    expect(res.status).toBe(302);
    const token = ctx.recorded.fetches.find((f) => f.opts.purpose === "token");
    expect(token.init.headers).toEqual({ "content-type": "application/x-www-form-urlencoded" });
    expect(new URLSearchParams(token.init.body).has("client_secret")).toBe(true);
  });
});
