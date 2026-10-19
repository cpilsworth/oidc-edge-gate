// Provider profiles: the seam W2 extends (janrain). Pins today's behaviour for
// generic/auth0 and exercises both token endpoint auth methods.
import { describe, it, expect, beforeEach } from "vitest";
import { CORE_AUTHORIZE_PARAMS, defineProvider } from "../providers/define.js";
import { DEFAULT_PROVIDER, PROVIDERS, getProvider } from "../providers/index.js";
import generic from "../providers/generic.js";
import auth0 from "../providers/auth0.js";
import { buildTokenRequest } from "../lib/token.js";
import { settingsFor } from "../lib/settings.js";
import { ISSUER, OPTIONS, makeCtx, newOp, oidcAuth, runCallback, startLogin } from "./support.js";

describe("registered profiles", () => {
  it("generic is the default; generic and auth0 are registered", () => {
    expect(DEFAULT_PROVIDER).toBe("generic");
    expect(Object.keys(PROVIDERS)).toEqual(["generic", "auth0"]);
    expect(getProvider("auth0")).toBe(auth0);
    expect(() => getProvider("janrain")).toThrow(/unknown oidc-auth provider/);
    expect(settingsFor(makeCtx("/"), OPTIONS).provider).toBe(generic);
  });

  it.each([generic, auth0])("$name keeps today's behaviour: client_secret_post, no extra authorize params, client_id + post_logout_redirect_uri", (p) => {
    expect(Object.isFrozen(p)).toBe(true);
    expect(p.tokenEndpointAuthMethod).toBe("client_secret_post");
    expect(p.authorizeParams).toEqual({});
    expect(p.logoutParams({ clientId: "c", postLogoutRedirectUri: "https://s.test/" })).toEqual({ client_id: "c", post_logout_redirect_uri: "https://s.test/" });
  });
});

describe("defineProvider (shape check at module load)", () => {
  const ok = { name: "x", tokenEndpointAuthMethod: "client_secret_basic", authorizeParams: { prompt: "login" }, logoutParams: () => ({}) };
  it("accepts and freezes a well-formed profile", () => {
    const p = defineProvider(ok);
    expect(Object.isFrozen(p) && Object.isFrozen(p.authorizeParams)).toBe(true);
  });
  it.each([
    [{ ...ok, extra: 1 }, /unknown key/],
    [{ ...ok, name: "Bad Name" }, /name/],
    [{ ...ok, tokenEndpointAuthMethod: "none" }, /tokenEndpointAuthMethod/],
    [{ ...ok, authorizeParams: { state: "x" } }, /core parameter "state"/],
    [{ ...ok, authorizeParams: { prompt: 1 } }, /must be a string/],
    [{ ...ok, logoutParams: undefined }, /logoutParams/],
  ])("rejects %#", (profile, msg) => {
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
    const { res } = await runCallback(op, start, { ctxOpts: { options } });
    expect(res.status).toBe(302);
  });
});
