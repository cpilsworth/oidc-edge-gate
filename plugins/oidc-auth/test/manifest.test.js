// oidc-auth manifest: declared capabilities, option validation, routes, egress.
import { describe, it, expect } from "vitest";
import { PluginConfigError } from "../../../src/sdk/index.js";
import oidcAuth, { DEFAULT_ADMIN_PATH, DEFAULT_CALLBACK_PATH, DEFAULT_LOGOUT_PATH, MAX_FETCHES } from "../index.js";
import { egressFor } from "../lib/options.js";
import { ISSUER } from "./support.js";

describe("manifest", () => {
  it("is an authenticator that owns exactly the two gate cookies and reads its secrets (active + verify-only previous HMAC key + admin revocation key)", () => {
    expect(oidcAuth.name).toBe("oidc-auth");
    expect(oidcAuth.kind).toBe("authenticator");
    expect(oidcAuth.cookies).toEqual(["__Host-edge_session", "__Host-edge_login"]);
    expect(oidcAuth.secrets).toEqual(["client_secret", "session_hmac_key", "session_hmac_key_previous", "revocation_admin_key"]);
    expect(typeof oidcAuth.authenticate).toBe("function");
    expect(typeof oidcAuth.challenge).toBe("function");
    expect(oidcAuth.phases).toEqual([]);
    expect(oidcAuth.trustedHeaderPrefixes).toEqual([]);
  });

  it("maxFetches covers the callback worst case: discovery + token + jwks + jwks-refresh", () => {
    expect(MAX_FETCHES).toBe(4);
    expect(oidcAuth.maxFetches).toBe(4);
  });
});

describe("validate(options)", () => {
  it("defaults: /.auth/callback, /.auth/logout, /.auth/admin/revoke, no webhook, provider generic, no extra egress, no issuer", () => {
    expect(oidcAuth.validate({})).toEqual({
      callback_path: DEFAULT_CALLBACK_PATH, logout_path: DEFAULT_LOGOUT_PATH, admin_path: DEFAULT_ADMIN_PATH,
      webhook_path: null, webhook_adapter: null, provider: "generic", extra_egress: [], issuer: null,
    });
    expect(DEFAULT_ADMIN_PATH).toBe("/.auth/admin/revoke");
  });

  it("accepts the injected route paths and issuer, and the auth0 provider", () => {
    expect(oidcAuth.validate({ callback_path: "/.auth/cb", logout_path: "/.auth/bye", issuer: ISSUER, provider: "auth0" })).toEqual({
      callback_path: "/.auth/cb", logout_path: "/.auth/bye", admin_path: DEFAULT_ADMIN_PATH,
      webhook_path: null, webhook_adapter: null, provider: "auth0", extra_egress: [], issuer: ISSUER,
    });
  });

  it("accepts admin_path null (route not claimed) and a webhook path with its adapter", () => {
    const o = oidcAuth.validate({ admin_path: null, webhook_path: "/.auth/webhook", webhook_adapter: "janrain" });
    expect(o.admin_path).toBeNull();
    expect(o.webhook_path).toBe("/.auth/webhook");
    expect(o.webhook_adapter).toBe("janrain");
    expect(oidcAuth.validate(o)).toEqual(o);
  });

  it("is idempotent (the kernel and the hooks may both normalize)", () => {
    const once = oidcAuth.validate({ issuer: ISSUER, extra_egress: ["https://cdn.idp.test/"] });
    expect(oidcAuth.validate(once)).toEqual(once);
  });

  it("normalizes extra_egress to de-duplicated origins", () => {
    expect(oidcAuth.validate({ extra_egress: ["https://a.test", "https://a.test/", "https://b.test:8443"] }).extra_egress)
      .toEqual(["https://a.test", "https://b.test:8443"]);
  });

  it.each([
    [{ callback: "/.auth/x" }, /unknown option/],
    [{ callback_path: "/login" }, /under \/\.auth\//],
    [{ logout_path: 5 }, /under \/\.auth\//],
    [{ callback_path: "/.auth/x", logout_path: "/.auth/x" }, /must differ/],
    [{ admin_path: "/admin/revoke" }, /admin_path must be a path under \/\.auth\/ or null/],
    [{ admin_path: 1 }, /admin_path must be a path under/],
    [{ admin_path: "/.auth/logout" }, /must differ/],
    [{ webhook_path: "/.auth/callback", webhook_adapter: "janrain" }, /must differ/],
    [{ webhook_path: "/hook", webhook_adapter: "janrain" }, /webhook_path must be a path under/],
    [{ webhook_path: "/.auth/webhook" }, /must be set together/],
    [{ webhook_adapter: "janrain" }, /must be set together/],
    [{ webhook_path: "/.auth/webhook", webhook_adapter: "okta" }, /webhook_adapter must be one of janrain/],
    [{ provider: "no-such-provider" }, /provider must be one of generic, auth0/],
    [{ provider: "__proto__" }, /provider must be one of/],
    [{ extra_egress: "https://a.test" }, /extra_egress must be an array/],
    [{ extra_egress: [5] }, /extra_egress must be an array/],
    [{ extra_egress: ["http://a.test"] }, /must be https/],
    [{ extra_egress: ["https://a.test/path"] }, /origin only/],
    [{ extra_egress: ["not a url"] }, /not a URL/],
    [{ issuer: 42 }, /issuer must be a string/],
  ])("rejects %j", (options, msg) => {
    expect(() => oidcAuth.validate(options)).toThrow(PluginConfigError);
    expect(() => oidcAuth.validate(options)).toThrow(msg);
  });
});

describe("routes(options)", () => {
  it("claims exactly the configured callback, logout and admin paths (and the webhook only when configured)", () => {
    expect(Object.keys(oidcAuth.routes(oidcAuth.validate({}))).sort()).toEqual(["/.auth/admin/revoke", "/.auth/callback", "/.auth/logout"]);
    expect(Object.keys(oidcAuth.routes({ callback_path: "/.auth/cb", logout_path: "/.auth/bye" })).sort())
      .toEqual(["/.auth/admin/revoke", "/.auth/bye", "/.auth/cb"]);
    expect(Object.keys(oidcAuth.routes({ admin_path: null })).sort()).toEqual(["/.auth/callback", "/.auth/logout"]);
    expect(Object.keys(oidcAuth.routes({ webhook_path: "/.auth/webhook", webhook_adapter: "janrain" })).sort())
      .toEqual(["/.auth/admin/revoke", "/.auth/callback", "/.auth/logout", "/.auth/webhook"]);
  });
});

describe("egress(options)", () => {
  it("is the issuer origin plus extra_egress", () => {
    expect(oidcAuth.egress({ issuer: ISSUER })).toEqual(["https://op.test"]);
    expect(oidcAuth.egress({ issuer: "https://tenant.idp.test/oauth2/default", extra_egress: ["https://keys.idp.test"] }))
      .toEqual(["https://tenant.idp.test", "https://keys.idp.test"]);
    expect(egressFor({ issuer: "https://op.test", extra_egress: ["https://op.test"] })).toEqual(["https://op.test"]);
  });

  it("allows a loopback http issuer (local IdP)", () => {
    expect(oidcAuth.egress({ issuer: "http://127.0.0.1:7681" })).toEqual(["http://127.0.0.1:7681"]);
  });

  it("without a usable issuer, nothing but extra_egress is fetchable (fail closed)", () => {
    expect(oidcAuth.egress({})).toEqual([]);
    expect(oidcAuth.egress({ issuer: "not a url" })).toEqual([]);
  });
});
