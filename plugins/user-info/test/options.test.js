// user-info plugin: manifest and validate() (every rule of §14.3).
import { describe, it, expect } from "vitest";
import { PluginConfigError } from "../../../src/sdk/index.js";
import userInfo from "../index.js";
import { egressFor, headerNameFor, parseTemplate, validateOptions } from "../lib/options.js";

const EP = "https://users.example.com/v1/users/{sub}";
const v = (extra) => userInfo.validate({ endpoint: EP, ...extra });

describe("user-info manifest", () => {
  it("is a beforeForward middleware with onLogin and handle, x-user- headers, two secrets, one fetch", () => {
    expect(userInfo.name).toBe("user-info");
    expect(userInfo.kind).toBe("middleware");
    expect(userInfo.phases).toEqual(["beforeForward"]);
    expect(typeof userInfo.beforeForward).toBe("function");
    expect(typeof userInfo.onLogin).toBe("function");
    expect(typeof userInfo.handle).toBe("function");
    expect(userInfo.trustedHeaderPrefixes).toEqual(["x-user-"]);
    expect(userInfo.secrets).toEqual(["user_info_username", "user_info_password"]);
    expect(userInfo.maxFetches).toBe(2);
    expect(userInfo.identityHeaders).toBe(true);
    expect(userInfo.defaults).toEqual({ when: { authenticated: true } });
    expect(userInfo.allowSkipOnError).toBe(true);
    expect(userInfo.cookies).toEqual([]);
    expect(userInfo.routes).toBeUndefined();
  });

  it("egress(options) is the origin(s) of endpoint and profile_endpoint", () => {
    expect(userInfo.egress(v({}))).toEqual(["https://users.example.com"]);
    expect(userInfo.egress(v({ profile_endpoint: "https://profiles.example.com:8443/p?id={sub}" })))
      .toEqual(["https://users.example.com", "https://profiles.example.com:8443"]);
    expect(egressFor({})).toEqual([]);
    expect(egressFor({ endpoint: "not a url" })).toEqual([]);
  });
});

describe("validate()", () => {
  it("fills every default; profile_endpoint defaults to endpoint", () => {
    expect(v({})).toEqual({
      endpoint: EP,
      groups_path: "groups",
      on_login_error: "fail",
      degrade_ttl_seconds: 300,
      profile_endpoint: EP,
      profile_fields: [],
      expose: "none",
      cache_ttl_seconds: 300,
    });
    expect(Object.isFrozen(v({}))).toBe(true);
    expect(Object.isFrozen(v({ profile_fields: ["a"] }).profile_fields)).toBe(true);
  });

  it("accepts a full, explicit configuration", () => {
    const full = {
      endpoint: "https://users.example.com/groups?user={sub}",
      groups_path: "data.memberships",
      on_login_error: "degrade",
      degrade_ttl_seconds: 120,
      profile_endpoint: "https://users.example.com/profile/{sub}",
      profile_fields: ["given_name", "department", "_id"],
      expose: "headers",
      cache_ttl_seconds: 900,
    };
    expect(userInfo.validate(full)).toEqual(full);
  });

  it("endpoint is required", () => {
    expect(() => userInfo.validate({})).toThrow(PluginConfigError);
    expect(() => userInfo.validate({})).toThrow(/endpoint is required/);
  });

  it("rejects unknown keys (including the ref-level on_error/when)", () => {
    for (const k of ["endpont", "on_error", "when", "timeout", "cache"]) {
      expect(() => v({ [k]: 1 }), k).toThrow(/unknown option/);
    }
  });

  it("templates: https only (http only for localhost/127.0.0.1); no credentials, fragment or relative URL", () => {
    for (const bad of [
      "http://users.example.com/{sub}", "ftp://users.example.com/{sub}", "//users.example.com/{sub}", "/users/{sub}",
      "https://user:pw@users.example.com/{sub}", "https://users.example.com/{sub}#frag", "users.example.com/{sub}",
      "https://users.example.com/ {sub}", "https://users.example.com/\n{sub}", "", 42, null, ["https://x.example/"],
      `https://users.example.com/${"a".repeat(2100)}`,
      "https://users.example.com/a/../{sub}", "https://users.example.com/./{sub}", "https://users.example.com/a\\{sub}",
      "https://users.example.com/a<{sub}", "https://users.example.com/a\"{sub}",
    ]) {
      expect(() => v({ endpoint: bad }), JSON.stringify(bad)).toThrow(PluginConfigError);
      expect(() => v({ profile_endpoint: bad }), JSON.stringify(bad)).toThrow(PluginConfigError);
    }
    expect(v({ endpoint: "http://localhost:8787/u/{sub}" }).endpoint).toBe("http://localhost:8787/u/{sub}");
    expect(v({ endpoint: "http://127.0.0.1/u/{sub}" }).endpoint).toBe("http://127.0.0.1/u/{sub}");
    expect(v({ endpoint: "https://users.example.com" }).endpoint).toBe("https://users.example.com");
    expect(v({ endpoint: "https://users.example.com?u={sub}" }).endpoint).toBe("https://users.example.com?u={sub}");
  });

  it("R1: a template with {email} fails to load (lookups are by the verified sub only)", () => {
    for (const t of [
      "https://users.example.com/lookup?mail={email}", "https://users.example.com/u/{sub}/{email}", "https://users.example.com/{email}",
    ]) {
      expect(() => v({ endpoint: t }), t).toThrow(PluginConfigError);
      expect(() => v({ endpoint: t }), t).toThrow(/\{email\} template variable is not supported; user-info lookups are by the verified \{sub\} only/);
      expect(() => v({ profile_endpoint: t }), t).toThrow(/verified \{sub\} only/);
    }
    // {sub} behaviour is unchanged.
    expect(v({ endpoint: "https://users.example.com/u/{sub}?again={sub}" }).endpoint).toBe("https://users.example.com/u/{sub}?again={sub}");
  });

  it("templates: only {sub}, never in the host, braces balanced", () => {
    for (const bad of [
      "https://users.example.com/{name}", "https://users.example.com/{}", "https://users.example.com/{sub",
      "https://users.example.com/sub}", "https://users.example.com/{{sub}}", "https://{sub}.example.com/x",
      "https://users.example.com:{sub}/x", "https://{email}/x", "https://users.example.com/{SUB}",
    ]) {
      expect(() => v({ endpoint: bad }), bad).toThrow(PluginConfigError);
    }
    expect(parseTemplate("https://u.example.com/{sub}/x/{sub}", "endpoint"))
      .toEqual({ origin: "https://u.example.com", variables: ["sub"] });
    expect(parseTemplate("https://u.example.com/static", "endpoint").variables).toEqual([]);
  });

  it("groups_path is a dot path of JSON keys", () => {
    for (const ok of ["groups", "data.groups", "a.b.c", "roles_v2", "x-groups"]) expect(v({ groups_path: ok }).groups_path).toBe(ok);
    for (const bad of ["", ".groups", "groups.", "a..b", "a[0]", "a b", "a/b", 1, null, ["groups"], "__proto__", "a.constructor"]) {
      expect(() => v({ groups_path: bad }), JSON.stringify(bad)).toThrow(/groups_path/);
    }
  });

  it("on_login_error and expose are enums", () => {
    expect(v({ on_login_error: "degrade" }).on_login_error).toBe("degrade");
    expect(v({ expose: "headers" }).expose).toBe("headers");
    for (const bad of ["skip", "FAIL", "", null, true]) expect(() => v({ on_login_error: bad }), String(bad)).toThrow(/on_login_error/);
    for (const bad of ["header", "json", "", null, true]) expect(() => v({ expose: bad }), String(bad)).toThrow(/expose/);
  });

  it("degrade_ttl_seconds and cache_ttl_seconds are positive integers", () => {
    for (const k of ["degrade_ttl_seconds", "cache_ttl_seconds"]) {
      expect(v({ [k]: 1 })[k]).toBe(1);
      for (const bad of [0, -5, 1.5, "300", NaN, Infinity, null, 2 ** 60]) expect(() => v({ [k]: bad }), `${k}=${bad}`).toThrow(new RegExp(k));
    }
  });

  it("profile_fields are unique identifier strings that map to distinct x-user-* headers", () => {
    expect(v({ profile_fields: ["given_name", "Dept", "a1"] }).profile_fields).toEqual(["given_name", "Dept", "a1"]);
    for (const bad of [
      "given_name", [""], ["given-name"], ["1abc"], ["a b"], ["a.b"], [1], [null], ["__proto__"], ["constructor"],
      ["given_name", "Given_Name"], ["x".repeat(65)], Array.from({ length: 65 }, (_, i) => `f${i}`),
    ]) {
      expect(() => v({ profile_fields: bad }), JSON.stringify(bad).slice(0, 60)).toThrow(/profile_fields/);
    }
    expect(headerNameFor("Given_Name")).toBe("x-user-given-name");
  });

  it("validateOptions rejects non-objects", () => {
    for (const bad of [null, [], "x"]) expect(() => validateOptions(bad)).toThrow(PluginConfigError);
  });
});
