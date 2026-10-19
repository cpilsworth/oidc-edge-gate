// user-info backend helpers: URL templates, the Basic header, the bounded JSON
// read and dot paths.
import { describe, it, expect } from "vitest";
import { PluginError } from "../../../src/sdk/index.js";
import { createTestContext } from "../../../src/sdk/testing.js";
import userInfo from "../index.js";
import {
  basicAuthorization, expandTemplate, getJson, LookupFailure, MAX_RESPONSE_BYTES, readPath, requireAuthorization,
} from "../lib/backend.js";

const opts = userInfo.validate({ endpoint: "https://users.example.com/u/{sub}" });

const reason = async (p) => {
  try { await p; } catch (e) { return e instanceof LookupFailure ? e.reason : `not a LookupFailure: ${e && e.name}`; }
  return "resolved";
};
const syncReason = (fn) => {
  try { fn(); } catch (e) { return e instanceof LookupFailure ? e.reason : `not a LookupFailure: ${e && e.name}`; }
  return "returned";
};

describe("expandTemplate", () => {
  it("substitutes {sub} with its encodeURIComponent value", () => {
    expect(expandTemplate("https://u.example.com/users/{sub}", { sub: "auth0|abc" }))
      .toBe("https://u.example.com/users/auth0%7Cabc");
    expect(expandTemplate("https://u.example.com/q?id={sub}&again={sub}", { sub: "a+b" }))
      .toBe("https://u.example.com/q?id=a%2Bb&again=a%2Bb");
  });

  it("R1: {email} is never expanded, even with an email present (bad_url, no URL built)", () => {
    expect(syncReason(() => expandTemplate("https://u.example.com/q?mail={email}&id={sub}", { sub: "1", email: "a@example.com" })))
      .toBe("bad_url");
    expect(syncReason(() => expandTemplate("https://u.example.com/{email}", { sub: "s", email: "a@example.com" }))).toBe("bad_url");
  });

  it("a sub containing /, ?, # and .. cannot change the path, query or fragment", () => {
    const url = expandTemplate("https://u.example.com/users/{sub}/groups", { sub: "../admin/x?y=1#z" });
    expect(url).toBe("https://u.example.com/users/..%2Fadmin%2Fx%3Fy%3D1%23z/groups");
    const u = new URL(url);
    expect(u.pathname).toBe("/users/..%2Fadmin%2Fx%3Fy%3D1%23z/groups");
    expect(u.search).toBe("");
    expect(u.hash).toBe("");
  });

  it("a value of \".\" or \"..\" that would collapse a path segment is bad_url (no traversal)", () => {
    for (const sub of [".", ".."]) {
      expect(syncReason(() => expandTemplate("https://u.example.com/users/{sub}/groups", { sub })), sub).toBe("bad_url");
    }
    // Dots inside a longer segment, or in the query, are harmless.
    expect(expandTemplate("https://u.example.com/users/{sub}", { sub: "..x" })).toBe("https://u.example.com/users/..x");
    expect(expandTemplate("https://u.example.com/q?id={sub}", { sub: ".." })).toBe("https://u.example.com/q?id=..");
    // An encoded dot in the value is double-encoded, never decoded to a dot segment.
    expect(expandTemplate("https://u.example.com/users/{sub}", { sub: "%2e%2e" })).toBe("https://u.example.com/users/%252e%252e");
  });

  it("keeps the configured origin; unicode is UTF-8 percent-encoded", () => {
    expect(new URL(expandTemplate("https://u.example.com/{sub}", { sub: "@evil.example" })).origin).toBe("https://u.example.com");
    expect(expandTemplate("https://u.example.com/{sub}", { sub: "José" })).toBe("https://u.example.com/Jos%C3%A9");
  });

  it("a variable without a value is a lookup failure (missing_variable)", () => {
    expect(syncReason(() => expandTemplate("https://u.example.com/{sub}", {}))).toBe("missing_variable");
    expect(syncReason(() => expandTemplate("https://u.example.com/{sub}", null))).toBe("missing_variable");
  });

  it("an unencodable value (lone surrogate) or a bad template is bad_url", () => {
    expect(syncReason(() => expandTemplate("https://u.example.com/{sub}", { sub: "a\ud800" }))).toBe("bad_url");
    expect(syncReason(() => expandTemplate("https://{sub}.example.com/", { sub: "a" }))).toBe("bad_url");
  });
});

describe("basicAuthorization / requireAuthorization", () => {
  it("is Basic base64(username:password), UTF-8 safe", () => {
    expect(basicAuthorization("svc", "pw")).toBe(`Basic ${btoa("svc:pw")}`);
    const h = basicAuthorization("sérvice", "pä:ss€");
    const bin = atob(h.slice("Basic ".length));
    const decoded = new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
    expect(decoded).toBe("sérvice:pä:ss€");
  });

  it("missing credentials → PluginError 500 internal_error, logged without values", () => {
    for (const secrets of [{}, { user_info_username: "svc-user" }, { user_info_password: "pw-SECRET-1" }, { user_info_username: "", user_info_password: "pw-SECRET-1" }]) {
      const ctx = createTestContext({ plugin: userInfo, secrets, options: opts });
      let err;
      try { requireAuthorization(ctx); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(PluginError);
      expect(err.status).toBe(500);
      expect(err.code).toBe("internal_error");
      expect(ctx.recorded.logs).toHaveLength(1);
      expect(ctx.recorded.logs[0].level).toBe("error");
      expect(ctx.recorded.logs[0].fields.reason).toBe("missing_credentials");
      const logText = JSON.stringify(ctx.recorded.logs);
      expect(logText).not.toContain("svc-user");
      expect(logText).not.toContain("pw-SECRET-1");
    }
  });

  it("W2.R R12: a username containing \":\" → PluginError 500 internal_error, fixed reason, no values logged", () => {
    const ctx = createTestContext({ plugin: userInfo, secrets: { user_info_username: "svc:user-X", user_info_password: "pw-SECRET-1" }, options: opts });
    let err;
    try { requireAuthorization(ctx); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(PluginError);
    expect(err).toMatchObject({ status: 500, code: "internal_error" });
    expect(ctx.recorded.logs).toHaveLength(1);
    expect(ctx.recorded.logs[0]).toMatchObject({ level: "error", fields: { reason: "username_contains_colon" } });
    const logText = JSON.stringify(ctx.recorded.logs);
    expect(logText).not.toContain("svc:user-X");
    expect(logText).not.toContain("user-X");
    expect(logText).not.toContain("pw-SECRET-1");
    // A ":" in the password is fine (only the first ":" splits).
    const ok = createTestContext({ plugin: userInfo, secrets: { user_info_username: "svc", user_info_password: "p:w" }, options: opts });
    expect(requireAuthorization(ok)).toBe(`Basic ${btoa("svc:p:w")}`);
  });
});

describe("getJson", () => {
  const ctxWith = (fetch) => createTestContext({ plugin: userInfo, options: opts, fetch });
  const URL_ = "https://users.example.com/u/1";

  it("GETs with the Authorization and Accept headers, purpose set, cache left at pass", async () => {
    const ctx = ctxWith(() => Response.json({ ok: 1 }));
    expect(await getJson(ctx, URL_, "Basic abc", "user-info-groups")).toEqual({ ok: 1 });
    const f = ctx.recorded.fetches[0];
    expect(f.url).toBe(URL_);
    expect(f.method).toBe("GET");
    expect(f.init.headers).toEqual({ authorization: "Basic abc", accept: "application/json" });
    expect(f.opts).toEqual({ purpose: "user-info-groups" });
  });

  it("maps each failure kind to a fixed reason", async () => {
    expect(await reason(getJson(ctxWith(() => { throw new TypeError("connect ECONNREFUSED https://users.example.com/u/1"); }), URL_, "B", "p"))).toBe("network_error");
    expect(await reason(getJson(ctxWith(() => new Response("nope", { status: 500 })), URL_, "B", "p"))).toBe("http_status");
    expect(await reason(getJson(ctxWith(() => new Response(null, { status: 302, headers: { location: "https://evil.example/" } })), URL_, "B", "p"))).toBe("http_status");
    expect(await reason(getJson(ctxWith(() => new Response("<html>", { status: 200 })), URL_, "B", "p"))).toBe("bad_json");
    expect(await reason(getJson(ctxWith(() => new Response("", { status: 200 })), URL_, "B", "p"))).toBe("bad_json");
    expect(await reason(getJson(ctxWith(() => new Response("x".repeat(MAX_RESPONSE_BYTES + 1), { status: 200 })), URL_, "B", "p"))).toBe("too_large");
    expect(await reason(getJson(ctxWith(() => new Response("{}", { status: 200, headers: { "content-length": String(MAX_RESPONSE_BYTES + 1) } })), URL_, "B", "p"))).toBe("too_large");
  });

  it("carries the HTTP status on http_status", async () => {
    await expect(getJson(ctxWith(() => new Response("", { status: 404 })), URL_, "B", "p"))
      .rejects.toMatchObject({ reason: "http_status", status: 404 });
  });

  it("kernel fetch-policy errors (egress/budget PluginErrors) propagate unchanged", async () => {
    const ctx = ctxWith(() => Response.json({}));
    await expect(getJson(ctx, "https://evil.example/u/1", "B", "p")).rejects.toMatchObject({ status: 500, code: "egress_denied" });
    const ctx2 = ctxWith(() => Response.json({}));
    await getJson(ctx2, URL_, "B", "p");
    await getJson(ctx2, URL_, "B", "p"); // maxFetches is 2 (W2.R R5)
    await expect(getJson(ctx2, URL_, "B", "p")).rejects.toMatchObject({ status: 503, code: "budget_exceeded" });
  });
});

describe("readPath", () => {
  it("reads own properties of plain objects along a dot path", () => {
    expect(readPath({ groups: ["a"] }, "groups")).toEqual(["a"]);
    expect(readPath({ data: { groups: ["a"] } }, "data.groups")).toEqual(["a"]);
    expect(readPath({ data: null }, "data.groups")).toBeUndefined();
    expect(readPath({ data: [{ groups: 1 }] }, "data.groups")).toBeUndefined();
    expect(readPath({}, "toString")).toBeUndefined();
    expect(readPath(["a"], "length")).toBeUndefined();
    expect(readPath("str", "length")).toBeUndefined();
    expect(readPath(null, "groups")).toBeUndefined();
  });
});
