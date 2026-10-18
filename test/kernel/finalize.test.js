import { describe, it, expect } from "vitest";
import { finalizeResponse, getSetCookies, setCookieName, PROTECTED_RESPONSE_HEADERS } from "../../src/kernel/finalize.js";
import { NO_STORE_HEADERS } from "../../src/sdk/http.js";

const OWNED = ["__Host-edge_session", "edge_state"];
const RESERVED = ["x-auth-", "x-recaptcha-"];

function originResponse(extraHeaders = [], status = 200) {
  const h = new Headers([
    ["content-type", "text/html"],
    ["cache-control", "public, max-age=600"],
    ["surrogate-control", "max-age=3600"],
    ["age", "42"],
    ...extraHeaders,
  ]);
  return new Response("body", { status, headers: h });
}

function warnSink() {
  const warnings = [];
  return { warnings, log: { warn: (msg, fields) => warnings.push({ msg, ...fields }) } };
}

describe("finalizeResponse — owned cookies", () => {
  it("strips owned Set-Cookie lines from handler responses and keeps the rest", () => {
    const res = originResponse([
      ["set-cookie", "__Host-edge_session=forged; Path=/"],
      ["set-cookie", "edge_state=x; Path=/"],
      ["set-cookie", "site_pref=dark; Path=/"],
    ]);
    const { log, warnings } = warnSink();
    const out = finalizeResponse(res, { requestId: "r", source: "handler", ownedCookies: OWNED, reservedPrefixes: RESERVED, log });
    expect(getSetCookies(out.headers)).toEqual(["site_pref=dark; Path=/"]);
    expect(warnings.map((w) => w.cookie)).toEqual(["__Host-edge_session", "edge_state"]);
  });

  it("strips owned cookies from kernel responses too", () => {
    const res = new Response("x", { status: 403, headers: [["set-cookie", "edge_state=x"]] });
    const out = finalizeResponse(res, { requestId: "r", source: "kernel", ownedCookies: OWNED });
    expect(getSetCookies(out.headers)).toEqual([]);
  });

  it("keeps a plugin response's own declared cookies but strips other plugins' cookies", () => {
    const res = new Response(null, { status: 302, headers: [
      ["location", "https://idp.example/authorize"],
      ["set-cookie", "edge_state=s; Path=/; HttpOnly"],
      ["set-cookie", "__Host-edge_session=stolen; Path=/"],
    ] });
    const out = finalizeResponse(res, {
      requestId: "r", source: "plugin", producer: { name: "sess", cookies: ["edge_state"] }, ownedCookies: OWNED,
    });
    expect(getSetCookies(out.headers)).toEqual(["edge_state=s; Path=/; HttpOnly"]);
  });

  it("appends plugin cookie writes after stripping", () => {
    const res = originResponse([["set-cookie", "__Host-edge_session=forged"]]);
    const out = finalizeResponse(res, {
      requestId: "r", source: "handler", ownedCookies: OWNED,
      cookieWrites: ["__Host-edge_session=real; Path=/; SameSite=Lax; HttpOnly; Secure"],
    });
    expect(getSetCookies(out.headers)).toEqual(["__Host-edge_session=real; Path=/; SameSite=Lax; HttpOnly; Secure"]);
  });

  it("leaves malformed Set-Cookie lines alone (they match no owned name)", () => {
    expect(setCookieName("garbage")).toBe("");
    expect(setCookieName(" a = b")).toBe("a");
    const out = finalizeResponse(originResponse([["set-cookie", "garbage"]]), { requestId: "r", source: "handler", ownedCookies: OWNED });
    expect(getSetCookies(out.headers)).toEqual(["garbage"]);
  });
});

describe("finalizeResponse — plugin response headers", () => {
  it("merges plugin headers (later plugins win)", () => {
    const out = finalizeResponse(originResponse(), {
      requestId: "r",
      responseHeaders: [
        { plugin: "a", headers: new Headers({ "content-security-policy": "default-src 'self'", "x-frame-options": "SAMEORIGIN" }) },
        { plugin: "b", headers: new Headers({ "x-frame-options": "DENY" }) },
      ],
    });
    expect(out.headers.get("content-security-policy")).toBe("default-src 'self'");
    expect(out.headers.get("x-frame-options")).toBe("DENY");
  });

  it("ignores set-cookie, cache headers and reserved prefixes, with a warning each", () => {
    const { log, warnings } = warnSink();
    const extra = new Headers();
    extra.append("set-cookie", "__Host-edge_session=forged");
    extra.set("cache-control", "public, max-age=99999");
    extra.set("surrogate-control", "max-age=99999");
    extra.set("age", "1");
    extra.set("expires", "Wed, 21 Oct 2099 07:28:00 GMT");
    extra.set("x-auth-subject", "admin");
    extra.set("x-auth-request-id", "spoof");
    extra.set("x-recaptcha-score", "1");
    const out = finalizeResponse(originResponse([], 500), {
      requestId: "rid", reservedPrefixes: RESERVED, responseHeaders: [{ plugin: "evil", headers: extra }], log,
    });
    expect(getSetCookies(out.headers)).toEqual([]);
    expect(out.headers.get("cache-control")).toBe(NO_STORE_HEADERS["cache-control"]);
    expect(out.headers.get("surrogate-control")).toBe("private");
    expect(out.headers.has("age")).toBe(false);
    expect(out.headers.has("expires")).toBe(false);
    expect(out.headers.has("x-auth-subject")).toBe(false);
    expect(out.headers.get("x-auth-request-id")).toBe("rid");
    expect(out.headers.has("x-recaptcha-score")).toBe(false);
    expect(warnings.filter((w) => w.from === "evil").map((w) => w.header).sort())
      .toEqual(["age", "cache-control", "expires", "set-cookie", "surrogate-control", "x-auth-request-id", "x-auth-subject", "x-recaptcha-score"]);
    expect(PROTECTED_RESPONSE_HEADERS).toContain("set-cookie");
  });
});

describe("finalizeResponse — caching and request id", () => {
  it("applies NO_STORE_HEADERS and removes age on every response", () => {
    const out = finalizeResponse(originResponse(), { requestId: "r" });
    for (const [k, v] of Object.entries(NO_STORE_HEADERS)) expect(out.headers.get(k)).toBe(v);
    expect(out.headers.has("age")).toBe(false);
  });

  it("adds x-auth-request-id to >= 400 responses that lack it, never to 2xx/3xx", () => {
    expect(finalizeResponse(originResponse([], 404), { requestId: "rid" }).headers.get("x-auth-request-id")).toBe("rid");
    expect(finalizeResponse(originResponse([], 200), { requestId: "rid" }).headers.has("x-auth-request-id")).toBe(false);
    expect(finalizeResponse(new Response(null, { status: 302, headers: { location: "/" } }), { requestId: "rid" })
      .headers.has("x-auth-request-id")).toBe(false);
  });

  it("keeps an existing x-auth-request-id", () => {
    const res = new Response("x", { status: 500, headers: { "x-auth-request-id": "orig" } });
    expect(finalizeResponse(res, { requestId: "rid" }).headers.get("x-auth-request-id")).toBe("orig");
  });
});

describe("finalizeResponse — response handling", () => {
  it("returns a new Response with the same status, statusText and body", async () => {
    const res = new Response("hello", { status: 201, statusText: "Created", headers: { "x-a": "1" } });
    const out = finalizeResponse(res, { requestId: "r" });
    expect(out).not.toBe(res);
    expect(out.status).toBe(201);
    expect(out.statusText).toBe("Created");
    expect(out.headers.get("x-a")).toBe("1");
    expect(await out.text()).toBe("hello");
  });

  it("works on a response with immutable headers (Response.redirect)", () => {
    const res = Response.redirect("https://idp.example/login", 302);
    expect(() => res.headers.set("x", "y")).toThrow();
    const out = finalizeResponse(res, { requestId: "r" });
    expect(out.status).toBe(302);
    expect(out.headers.get("location")).toBe("https://idp.example/login");
    expect(out.headers.get("cache-control")).toBe("private, no-store");
  });

  it("does not mutate the input's headers", () => {
    const res = originResponse([["set-cookie", "edge_state=x"]]);
    finalizeResponse(res, { requestId: "r", ownedCookies: OWNED, source: "handler" });
    expect(res.headers.get("age")).toBe("42");
    expect(getSetCookies(res.headers)).toEqual(["edge_state=x"]);
  });

  it("handles null-body statuses", () => {
    const out = finalizeResponse(new Response(null, { status: 204 }), { requestId: "r" });
    expect(out.status).toBe(204);
  });

  it("rejects a non-Response", () => {
    expect(() => finalizeResponse({ status: 200 }, {})).toThrow(TypeError);
  });
});
