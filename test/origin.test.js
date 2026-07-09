import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { forwardToOrigin, originErrorPage } from "../src/origin.js";
import { reqFor } from "./helpers.js";

// Covers forwardToOrigin (the security-critical x-auth-* / x-push-invalidation
// strip, the EDS BYO-CDN header contract, cache-control rewrite, gate-cookie
// strip) and originErrorPage (branded /errors/{status} page fetch + fallback).

let seen; // capture what the gate sent to origin
const realFetch = globalThis.fetch;
const config = {
  originHostname: "main--mysite--myorg.aem.live",
  forwardedHost: "www.example.com",
  pushInvalidation: true,
  backends: { origin: "origin", idp: "idp" },
};

beforeEach(() => {
  seen = null;
  globalThis.fetch = async (input, init) => {
    const r = input instanceof Request ? input : new Request(input, init);
    seen = { url: r.url, headers: r.headers };
    // Origin replies with a publicly-cacheable header to test the carve-out.
    return new Response("body", { headers: { "cache-control": "public, max-age=3600", "age": "120" } });
  };
});

afterEach(() => { globalThis.fetch = realFetch; });

describe("forwardToOrigin — client header spoofing (C1)", () => {
  it("C1a public tier: inbound x-auth-* headers are stripped before reaching origin", async () => {
    const req = reqFor("/blog/post", {
      headers: {
        "x-auth-subject": "attacker",
        "x-auth-groups": "admins",
        "x-auth-name": "spoof",
      },
    });
    await forwardToOrigin(req, null, "public", config);
    expect(seen.headers.get("x-auth-subject")).toBeNull();
    expect(seen.headers.get("x-auth-groups")).toBeNull();
    expect(seen.headers.get("x-auth-name")).toBeNull();
  });

  it("C1b protected tier: inbound x-auth-name and x-auth-roles are stripped; gate-managed headers are set", async () => {
    const session = { sub: "user-123", groups: ["site-readers"] };
    const req = reqFor("/members/x", {
      headers: {
        "x-auth-name": "spoof",
        "x-auth-roles": "admin",
      },
    });
    await forwardToOrigin(req, session, "protected", config);
    expect(seen.headers.get("x-auth-name")).toBeNull();
    expect(seen.headers.get("x-auth-roles")).toBeNull();
    // Gate-managed headers must still reach origin.
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-groups")).toBe("site-readers");
  });

  it("C1c pushInvalidation:false: inbound x-push-invalidation header is stripped", async () => {
    const noInvalidationConfig = { ...config, pushInvalidation: false };
    const req = reqFor("/blog/post", {
      headers: { "x-push-invalidation": "enabled" },
    });
    await forwardToOrigin(req, null, "public", noInvalidationConfig);
    expect(seen.headers.get("x-push-invalidation")).toBeNull();
  });
});

describe("forwardToOrigin", () => {
  it("P3 forwards to the EDS origin with x-auth-* and strips the cookie", async () => {
    const session = { sub: "user-123", groups: ["site-readers"] };
    await forwardToOrigin(reqFor("/members/x", { cookie: "__Host-edge_session=abc" }), session, "protected", config);
    expect(new URL(seen.url).hostname).toBe("main--mysite--myorg.aem.live");
    expect(seen.headers.get("cookie")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-groups")).toBe("site-readers");
    expect(seen.headers.get("x-forwarded-host")).toBe("www.example.com");
    expect(seen.headers.get("x-push-invalidation")).toBe("enabled");
    // edge↔origin correlation id is always injected.
    expect(seen.headers.get("x-auth-request-id")).toBeTruthy();
  });

  it("protected/secured responses are kept out of every cache (surrogate + browser)", async () => {
    const res = await forwardToOrigin(reqFor("/api/orders"), { sub: "x", groups: [] }, "secured", config);
    expect(res.headers.get("surrogate-control")).toBe("private"); // outer AEM CDN
    expect(res.headers.get("cache-control")).toBe("private, no-store"); // browser
    expect(res.headers.get("age")).toBeNull();
  });

  it("public responses are also kept out of every cache and inject no identity", async () => {
    const res = await forwardToOrigin(reqFor("/blog/post"), null, "public", config);
    // No caching on any tier: the origin's public, max-age header is overridden.
    expect(res.headers.get("cache-control")).toBe("private, no-store"); // browser
    expect(res.headers.get("surrogate-control")).toBe("private"); // outer AEM CDN
    expect(res.headers.get("age")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBeNull();
  });

  it("strips origin Set-Cookie entries for gate-owned cookie names", async () => {
    globalThis.fetch = async (input, init) => {
      const r = input instanceof Request ? input : new Request(input, init);
      seen = { url: r.url, headers: r.headers };
      return new Response("body", {
        headers: [
          ["set-cookie", "__Host-edge_session=attacker; Path=/"],
          ["set-cookie", "__Host-edge_login=attacker; Path=/"],
          ["set-cookie", "eds_pref=ok; Path=/"],
        ],
      });
    };

    const res = await forwardToOrigin(reqFor("/members/x"), { sub: "x", groups: [] }, "protected", config);
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie")];
    expect(setCookies.join("\n")).not.toContain("__Host-edge_session=");
    expect(setCookies.join("\n")).not.toContain("__Host-edge_login=");
    expect(setCookies.join("\n")).toContain("eds_pref=ok");
  });

  it("strips gate cookies via the getSetCookie-fallback path when Headers lacks getSetCookie", async () => {
    // Simulate a runtime without Headers.getSetCookie (line 81 fallback): the
    // single-cookie case is unambiguous — headers.get("set-cookie") returns the
    // line, and the gate cookie must still be stripped.
    globalThis.fetch = async (input, init) => {
      const r = input instanceof Request ? input : new Request(input, init);
      seen = { url: r.url, headers: r.headers };
      return new Response("body", { headers: [["set-cookie", "__Host-edge_session=attacker; Path=/"]] });
    };
    const origGetSetCookie = Headers.prototype.getSetCookie;
    delete Headers.prototype.getSetCookie;
    try {
      const res = await forwardToOrigin(reqFor("/members/x"), { sub: "x", groups: [] }, "protected", config);
      // The gate cookie was stripped; no set-cookie should remain.
      expect(res.headers.get("set-cookie")).toBeNull();
    } finally {
      if (origGetSetCookie) Object.defineProperty(Headers.prototype, "getSetCookie", { value: origGetSetCookie, configurable: true, writable: true });
    }
  });
});

describe("forwardToOrigin — session field fallbacks", () => {
  it("sends empty x-auth-email and x-auth-groups when the session omits them", async () => {
    // A session minted from an id_token with no email/groups claim still has
    // sub but no email/groups; origin.js must not crash on undefined.
    const session = { sub: "user-123" }; // no email, no groups
    await forwardToOrigin(reqFor("/members/x"), session, "protected", config);
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-email")).toBe("");
    expect(seen.headers.get("x-auth-groups")).toBe("");
  });

  it("sends empty x-auth-subject when the session has no sub", async () => {
    // Defensive: isValidSession requires sub, but origin.js must not crash
    // even if a code path reaches it with a malformed session.
    const session = {};
    await forwardToOrigin(reqFor("/members/x"), session, "protected", config);
    expect(seen.headers.get("x-auth-subject")).toBe("");
    expect(seen.headers.get("x-auth-email")).toBe("");
    expect(seen.headers.get("x-auth-groups")).toBe("");
  });

  it("joins an array of groups with commas in x-auth-groups", async () => {
    const session = { sub: "u", email: "e@x", groups: ["a", "b", "c"] };
    await forwardToOrigin(reqFor("/members/x"), session, "protected", config);
    expect(seen.headers.get("x-auth-groups")).toBe("a,b,c");
  });

  it("preserves a malformed Set-Cookie line without '=' (cookieName no-= branch)", async () => {
    // A Set-Cookie with no '=' is malformed but shouldn't crash cookieName.
    // It returns "" which matches no gate cookie, so the line passes through.
    globalThis.fetch = async (input, init) => {
      const r = input instanceof Request ? input : new Request(input, init);
      seen = { url: r.url, headers: r.headers };
      return new Response("body", { headers: [["set-cookie", "weirdnoequals"]] });
    };
    const res = await forwardToOrigin(reqFor("/members/x"), { sub: "x", groups: [] }, "protected", config);
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie")].filter(Boolean);
    expect(setCookies.join("\n")).toContain("weirdnoequals");
  });
});

describe("forwardToOrigin — upstream proxy (e.g. /api -> swapi.dev)", () => {
  it("targets the upstream host with the path preserved, no EDS/identity headers", async () => {
    const session = { sub: "user-1", email: "e@x", groups: ["site-readers"] };
    const res = await forwardToOrigin(
      reqFor("/api/people/1?format=json"), session, "secured", config, "https://swapi.dev");
    // Correct absolute target: upstream host + original path + query.
    expect(seen.url).toBe("https://swapi.dev/api/people/1?format=json");
    expect(seen.headers.get("host")).toBe("swapi.dev");
    // Third-party upstream: EDS BYO-CDN + identity headers must NOT be sent.
    expect(seen.headers.get("x-forwarded-host")).toBeNull();
    expect(seen.headers.get("x-push-invalidation")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBeNull();
    expect(seen.headers.get("x-auth-email")).toBeNull();
    // Still not cached.
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("does not leak the gate session cookie to the upstream", async () => {
    await forwardToOrigin(
      reqFor("/api/people", { headers: { cookie: "__Host-edge_session=secret" } }),
      { sub: "u", groups: [] }, "secured", config, "https://swapi.dev");
    expect(seen.headers.get("cookie")).toBeNull();
  });
});

describe("originErrorPage — branded /errors/{status} page", () => {
  it("serves the origin's /errors/403 page with the error status, no-store", async () => {
    globalThis.fetch = async (input, init) => {
      const r = input instanceof Request ? input : new Request(input, init);
      seen = { url: r.url };
      return new Response("<h1>Forbidden</h1>", { status: 200, headers: { "content-type": "text/html" } });
    };
    const res = await originErrorPage(403, config, reqFor("/protected/medical/x"), { error: "forbidden" });
    expect(seen.url).toBe(`https://${config.originHostname}/errors/403`);
    expect(res.status).toBe(403); // origin page returned under the error status
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(await res.text()).toBe("<h1>Forbidden</h1>");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("surrogate-control")).toBe("private");
  });

  it("falls back to the JSON body when the origin has no error page (non-200)", async () => {
    globalThis.fetch = async () => new Response("not found", { status: 404 });
    const res = await originErrorPage(403, config, reqFor("/protected/medical/x"), { error: "forbidden" });
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ error: "forbidden" });
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("falls back to the JSON body when the origin fetch throws", async () => {
    globalThis.fetch = async () => { throw new Error("origin unreachable"); };
    const res = await originErrorPage(403, config, reqFor("/protected/medical/x"), { error: "forbidden" });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });
});
