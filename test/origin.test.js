import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { forwardToOrigin } from "../src/origin.js";
import { reqFor } from "./helpers.js";

// edge-gate has no originErrorPage (the worker fetched a branded /errors/{status}
// page; edge returns JSON 403 from index.js instead). So this suite covers only
// forwardToOrigin: the security-critical x-auth-* / x-push-invalidation strip,
// the EDS BYO-CDN header contract, cache-control rewrite, and gate-cookie strip.

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
    await forwardToOrigin(reqFor("/members/x", { cookie: "__edge_session=abc" }), session, "protected", config);
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

  it("public responses preserve origin caching, set no Surrogate-Control, inject no identity", async () => {
    const res = await forwardToOrigin(reqFor("/blog/post"), null, "public", config);
    expect(res.headers.get("cache-control")).toBe("public, max-age=3600");
    // The outer AEM CDN must still be allowed to cache public content.
    expect(res.headers.get("surrogate-control")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBeNull();
  });

  it("strips origin Set-Cookie entries for gate-owned cookie names", async () => {
    globalThis.fetch = async (input, init) => {
      const r = input instanceof Request ? input : new Request(input, init);
      seen = { url: r.url, headers: r.headers };
      return new Response("body", {
        headers: [
          ["set-cookie", "__edge_session=attacker; Path=/"],
          ["set-cookie", "__edge_login=attacker; Path=/"],
          ["set-cookie", "eds_pref=ok; Path=/"],
        ],
      });
    };

    const res = await forwardToOrigin(reqFor("/members/x"), { sub: "x", groups: [] }, "protected", config);
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("set-cookie")];
    expect(setCookies.join("\n")).not.toContain("__edge_session=");
    expect(setCookies.join("\n")).not.toContain("__edge_login=");
    expect(setCookies.join("\n")).toContain("eds_pref=ok");
  });
});
