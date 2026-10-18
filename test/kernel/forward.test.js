// Kernel forward step (src/kernel/forward.js; was src/origin.js + test/origin.test.js).
// Covers forward() (the x-auth-* / plugin-prefix / x-push-invalidation strip,
// the EDS BYO-CDN header contract, identity/default/rule/secret/plugin header
// layering, upstream proxying, body streaming) and errorPage() (branded
// /errors/{status} page + JSON fallback). No-store and gate-cookie stripping
// moved to the finalizer; the last block checks forward() + finalizeResponse()
// together so the end-to-end guarantee stays pinned here too.
import { describe, it, expect, beforeEach } from "vitest";
import { forward, errorPage } from "../../src/kernel/forward.js";
import { createFetchBudget } from "../../src/kernel/fetch.js";
import { finalizeResponse } from "../../src/kernel/finalize.js";
import { createIdentity } from "../../src/sdk/index.js";
import { reqFor } from "../helpers.js";

const gate = {
  originHostname: "main--mysite--myorg.aem.live",
  forwardedHost: "www.example.com",
  pushInvalidation: true,
};
const RESERVED = ["x-auth-", "x-recaptcha-"];
const OWNED = ["__Host-edge_session", "__Host-edge_login"];

let seen; // what the gate sent
let modes; // CacheOverride mode per fetch
let responder;

beforeEach(() => {
  seen = null;
  modes = [];
  responder = () => new Response("body", { headers: { "cache-control": "public, max-age=3600", age: "120" } });
});

async function recordingFetch(input, init) {
  const r = input instanceof Request ? input : new Request(input, init);
  seen = { url: r.url, headers: r.headers, method: r.method, body: r.body ? await r.clone().text() : null };
  modes.push(init && init.cacheOverride && init.cacheOverride.mode);
  return responder(r);
}

const identity = (fields = {}) => createIdentity({ sub: "user-123", method: "oidc-session", issuedAt: 1, expiresAt: 2, ...fields });

/** Build a ForwardInput the way the pipeline does, over a real fetch budget. */
function inputFor(request, {
  ident = null, upstream, headers, secretHeaders, forwardIdentity = false, pluginHeaders, secrets = {}, tier = "public",
} = {}) {
  const budget = createFetchBudget({ fetchImpl: recordingFetch, logSink: () => {} });
  return {
    request,
    url: new URL(request.url),
    classification: Object.freeze({
      rule: null, tier, auth: tier === "public" ? "none" : "required", audience: undefined,
      upstream, headers, secretHeaders, forwardIdentity, handler: "origin", middleware: [],
    }),
    identity: ident,
    pluginHeaders: new Headers(pluginHeaders || {}),
    stripPrefixes: [...RESERVED],
    ownedCookies: [...OWNED],
    secret: (k) => secrets[k],
    fetch: (i, init, opts) => budget.kernelFetch(i, init, { purpose: "forward", ...opts }),
    requestId: "rid-1",
  };
}

describe("forward — client header spoofing (C1)", () => {
  it("C1a public tier: inbound x-auth-* headers are stripped before reaching origin", async () => {
    const req = reqFor("/blog/post", { headers: { "x-auth-subject": "attacker", "x-auth-groups": "admins", "x-auth-name": "spoof" } });
    await forward(inputFor(req), gate);
    expect(seen.headers.get("x-auth-subject")).toBeNull();
    expect(seen.headers.get("x-auth-groups")).toBeNull();
    expect(seen.headers.get("x-auth-name")).toBeNull();
  });

  it("C1b protected tier: inbound x-auth-name and x-auth-roles are stripped; gate-managed headers are set", async () => {
    const req = reqFor("/members/x", { headers: { "x-auth-name": "spoof", "x-auth-roles": "admin" } });
    await forward(inputFor(req, { ident: identity({ groups: ["site-readers"] }), tier: "protected" }), gate);
    expect(seen.headers.get("x-auth-name")).toBeNull();
    expect(seen.headers.get("x-auth-roles")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-groups")).toBe("site-readers");
  });

  it("C1c pushInvalidation:false: inbound x-push-invalidation header is stripped", async () => {
    await forward(inputFor(reqFor("/blog/post", { headers: { "x-push-invalidation": "enabled" } })), { ...gate, pushInvalidation: false });
    expect(seen.headers.get("x-push-invalidation")).toBeNull();
  });

  it("C1d inbound plugin-prefixed (x-recaptcha-*) headers are stripped unconditionally", async () => {
    await forward(inputFor(reqFor("/blog/post", { headers: { "x-recaptcha-score": "1.0", "x-recaptcha-hostname": "attacker.example" } })), gate);
    expect(seen.headers.get("x-recaptcha-score")).toBeNull();
    expect(seen.headers.get("x-recaptcha-hostname")).toBeNull();
  });

  // F10: "_" lookalikes are stripped like the dashed name.
  it("F10 underscore lookalikes of reserved headers (x_auth_*, x_recaptcha_*, x_push_invalidation) are stripped", async () => {
    const req = reqFor("/blog/post", { headers: {
      x_auth_groups: "admins", "X_Auth_Subject": "attacker", "x-auth_email": "a@evil", x_recaptcha_score: "1.0",
      x_push_invalidation: "enabled", "x_other": "kept",
    } });
    await forward(inputFor(req), { ...gate, pushInvalidation: false });
    for (const n of ["x_auth_groups", "x_auth_subject", "x-auth_email", "x_recaptcha_score", "x_push_invalidation", "x-push-invalidation"]) {
      expect(seen.headers.get(n), n).toBeNull();
    }
    expect(seen.headers.get("x_other")).toBe("kept");
  });

  it("an inbound x-auth-request-id is replaced by the kernel's request id", async () => {
    await forward(inputFor(reqFor("/x", { headers: { "x-auth-request-id": "client" } })), gate);
    expect(seen.headers.get("x-auth-request-id")).toBe("rid-1");
  });
});

describe("forward — EDS origin", () => {
  it("P3 forwards to the EDS origin with x-auth-* and strips the cookie", async () => {
    const req = reqFor("/members/x", { cookie: "__Host-edge_session=abc" });
    await forward(inputFor(req, { ident: identity({ groups: ["site-readers"] }), tier: "protected" }), gate);
    expect(new URL(seen.url).hostname).toBe("main--mysite--myorg.aem.live");
    expect(seen.headers.get("host")).toBe("main--mysite--myorg.aem.live");
    expect(seen.headers.get("cookie")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-groups")).toBe("site-readers");
    expect(seen.headers.get("x-forwarded-host")).toBe("www.example.com");
    expect(seen.headers.get("x-push-invalidation")).toBe("enabled");
    expect(seen.headers.get("x-auth-request-id")).toBe("rid-1");
  });

  it("path and query are preserved", async () => {
    await forward(inputFor(reqFor("/a/b/?q=1&r=2")), gate);
    expect(seen.url).toBe("https://main--mysite--myorg.aem.live/a/b/?q=1&r=2");
  });

  it("local dev: x-forwarded-host is the request host (with port), not the configured domain", async () => {
    await forward(inputFor(new Request("http://localhost:7676/members/x")), gate);
    expect(seen.headers.get("x-forwarded-host")).toBe("localhost:7676");
  });

  it("public / anonymous: no identity headers", async () => {
    await forward(inputFor(reqFor("/blog/post")), gate);
    for (const h of ["x-auth-subject", "x-auth-email", "x-auth-groups"]) expect(seen.headers.get(h)).toBeNull();
  });

  it("sends empty x-auth-email and x-auth-groups when the identity has none", async () => {
    await forward(inputFor(reqFor("/members/x"), { ident: identity(), tier: "protected" }), gate);
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-email")).toBe("");
    expect(seen.headers.get("x-auth-groups")).toBe("");
  });

  it("joins groups with commas in x-auth-groups", async () => {
    await forward(inputFor(reqFor("/members/x"), { ident: identity({ email: "e@x", groups: ["a", "b", "c"] }), tier: "protected" }), gate);
    expect(seen.headers.get("x-auth-email")).toBe("e@x");
    expect(seen.headers.get("x-auth-groups")).toBe("a,b,c");
  });

  it("streams a request body through with its method", async () => {
    const req = reqFor("/members/x", { method: "POST", body: "a=1&b=2", headers: { "content-type": "application/x-www-form-urlencoded" } });
    await forward(inputFor(req, { ident: identity(), tier: "protected" }), gate);
    expect(seen.method).toBe("POST");
    expect(seen.body).toBe("a=1&b=2");
  });

  it("returns the origin response as-is (no-store is the finalizer's job)", async () => {
    const res = await forward(inputFor(reqFor("/x")), gate);
    expect(res.headers.get("cache-control")).toBe("public, max-age=3600");
  });
});

describe("forward — policy-configured headers", () => {
  it("rule headers reach the EDS origin and override a client-supplied header of the same name", async () => {
    await forward(inputFor(reqFor("/blog/post", { headers: { "x-edge-gate-secret": "attacker-value" } }), { headers: { "x-edge-gate-secret": "s3cr3t" } }), gate);
    expect(seen.headers.get("x-edge-gate-secret")).toBe("s3cr3t");
  });

  it("rule headers reach an upstream override target too", async () => {
    await forward(inputFor(reqFor("/form/submit"), { upstream: "https://forms.example.com", headers: { "x-edge-gate-secret": "s3cr3t" } }), gate);
    expect(seen.url).toBe("https://forms.example.com/form/submit");
    expect(seen.headers.get("x-edge-gate-secret")).toBe("s3cr3t");
  });

  it("policy default_headers reach the EDS origin but are NOT leaked to a third-party upstream", async () => {
    const g = { ...gate, defaultHeaders: { "x-edge-gate-secret": "s3cr3t" } };
    await forward(inputFor(reqFor("/blog/post")), g);
    expect(seen.headers.get("x-edge-gate-secret")).toBe("s3cr3t");
    await forward(inputFor(reqFor("/api/people"), { upstream: "https://swapi.dev" }), g);
    expect(seen.headers.get("x-edge-gate-secret")).toBeNull();
  });

  it("a rule's own headers still reach an upstream when default_headers is set (and win over it on EDS)", async () => {
    const g = { ...gate, defaultHeaders: { "x-edge-gate-secret": "site-secret", "x-k": "default" } };
    await forward(inputFor(reqFor("/form/submit"), { upstream: "https://forms.example.com", headers: { "x-form-key": "form-specific" } }), g);
    expect(seen.headers.get("x-form-key")).toBe("form-specific");
    expect(seen.headers.get("x-edge-gate-secret")).toBeNull();
    await forward(inputFor(reqFor("/x"), { headers: { "x-k": "rule" } }), g);
    expect(seen.headers.get("x-k")).toBe("rule");
  });

  it("no rule headers -> nothing extra sent", async () => {
    await forward(inputFor(reqFor("/blog/post")), gate);
    expect(seen.headers.get("x-edge-gate-secret")).toBeNull();
  });

  it("secret_headers resolve through input.secret, to EDS and upstream alike", async () => {
    await forward(inputFor(reqFor("/x", { headers: { "x-form-key": "client" } }), { secretHeaders: { "x-form-key": "form_key" }, secrets: { form_key: "from-secret" } }), gate);
    expect(seen.headers.get("x-form-key")).toBe("from-secret");
    await forward(inputFor(reqFor("/x"), { upstream: "https://forms.example.com", secretHeaders: { "x-form-key": "form_key" }, secrets: { form_key: "from-secret" } }), gate);
    expect(seen.headers.get("x-form-key")).toBe("from-secret");
  });

  it("a missing secret for secret_headers fails closed (throws, nothing fetched) without naming the value", async () => {
    await expect(forward(inputFor(reqFor("/x"), { secretHeaders: { "x-form-key": "form_key" } }), gate)).rejects.toThrow(/secret "form_key" is not configured/);
    expect(seen).toBeNull();
  });

  it("plugin headers (ctx.forwardHeaders) reach EDS and upstream", async () => {
    await forward(inputFor(reqFor("/x"), { pluginHeaders: { "x-recaptcha-score": "0.9" } }), gate);
    expect(seen.headers.get("x-recaptcha-score")).toBe("0.9");
    await forward(inputFor(reqFor("/x"), { upstream: "https://forms.example.com", pluginHeaders: { "x-recaptcha-score": "0.8" } }), gate);
    expect(seen.headers.get("x-recaptcha-score")).toBe("0.8");
  });
});

describe("forward — upstream proxy (e.g. /api -> swapi.dev)", () => {
  it("targets the upstream host with the path preserved, no EDS/identity headers", async () => {
    await forward(inputFor(reqFor("/api/people/1?format=json"), { upstream: "https://swapi.dev", ident: identity({ email: "e@x", groups: ["site-readers"] }), tier: "secured" }), gate);
    expect(seen.url).toBe("https://swapi.dev/api/people/1?format=json");
    expect(seen.headers.get("host")).toBe("swapi.dev");
    expect(seen.headers.get("x-forwarded-host")).toBeNull();
    expect(seen.headers.get("x-push-invalidation")).toBeNull();
    expect(seen.headers.get("x-auth-subject")).toBeNull();
    expect(seen.headers.get("x-auth-email")).toBeNull();
    expect(seen.headers.get("x-auth-request-id")).toBe("rid-1");
  });

  it("a trailing slash on the upstream base is not doubled", async () => {
    await forward(inputFor(reqFor("/api/x"), { upstream: "https://swapi.dev/" }), gate);
    expect(seen.url).toBe("https://swapi.dev/api/x");
  });

  it("a client-supplied x-forwarded-host passes through to an upstream unchanged", async () => {
    await forward(inputFor(reqFor("/api/x", { headers: { "x-forwarded-host": "client.example" } }), { upstream: "https://swapi.dev" }), gate);
    expect(seen.headers.get("x-forwarded-host")).toBe("client.example");
  });

  it("forward_identity: true sends identity headers to the upstream too", async () => {
    await forward(inputFor(reqFor("/api/x"), { upstream: "https://swapi.dev", forwardIdentity: true, ident: identity({ groups: ["g"] }), tier: "secured" }), gate);
    expect(seen.headers.get("x-auth-subject")).toBe("user-123");
    expect(seen.headers.get("x-auth-groups")).toBe("g");
    expect(seen.headers.get("x-forwarded-host")).toBeNull(); // still no EDS contract headers
  });

  it("does not leak the gate session cookie to the upstream", async () => {
    await forward(inputFor(reqFor("/api/people", { headers: { cookie: "__Host-edge_session=secret" } }), { upstream: "https://swapi.dev", ident: identity(), tier: "secured" }), gate);
    expect(seen.headers.get("cookie")).toBeNull();
  });
});

describe("errorPage — branded /errors/{status} page", () => {
  it("serves the origin's /errors/403 page under the error status with the request id", async () => {
    responder = () => new Response("<h1>Forbidden</h1>", { status: 200, headers: { "content-type": "text/html" } });
    const res = await errorPage(403, inputFor(reqFor("/protected/medical/x")), { error: "forbidden" }, gate);
    expect(seen.url).toBe(`https://${gate.originHostname}/errors/403`);
    expect(seen.headers.get("host")).toBe(gate.originHostname);
    expect(seen.headers.get("x-forwarded-host")).toBe("www.example.com");
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(res.headers.get("x-auth-request-id")).toBe("rid-1");
    expect(await res.text()).toBe("<h1>Forbidden</h1>");
  });

  it("sends policy default_headers, so a header-gated origin still serves its error page", async () => {
    responder = () => new Response("<h1>Forbidden</h1>", { headers: { "content-type": "text/html" } });
    await errorPage(403, inputFor(reqFor("/protected/medical/x")), { error: "forbidden" }, { ...gate, defaultHeaders: { "x-edge-gate-secret": "s3cr3t" } });
    expect(seen.headers.get("x-edge-gate-secret")).toBe("s3cr3t");
  });

  it("defaults the content-type to html when the origin sends none", async () => {
    responder = () => { const r = new Response("x"); r.headers.delete("content-type"); return r; };
    const res = await errorPage(403, inputFor(reqFor("/x")), { error: "forbidden" }, gate);
    expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
  });

  it("falls back to the JSON body when the origin has no error page (non-200)", async () => {
    responder = () => new Response("not found", { status: 404 });
    const res = await errorPage(403, inputFor(reqFor("/protected/medical/x")), { error: "forbidden" }, gate);
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(res.headers.get("x-auth-request-id")).toBe("rid-1");
    expect(await res.json()).toEqual({ error: "forbidden" });
  });

  it("falls back to the JSON body when the origin fetch throws", async () => {
    responder = () => { throw new Error("origin unreachable"); };
    const res = await errorPage(403, inputFor(reqFor("/protected/medical/x")), { error: "forbidden" }, gate);
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
  });
});

describe("function cache bypass (CacheOverride mode must be positional)", () => {
  it("the stub treats an init object as override, a positional string as that mode", async () => {
    const { CacheOverride } = await import("fastly:cache-override");
    expect(new CacheOverride({ mode: "pass" }).mode).toBe("override");
    expect(new CacheOverride("pass").mode).toBe("pass");
    expect(new CacheOverride("override", { ttl: 60 }).ttl).toBe(60);
    expect(() => new CacheOverride("bogus")).toThrow(TypeError);
  });

  it("forward fetches with mode pass (EDS origin and upstream)", async () => {
    await forward(inputFor(reqFor("/x")), gate);
    await forward(inputFor(reqFor("/api/people"), { upstream: "https://swapi.dev" }), gate);
    expect(modes).toEqual(["pass", "pass"]);
  });

  it("errorPage fetches the branded page with mode pass", async () => {
    responder = () => new Response("<h1>403</h1>", { headers: { "content-type": "text/html" } });
    const res = await errorPage(403, inputFor(reqFor("/protected/x")), { error: "forbidden" }, gate);
    expect(res.status).toBe(403);
    expect(modes).toEqual(["pass"]);
  });
});

describe("forward + finalizer (the end-to-end response guarantees)", () => {
  const finalize = (res) => finalizeResponse(res, { requestId: "rid-1", source: "handler", ownedCookies: OWNED, reservedPrefixes: RESERVED });

  it("every tier's response is kept out of every cache", async () => {
    for (const [req, opts] of [[reqFor("/blog/post"), {}], [reqFor("/api/orders"), { ident: identity(), tier: "secured" }], [reqFor("/api/x"), { upstream: "https://swapi.dev" }]]) {
      const res = finalize(await forward(inputFor(req, opts), gate));
      expect(res.headers.get("surrogate-control")).toBe("private");
      expect(res.headers.get("cache-control")).toBe("private, no-store");
      expect(res.headers.get("age")).toBeNull();
    }
  });

  it("origin Set-Cookie for gate-owned names is stripped; other cookies and malformed lines survive", async () => {
    responder = () => new Response("body", {
      headers: [
        ["set-cookie", "__Host-edge_session=attacker; Path=/"],
        ["set-cookie", "__Host-edge_login=attacker; Path=/"],
        ["set-cookie", "eds_pref=ok; Path=/"],
        ["set-cookie", "weirdnoequals"],
      ],
    });
    const res = finalize(await forward(inputFor(reqFor("/members/x"), { ident: identity(), tier: "protected" }), gate));
    const lines = res.headers.getSetCookie().join("\n");
    expect(lines).not.toContain("__Host-edge_session=");
    expect(lines).not.toContain("__Host-edge_login=");
    expect(lines).toContain("eds_pref=ok");
    expect(lines).toContain("weirdnoequals");
  });

  it("strips gate cookies via the getSetCookie-fallback path when Headers lacks getSetCookie", async () => {
    responder = () => new Response("body", { headers: [["set-cookie", "__Host-edge_session=attacker; Path=/"]] });
    const origin = await forward(inputFor(reqFor("/members/x"), { ident: identity(), tier: "protected" }), gate);
    const orig = Headers.prototype.getSetCookie;
    delete Headers.prototype.getSetCookie;
    try {
      expect(finalize(origin).headers.get("set-cookie")).toBeNull();
    } finally {
      if (orig) Object.defineProperty(Headers.prototype, "getSetCookie", { value: orig, configurable: true, writable: true });
    }
  });
});
