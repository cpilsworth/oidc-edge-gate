// W0.1 characterization suite — EMBEDDED (sandbox) configuration.
//
// Freezes today's externally visible behaviour of the gate as it actually runs
// on the sandbox program: the Fastly stores are unprovisioned (constructors
// throw), so loadConfig falls back to src/embedded-config.js and KV is null
// (discovery/JWKS are live-fetched; no single-use state marker).
//
// These tests drive ONLY `handleRequest` and observe ONLY responses and
// outbound fetches. They must keep passing, unchanged, across the kernel +
// plugin refactor. If one fails after a refactor, that is a behaviour change:
// either fix the refactor or change the test deliberately (and say why).
//
// Values below are frozen copies of today's embedded config (non-secret
// values only). They are intentionally NOT imported from the config module.
import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import { createEnv, run, gateRequest, setCookies, cookiePair, expectNoStore, SESSION_COOKIE, LOGIN_COOKIE, SITEVERIFY_URL } from "./harness.js";
import { handleRequest } from "../../src/index.js";

// Sandbox: every store constructor throws, exactly as on the real program.
vi.mock("fastly:config-store", () => ({
  ConfigStore: class { constructor() { throw new Error("No ConfigStore named 'config_default' exists"); } },
}));
vi.mock("fastly:secret-store", () => ({
  SecretStore: class { constructor() { throw new Error("No SecretStore named 'secret_default' exists"); } },
}));
vi.mock("fastly:kv-store", () => ({
  KVStore: class { constructor() { throw new Error("No KVStore named 'kv_default' exists"); } },
}));

const ISSUER = "https://dev-37naouno.us.auth0.com";
const ISSUER_HOST = "dev-37naouno.us.auth0.com";
const CLIENT_ID = "IgIFZftc6r4IkUBxGhgfwCBgTQaaMpeO";
const REDIRECT_URI = "https://edgefunction-p31359-e2079124-oidc-edge-gate.adobeaemcloud.com/.auth/callback";
const FORWARDED_HOST = "edgefunction-p31359-e2079124-oidc-edge-gate.adobeaemcloud.com";
const ORIGIN = "main--az-poc-ch--hmehta-adobe.aem.live";
const GROUPS_CLAIM = "https://oidc.workers.dev/groups";
const SCOPES = "openid profile email groups";
const SWAPI = "swapi.dev";
const FORM_UPSTREAM = "requestbin.cpilsworth.workers.dev";
const IDENTITY_HEADERS = ["x-auth-subject", "x-auth-email", "x-auth-groups"];
const JSON_CT = "application/json; charset=utf-8";

let env;
let rec;

beforeAll(async () => {
  env = await createEnv({
    issuer: ISSUER, clientId: CLIENT_ID, originHost: ORIGIN, groupsClaim: GROUPS_CLAIM,
    upstreamHosts: [SWAPI, FORM_UPSTREAM],
  });
  rec = env.rec;
});
beforeEach(() => env.install());
afterEach(() => { env.uninstall(); vi.useRealTimers(); });

/** The single forwarded request the gate made to `host` (asserts exactly one). */
function onlyCallTo(host) {
  const calls = rec.to(host);
  expect(calls, `calls to ${host}`).toHaveLength(1);
  return calls[0];
}

function expectNoIdentity(call) {
  for (const h of IDENTITY_HEADERS) expect(call.headers.get(h), h).toBeNull();
}

async function expectJsonError(res, status, error) {
  expect(res.status).toBe(status);
  expect(res.headers.get("content-type")).toBe(JSON_CT);
  expect(await res.json()).toEqual({ error });
  expect(res.headers.get("x-auth-request-id")).toBeTruthy();
  expectNoStore(expect, res);
}

function expectLoginRedirect(res) {
  expect(res.status).toBe(302);
  const loc = new URL(res.headers.get("location"));
  expect(`${loc.origin}${loc.pathname}`).toBe(`${ISSUER}/authorize`);
  expect(setCookies(res).map((c) => c.name)).toEqual([LOGIN_COOKIE]);
  expect(rec.to(ORIGIN)).toHaveLength(0);
}

// ---------------------------------------------------------------------------
describe("public tier (embedded rules)", () => {
  const PUBLIC_PATHS = [
    "/", "/scripts/x.js", "/styles/x.css", "/blocks/x/x.js", "/icons/x.svg", "/fonts/x.woff2",
    "/media_123.png", "/.well-known/x", "/sitemap.xml", "/robots.txt", "/nav", "/footer",
    "/nav.plain.html", "/footer.plain.html", "/content/nav.plain.html", "/content/footer.plain.html",
    "/errors/404",
  ];

  it.each(PUBLIC_PATHS)("public %s forwards to the EDS origin without identity headers, even with a garbage session cookie", async (path) => {
    const res = await run(`${path}?q=1`, { cookie: `${SESSION_COOKIE}=garbage.notsigned; other=1` });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
    expectNoStore(expect, res);
    expect(setCookies(res)).toEqual([]);
    const call = onlyCallTo(ORIGIN);
    expect(call.url).toBe(`https://${ORIGIN}${path}?q=1`);
    expect(call.method).toBe("GET");
    expect(call.headers.get("host")).toBe(ORIGIN);
    expect(call.headers.get("x-forwarded-host")).toBe(FORWARDED_HOST);
    expect(call.headers.get("x-push-invalidation")).toBe("enabled");
    expect(call.headers.get("x-auth-request-id")).toBeTruthy();
    expect(call.headers.get("cookie")).toBeNull();
    expectNoIdentity(call);
    // Public routes never touch the IdP.
    expect(rec.to(ISSUER_HOST)).toHaveLength(0);
  });

  it("public response is rewritten to no-store: origin cache headers overridden, Age dropped, nosniff added", async () => {
    rec.route(ORIGIN, () => new Response("x", {
      status: 200,
      headers: { "cache-control": "public, max-age=600", "surrogate-control": "max-age=3600", age: "120", "content-type": "text/css", etag: "\"abc\"" },
    }));
    const res = await run("/styles/x.css");
    expectNoStore(expect, res);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("content-type")).toBe("text/css");
    expect(res.headers.get("etag")).toBe("\"abc\"");
  });

  it("public origin error status (404) is passed through with no-store", async () => {
    rec.route(ORIGIN, () => new Response("nope", { status: 404, headers: { "content-type": "text/html" } }));
    const res = await run("/scripts/missing.js");
    expect(res.status).toBe(404);
    expect(await res.text()).toBe("nope");
    expectNoStore(expect, res);
  });

  it("public request on localhost sends x-forwarded-host = the request host (localhost-aware)", async () => {
    const res = await handleRequest({ request: gateRequest("http://localhost:7676/scripts/x.js") });
    expect(res.status).toBe(200);
    expect(onlyCallTo(ORIGIN).headers.get("x-forwarded-host")).toBe("localhost:7676");
  });
});

// ---------------------------------------------------------------------------
describe("default tier (unmatched path → protected, deny-by-default)", () => {
  it("anonymous /some/page → 302 to the IdP authorize endpoint with the full PKCE/OIDC parameter set", async () => {
    const res = await run("/some/page");
    expectLoginRedirect(res);
    expectNoStore(expect, res);
    const p = new URL(res.headers.get("location")).searchParams;
    expect(p.get("response_type")).toBe("code");
    expect(p.get("client_id")).toBe(CLIENT_ID);
    expect(p.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(p.get("scope")).toBe(SCOPES);
    expect(p.get("state")).toMatch(/^[A-Za-z0-9_-]{16,}$/);
    expect(p.get("nonce")).toMatch(/^[A-Za-z0-9_-]{16,}$/);
    expect(p.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get("code_challenge_method")).toBe("S256");
    expect([...p.keys()].sort()).toEqual(
      ["client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri", "response_type", "scope", "state"]);
  });

  it("anonymous login 302 sets __Host-edge_login with Path=/, Max-Age=600, SameSite=Lax, HttpOnly, Secure", async () => {
    const res = await run("/some/page");
    const [c] = setCookies(res);
    expect(c.name).toBe(LOGIN_COOKIE);
    expect(c.value).not.toBe("");
    expect(c.attrs).toEqual(new Set(["path=/", "max-age=600", "samesite=lax", "httponly", "secure"]));
  });

  it("each login start uses a fresh state, nonce and code_challenge", async () => {
    const a = new URL((await run("/some/page")).headers.get("location")).searchParams;
    const b = new URL((await run("/some/page")).headers.get("location")).searchParams;
    for (const k of ["state", "nonce", "code_challenge"]) expect(a.get(k)).not.toBe(b.get(k));
  });

  it("sandbox (KV null): every login start live-fetches the discovery document from the issuer", async () => {
    await run("/some/page");
    await run("/other/page");
    const disc = rec.to(ISSUER_HOST);
    expect(disc.map((c) => c.pathname)).toEqual(["/.well-known/openid-configuration", "/.well-known/openid-configuration"]);
  });

  it("login start on localhost uses a request-derived redirect_uri", async () => {
    const res = await handleRequest({ request: gateRequest("http://localhost:7676/some/page") });
    expect(new URL(res.headers.get("location")).searchParams.get("redirect_uri")).toBe("http://localhost:7676/.auth/callback");
  });

  it("discovery fetch failure while starting a login → 500 internal_error", async () => {
    rec.route(`${ISSUER}/.well-known/openid-configuration`, () => new Response("down", { status: 503 }));
    await expectJsonError(await run("/some/page"), 500, "internal_error");
  });

  // DELIBERATE CHANGE (bare-section fix): a "P/*" rule now also covers the bare
  // path "P", so "/api" is classified by "/api/*" (embedded: public → swapi)
  // instead of falling to the protected default.
  it("/api (bare section path) is covered by /api/* and forwarded like the rest of the section", async () => {
    const res = await run("/api");
    expect(res.status).toBe(200);
    expect(onlyCallTo(SWAPI).url).toBe("https://swapi.dev/api");
  });

  it("a path that only shares a prefix with a section (/apiary) is NOT covered by /api/* → protected default", async () => {
    expectLoginRedirect(await run("/apiary"));
  });
});

// ---------------------------------------------------------------------------
describe("protected tier and audience gating", () => {
  it("anonymous /protected/x → 302 login (no origin call)", async () => {
    expectLoginRedirect(await run("/protected/x"));
  });

  it("garbage or tampered session cookie on /protected/x → 302 login", async () => {
    expectLoginRedirect(await run("/protected/x", { cookie: `${SESSION_COOKIE}=garbage` }));
    const good = await env.session([]);
    const tampered = good.slice(0, -2) + (good.endsWith("AA") ? "BB" : "AA");
    expectLoginRedirect(await run("/protected/x", { cookie: tampered }));
  });

  it("expired session (past the 3600s TTL) on /protected/x → 302 login", async () => {
    const cookie = await env.session([]);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 3601 * 1000);
    expectLoginRedirect(await run("/protected/x", { cookie }));
  });

  it("valid session on /protected/x forwards to EDS with identity headers and no cookie", async () => {
    const cookie = await env.session(["medical"]);
    const res = await run("/protected/x?a=1", { cookie: `foo=bar; ${cookie}` });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
    expectNoStore(expect, res);
    const call = onlyCallTo(ORIGIN);
    expect(call.url).toBe(`https://${ORIGIN}/protected/x?a=1`);
    expect(call.headers.get("host")).toBe(ORIGIN);
    expect(call.headers.get("x-forwarded-host")).toBe(FORWARDED_HOST);
    expect(call.headers.get("x-push-invalidation")).toBe("enabled");
    expect(call.headers.get("x-auth-subject")).toBe("user-123");
    expect(call.headers.get("x-auth-email")).toBe("u@example.com");
    expect(call.headers.get("x-auth-groups")).toBe("medical");
    expect(call.headers.get("x-auth-request-id")).toBeTruthy();
    expect(call.headers.get("cookie")).toBeNull();
    // Authenticated traffic is validated locally: no IdP round-trip.
    expect(rec.to(ISSUER_HOST)).toHaveLength(0);
  });

  it("groups come only from the namespaced claim: a plain `groups` claim yields x-auth-groups=''", async () => {
    // The mock OP always emits `groups: ["site-readers"]`; with the namespaced
    // claim absent the session must carry no groups (no fallback chain).
    // Not memoized: log in directly with the namespaced claim removed.
    const { sessionCookie } = await env.login({ claims: { [GROUPS_CLAIM]: undefined } });
    rec.reset();
    await run("/protected/x", { cookie: sessionCookie });
    expect(onlyCallTo(ORIGIN).headers.get("x-auth-groups")).toBe("");
  });

  it("multiple groups are forwarded comma-joined in x-auth-groups", async () => {
    const cookie = await env.session(["medical", "market-access"]);
    await run("/protected/x", { cookie });
    expect(onlyCallTo(ORIGIN).headers.get("x-auth-groups")).toBe("medical,market-access");
  });

  it("POST to /protected/x with a session forwards method and body intact", async () => {
    const cookie = await env.session([]);
    const res = await run("/protected/x", { method: "POST", cookie, body: "a=1&b=2", headers: { "content-type": "application/x-www-form-urlencoded" } });
    expect(res.status).toBe(200);
    const call = onlyCallTo(ORIGIN);
    expect(call.method).toBe("POST");
    expect(call.bodyText).toBe("a=1&b=2");
    expect(call.headers.get("content-type")).toBe("application/x-www-form-urlencoded");
  });

  it.each([
    ["/protected/medical/x", ["market-access"]],
    ["/protected/market-access/x", ["medical"]],
    ["/protected/medical/x", []],
  ])("session without the audience group on %s → 403 branded /errors/403 page from origin", async (path, groups) => {
    const cookie = await env.session(groups);
    rec.route(ORIGIN, (req, call) => call.pathname === "/errors/403"
      ? new Response("<h1>forbidden</h1>", { status: 200, headers: { "content-type": "text/html; charset=utf-8", "set-cookie": "eds=1", age: "50" } })
      : new Response("SHOULD-NOT-BE-SERVED"));
    const res = await run(path, { cookie });
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toBe("<h1>forbidden</h1>");
    expectNoStore(expect, res);
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    // Only status/content-type/body survive from the error-page fetch.
    expect(setCookies(res)).toEqual([]);
    const call = onlyCallTo(ORIGIN);
    expect(call.url).toBe(`https://${ORIGIN}/errors/403`);
    expect(call.headers.get("host")).toBe(ORIGIN);
    expect(call.headers.get("x-forwarded-host")).toBe(FORWARDED_HOST);
    expect(call.headers.get("cookie")).toBeNull();
    expectNoIdentity(call);
  });

  it("403 falls back to JSON {error:'forbidden'} when the origin /errors/403 page is not OK", async () => {
    const cookie = await env.session([]);
    rec.route(ORIGIN, () => new Response("missing", { status: 404 }));
    await expectJsonError(await run("/protected/medical/x", { cookie }), 403, "forbidden");
  });

  it("403 falls back to JSON {error:'forbidden'} when the origin /errors/403 fetch throws", async () => {
    const cookie = await env.session([]);
    rec.route(ORIGIN, () => { throw new TypeError("fetch failed"); });
    await expectJsonError(await run("/protected/medical/x", { cookie }), 403, "forbidden");
  });

  it.each([
    ["/protected/medical/x", ["medical"], "medical"],
    ["/protected/market-access/x", ["market-access"], "market-access"],
    ["/protected/market-access/x", ["medical", "market-access"], "medical,market-access"],
  ])("session with the audience group on %s → forwarded", async (path, groups, header) => {
    const cookie = await env.session(groups);
    const res = await run(path, { cookie });
    expect(res.status).toBe(200);
    const call = onlyCallTo(ORIGIN);
    expect(call.pathname).toBe(path);
    expect(call.headers.get("x-auth-groups")).toBe(header);
  });

  it("anonymous on an audience route → 302 login (authentication precedes authorization)", async () => {
    expectLoginRedirect(await run("/protected/medical/x"));
  });

  // DELIBERATE CHANGE (security fix): the bare section path used to match only
  // "/protected/*" and skipped the medical audience check. "/protected/medical/*"
  // now covers "/protected/medical" itself.
  it("/protected/medical (no trailing slash) is audience-gated: no medical group → 403, never forwarded", async () => {
    rec.route(ORIGIN, (req, call) => call.pathname === "/errors/403"
      ? new Response("<h1>branded 403</h1>", { headers: { "content-type": "text/html" } })
      : new Response("SHOULD NOT BE FETCHED"));
    const res = await run("/protected/medical", { cookie: await env.session([]) });
    expect(res.status).toBe(403);
    expect(rec.to(ORIGIN).map((c) => c.pathname)).toEqual(["/errors/403"]);
  });

  it("/protected/medical (no trailing slash) with the medical group is forwarded as-is", async () => {
    const res = await run("/protected/medical", { cookie: await env.session(["medical"]) });
    expect(res.status).toBe(200);
    expect(onlyCallTo(ORIGIN).pathname).toBe("/protected/medical");
  });

  it("/protected/market-access (no trailing slash) is gated by its own audience too", async () => {
    const res = await run("/protected/market-access", { cookie: await env.session(["medical"]) });
    expect(res.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
describe("trailing slash (EDS directory pages)", () => {
  it("/protected/medical/ is audience-gated and forwarded with the trailing slash preserved", async () => {
    const res = await run("/protected/medical/", { cookie: await env.session(["medical"]) });
    expect(res.status).toBe(200);
    expect(onlyCallTo(ORIGIN).url).toBe(`https://${ORIGIN}/protected/medical/`);
  });

  it("/protected/medical/ without the medical group → 403", async () => {
    rec.route(ORIGIN, () => new Response("err", { status: 404 }));
    const res = await run("/protected/medical/", { cookie: await env.session([]) });
    expect(res.status).toBe(403);
  });

  it("duplicate trailing slashes collapse to one: /protected/medical// → /protected/medical/", async () => {
    await run("/protected/medical//", { cookie: await env.session(["medical"]) });
    expect(onlyCallTo(ORIGIN).pathname).toBe("/protected/medical/");
  });
});

// ---------------------------------------------------------------------------
describe("/api/* (embedded: public, upstream https://swapi.dev)", () => {
  it("/api/people/1 forwards to swapi.dev with path and query preserved and no EDS/identity headers", async () => {
    const res = await run("/api/people/1?format=json", {
      cookie: `${SESSION_COOKIE}=whatever`,
      headers: { "x-push-invalidation": "enabled", "x-auth-subject": "spoof" },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(`upstream-body:${SWAPI}`);
    expectNoStore(expect, res);
    expect(rec.to(ORIGIN)).toHaveLength(0);
    const call = onlyCallTo(SWAPI);
    expect(call.url).toBe("https://swapi.dev/api/people/1?format=json");
    expect(call.headers.get("host")).toBe(SWAPI);
    expect(call.headers.get("x-forwarded-host")).toBeNull();
    expect(call.headers.get("x-push-invalidation")).toBeNull();
    expect(call.headers.get("cookie")).toBeNull();
    expectNoIdentity(call);
    // The correlation id IS sent to the third-party upstream today.
    expect(call.headers.get("x-auth-request-id")).toBeTruthy();
  });

  it("/api/* does not forward identity headers to swapi even with a valid session (session never read on public)", async () => {
    const cookie = await env.session(["medical"]);
    await run("/api/films/", { cookie });
    const call = onlyCallTo(SWAPI);
    expect(call.pathname).toBe("/api/films/");
    expectNoIdentity(call);
  });

  it("/api/* passes a client-supplied x-forwarded-host through to the upstream unchanged", async () => {
    await run("/api/people/", { headers: { "x-forwarded-host": "evil.example" } });
    expect(onlyCallTo(SWAPI).headers.get("x-forwarded-host")).toBe("evil.example");
  });
});

// ---------------------------------------------------------------------------
describe("/form and /form/* (reCAPTCHA)", () => {
  const FORM_CT = "application/x-www-form-urlencoded";

  it("GET /form forwards to the EDS origin (public, no upstream, no reCAPTCHA)", async () => {
    const res = await run("/form");
    expect(res.status).toBe(200);
    expect(onlyCallTo(ORIGIN).pathname).toBe("/form");
    expect(rec.calls.filter((c) => c.url.startsWith(SITEVERIFY_URL))).toHaveLength(0);
  });

  it("POST /form (exact rule, no recaptcha flag) forwards to EDS without siteverify", async () => {
    const res = await run("/form", { method: "POST", body: "a=1", headers: { "content-type": FORM_CT } });
    expect(res.status).toBe(200);
    const call = onlyCallTo(ORIGIN);
    expect(call.method).toBe("POST");
    expect(call.bodyText).toBe("a=1");
    expect(rec.calls.filter((c) => c.url.startsWith(SITEVERIFY_URL))).toHaveLength(0);
  });

  it("GET /form/x is not reCAPTCHA-checked and forwards to the form upstream with the rule header", async () => {
    const res = await run("/form/x?y=1");
    expect(res.status).toBe(200);
    expect(rec.calls.filter((c) => c.url.startsWith(SITEVERIFY_URL))).toHaveLength(0);
    const call = onlyCallTo(FORM_UPSTREAM);
    expect(call.url).toBe(`https://${FORM_UPSTREAM}/form/x?y=1`);
    expect(call.headers.get("host")).toBe(FORM_UPSTREAM);
    expect(call.headers.get("x-edge-gate-secret")).toBeTruthy(); // value is a secret; presence only
    expect(call.headers.get("x-forwarded-host")).toBeNull();
    expect(call.headers.get("x-push-invalidation")).toBeNull();
    expectNoIdentity(call);
  });

  it("POST /form/x without a token → 400 recaptcha_failed; neither siteverify nor upstream is called", async () => {
    await expectJsonError(await run("/form/x", { method: "POST", body: "name=Ada", headers: { "content-type": FORM_CT } }), 400, "recaptcha_failed");
    expect(rec.calls).toHaveLength(0);
  });

  it("POST /form/x with an empty body → 400 recaptcha_failed", async () => {
    await expectJsonError(await run("/form/x", { method: "POST" }), 400, "recaptcha_failed");
    expect(rec.to(FORM_UPSTREAM)).toHaveLength(0);
  });

  it("POST /form/x whose token Google rejects → 400 recaptcha_failed, upstream not called", async () => {
    rec.route(SITEVERIFY_URL, () => Response.json({ success: false, "error-codes": ["invalid-input-response"] }));
    await expectJsonError(await run("/form/x", { method: "POST", body: "g-recaptcha-response=bad", headers: { "content-type": FORM_CT } }), 400, "recaptcha_failed");
    expect(rec.to(FORM_UPSTREAM)).toHaveLength(0);
  });

  it("POST /form/x when siteverify is unreachable or non-OK → 400 recaptcha_failed (fails closed)", async () => {
    rec.route(SITEVERIFY_URL, () => { throw new TypeError("fetch failed"); });
    await expectJsonError(await run("/form/x", { method: "POST", body: "g-recaptcha-response=t", headers: { "content-type": FORM_CT } }), 400, "recaptcha_failed");
    rec.route(SITEVERIFY_URL, () => new Response("err", { status: 500 }));
    await expectJsonError(await run("/form/x", { method: "POST", body: "g-recaptcha-response=t", headers: { "content-type": FORM_CT } }), 400, "recaptcha_failed");
    expect(rec.to(FORM_UPSTREAM)).toHaveLength(0);
  });

  it("POST /form/x with a valid token → siteverify POSTed, then forwarded with body intact and x-recaptcha-* headers", async () => {
    const body = "name=Ada&g-recaptcha-response=tok-123&msg=hi%20there";
    const res = await run("/form/x", { method: "POST", body, headers: { "content-type": FORM_CT } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(`upstream-body:${FORM_UPSTREAM}`);
    expectNoStore(expect, res);

    const [sv] = rec.calls.filter((c) => c.url === SITEVERIFY_URL);
    expect(sv.method).toBe("POST");
    expect(sv.headers.get("content-type")).toBe(FORM_CT);
    const svForm = new URLSearchParams(sv.bodyText);
    expect(svForm.get("response")).toBe("tok-123");
    expect(svForm.get("secret")).toBeTruthy();
    // siteverify happens before the forward.
    expect(rec.calls.map((c) => c.host)).toEqual(["www.google.com", FORM_UPSTREAM]);

    const call = onlyCallTo(FORM_UPSTREAM);
    expect(call.method).toBe("POST");
    expect(call.bodyText).toBe(body); // token field is forwarded too
    expect(call.headers.get("content-type")).toBe(FORM_CT);
    expect(call.headers.get("x-recaptcha-score")).toBe("0.9");
    expect(call.headers.get("x-recaptcha-hostname")).toBe("www.example.com");
    expect(call.headers.get("x-recaptcha-challenge-ts")).toBe("2024-01-01T00:00:00Z");
    expect(call.headers.get("x-edge-gate-secret")).toBeTruthy();
    expectNoIdentity(call);
  });

  it("multipart POST /form/x: token extracted from the multipart field and binary body forwarded byte-for-byte", async () => {
    const boundary = "----charboundary";
    const enc = new TextEncoder();
    const binary = new Uint8Array(256).map((_, i) => i);
    const parts = [
      enc.encode(`--${boundary}\r\nContent-Disposition: form-data; name="g-recaptcha-response"\r\n\r\ntok-mp\r\n`),
      enc.encode(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="b.bin"\r\nContent-Type: application/octet-stream\r\n\r\n`),
      binary,
      enc.encode(`\r\n--${boundary}--\r\n`),
    ];
    const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { bytes.set(p, o); o += p.length; }
    const res = await run("/form/upload", { method: "POST", body: bytes, headers: { "content-type": `multipart/form-data; boundary=${boundary}` } });
    expect(res.status).toBe(200);
    const [sv] = rec.calls.filter((c) => c.url === SITEVERIFY_URL);
    expect(new URLSearchParams(sv.bodyText).get("response")).toBe("tok-mp");
    expect([...onlyCallTo(FORM_UPSTREAM).bodyBytes]).toEqual([...bytes]);
  });

  it("spoofed inbound x-recaptcha-* headers are stripped (v2 result without score → no score header)", async () => {
    rec.route(SITEVERIFY_URL, () => Response.json({ success: true, hostname: "www.example.com", challenge_ts: "2024-01-01T00:00:00Z" }));
    await run("/form/x", {
      method: "POST", body: "g-recaptcha-response=t",
      headers: { "content-type": FORM_CT, "x-recaptcha-score": "1.0", "x-recaptcha-custom": "spoof" },
    });
    const call = onlyCallTo(FORM_UPSTREAM);
    expect(call.headers.get("x-recaptcha-score")).toBeNull();
    expect(call.headers.get("x-recaptcha-custom")).toBeNull();
    expect(call.headers.get("x-recaptcha-hostname")).toBe("www.example.com");
  });

  it("spoofed inbound x-recaptcha-score is overwritten by Google's score", async () => {
    rec.route(SITEVERIFY_URL, () => Response.json({ success: true, score: 0.6 }));
    await run("/form/x", { method: "POST", body: "g-recaptcha-response=t", headers: { "content-type": FORM_CT, "x-recaptcha-score": "1.0" } });
    expect(onlyCallTo(FORM_UPSTREAM).headers.get("x-recaptcha-score")).toBe("0.6");
  });

  it("spoofed x-recaptcha-* on a GET /form/x (not verified) is stripped too", async () => {
    await run("/form/x", { headers: { "x-recaptcha-score": "1.0" } });
    expect(onlyCallTo(FORM_UPSTREAM).headers.get("x-recaptcha-score")).toBeNull();
  });

  // DELIBERATE CHANGE: the embedded config now sets recaptcha_min_score = 0.5
  // (Google's recommended starting threshold). Previously no threshold was set
  // and a v3 score of 0.0 passed.
  it.each([0.0, 0.3, 0.49])("a v3 score of %s is below the 0.5 threshold → 400 recaptcha_failed, never forwarded", async (score) => {
    rec.route(SITEVERIFY_URL, () => Response.json({ success: true, score }));
    const res = await run("/form/x", { method: "POST", body: "g-recaptcha-response=t", headers: { "content-type": FORM_CT } });
    await expectJsonError(res, 400, "recaptcha_failed");
    expect(rec.to(FORM_UPSTREAM)).toHaveLength(0);
  });

  it.each([0.5, 0.7])("a v3 score of %s meets the 0.5 threshold → forwarded", async (score) => {
    rec.route(SITEVERIFY_URL, () => Response.json({ success: true, score }));
    const res = await run("/form/x", { method: "POST", body: "g-recaptcha-response=t", headers: { "content-type": FORM_CT } });
    expect(res.status).toBe(200);
    expect(onlyCallTo(FORM_UPSTREAM).headers.get("x-recaptcha-score")).toBe(String(score));
  });

  it.each(["PUT", "PATCH", "DELETE"])("%s /form/x is NOT reCAPTCHA-checked (only POST is) and is forwarded", async (method) => {
    const res = await run("/form/x", { method, body: method === "DELETE" ? undefined : "a=1", headers: { "content-type": FORM_CT } });
    expect(res.status).toBe(200);
    expect(rec.calls.filter((c) => c.url === SITEVERIFY_URL)).toHaveLength(0);
    expect(onlyCallTo(FORM_UPSTREAM).method).toBe(method);
  });

  it("rule header x-edge-gate-secret overrides a client-supplied header of the same name", async () => {
    await run("/form/x", { headers: { "x-edge-gate-secret": "client-guess" } });
    const v = onlyCallTo(FORM_UPSTREAM).headers.get("x-edge-gate-secret");
    expect(v).toBeTruthy();
    expect(v).not.toBe("client-guess");
  });

  // Documents the CURRENT ordering on the embedded config: the reCAPTCHA check
  // runs before (and here, instead of) any session handling — siteverify is
  // called for a /form/* POST whatever cookies are sent, a bad token is
  // rejected even with a valid session, and the session never reaches the
  // upstream. EXPECTED TO CHANGE deliberately (decision D6): forms stay public
  // by default, but on protected routes reCAPTCHA will run AFTER
  // authentication. See store-backed.test.js for the protected-rule variant.
  it("recaptcha-runs-before-auth (embedded): siteverify gates /form/* POSTs regardless of session cookies", async () => {
    const valid = await env.session(["medical"]);
    for (const cookie of [undefined, `${SESSION_COOKIE}=garbage`, valid]) {
      rec.reset();
      const res = await run("/form/x", { method: "POST", cookie, body: "g-recaptcha-response=t", headers: { "content-type": FORM_CT } });
      expect(res.status).toBe(200);
      expect(rec.calls[0].url).toBe(SITEVERIFY_URL);
      const call = onlyCallTo(FORM_UPSTREAM);
      expect(call.headers.get("cookie")).toBeNull();
      expectNoIdentity(call);
    }
    rec.reset();
    rec.route(SITEVERIFY_URL, () => Response.json({ success: false }));
    const res = await run("/form/x", { method: "POST", cookie: valid, body: "g-recaptcha-response=t", headers: { "content-type": FORM_CT } });
    await expectJsonError(res, 400, "recaptcha_failed");
  });
});

// ---------------------------------------------------------------------------
describe("header spoofing", () => {
  const SPOOF = {
    "x-auth-subject": "admin", "x-auth-email": "admin@evil.example", "x-auth-groups": "medical,market-access",
    "x-auth-anything": "spoof", "x-push-invalidation": "disabled", "x-forwarded-host": "evil.example", host: "evil.example",
  };

  it("public route: inbound x-auth-* stripped, host/x-forwarded-host/x-push-invalidation overwritten, cookie not forwarded", async () => {
    await run("/scripts/x.js", { headers: SPOOF, cookie: "a=b" });
    const call = onlyCallTo(ORIGIN);
    expectNoIdentity(call);
    expect(call.headers.get("x-auth-anything")).toBeNull();
    expect(call.headers.get("host")).toBe(ORIGIN);
    expect(call.headers.get("x-forwarded-host")).toBe(FORWARDED_HOST);
    expect(call.headers.get("x-push-invalidation")).toBe("enabled");
    expect(call.headers.get("cookie")).toBeNull();
  });

  it("protected route: inbound x-auth-* overwritten with the session's identity, cookie not forwarded", async () => {
    const cookie = await env.session([]);
    await run("/protected/x", { headers: SPOOF, cookie });
    const call = onlyCallTo(ORIGIN);
    expect(call.headers.get("x-auth-subject")).toBe("user-123");
    expect(call.headers.get("x-auth-email")).toBe("u@example.com");
    expect(call.headers.get("x-auth-groups")).toBe("");
    expect(call.headers.get("x-auth-anything")).toBeNull();
    expect(call.headers.get("cookie")).toBeNull();
  });

  it("spoofed x-auth-groups does not satisfy an audience rule (403, not forwarded)", async () => {
    rec.route(ORIGIN, (req, call) => call.pathname === "/errors/403" ? new Response("forbidden-page") : new Response("SECRET"));
    const res = await run("/protected/medical/x", { headers: { "x-auth-groups": "medical" }, cookie: await env.session([]) });
    expect(res.status).toBe(403);
    expect(rec.to(ORIGIN).map((c) => c.pathname)).toEqual(["/errors/403"]);
  });

  it("inbound x-auth-request-id is replaced by a gate-generated id", async () => {
    await run("/scripts/x.js", { headers: { "x-auth-request-id": "client-chosen" } });
    const id = onlyCallTo(ORIGIN).headers.get("x-auth-request-id");
    expect(id).toBeTruthy();
    expect(id).not.toBe("client-chosen");
  });

  it("inbound fastly-trace-id is used verbatim as the x-auth-request-id (forwarded and on error responses)", async () => {
    await run("/scripts/x.js", { headers: { "fastly-trace-id": "trace-abc" } });
    expect(onlyCallTo(ORIGIN).headers.get("x-auth-request-id")).toBe("trace-abc");
    const res = await run("/a%2fb", { headers: { "fastly-trace-id": "trace-abc" } });
    expect(res.headers.get("x-auth-request-id")).toBe("trace-abc");
  });
});

// ---------------------------------------------------------------------------
describe("path normalization", () => {
  it.each(["/protected%2fx", "/scripts%2F..%2Fprotected/x", "/scripts/%5c/x", "/a%5Cb"])(
    "encoded separator in %s → 400 bad_request, nothing fetched", async (path) => {
      await expectJsonError(await run(path), 400, "bad_request");
      expect(rec.calls).toHaveLength(0);
    });

  it.each(["/%zz", "/scripts/%E0%A4%A"])("malformed escape %s → 400 bad_request", async (path) => {
    await expectJsonError(await run(path), 400, "bad_request");
    expect(rec.calls).toHaveLength(0);
  });

  it.each(["/scripts/../protected/x", "/scripts/%2e%2e/protected/x", "/scripts/./../protected/x"])(
    "dot segments in %s are resolved before classification → treated as protected (302 login)", async (path) => {
      // Note: the WHATWG URL parser already resolves literal and %2e dot
      // segments; the gate's own resolver is a second line of defence.
      expectLoginRedirect(await run(path));
    });

  it("//protected/x (duplicate slash) is collapsed and classified protected", async () => {
    expectLoginRedirect(await run("//protected/x"));
  });

  it("/%70rotected/x is percent-decoded before classification → protected", async () => {
    expectLoginRedirect(await run("/%70rotected/x"));
  });

  it("the normalized path (not the raw one) is forwarded to origin", async () => {
    const cookie = await env.session([]);
    await run("//protected//%78?k=v", { cookie });
    expect(onlyCallTo(ORIGIN).url).toBe(`https://${ORIGIN}/protected/x?k=v`);
  });

  it("the normalized path is what login remembers as returnTo", async () => {
    const { callback } = await env.login({ returnPath: "//protected/%78?k=v" });
    expect(callback.headers.get("location")).toBe("/protected/x?k=v");
  });
});

// ---------------------------------------------------------------------------
describe("gate routes: /.auth/callback", () => {
  async function expectAuthError(res, status) {
    expect(res.status).toBe(status);
    expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    const id = res.headers.get("x-auth-request-id");
    expect(id).toBeTruthy();
    expect(await res.text()).toBe(`${status} — authentication error (request-id: ${id})\n`);
    expectNoStore(expect, res);
    expect(setCookies(res)).toEqual([]);
  }

  it("callback without a login-state cookie → 400 plain-text authentication error", async () => {
    await expectAuthError(await run("/.auth/callback?code=c&state=s"), 400);
    expect(rec.calls).toHaveLength(0);
  });

  it("callback with a forged (unsigned) login-state cookie → 400", async () => {
    await expectAuthError(await run("/.auth/callback?code=c&state=s", { cookie: `${LOGIN_COOKIE}=forged.value` }), 400);
  });

  it("callback whose state does not match the login cookie → 400", async () => {
    const { loginCookie } = await env.startLogin();
    rec.reset();
    await expectAuthError(await run("/.auth/callback?code=c&state=not-the-state", { cookie: loginCookie }), 400);
    expect(rec.calls).toHaveLength(0);
  });

  it("callback with an IdP error parameter → 401", async () => {
    const { loginCookie, params } = await env.startLogin();
    await expectAuthError(await run(`/.auth/callback?error=access_denied&state=${params.get("state")}`, { cookie: loginCookie }), 401);
  });

  it("callback without a code → 400", async () => {
    const { loginCookie, params } = await env.startLogin();
    await expectAuthError(await run(`/.auth/callback?state=${params.get("state")}`, { cookie: loginCookie }), 400);
  });

  it("callback whose code the IdP rejects at token exchange → 401", async () => {
    const { loginCookie, params } = await env.startLogin();
    await expectAuthError(await run(`/.auth/callback?code=unknown&state=${params.get("state")}`, { cookie: loginCookie }), 401);
  });

  it("callback whose id_token fails validation (bad nonce) → 400", async () => {
    const start = await env.startLogin();
    env.op.issueCode("bad-nonce-code", { claims: { nonce: "wrong" }, codeChallenge: start.params.get("code_challenge") });
    await expectAuthError(await run(`/.auth/callback?code=bad-nonce-code&state=${start.params.get("state")}`, { cookie: start.loginCookie }), 400);
  });

  it("happy path: 302 to returnTo with __Host-edge_session (Secure, HttpOnly, Path=/) and the login cookie cleared", async () => {
    const { callback } = await env.login({ groups: ["medical"], returnPath: "/protected/page?x=1" });
    expect(callback.status).toBe(302);
    expect(callback.headers.get("location")).toBe("/protected/page?x=1");
    expectNoStore(expect, callback);
    const cookies = setCookies(callback);
    expect(cookies.map((c) => c.name)).toEqual([SESSION_COOKIE, LOGIN_COOKIE]);
    const [session, cleared] = cookies;
    expect(session.value).not.toBe("");
    expect(session.attrs).toEqual(new Set(["path=/", "max-age=3600", "samesite=lax", "httponly", "secure"]));
    expect(cleared.value).toBe("");
    expect(cleared.attrs).toEqual(new Set(["path=/", "max-age=0", "samesite=lax", "httponly", "secure"]));
  });

  it("happy path: token exchange is a form POST with code, verifier, client id/secret and the configured redirect_uri", async () => {
    await env.login({ returnPath: "/protected/x" });
    const token = rec.calls.filter((c) => c.url === `${ISSUER}/token`);
    expect(token).toHaveLength(1);
    expect(token[0].method).toBe("POST");
    expect(token[0].headers.get("content-type")).toBe("application/x-www-form-urlencoded");
    const form = new URLSearchParams(token[0].bodyText);
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toMatch(/^code-/);
    expect(form.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(form.get("client_id")).toBe(CLIENT_ID);
    expect(form.get("client_secret")).toBeTruthy();
    expect(form.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    // Sandbox: discovery and JWKS are live-fetched (KV null).
    expect(rec.to(ISSUER_HOST).map((c) => c.pathname)).toContain("/jwks");
  });

  it("the session minted by the callback is accepted on the next protected request", async () => {
    const { sessionCookie } = await env.login({ groups: ["market-access"] });
    rec.reset();
    const res = await run("/protected/market-access/doc", { cookie: sessionCookie });
    expect(res.status).toBe(200);
  });

  it("a //evil.example request path is normalized to the local returnTo /evil.example/x (no open redirect)", async () => {
    // `//evil.example` normalizes to `/evil.example`, so it is already local by
    // the time it is recorded; Location stays same-origin.
    const { callback } = await env.login({ returnPath: "//evil.example/x" });
    expect(callback.headers.get("location")).toBe("/evil.example/x");
  });

  it("sandbox: replaying a consumed callback is not blocked by the gate (no KV marker) but by the IdP's single-use code → 401", async () => {
    const { start, code, state } = await env.login();
    const replay = await run(`/.auth/callback?code=${code}&state=${encodeURIComponent(state)}`, { cookie: start.loginCookie });
    await expectAuthError(replay, 401);
  });
});

describe("gate routes: /.auth/logout", () => {
  // DELIBERATE CHANGE: logout is POST-only with a same-site Origin check, and
  // answers 303 (was: any method, no Origin check, 302).
  const SITE = "https://www.example.com";
  const logout = (opts = {}) => run("/.auth/logout", { method: "POST", ...opts, headers: { origin: SITE, ...(opts.headers || {}) } });

  function expectBothCleared(res) {
    const cookies = setCookies(res);
    expect(cookies.map((c) => c.name)).toEqual([SESSION_COOKIE, LOGIN_COOKIE]);
    for (const c of cookies) {
      expect(c.value).toBe("");
      expect(c.attrs).toEqual(new Set(["path=/", "max-age=0", "samesite=lax", "httponly", "secure"]));
    }
  }

  it("same-site POST logout → 303 to the IdP end_session_endpoint (client_id + post_logout_redirect_uri), both cookies cleared", async () => {
    const res = await logout({ cookie: await env.session([]) });
    expect(res.status).toBe(303);
    const loc = new URL(res.headers.get("location"));
    expect(`${loc.origin}${loc.pathname}`).toBe(`${ISSUER}/logout`);
    expect(loc.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(loc.searchParams.get("post_logout_redirect_uri")).toBe("https://www.example.com/");
    expectBothCleared(res);
    expectNoStore(expect, res);
    expect(rec.to(ORIGIN)).toHaveLength(0);
  });

  it("logout when discovery has no end_session_endpoint → 303 to /", async () => {
    const { end_session_endpoint, ...rest } = env.op.discovery;
    rec.route(`${ISSUER}/.well-known/openid-configuration`, () => Response.json(rest));
    const res = await logout();
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/");
    expectBothCleared(res);
  });

  it("logout when discovery fails → still 303 to / with cookies cleared", async () => {
    rec.route(`${ISSUER}/.well-known/openid-configuration`, () => new Response("down", { status: 503 }));
    const res = await logout();
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/");
    expectBothCleared(res);
  });

  it("anonymous same-site POST logout still clears cookies", async () => {
    const res = await logout();
    expect(res.status).toBe(303);
    expectBothCleared(res);
  });

  it("GET logout → 405 Allow: POST; the session stays valid", async () => {
    const cookie = await env.session([]);
    const res = await run("/.auth/logout", { cookie });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
    expect(setCookies(res)).toHaveLength(0);
    expectNoStore(expect, res);
    // The session was not ended: it still opens a protected page.
    expect((await run("/protected/x", { cookie })).status).toBe(200);
  });

  it("cross-site POST logout (CSRF) → 403, no cookies cleared", async () => {
    const res = await run("/.auth/logout", { method: "POST", headers: { origin: "https://evil.example" }, cookie: await env.session([]) });
    expect(res.status).toBe(403);
    expect(setCookies(res)).toHaveLength(0);
  });

  it("POST logout from the configured public host (forwarded_host) is accepted", async () => {
    const res = await run("/.auth/logout", { method: "POST", headers: { origin: `https://${FORWARDED_HOST}` } });
    expect(res.status).toBe(303);
  });
});

// ---------------------------------------------------------------------------
describe("response hygiene", () => {
  function originWithCookies() {
    return () => {
      const h = new Headers({ "content-type": "text/html" });
      h.append("set-cookie", `${SESSION_COOKIE}=attacker; Path=/`);
      h.append("set-cookie", `${LOGIN_COOKIE}=attacker; Path=/`);
      h.append("set-cookie", "eds_pref=ok; Path=/");
      return new Response("body", { headers: h });
    };
  }

  it("public: origin Set-Cookie for gate cookie names is stripped; other origin cookies survive", async () => {
    rec.route(ORIGIN, originWithCookies());
    const res = await run("/scripts/x.js");
    expect(setCookies(res).map((c) => c.raw)).toEqual(["eds_pref=ok; Path=/"]);
  });

  it("protected: origin Set-Cookie for gate cookie names is stripped; other origin cookies survive", async () => {
    const cookie = await env.session([]);
    rec.route(ORIGIN, originWithCookies());
    const res = await run("/protected/x", { cookie });
    expect(setCookies(res).map((c) => c.raw)).toEqual(["eds_pref=ok; Path=/"]);
  });

  it("upstream: gate cookie names set by a third-party upstream are stripped too", async () => {
    rec.route(SWAPI, originWithCookies());
    const res = await run("/api/people/");
    expect(setCookies(res).map((c) => c.name)).toEqual(["eds_pref"]);
  });
});

// ---------------------------------------------------------------------------
describe("unexpected internal errors", () => {
  it("origin fetch throws on a protected route → 500 JSON internal_error with x-auth-request-id", async () => {
    const cookie = await env.session([]);
    rec.route(ORIGIN, () => { throw new TypeError("connect ECONNREFUSED"); });
    const res = await run("/protected/x", { cookie });
    await expectJsonError(res, 500, "internal_error");
  });

  it("origin fetch throws on a public route → 500 JSON internal_error", async () => {
    rec.route(ORIGIN, () => { throw new TypeError("connect ECONNREFUSED"); });
    await expectJsonError(await run("/"), 500, "internal_error");
  });

  it("upstream fetch throws on /api/* → 500 JSON internal_error", async () => {
    rec.route(SWAPI, () => { throw new TypeError("connect ECONNREFUSED"); });
    await expectJsonError(await run("/api/people/"), 500, "internal_error");
  });

  it("500 error id echoes an inbound fastly-trace-id", async () => {
    rec.route(ORIGIN, () => { throw new TypeError("boom"); });
    const res = await run("/", { headers: { "fastly-trace-id": "trace-500" } });
    expect(res.status).toBe(500);
    expect(res.headers.get("x-auth-request-id")).toBe("trace-500");
  });
});
