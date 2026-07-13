import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { KVStore } from "fastly:kv-store";
import { handleRequest } from "../src/index.js";
import { mintSessionCookie } from "../src/session.js";
import { createMockOp } from "./mock-op.js";
import { seedDiscovery, reqFor, getSetCookie } from "./helpers.js";
import { resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const ISSUER = "https://op.test";
const ORIGIN_HOST = "main--mysite--myorg.aem.live";
const HMAC_KEY = "test-hmac-key-at-least-32-bytes-long!!";

// Policy mirrors local.config.json: public assets/blog, protected tier, an
// audience-gated medical sub-tree, and a secured API tier; default protected.
const POLICY = {
  rules: [
    { path: "/", tier: "public" },
    { path: "/blog/*", tier: "public" },
    { path: "/styles/*", tier: "public" },
    { path: "/scripts/*", tier: "public" },
    { path: "/blocks/*", tier: "public" },
    { path: "/icons/*", tier: "public" },
    { path: "/protected/*", tier: "protected" },
    { path: "/protected/medical/*", tier: "protected", audience: ["medical"] },
    { path: "/api/*", tier: "secured" },
  ],
  default_headers: { "x-edge-gate-secret": "s3cr3t" },
  default_tier: "protected",
};

// The minted-cookie config matches what loadConfig will reconstruct.
const cookieConfig = { sessionKey: HMAC_KEY, sessionTtlSeconds: 3600, groupsClaim: "groups" };
const realFetch = globalThis.fetch;
let op;

async function sessionCookieHeader(groups) {
  const sc = await mintSessionCookie({ sub: "user-123", groups }, cookieConfig);
  const value = sc.match(/__Host-edge_session=([^;]*)/)[1];
  return `__Host-edge_session=${value}`;
}

function run(path, opts) {
  return handleRequest({ request: reqFor(path, opts) });
}

beforeEach(async () => {
  resetStubs();
  op = await createMockOp({ issuer: ISSUER, clientId: "test-client", originHostname: ORIGIN_HOST });
  seedConfig({
    issuer: ISSUER,
    client_id: "test-client",
    redirect_uri: "https://www.example.com/.auth/callback",
    scopes: "openid profile email groups",
    session_ttl_seconds: "3600",
    groups_claim: "groups",
    routes: JSON.stringify({ callback: "/.auth/callback", logout: "/.auth/logout" }),
    backends: JSON.stringify({ origin: "origin", idp: "idp" }),
    origin_hostname: ORIGIN_HOST,
    forwarded_host: "www.example.com",
    push_invalidation: "enabled",
    policy: JSON.stringify(POLICY),
  });
  seedSecrets({ client_secret: "test-client-secret", session_hmac_key: HMAC_KEY });
  // Seed discovery/JWKS so any login/callback path avoids a live IdP fetch.
  seedDiscovery(ISSUER, op.discovery, op.jwks);
  // Route every outbound fetch (origin + IdP) to the mock OP.
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
});

afterEach(() => { globalThis.fetch = realFetch; });

describe("gate end-to-end", () => {
  it("P4 public path forwards without auth", async () => {
    const res = await run("/blog/post");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
  });

  it("P1 protected path with no session → 302 to IdP", async () => {
    const res = await run("/protected/x");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/authorize");
  });

  it("N14 secured path with no session → 401 JSON, no redirect", async () => {
    const res = await run("/api/orders");
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(res.headers.get("location")).toBeNull();
  });

  it("H7 401 carries WWW-Authenticate: Bearer and nosniff + request id", async () => {
    const res = await run("/api/orders");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
  });

  it("P5/P7 secured path with authorized session → forward", async () => {
    const cookie = await sessionCookieHeader(["site-readers"]);
    const res = await run("/api/orders", { headers: { cookie } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
  });

  it("P7 protected path with valid session → forward to origin", async () => {
    const cookie = await sessionCookieHeader(["site-readers"]);
    const res = await run("/protected/x", { headers: { cookie } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("origin-body");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("N15 authenticated but wrong audience → branded /errors/403 page from origin, no-store", async () => {
    const cookie = await sessionCookieHeader(["other-group"]);
    const res = await run("/protected/medical/x", {
      headers: { cookie, "sec-fetch-mode": "navigate" },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(await res.text()).toBe("origin-body"); // the mock origin serves the error page
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  });

  it("N15b wrong-audience sub-resource fetch also gets the 403 error page", async () => {
    const cookie = await sessionCookieHeader(["other-group"]);
    for (const path of ["/protected/medical/media_abc.jpg", "/protected/medical/footer"]) {
      const res = await run(path, { headers: { cookie, "sec-fetch-mode": "cors" } });
      expect(res.status, path).toBe(403);
    }
  });

  it("N16 public assets load without auth even when user lacks role for protected page", async () => {
    const cookie = await sessionCookieHeader(["other-group"]);
    for (const path of ["/styles/main.css", "/scripts/app.js", "/blocks/header.js", "/icons/logo.svg"]) {
      const res = await run(path, { headers: { cookie } });
      expect(res.status, path).toBe(200);
    }
  });

  it("malformed session cookies fail closed without 500", async () => {
    const protectedRes = await run("/protected/x", { headers: { cookie: "__Host-edge_session=%" } });
    expect(protectedRes.status).toBe(302);
    expect(protectedRes.status).toBeLessThan(500);

    const securedRes = await run("/api/orders", { headers: { cookie: "__Host-edge_session=not-valid!!!" } });
    expect(securedRes.status).toBe(401);
    expect(securedRes.status).toBeLessThan(500);
  });

  it("policy-configured headers reach the origin (index.js -> classify -> forwardToOrigin wiring)", async () => {
    let seenHeaders;
    const realHandle = op.handle;
    op.handle = async (request) => {
      if (new URL(request.url).hostname === ORIGIN_HOST) seenHeaders = request.headers;
      return realHandle(request);
    };
    globalThis.fetch = (input, init) => op.handle(new Request(input, init));

    const res = await run("/blog/post");
    expect(res.status).toBe(200);
    expect(seenHeaders.get("x-edge-gate-secret")).toBe("s3cr3t");
  });

  it("full login round-trip: callback mints a session and 302s home", async () => {
    // Drive a protected request to get the login redirect + state cookie.
    const startRes = await run("/protected/x");
    const loginCookie = getSetCookie(startRes, "__Host-edge_login");
    const authUrl = new URL(startRes.headers.get("location"));
    const state = authUrl.searchParams.get("state");
    // We need the nonce + verifier from the signed cookie; replay it through the
    // callback. Register a code whose challenge matches what startLogin sent.
    op.issueCode("code-1", { codeChallenge: authUrl.searchParams.get("code_challenge"), accessToken: "atk" });
    // The mock OP mints an id_token with the nonce we hand it; but startLogin's
    // nonce is sealed in the cookie. Read it back the way handleCallback does.
    const { readStateCookie } = await import("../src/session.js");
    const saved = await readStateCookie(
      reqFor("/.auth/callback", { cookie: `__Host-edge_login=${loginCookie}` }),
      { sessionKey: HMAC_KEY });
    op.codes.get("code-1").claims = { nonce: saved.nonce };

    const cbRes = await run(`/.auth/callback?state=${state}&code=code-1`, {
      headers: { cookie: `__Host-edge_login=${loginCookie}` },
    });
    expect(cbRes.status).toBe(302);
    expect(cbRes.headers.get("location")).toBe("/protected/x");
    expect(getSetCookie(cbRes, "__Host-edge_session")).toBeTruthy();
  });
});

describe("gate — recaptcha-gated route", () => {
  const RECAPTCHA_POLICY = {
    rules: [{ path: "/form/*", tier: "public", recaptcha: true }],
    default_tier: "protected",
  };

  // Layer this test's own fetch wiring on top of the outer beforeEach's
  // op.handle routing: intercept Google's siteverify endpoint, defer
  // everything else (the EDS origin, the IdP) to the mock OP as usual.
  function mockGoogle(result) {
    const realHandle = op.handle;
    globalThis.fetch = async (input, init) => {
      const r = input instanceof Request ? input : new Request(input, init);
      if (new URL(r.url).hostname === "www.google.com") {
        return new Response(JSON.stringify(result), { status: 200 });
      }
      return realHandle(r);
    };
  }

  beforeEach(() => {
    seedConfig({ policy: JSON.stringify(RECAPTCHA_POLICY) });
    seedSecrets({ recaptcha_secret: "test-recaptcha-secret" });
  });

  it("valid token -> forwarded to origin, with the body intact", async () => {
    mockGoogle({ success: true });
    let seenBody;
    const realHandle = op.handle;
    op.handle = async (request) => {
      if (new URL(request.url).hostname === ORIGIN_HOST) seenBody = await request.clone().text();
      return realHandle(request);
    };
    globalThis.fetch = (input, init) => op.handle(new Request(input, init));
    mockGoogle({ success: true }); // re-apply after resetting fetch above

    const res = await run("/form/submit", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "name=Ada&g-recaptcha-response=good-token",
    });
    expect(res.status).toBe(200);
    expect(seenBody).toBe("name=Ada&g-recaptcha-response=good-token");
  });

  it("forwards Google's verification result to origin as trusted x-recaptcha-* headers", async () => {
    let seenHeaders;
    const realHandle = op.handle;
    op.handle = async (request) => {
      if (new URL(request.url).hostname === ORIGIN_HOST) seenHeaders = request.headers;
      return realHandle(request);
    };
    globalThis.fetch = (input, init) => op.handle(new Request(input, init));
    mockGoogle({ success: true, score: 0.9, hostname: "www.example.com", challenge_ts: "2026-07-13T10:00:00Z" });

    const res = await run("/form/submit", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "g-recaptcha-response=good-token",
    });
    expect(res.status).toBe(200);
    expect(seenHeaders.get("x-recaptcha-score")).toBe("0.9");
    expect(seenHeaders.get("x-recaptcha-hostname")).toBe("www.example.com");
    expect(seenHeaders.get("x-recaptcha-challenge-ts")).toBe("2026-07-13T10:00:00Z");
  });

  it("a client-spoofed x-recaptcha-score is overridden by the real verification result", async () => {
    let seenHeaders;
    const realHandle = op.handle;
    op.handle = async (request) => {
      if (new URL(request.url).hostname === ORIGIN_HOST) seenHeaders = request.headers;
      return realHandle(request);
    };
    globalThis.fetch = (input, init) => op.handle(new Request(input, init));
    mockGoogle({ success: true, score: 0.1 }); // the real (low) score

    const res = await run("/form/submit", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "x-recaptcha-score": "1.0", // attacker-supplied, should never reach origin
      },
      body: "g-recaptcha-response=good-token",
    });
    expect(res.status).toBe(200); // passesRecaptcha with no configured minScore just checks success
    expect(seenHeaders.get("x-recaptcha-score")).toBe("0.1");
  });

  it("binary multipart body round-trips byte-for-byte (no UTF-8 corruption of a file part)", async () => {
    mockGoogle({ success: true });
    const boundary = "----binaryBoundary123";
    const enc = new TextEncoder();
    const head = enc.encode(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="g-recaptcha-response"\r\n\r\n` +
      `good-token\r\n` +
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="x.bin"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`,
    );
    // Invalid UTF-8 byte sequences — a naive text()-decode-then-reencode round
    // trip would replace these with U+FFFD and corrupt the file part.
    const binaryChunk = new Uint8Array([0xff, 0xfe, 0x00, 0x01, 0x80, 0x81, 0xc3, 0x28]);
    const tail = enc.encode(`\r\n--${boundary}--\r\n`);
    const fullBody = new Uint8Array(head.length + binaryChunk.length + tail.length);
    fullBody.set(head, 0);
    fullBody.set(binaryChunk, head.length);
    fullBody.set(tail, head.length + binaryChunk.length);

    let seenBytes;
    const realHandle = op.handle;
    op.handle = async (request) => {
      if (new URL(request.url).hostname === ORIGIN_HOST) seenBytes = new Uint8Array(await request.clone().arrayBuffer());
      return realHandle(request);
    };
    globalThis.fetch = (input, init) => op.handle(new Request(input, init));
    mockGoogle({ success: true });

    const res = await run("/form/submit", {
      method: "POST",
      headers: { "content-type": `multipart/form-data; boundary=${boundary}` },
      body: fullBody,
    });
    expect(res.status).toBe(200);
    expect(seenBytes).toEqual(fullBody);
  });

  it("missing/invalid token -> 400, never reaches origin", async () => {
    mockGoogle({ success: false, "error-codes": ["invalid-input-response"] });
    let originHit = false;
    const realHandle = op.handle;
    op.handle = async (request) => {
      if (new URL(request.url).hostname === ORIGIN_HOST) originHit = true;
      return realHandle(request);
    };
    globalThis.fetch = (input, init) => op.handle(new Request(input, init));
    mockGoogle({ success: false, "error-codes": ["invalid-input-response"] });

    const res = await run("/form/submit", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "name=Ada&g-recaptcha-response=bad-token",
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "recaptcha_failed" });
    expect(originHit).toBe(false);
  });

  it("GET to the same route is not checked (nothing to validate)", async () => {
    mockGoogle({ success: false }); // would fail if the gate mistakenly checked it
    const res = await run("/form/submit");
    expect(res.status).toBe(200);
  });

  it("misconfigured: recaptcha required but no secret provisioned -> 500", async () => {
    resetStubs(); // drop every seeded secret, including recaptcha_secret
    seedConfig({
      issuer: ISSUER,
      client_id: "test-client",
      redirect_uri: "https://www.example.com/.auth/callback",
      scopes: "openid profile email groups",
      session_ttl_seconds: "3600",
      groups_claim: "groups",
      routes: JSON.stringify({ callback: "/.auth/callback", logout: "/.auth/logout" }),
      backends: JSON.stringify({ origin: "origin", idp: "idp" }),
      origin_hostname: ORIGIN_HOST,
      forwarded_host: "www.example.com",
      push_invalidation: "enabled",
      policy: JSON.stringify(RECAPTCHA_POLICY),
    });
    seedSecrets({ client_secret: "test-client-secret", session_hmac_key: HMAC_KEY }); // no recaptcha_secret

    const res = await run("/form/submit", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "g-recaptcha-response=whatever",
    });
    expect(res.status).toBe(500);
  });
});
