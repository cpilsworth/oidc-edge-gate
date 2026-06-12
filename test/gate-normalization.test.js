import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { handleRequest } from "../src/index.js";
import { createMockOp } from "./mock-op.js";
import { seedDiscovery, reqFor } from "./helpers.js";
import { resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

// H1: the gate must normalize the request path *before* classification, so a
// malicious encoding can't be classified as public and forwarded verbatim to an
// origin that decodes/collapses it and serves protected content unauthenticated.
//
// To prove the gate closes the hole regardless of policy posture, this suite
// deliberately uses the *vulnerable* sample shape ({"/*":"public"}): without
// normalization, //protected and /%70rotected slip through as public.

const ISSUER = "https://op.test";
const ORIGIN_HOST = "main--mysite--myorg.aem.live";
const HMAC_KEY = "test-hmac-key-at-least-32-bytes-long!!";

const VULNERABLE_POLICY = {
  rules: [
    { path: "/*", tier: "public" },
    { path: "/protected/*", tier: "protected" },
  ],
  default_tier: "protected",
};

const realFetch = globalThis.fetch;
let op;

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
    policy: JSON.stringify(VULNERABLE_POLICY),
  });
  seedSecrets({ client_secret: "test-client-secret", session_hmac_key: HMAC_KEY });
  seedDiscovery(ISSUER, op.discovery, op.jwks);
  globalThis.fetch = (input, init) => op.handle(new Request(input, init));
});

afterEach(() => { globalThis.fetch = realFetch; });

describe("H1 path normalization", () => {
  it("a clean public path still forwards", async () => {
    const res = await run("/blog/post");
    expect(res.status).toBe(200);
  });

  it("//protected/secret is treated as protected, not public", async () => {
    const res = await run("//protected/secret");
    expect(res.status).toBe(302); // no session, HTML client → login
    expect(res.headers.get("location")).toContain("/authorize");
  });

  it("/%70rotected/secret (encoded 'p') is treated as protected", async () => {
    const res = await run("/%70rotected/secret");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/authorize");
  });

  it("an encoded slash is rejected with 400", async () => {
    const res = await run("/protected%2fsecret");
    expect(res.status).toBe(400);
  });

  it("the normalized path is what reaches origin (gate and origin agree)", async () => {
    let seenPath = null;
    globalThis.fetch = (input, init) => {
      const r = new Request(input, init);
      const u = new URL(r.url);
      if (u.hostname === ORIGIN_HOST) seenPath = u.pathname;
      return op.handle(r);
    };
    const res = await run("//blog//post"); // public, but doubled slashes
    expect(res.status).toBe(200);
    expect(seenPath).toBe("/blog/post");
  });
});
