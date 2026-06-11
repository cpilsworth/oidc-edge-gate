import { describe, it, expect } from "vitest";
import { SESSION_COOKIE, mintSessionCookie, readSession, clearSessionCookie,
         mintStateCookie, readStateCookie, clearStateCookie } from "../src/session.js";
import { sign } from "../src/cookies.js";
import { reqFor } from "./helpers.js";

// edge-gate's mintSessionCookie reads group membership from config.groupsClaim,
// so the test config must declare it (matches local.config.json default).
const config = {
  sessionKey: "test-hmac-key-at-least-32-bytes-long!!",
  sessionTtlSeconds: 3600,
  groupsClaim: "groups",
};

async function signedSessionCookie(body) {
  const token = await sign(JSON.stringify(body), config.sessionKey);
  return `__edge_session=${encodeURIComponent(token)}`;
}

async function signedLoginCookie(body) {
  const token = await sign(JSON.stringify(body), config.sessionKey);
  return `__edge_login=${encodeURIComponent(token)}`;
}

describe("session", () => {
  it("uses the project cookie name", () => { expect(SESSION_COOKIE).toBe("__edge_session"); });

  it("mints then reads a valid session (edge keeps email + name)", async () => {
    const setCookie = await mintSessionCookie(
      { sub: "user-123", email: "u@example.com", name: "User", groups: ["site-readers"] }, config);
    const value = setCookie.match(/__edge_session=([^;]*)/)[1];
    const req = reqFor("/members/x", { cookie: `__edge_session=${value}` });
    const s = await readSession(req, config);
    expect(s.sub).toBe("user-123");
    expect(s.groups).toEqual(["site-readers"]);
    // Unlike the worker, edge-gate forwards email/name to origin, so it keeps them.
    expect(s.email).toBe("u@example.com");
    expect(s.name).toBe("User");
  });

  it("returns null for an expired session", async () => {
    const expired = { ...config, sessionTtlSeconds: -10 };
    const setCookie = await mintSessionCookie({ sub: "x" }, expired);
    const value = setCookie.match(/__edge_session=([^;]*)/)[1];
    const s = await readSession(reqFor("/m", { cookie: `__edge_session=${value}` }), config);
    expect(s).toBeNull();
  });

  it("returns null for a tampered session", async () => {
    const setCookie = await mintSessionCookie({ sub: "x" }, config);
    const value = setCookie.match(/__edge_session=([^;]*)/)[1];
    const tampered = value.slice(0, -2) + (value.endsWith("aa") ? "bb" : "aa");
    expect(await readSession(reqFor("/m", { cookie: `__edge_session=${tampered}` }), config)).toBeNull();
  });

  it("returns null instead of throwing for malformed percent-encoded cookie values", async () => {
    await expect(readSession(reqFor("/m", { cookie: "__edge_session=%" }), config))
      .resolves.toBeNull();
  });

  it("returns null instead of throwing for invalid base64 session tokens", async () => {
    await expect(readSession(reqFor("/m", { cookie: "__edge_session=not-valid!!!" }), config))
      .resolves.toBeNull();
  });

  it("returns null instead of throwing for malformed login-state cookies", async () => {
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: "__edge_login=%" }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: "__edge_login=garbage!!!" }), config))
      .resolves.toBeNull();
  });

  it("rejects signed session cookies with valid JSON but missing required fields", async () => {
    const now = Math.floor(Date.now() / 1000);
    const base = { sub: "user-123", iat: now, exp: now + 3600, groups: ["site-readers"] };

    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ ...base, sub: "" }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ iat: now, exp: now + 3600, groups: [] }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ sub: "x", exp: now + 3600, groups: [] }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ sub: "x", iat: now, groups: [] }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ sub: "x", iat: now, exp: now + 3600 }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie({ sub: "x", iat: now, exp: now + 3600, groups: "admins" }) }), config))
      .resolves.toBeNull();
    await expect(readSession(reqFor("/m", { cookie: await signedSessionCookie("not-an-object") }), config))
      .resolves.toBeNull();
  });

  it("rejects signed login-state cookies with valid JSON but missing required fields", async () => {
    const base = { state: "s", nonce: "n", verifier: "v", returnTo: "/members/x" };

    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie({ ...base, state: "" }) }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie({ state: "s", verifier: "v", returnTo: "/" }) }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie({ state: "s", nonce: "n", returnTo: "/" }) }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie({ state: "s", nonce: "n", verifier: "v" }) }), config))
      .resolves.toBeNull();
    await expect(readStateCookie(reqFor("/.auth/callback", { cookie: await signedLoginCookie([]) }), config))
      .resolves.toBeNull();
  });

  it("state cookie round-trips and clears", async () => {
    const setCookie = await mintStateCookie({ state: "s", nonce: "n", verifier: "v", returnTo: "/members/x" }, config);
    expect(setCookie).toContain("__edge_login=");
    const value = setCookie.match(/__edge_login=([^;]*)/)[1];
    const saved = await readStateCookie(reqFor("/.auth/callback", { cookie: `__edge_login=${value}` }), config);
    expect(saved.returnTo).toBe("/members/x");
    expect(clearStateCookie()).toContain("Max-Age=0");
    expect(clearSessionCookie()).toContain("Max-Age=0");
  });
});
