// The logout route (ported from the legacy handleLogout tests and the
// adapter's logout-lifecycle tests).
import { describe, it, expect, beforeEach } from "vitest";
import { isIdentity } from "../../../src/sdk/index.js";
import { buildSession, encodeSession } from "../lib/session.js";
import { CLIENT_ID, HMAC_KEY, ISSUER, OPTIONS, SITE, logoutRoute, makeCtx, newOp, oidcAuth } from "./support.js";

let op;
beforeEach(async () => { op = await newOp(); });

const LOGOUT = "/.auth/logout";
const SESSION = "__Host-edge_session";
const LOGIN = "__Host-edge_login";

async function sessionCookie(groups = ["g"]) {
  const token = await encodeSession(buildSession({ sub: "user-123", email: "u@example.com", groups }, 3600), HMAC_KEY);
  return `${SESSION}=${token}`;
}

function logout({ method = "POST", headers = { origin: SITE }, url = LOGOUT, ...rest } = {}) {
  const ctx = makeCtx(url, { op, method, headers, ...rest });
  return logoutRoute(rest.options || OPTIONS)(ctx, rest.options || OPTIONS).then((res) => ({ ctx, res }));
}

const bothCleared = (ctx) => expect(ctx.recorded.cookies).toEqual([{ name: SESSION, cleared: true }, { name: LOGIN, cleared: true }]);

describe("same-site POST", () => {
  it("P6 clears both cookies and 303s to end_session_endpoint with client_id + post_logout_redirect_uri", async () => {
    const { ctx, res } = await logout({ cookie: await sessionCookie() });
    expect(res.status).toBe(303);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    const loc = new URL(res.headers.get("location"));
    expect(`${loc.origin}${loc.pathname}`).toBe(`${ISSUER}/logout`);
    expect([...loc.searchParams]).toEqual([["client_id", CLIENT_ID], ["post_logout_redirect_uri", `${SITE}/`]]);
    bothCleared(ctx);
    expect(ctx.recorded.fetches.map((f) => f.opts)).toEqual([{ purpose: "discovery", cache: { ttl: 3600 } }]);
  });

  it("emits logout with the current identity", async () => {
    const { ctx } = await logout({ cookie: await sessionCookie(["g"]) });
    expect(ctx.recorded.lifecycle).toHaveLength(1);
    const { event, value } = ctx.recorded.lifecycle[0];
    expect(event).toBe("logout");
    expect(isIdentity(value)).toBe(true);
    expect(value).toMatchObject({ sub: "user-123", groups: ["g"], method: "oidc-session" });
  });

  it("anonymous: emits logout with null and still clears both cookies", async () => {
    const { ctx, res } = await logout();
    expect(res.status).toBe(303);
    expect(ctx.recorded.lifecycle).toEqual([{ event: "logout", value: null }]);
    bothCleared(ctx);
  });

  it("a failing logout subscriber is logged and does not block the logout", async () => {
    const { ctx, res } = await logout({ lifecycle: { emitLogout: async () => { throw new Error("boom"); } } });
    expect(res.status).toBe(303);
    bothCleared(ctx);
    expect(ctx.recorded.logs).toContainEqual(expect.objectContaining({ level: "error", msg: "oidc logout hook failed" }));
  });

  it("no end_session_endpoint → 303 to '/'", async () => {
    const { end_session_endpoint, ...rest } = op.discovery;
    const { ctx, res } = await logout({ fetch: async () => Response.json(rest) });
    expect(end_session_endpoint).toBeTruthy();
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/");
    bothCleared(ctx);
  });

  it.each([
    ["a non-OK discovery response", async () => new Response("down", { status: 503 })],
    ["a throwing fetch", async () => { throw new Error("network down"); }],
    ["an invalid discovery document", async () => Response.json({ issuer: "https://evil.test" })],
  ])("discovery failure (%s) → still 303 to '/' with both cookies cleared", async (_label, fetch) => {
    const { ctx, res } = await logout({ fetch });
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/");
    bothCleared(ctx);
  });

  it("discovery is served from KV when cached", async () => {
    const kv = { [`oidc:discovery:${ISSUER}`]: JSON.stringify({ value: op.discovery, expires: Date.now() + 60_000 }) };
    const { ctx, res } = await logout({ kv, fetch: () => { throw new Error("no fetch"); } });
    expect(res.headers.get("location")).toMatch(/^https:\/\/op\.test\/logout\?/);
    expect(ctx.recorded.fetches).toEqual([]);
  });

  it("accepts a same-site Referer when the browser omitted Origin", async () => {
    expect((await logout({ headers: { referer: `${SITE}/account` } })).res.status).toBe(303);
  });

  it("accepts the configured public host (forwarded_host) when the function sees an internal hostname", async () => {
    const config = { ...makeCtx("/").config, forwardedHost: "www.public.example" };
    const { res } = await logout({ url: "https://edgefunction-internal.example/.auth/logout", headers: { origin: "https://www.public.example" }, config });
    expect(res.status).toBe(303);
  });

  it("a custom logout_path is served by the same handler", async () => {
    const options = oidcAuth.validate({ logout_path: "/.auth/bye", issuer: ISSUER });
    const { res } = await logout({ url: "/.auth/bye", options });
    expect(res.status).toBe(303);
  });
});

describe("rejections: nothing cleared, no logout event", () => {
  it.each(["GET", "HEAD", "PUT", "DELETE"])("%s → 405 with Allow: POST", async (method) => {
    const { ctx, res } = await logout({ method, cookie: await sessionCookie() });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("x-auth-request-id")).toBe("test-request-id");
    if (method !== "HEAD") expect(await res.json()).toEqual({ error: "method_not_allowed" });
    expect(ctx.recorded.cookies).toEqual([]);
    expect(ctx.recorded.lifecycle).toEqual([]);
    expect(ctx.recorded.fetches).toEqual([]);
  });

  it.each([
    ["a cross-site Origin", { origin: "https://evil.example" }],
    ["an opaque Origin: null", { origin: "null" }],
    ["a cross-site Referer and no Origin", { referer: "https://evil.example/page" }],
    ["a malformed Referer and no Origin", { referer: "not a url" }],
    ["neither Origin nor Referer", {}],
    ["the right host over the wrong scheme", { origin: "http://www.example.com" }],
  ])("POST with %s → 403 forbidden", async (_label, headers) => {
    const { ctx, res } = await logout({ headers, cookie: await sessionCookie() });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    expect(res.headers.get("x-auth-request-id")).toBe("test-request-id");
    expect(ctx.recorded.cookies).toEqual([]);
    expect(ctx.recorded.lifecycle).toEqual([]);
  });
});
