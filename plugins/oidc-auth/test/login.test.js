// challenge(): the login start (302 to the IdP) and the secured-tier null.
import { describe, it, expect, beforeAll } from "vitest";
import { decodeLoginState } from "../lib/state.js";
import { HMAC_KEY, ISSUER, OPTIONS, CLIENT_ID, makeCtx, newOp, oidcAuth, startLogin } from "./support.js";

let op;
beforeAll(async () => { op = await newOp(); });

describe("challenge, interactive (protected tier)", () => {
  it("302s to the authorize endpoint with exactly the PKCE/OIDC parameter set", async () => {
    const { res } = await startLogin(op, "/members/x");
    expect(res.status).toBe(302);
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    const loc = new URL(res.headers.get("location"));
    expect(`${loc.origin}${loc.pathname}`).toBe(`${ISSUER}/authorize`);
    const p = loc.searchParams;
    expect([...p.keys()]).toEqual(["response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"]);
    expect(p.get("response_type")).toBe("code");
    expect(p.get("client_id")).toBe(CLIENT_ID);
    expect(p.get("redirect_uri")).toBe("https://www.example.com/.auth/callback");
    expect(p.get("scope")).toBe("openid profile email groups");
    expect(p.get("code_challenge_method")).toBe("S256");
  });

  it("sets the signed login-state cookie (Max-Age 600, SameSite Lax) carrying state, nonce, verifier and the return path", async () => {
    const { ctx, params } = await startLogin(op, "/members/x?y=1");
    expect(ctx.recorded.cookies).toHaveLength(1);
    const [w] = ctx.recorded.cookies;
    expect(w.name).toBe("__Host-edge_login");
    expect(w.attrs).toEqual({ maxAge: 600, sameSite: "Lax" });
    const saved = await decodeLoginState(w.value, HMAC_KEY);
    expect(saved.state).toBe(params.get("state"));
    expect(saved.nonce).toBe(params.get("nonce"));
    expect(saved.returnTo).toBe("/members/x?y=1");
    const dg = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(saved.verifier));
    expect(params.get("code_challenge")).toBe(Buffer.from(dg).toString("base64url"));
  });

  it("fetches discovery once, through ctx.fetch (purpose discovery)", async () => {
    const { ctx } = await startLogin(op);
    expect(ctx.recorded.fetches.map((f) => f.opts.purpose)).toEqual(["discovery"]);
  });

  it("local dev: redirect_uri follows the request origin and the configured callback path", async () => {
    const options = oidcAuth.validate({ callback_path: "/.auth/cb", issuer: ISSUER });
    const ctx = makeCtx("http://localhost:7676/members/x", { op, options });
    const res = await oidcAuth.challenge(ctx, options, { interactive: true });
    expect(new URL(res.headers.get("location")).searchParams.get("redirect_uri")).toBe("http://localhost:7676/.auth/cb");
  });

  it("a discovery failure throws (the kernel answers 500 internal_error), and no cookie is set", async () => {
    const ctx = makeCtx("/members/x", { fetch: async () => new Response("down", { status: 503 }) });
    await expect(oidcAuth.challenge(ctx, OPTIONS, { interactive: true })).rejects.toThrow(/discovery fetch failed/);
    expect(ctx.recorded.cookies).toEqual([]);
  });

  it("an authorize endpoint on another origin is fine (a redirect, not a fetch)", async () => {
    const doc = { ...op.discovery, authorization_endpoint: "https://login.elsewhere.test/authorize" };
    const ctx = makeCtx("/members/x", { fetch: async () => Response.json(doc) });
    const res = await oidcAuth.challenge(ctx, OPTIONS, { interactive: true });
    expect(res.headers.get("location")).toMatch(/^https:\/\/login\.elsewhere\.test\/authorize\?/);
  });

  it("each login uses a fresh state, nonce and code_challenge", async () => {
    const a = (await startLogin(op)).params;
    const b = (await startLogin(op)).params;
    for (const k of ["state", "nonce", "code_challenge"]) expect(a.get(k)).not.toBe(b.get(k));
  });
});

describe("challenge, non-interactive (secured tier)", () => {
  it("returns null without fetching or setting cookies, so the kernel answers 401 Bearer", async () => {
    const ctx = makeCtx("/api/x");
    expect(await oidcAuth.challenge(ctx, OPTIONS, { interactive: false })).toBeNull();
    expect(ctx.recorded.fetches).toEqual([]);
    expect(ctx.recorded.cookies).toEqual([]);
  });
});
