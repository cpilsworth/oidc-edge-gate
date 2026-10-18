// Session cookie: format, strict shape checks, identity mapping, and wire
// compatibility with sessions minted by the pre-plugin gate's session module.
import { describe, it, expect } from "vitest";
import { isIdentity } from "../../../src/sdk/index.js";
import { sign } from "../../../src/sdk/cookies.js";
import { base64UrlDecode, fromUtf8 } from "../../../src/sdk/encoding.js";
import {
  SESSION_COOKIE, buildSession, clearSession, decodeSession, encodeSession, isValidSession, readSession,
  sessionToIdentity, writeSession,
} from "../lib/session.js";
import { HMAC_KEY, OPTIONS, makeCtx, oidcAuth } from "./support.js";

const now = () => Math.floor(Date.now() / 1000);

/** A token exactly as the legacy mintSessionCookie built it. */
async function legacyToken(fields) {
  return sign(JSON.stringify(fields), HMAC_KEY);
}
const cookieOf = (token) => `${SESSION_COOKIE}=${encodeURIComponent(token)}`;
const authenticate = (cookie) => oidcAuth.authenticate(makeCtx("/protected/x", { cookie }), OPTIONS);

describe("session wire format", () => {
  it("uses the __Host- cookie name", () => {
    expect(SESSION_COOKIE).toBe("__Host-edge_session");
  });

  it("payload is JSON in the legacy key order {sub,email,name,groups,iat,exp}, HMAC-signed with the legacy scheme", async () => {
    const session = buildSession({ sub: "u1", email: "u@example.com", name: "U", groups: ["a"] }, 3600, 1_000);
    expect(JSON.stringify(session)).toBe('{"sub":"u1","email":"u@example.com","name":"U","groups":["a"],"iat":1000,"exp":4600}');
    const token = await encodeSession(session, HMAC_KEY);
    expect(token).toBe(await legacyToken(session)); // byte-identical to the legacy minting
    expect(fromUtf8(base64UrlDecode(token.split(".")[0]))).toBe(JSON.stringify(session));
  });

  it("absent email/name are omitted from the payload, as before", () => {
    expect(JSON.stringify(buildSession({ sub: "u1", groups: [] }, 60, 10))).toBe('{"sub":"u1","groups":[],"iat":10,"exp":70}');
  });

  it("writeSession sets the cookie through ctx.cookies with Max-Age = the TTL (secure attributes are the kernel's)", async () => {
    const ctx = makeCtx("/");
    await writeSession(ctx, buildSession({ sub: "u1", groups: [] }, 3600), HMAC_KEY, 3600);
    expect(ctx.recorded.cookies).toHaveLength(1);
    expect(ctx.recorded.cookies[0]).toMatchObject({ name: SESSION_COOKIE, attrs: { maxAge: 3600 } });
    clearSession(ctx);
    expect(ctx.recorded.cookies[1]).toEqual({ name: SESSION_COOKIE, cleared: true });
  });
});

describe("authenticate (existing sessions stay valid)", () => {
  it("a session minted by the pre-plugin gate authenticates", async () => {
    const t = now();
    const token = await legacyToken({ sub: "user-123", email: "u@example.com", name: "U", groups: ["a", "b"], iat: t, exp: t + 3600 });
    const identity = await authenticate(cookieOf(token));
    expect(isIdentity(identity)).toBe(true);
    expect(identity).toMatchObject({ sub: "user-123", email: "u@example.com", name: "U", groups: ["a", "b"], method: "oidc-session", issuedAt: t, expiresAt: t + 3600 });
    expect(Object.isFrozen(identity)).toBe(true);
  });

  it("no cookie → null without touching the secret", async () => {
    const ctx = makeCtx("/protected/x", { secrets: {} });
    expect(await oidcAuth.authenticate(ctx, OPTIONS)).toBeNull();
  });

  it("a cookie but no session_hmac_key → throws (500), never a silent anonymous pass", async () => {
    const t = now();
    const ctx = makeCtx("/protected/x", { secrets: {}, cookie: cookieOf(await legacyToken({ sub: "x", groups: [], iat: t, exp: t + 60 })) });
    await expect(oidcAuth.authenticate(ctx, OPTIONS)).rejects.toThrow(/session_hmac_key/);
  });

  it("garbage, tampered, malformed, expired or wrong-key cookies → null (the kernel then challenges)", async () => {
    const t = now();
    const good = await legacyToken({ sub: "x", groups: [], iat: t, exp: t + 3600 });
    const tampered = good.slice(0, -2) + (good.endsWith("aa") ? "bb" : "aa");
    const expired = await legacyToken({ sub: "x", groups: [], iat: t - 100, exp: t - 10 });
    const wrongKey = await sign(JSON.stringify({ sub: "x", groups: [], iat: t, exp: t + 3600 }), "another-key-at-least-32-bytes-long!!!!");
    const notJson = await sign("this is not json", HMAC_KEY);
    for (const cookie of [
      `${SESSION_COOKIE}=garbage`, `${SESSION_COOKIE}=%`, `${SESSION_COOKIE}=not-valid!!!`,
      cookieOf(tampered), cookieOf(expired), cookieOf(wrongKey), cookieOf(notJson),
    ]) {
      expect(await authenticate(cookie), cookie).toBeNull();
    }
  });

  it("groups are normalized by createIdentity (non-strings and duplicates dropped)", async () => {
    const t = now();
    const identity = await authenticate(cookieOf(await legacyToken({ sub: "x", groups: ["a", 5, "a", "", "b"], iat: t, exp: t + 60 })));
    expect(identity.groups).toEqual(["a", "b"]);
  });

  it("non-string email/name in a session are dropped from the identity", async () => {
    const t = now();
    const identity = await authenticate(cookieOf(await legacyToken({ sub: "x", email: 5, name: { n: 1 }, groups: [], iat: t, exp: t + 60 })));
    expect(identity.email).toBeUndefined();
    expect(identity.name).toBeUndefined();
  });
});

describe("isValidSession (strict shape)", () => {
  const t = now();
  const base = { sub: "user-123", iat: t, exp: t + 3600, groups: ["site-readers"] };
  it.each([
    ["empty sub", { ...base, sub: "" }],
    ["missing sub", { iat: t, exp: t + 3600, groups: [] }],
    ["missing iat", { sub: "x", exp: t + 3600, groups: [] }],
    ["missing exp", { sub: "x", iat: t, groups: [] }],
    ["missing groups", { sub: "x", iat: t, exp: t + 3600 }],
    ["string groups", { sub: "x", iat: t, exp: t + 3600, groups: "admins" }],
    ["non-finite exp", { ...base, exp: Infinity }],
    ["a string", "not-an-object"],
    ["an array", []],
    ["null", null],
  ])("rejects %s", async (_label, value) => {
    expect(isValidSession(value)).toBe(false);
    expect(await decodeSession(await sign(JSON.stringify(value), HMAC_KEY), HMAC_KEY)).toBeNull();
  });

  it("accepts a well-formed unexpired session", () => {
    expect(isValidSession(base)).toBe(true);
  });
});

describe("readSession / sessionToIdentity", () => {
  it("reads through ctx.cookies and maps to an Identity", async () => {
    const t = now();
    const ctx = makeCtx("/", { cookie: cookieOf(await legacyToken({ sub: "s", groups: ["g"], iat: t, exp: t + 5 })) });
    const s = await readSession(ctx, HMAC_KEY);
    expect(s).toMatchObject({ sub: "s", groups: ["g"] });
    expect(sessionToIdentity(s).method).toBe("oidc-session");
  });
});
