// Session cookie v2 (docs/architecture/plugins.md §14.2): wire format, strict
// shape checks, keyring + kid binding, key rotation, typ binding against the
// login-state cookie (F19), size guard, lifetime and identity mapping.
import { describe, it, expect } from "vitest";
import { createIdentityDraft, isIdentity } from "../../../src/sdk/index.js";
import { sign } from "../../../src/sdk/cookies.js";
import { base64UrlDecode, base64UrlEncode, fromUtf8 } from "../../../src/sdk/encoding.js";
import {
  MAX_SESSION_COOKIE_BYTES, SESSION_COOKIE, SessionTooLargeError, buildSession, clearSession, decodeSession, encodeSession,
  isValidSession, readSession, sessionToIdentity, writeSession,
} from "../lib/session.js";
import { keyId, toKeyring } from "../lib/signed-cookie.js";
import { LOGIN_COOKIE, decodeLoginState, readLoginState, writeLoginState } from "../lib/state.js";
import { HMAC_KEY, OPTIONS, SECRETS, makeCtx, oidcAuth } from "./support.js";

const now = () => Math.floor(Date.now() / 1000);
const PREVIOUS_KEY = "previous-plugin-test-hmac-key-32-bytes!!";
const OTHER_KEY = "another-key-at-least-32-bytes-long!!!!";
const SID = "AAAAAAAAAAAAAAAAAAAAAA"; // 22 base64url chars = 16 bytes

const payloadOf = (token) => JSON.parse(fromUtf8(base64UrlDecode(token.split(".")[0])));
const cookieOf = (token) => `${SESSION_COOKIE}=${encodeURIComponent(token)}`;
const withPrevious = (previous) => ({ ...SECRETS, session_hmac_key_previous: previous });
const authenticate = (cookie, secrets = SECRETS) => oidcAuth.authenticate(makeCtx("/protected/x", { cookie, secrets }), OPTIONS);

/** A v2 payload signed directly (bypassing encodeSession), for shape tests. */
async function rawToken(fields, key = HMAC_KEY) {
  return sign(JSON.stringify(fields), key);
}
/** A valid v2 payload for `key`, with overrides. */
async function v2Fields(overrides = {}, key = HMAC_KEY) {
  const t = now();
  return { v: 2, typ: "session", kid: await keyId(key), sid: SID, sub: "user-123", groups: ["a"], iat: t, exp: t + 3600, ...overrides };
}
/** A freshly minted session token, as the callback mints it. */
async function mint(who = { sub: "user-123", groups: ["a"] }, key = HMAC_KEY, ttl = 3600) {
  return encodeSession(buildSession(who, ttl), key);
}

describe("keyId", () => {
  it("is the first 8 base64url chars of SHA-256(key), memoized per key", async () => {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(HMAC_KEY));
    const expected = base64UrlEncode(new Uint8Array(digest)).slice(0, 8);
    expect(await keyId(HMAC_KEY)).toBe(expected);
    expect(keyId(HMAC_KEY)).toBe(keyId(HMAC_KEY)); // same promise
    expect(await keyId(PREVIOUS_KEY)).toMatch(/^[A-Za-z0-9_-]{8}$/);
    expect(await keyId(PREVIOUS_KEY)).not.toBe(expected);
  });

  it("toKeyring keeps non-empty strings, de-duplicates and caps at two", () => {
    expect(toKeyring("a")).toEqual(["a"]);
    expect(toKeyring(["a", undefined])).toEqual(["a"]);
    expect(toKeyring(["a", ""])).toEqual(["a"]);
    expect(toKeyring(["a", "a"])).toEqual(["a"]);
    expect(toKeyring(["a", "b", "c"])).toEqual(["a", "b"]);
  });
});

describe("session wire format v2", () => {
  it("uses the __Host- cookie name", () => {
    expect(SESSION_COOKIE).toBe("__Host-edge_session");
  });

  it("payload is {v,typ,kid,sid,sub,email,name,groups,iat,exp} in that order, HMAC-signed with the active key", async () => {
    const session = buildSession({ sub: "u1", email: "u@example.com", name: "U", groups: ["a"] }, 3600, 1_000);
    const token = await encodeSession(session, HMAC_KEY);
    const json = fromUtf8(base64UrlDecode(token.split(".")[0]));
    const kid = await keyId(HMAC_KEY);
    expect(json).toBe(`{"v":2,"typ":"session","kid":"${kid}","sid":"${session.sid}","sub":"u1","email":"u@example.com","name":"U","groups":["a"],"iat":1000,"exp":4600}`);
    expect(token).toBe(await sign(json, HMAC_KEY)); // base64url(JSON).base64url(HMAC-SHA256)
  });

  it("absent email/name are omitted from the payload", async () => {
    const token = await encodeSession(buildSession({ sub: "u1", groups: [] }, 60, 10), HMAC_KEY);
    expect(Object.keys(payloadOf(token))).toEqual(["v", "typ", "kid", "sid", "sub", "groups", "iat", "exp"]);
  });

  it("only wire-format fields are serialized (extra properties and a stale kid are dropped)", async () => {
    const session = { ...buildSession({ sub: "u1", groups: [] }, 60), kid: "zzzzzzzz", attrs: { x: 1 }, extra: true };
    const p = payloadOf(await encodeSession(session, HMAC_KEY));
    expect(p.kid).toBe(await keyId(HMAC_KEY));
    expect(p).not.toHaveProperty("attrs");
    expect(p).not.toHaveProperty("extra");
  });

  it("sid is 16 random bytes (22 base64url chars), fresh for every session", () => {
    const sids = new Set(Array.from({ length: 200 }, () => buildSession({ sub: "u", groups: [] }, 60).sid));
    expect(sids.size).toBe(200);
    for (const sid of sids) expect(sid).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(base64UrlDecode([...sids][0])).toHaveLength(16);
  });

  it("v2 round trip: encode → decode returns the payload", async () => {
    const session = buildSession({ sub: "u1", email: "u@example.com", groups: ["a", "b"] }, 3600);
    const decoded = await decodeSession(await encodeSession(session, HMAC_KEY), HMAC_KEY);
    expect(decoded).toEqual({ ...JSON.parse(JSON.stringify(session)), kid: await keyId(HMAC_KEY) });
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

describe("lifetime", () => {
  it("exp is now + ttl when the identity expires later (or has no expiresAt)", () => {
    expect(buildSession({ sub: "u", groups: [], expiresAt: 99_999 }, 3600, 1_000).exp).toBe(4_600);
    expect(buildSession({ sub: "u", groups: [] }, 3600, 1_000).exp).toBe(4_600);
  });

  it("exp is the identity's expiresAt when that is earlier (draft.limitLifetime cap)", () => {
    const draft = createIdentityDraft({ sub: "u", groups: ["g"] });
    draft.limitLifetime(300);
    const identity = draft.toIdentity({ method: "oidc-session", issuedAt: 1_000, expiresAt: 4_600 });
    expect(identity.expiresAt).toBe(1_300);
    const s = buildSession(identity, 3600, 1_000);
    expect(s).toMatchObject({ iat: 1_000, exp: 1_300 });
  });

  it("writeSession clamps Max-Age to the payload lifetime (exp - iat)", async () => {
    const ctx = makeCtx("/");
    await writeSession(ctx, buildSession({ sub: "u", groups: [], expiresAt: now() + 300 }, 3600), HMAC_KEY, 3600);
    expect(ctx.recorded.cookies[0].attrs).toEqual({ maxAge: 300 });
  });
});

describe("size guard", () => {
  it(`an encoded session over ${MAX_SESSION_COOKIE_BYTES} bytes throws SessionTooLargeError and sets no cookie`, async () => {
    const groups = Array.from({ length: 300 }, (_, i) => `group-with-a-fairly-long-name-${i}`);
    const ctx = makeCtx("/");
    const err = await writeSession(ctx, buildSession({ sub: "u", groups }, 3600), HMAC_KEY, 3600).catch((e) => e);
    expect(err).toBeInstanceOf(SessionTooLargeError);
    expect(err.name).toBe("SessionTooLargeError");
    expect(err.bytes).toBeGreaterThan(MAX_SESSION_COOKIE_BYTES);
    expect(ctx.recorded.cookies).toEqual([]);
  });

  it("a session just under the limit is set", async () => {
    const ctx = makeCtx("/");
    await writeSession(ctx, buildSession({ sub: "u", groups: Array.from({ length: 40 }, (_, i) => `g${i}`) }, 3600), HMAC_KEY, 3600);
    expect(ctx.recorded.cookies[0].value.length).toBeLessThanOrEqual(MAX_SESSION_COOKIE_BYTES);
  });
});

describe("authenticate", () => {
  it("a freshly minted v2 session authenticates; identity.sessionId is the sid", async () => {
    const session = buildSession({ sub: "user-123", email: "u@example.com", name: "U", groups: ["a", "b"] }, 3600);
    const identity = await authenticate(cookieOf(await encodeSession(session, HMAC_KEY)));
    expect(isIdentity(identity)).toBe(true);
    expect(identity).toMatchObject({
      sub: "user-123", email: "u@example.com", name: "U", groups: ["a", "b"], method: "oidc-session",
      sessionId: session.sid, issuedAt: session.iat, expiresAt: session.exp,
    });
    expect(Object.isFrozen(identity)).toBe(true);
  });

  it("no cookie → null without touching the secret", async () => {
    const ctx = makeCtx("/protected/x", { secrets: {} });
    expect(await oidcAuth.authenticate(ctx, OPTIONS)).toBeNull();
  });

  it("a cookie but no session_hmac_key → throws (500), never a silent anonymous pass", async () => {
    const ctx = makeCtx("/protected/x", { secrets: {}, cookie: cookieOf(await mint()) });
    await expect(oidcAuth.authenticate(ctx, OPTIONS)).rejects.toThrow(/session_hmac_key/);
  });

  it("garbage, tampered, malformed, expired or wrong-key cookies → null (the kernel then challenges)", async () => {
    const t = now();
    const good = await mint();
    const tampered = good.slice(0, -2) + (good.endsWith("aa") ? "bb" : "aa");
    const [body, sig] = good.split(".");
    const forgedBody = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ ...payloadOf(good), groups: ["admin"] })));
    const expired = await rawToken(await v2Fields({ iat: t - 100, exp: t - 10 }));
    const wrongKey = await mint(undefined, OTHER_KEY);
    const notJson = await sign("this is not json", HMAC_KEY);
    for (const cookie of [
      `${SESSION_COOKIE}=garbage`, `${SESSION_COOKIE}=%`, `${SESSION_COOKIE}=not-valid!!!`,
      cookieOf(tampered), cookieOf(`${forgedBody}.${sig}`), cookieOf(`${body}.`), cookieOf(expired), cookieOf(wrongKey), cookieOf(notJson),
    ]) {
      expect(await authenticate(cookie), cookie).toBeNull();
    }
  });

  it("v1 (legacy) sessions are rejected: everyone logs in once after the cutover", async () => {
    const t = now();
    const v1 = await rawToken({ sub: "user-123", email: "u@example.com", name: "U", groups: ["a"], iat: t, exp: t + 3600 });
    expect(await decodeSession(v1, HMAC_KEY)).toBeNull();
    expect(await authenticate(cookieOf(v1))).toBeNull();
  });

  it("groups are normalized by createIdentity (non-strings and duplicates dropped)", async () => {
    const identity = await authenticate(cookieOf(await rawToken(await v2Fields({ groups: ["a", 5, "a", "", "b"] }))));
    expect(identity.groups).toEqual(["a", "b"]);
  });

  it("non-string email/name in a session are dropped from the identity", async () => {
    const identity = await authenticate(cookieOf(await rawToken(await v2Fields({ email: 5, name: { n: 1 } }))));
    expect(identity.email).toBeUndefined();
    expect(identity.name).toBeUndefined();
  });
});

describe("keyring and kid binding", () => {
  it("kid mismatch: a token signed by the active key but claiming another kid → null", async () => {
    const forgedKid = await rawToken(await v2Fields({ kid: await keyId(PREVIOUS_KEY) }));
    expect(await decodeSession(forgedKid, [HMAC_KEY, PREVIOUS_KEY])).toBeNull();
    expect(await authenticate(cookieOf(forgedKid), withPrevious(PREVIOUS_KEY))).toBeNull();
  });

  it("kid mismatch: a token signed by the previous key but claiming the active kid → null", async () => {
    const t = await rawToken(await v2Fields({ kid: await keyId(HMAC_KEY) }), PREVIOUS_KEY);
    expect(await decodeSession(t, [HMAC_KEY, PREVIOUS_KEY])).toBeNull();
  });

  it("a kid never selects a key: a token signed by a key outside the keyring is rejected whatever its kid", async () => {
    for (const kid of [await keyId(HMAC_KEY), await keyId(PREVIOUS_KEY), await keyId(OTHER_KEY)]) {
      expect(await decodeSession(await rawToken(await v2Fields({ kid }), OTHER_KEY), [HMAC_KEY, PREVIOUS_KEY])).toBeNull();
    }
  });

  it.each([["missing", undefined], ["short", "abc"], ["non-string", 12345678], ["bad chars", "abc$efgh"]])("kid %s → null", async (_l, kid) => {
    expect(await decodeSession(await rawToken(await v2Fields({ kid })), HMAC_KEY)).toBeNull();
  });

  it("rotation: a cookie signed with the old key verifies once that key is session_hmac_key_previous", async () => {
    const old = buildSession({ sub: "user-123", groups: ["a"] }, 3600);
    const oldToken = await encodeSession(old, PREVIOUS_KEY); // minted before the rotation (PREVIOUS_KEY was active)
    expect(await authenticate(cookieOf(oldToken))).toBeNull(); // no previous key configured → logged out
    const identity = await authenticate(cookieOf(oldToken), withPrevious(PREVIOUS_KEY));
    expect(identity).toMatchObject({ sub: "user-123", groups: ["a"], sessionId: old.sid });
  });

  it("rotation: new cookies are signed with the active key and carry its kid (never the previous key's)", async () => {
    const ctx = makeCtx("/", { secrets: withPrevious(PREVIOUS_KEY) });
    await writeSession(ctx, buildSession({ sub: "u", groups: [] }, 3600), HMAC_KEY, 3600);
    const token = ctx.recorded.cookies[0].value;
    expect(payloadOf(token).kid).toBe(await keyId(HMAC_KEY));
    expect(await decodeSession(token, HMAC_KEY)).not.toBeNull();
    expect(await decodeSession(token, PREVIOUS_KEY)).toBeNull();
    expect(await authenticate(cookieOf(token), withPrevious(PREVIOUS_KEY))).not.toBeNull();
  });

  it("a previous key equal to the active key is harmless", async () => {
    const token = await mint();
    expect(await authenticate(cookieOf(token), withPrevious(HMAC_KEY))).not.toBeNull();
    expect(await authenticate(cookieOf(await mint(undefined, OTHER_KEY)), withPrevious(HMAC_KEY))).toBeNull();
  });

  it("a previous key shorter than 32 bytes is ignored with a warning", async () => {
    const weak = "short-previous-key";
    const ctx = makeCtx("/protected/x", { secrets: withPrevious(weak), cookie: cookieOf(await mint(undefined, weak)) });
    expect(await oidcAuth.authenticate(ctx, OPTIONS)).toBeNull();
    expect(ctx.recorded.logs).toContainEqual(expect.objectContaining({ level: "warn", msg: expect.stringMatching(/session_hmac_key_previous.*ignored/) }));
    expect(JSON.stringify(ctx.recorded.logs)).not.toContain(weak);
  });

  it("readSession reads the previous key through ctx.secret (declared, so no access-denied warning)", async () => {
    const ctx = makeCtx("/", { cookie: cookieOf(await mint()) });
    expect(await readSession(ctx, HMAC_KEY)).not.toBeNull();
    expect(ctx.recorded.logs).toEqual([]);
  });
});

describe("typ binding: session vs login state (F19)", () => {
  const loginState = { state: "s".repeat(22), nonce: "n".repeat(22), verifier: "v".repeat(43), returnTo: "/x" };

  async function loginToken(key = HMAC_KEY) {
    const ctx = makeCtx("/");
    await writeLoginState(ctx, loginState, key);
    return ctx.recorded.cookies.find((c) => c.name === LOGIN_COOKIE).value;
  }

  it("the login-state payload is {typ: \"login\", kid, state, nonce, verifier, returnTo}", async () => {
    const p = payloadOf(await loginToken());
    expect(p).toEqual({ typ: "login", kid: await keyId(HMAC_KEY), ...loginState });
    expect(Object.keys(p)).toEqual(["typ", "kid", "state", "nonce", "verifier", "returnTo"]);
  });

  it("a valid session token fails as login state", async () => {
    const session = await mint();
    expect(await decodeSession(session, HMAC_KEY)).not.toBeNull();
    expect(await decodeLoginState(session, HMAC_KEY)).toBeNull();
    // even one that also carries the login fields
    const hybrid = await rawToken({ ...(await v2Fields()), ...loginState });
    expect(await decodeSession(hybrid, HMAC_KEY)).not.toBeNull();
    expect(await decodeLoginState(hybrid, HMAC_KEY)).toBeNull();
  });

  it("a valid login-state token fails as a session", async () => {
    const login = await loginToken();
    expect(await decodeLoginState(login, HMAC_KEY)).toMatchObject(loginState);
    expect(await decodeSession(login, HMAC_KEY)).toBeNull();
    expect(await authenticate(cookieOf(login))).toBeNull();
    // even one that also carries the session fields
    const hybrid = await rawToken({ ...(await v2Fields()), ...loginState, typ: "login" });
    expect(await decodeLoginState(hybrid, HMAC_KEY)).not.toBeNull();
    expect(await decodeSession(hybrid, HMAC_KEY)).toBeNull();
  });

  it("legacy login state without typ is rejected", async () => {
    expect(await decodeLoginState(await rawToken({ kid: await keyId(HMAC_KEY), ...loginState }), HMAC_KEY)).toBeNull();
    expect(await decodeLoginState(await rawToken(loginState), HMAC_KEY)).toBeNull();
  });

  it("login state survives a key rotation (verified with session_hmac_key_previous, kid-bound)", async () => {
    const inFlight = await loginToken(PREVIOUS_KEY);
    const ctx = (secrets) => makeCtx("/.auth/callback", { secrets, cookie: `${LOGIN_COOKIE}=${encodeURIComponent(inFlight)}` });
    expect(await readLoginState(ctx(SECRETS), HMAC_KEY)).toBeNull();
    expect(await readLoginState(ctx(withPrevious(PREVIOUS_KEY)), HMAC_KEY)).toMatchObject(loginState);
    const forgedKid = await rawToken({ typ: "login", kid: await keyId(HMAC_KEY), ...loginState }, PREVIOUS_KEY);
    expect(await decodeLoginState(forgedKid, [HMAC_KEY, PREVIOUS_KEY])).toBeNull();
  });
});

describe("isValidSession (strict shape)", () => {
  const t = now();
  const base = { v: 2, typ: "session", kid: "abcdEFGH", sid: SID, sub: "user-123", iat: t, exp: t + 3600, groups: ["site-readers"] };
  it.each([
    ["v1 (no v/typ/kid/sid)", { sub: "user-123", iat: t, exp: t + 3600, groups: [] }],
    ["v: 1", { ...base, v: 1 }],
    ["v: \"2\"", { ...base, v: "2" }],
    ["wrong typ", { ...base, typ: "login" }],
    ["missing typ", { ...base, typ: undefined }],
    ["missing kid", { ...base, kid: undefined }],
    ["missing sid", { ...base, sid: undefined }],
    ["short sid", { ...base, sid: "abc" }],
    ["non-string sid", { ...base, sid: 1234 }],
    ["empty sub", { ...base, sub: "" }],
    ["missing iat", { ...base, iat: undefined }],
    ["missing exp", { ...base, exp: undefined }],
    ["missing groups", { ...base, groups: undefined }],
    ["string groups", { ...base, groups: "admins" }],
    ["non-finite exp", { ...base, exp: Infinity }],
    ["expired", { ...base, exp: t - 1 }],
    ["a string", "not-an-object"],
    ["an array", []],
    ["null", null],
  ])("rejects %s", async (_label, value) => {
    expect(isValidSession(value)).toBe(false);
    // Sign with the real kid (unless the case is about the kid) so only the shape fault rejects it.
    const signed = value && typeof value === "object" && !Array.isArray(value) && value.kid === base.kid ? { ...value, kid: await keyId(HMAC_KEY) } : value;
    expect(await decodeSession(await sign(JSON.stringify(signed), HMAC_KEY), HMAC_KEY)).toBeNull();
  });

  it("accepts a well-formed unexpired session", () => {
    expect(isValidSession(base)).toBe(true);
  });
});

describe("readSession / sessionToIdentity", () => {
  it("reads through ctx.cookies and maps to an Identity with sessionId", async () => {
    const ctx = makeCtx("/", { cookie: cookieOf(await rawToken(await v2Fields({ sub: "s", groups: ["g"] }))) });
    const s = await readSession(ctx, HMAC_KEY);
    expect(s).toMatchObject({ sub: "s", groups: ["g"], sid: SID });
    expect(sessionToIdentity(s)).toMatchObject({ method: "oidc-session", sessionId: SID });
  });

  it("no cookie → null", async () => {
    expect(await readSession(makeCtx("/"), HMAC_KEY)).toBeNull();
  });
});
