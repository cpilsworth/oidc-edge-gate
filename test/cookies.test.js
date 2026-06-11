import { describe, it, expect } from "vitest";
import { parseCookies, serializeCookie, sign, unsign } from "../src/cookies.js";

const KEY = "test-hmac-key-at-least-32-bytes-long!!";

describe("cookies", () => {
  it("parses a cookie header into a map", () => {
    expect(parseCookies("a=1; b=two%20words")).toEqual({ a: "1", b: "two words" });
    expect(parseCookies(null)).toEqual({});
  });

  it("skips malformed percent-encoded values without throwing", () => {
    expect(parseCookies("__edge_session=%; good=1")).toEqual({ good: "1" });
  });
  it("serializes with security attributes by default", () => {
    const c = serializeCookie("__edge_session", "v", { maxAge: 60 });
    expect(c).toContain("__edge_session=v");
    expect(c).toContain("HttpOnly");
    expect(c).toContain("Secure");
    expect(c).toContain("SameSite=Lax");
    expect(c).toContain("Max-Age=60");
  });
  it("sign/unsign round-trips and rejects tampering", async () => {
    const token = await sign(JSON.stringify({ sub: "x" }), KEY);
    expect(await unsign(token, KEY)).toBe('{"sub":"x"}');
    expect(await unsign(token + "x", KEY)).toBeNull();
    expect(await unsign(token, "wrong-key")).toBeNull();
  });

  it("unsign returns null for garbage tokens without throwing", async () => {
    await expect(unsign("not-valid-base64!!!", KEY)).resolves.toBeNull();
    await expect(unsign(".", KEY)).resolves.toBeNull();
    await expect(unsign("payload-only.", KEY)).resolves.toBeNull();
    await expect(unsign("", KEY)).resolves.toBeNull();
  });
});
