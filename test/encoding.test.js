import { describe, it, expect } from "vitest";
import { base64UrlEncode, base64UrlDecode, decodeJsonSegment, timingSafeEqual, utf8, fromUtf8 } from "../src/encoding.js";

describe("encoding", () => {
  it("round-trips base64url without padding", () => {
    const bytes = new Uint8Array([255, 0, 128, 64, 1]);
    const s = base64UrlEncode(bytes);
    expect(s).not.toMatch(/[+/=]/);
    expect([...base64UrlDecode(s)]).toEqual([...bytes]);
  });
  it("decodes a base64url JSON segment", () => {
    const seg = base64UrlEncode(utf8(JSON.stringify({ a: 1 })));
    expect(decodeJsonSegment(seg)).toEqual({ a: 1 });
  });
  it("timingSafeEqual is true only for equal strings", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
  });
  it("utf8 round-trips", () => { expect(fromUtf8(utf8("héllo"))).toBe("héllo"); });
});
