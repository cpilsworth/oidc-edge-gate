// lib/admin-signature.js: the shared signing helper of the admin revocation
// API (docs/architecture/plugins.md §15.5).
import { describe, it, expect } from "vitest";
import { base64UrlEncode, utf8 } from "../../../src/sdk/encoding.js";
import {
  ADMIN_SIGNATURE_SCHEME, JTI_RE, buildAdminRequestBody, newJti, parseAdminAuthorization, signAdminBody, signAdminRequest,
  verifyAdminSignature,
} from "../lib/admin-signature.js";

const KEY = "admin-signature-test-key-at-least-32-bytes!";
const OTHER_KEY = "another-admin-signature-key-32-bytes-long!!";
const BODY = '{"v":1,"aud":"www.example.com","iat":1700000000,"jti":"abcdefghijklmnopqrstuv","scope":"session","sid":"AAAAAAAAAAAAAAAAAAAAAA"}';

async function referenceTag(key, body) {
  const k = await crypto.subtle.importKey("raw", utf8(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, utf8(body)));
}

describe("signAdminBody", () => {
  it("is `Gate-Revoke-HMAC-SHA256 <base64url(HMAC-SHA256(key, body))>`, unpadded", async () => {
    const header = await signAdminBody(KEY, BODY);
    expect(ADMIN_SIGNATURE_SCHEME).toBe("Gate-Revoke-HMAC-SHA256");
    expect(header).toBe(`Gate-Revoke-HMAC-SHA256 ${base64UrlEncode(await referenceTag(KEY, BODY))}`);
    expect(header).toMatch(/^Gate-Revoke-HMAC-SHA256 [A-Za-z0-9_-]{43}$/);
  });

  it("string, Uint8Array and ArrayBuffer bodies sign the same bytes", async () => {
    const bytes = utf8(BODY);
    const a = await signAdminBody(KEY, BODY);
    expect(await signAdminBody(KEY, bytes)).toBe(a);
    expect(await signAdminBody(KEY, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength))).toBe(a);
  });

  it("rejects an empty key or a non-bytes body", async () => {
    await expect(signAdminBody("", BODY)).rejects.toThrow(TypeError);
    await expect(signAdminBody(KEY, { a: 1 })).rejects.toThrow(TypeError);
  });
});

describe("verifyAdminSignature", () => {
  it("accepts the signature over the exact bytes", async () => {
    expect(await verifyAdminSignature(KEY, utf8(BODY), await signAdminBody(KEY, BODY))).toBe(true);
    expect(await verifyAdminSignature(KEY, BODY, await signAdminBody(KEY, BODY))).toBe(true);
  });

  it("rejects a whitespace change, a tampered byte, another key", async () => {
    const header = await signAdminBody(KEY, BODY);
    expect(await verifyAdminSignature(KEY, BODY.replace(",", ", "), header)).toBe(false);
    expect(await verifyAdminSignature(KEY, `${BODY}\n`, header)).toBe(false);
    expect(await verifyAdminSignature(KEY, BODY.replace("session", "sessioN"), header)).toBe(false);
    expect(await verifyAdminSignature(OTHER_KEY, BODY, header)).toBe(false);
  });

  it("strict header parsing", async () => {
    const header = await signAdminBody(KEY, BODY);
    const tag = header.split(" ")[1];
    const bad = [
      `gate-revoke-hmac-sha256 ${tag}`, // wrong casing
      `GATE-REVOKE-HMAC-SHA256 ${tag}`,
      `Gate-Revoke-HMAC-SHA512 ${tag}`, // wrong scheme
      `Bearer ${tag}`,
      `Gate-Revoke-HMAC-SHA256  ${tag}`, // two spaces
      `Gate-Revoke-HMAC-SHA256\t${tag}`,
      ` ${header}`,
      `${header} `,
      `${header}=`, // padded base64
      `Gate-Revoke-HMAC-SHA256 ${tag}==`,
      `Gate-Revoke-HMAC-SHA256 ${tag.slice(0, 42)}`, // wrong length
      `Gate-Revoke-HMAC-SHA256 ${tag}A`,
      `Gate-Revoke-HMAC-SHA256 ${tag.replace(/-/g, "+").replace(/_/g, "/")}${/[-_]/.test(tag) ? "" : "+"}`, // base64, not base64url
      `Gate-Revoke-HMAC-SHA256 ${tag}, Gate-Revoke-HMAC-SHA256 ${tag}`,
      `Gate-Revoke-HMAC-SHA256 tag=${tag}`,
      tag,
      "",
      null,
      undefined,
    ];
    for (const h of bad) expect(await verifyAdminSignature(KEY, BODY, h), String(h)).toBe(false);
  });

  it("rejects a non-canonical last character (same bytes, other text)", async () => {
    const header = await signAdminBody(KEY, BODY);
    const tag = header.split(" ")[1];
    // 43 chars encode 258 bits: the last char carries 2 unused low bits.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alphabet.indexOf(tag[42]);
    const variant = `${tag.slice(0, 42)}${alphabet[last | 1]}`;
    expect(variant).not.toBe(tag);
    expect(parseAdminAuthorization(`${ADMIN_SIGNATURE_SCHEME} ${variant}`)).toBeNull();
    expect(await verifyAdminSignature(KEY, BODY, `${ADMIN_SIGNATURE_SCHEME} ${variant}`)).toBe(false);
  });

  it("never throws: an empty key is simply false", async () => {
    expect(await verifyAdminSignature("", BODY, await signAdminBody(KEY, BODY))).toBe(false);
    expect(await verifyAdminSignature(undefined, BODY, await signAdminBody(KEY, BODY))).toBe(false);
  });

  it("uses crypto.subtle.verify (constant time)", async () => {
    const header = await signAdminBody(KEY, BODY);
    const original = crypto.subtle.verify;
    let calls = 0;
    crypto.subtle.verify = function (...args) { calls += 1; return original.apply(this, args); };
    try {
      expect(await verifyAdminSignature(KEY, BODY, header)).toBe(true);
    } finally {
      crypto.subtle.verify = original;
    }
    expect(calls).toBe(1);
  });
});

describe("request body helpers", () => {
  it("newJti: 43 base64url chars, random", () => {
    const a = newJti();
    expect(a).toMatch(JTI_RE);
    expect(a).toHaveLength(43);
    expect(newJti()).not.toBe(a);
  });

  it("buildAdminRequestBody: session and user shapes, in key order", () => {
    const s = buildAdminRequestBody({ aud: "h", scope: "session", sid: "AAAAAAAAAAAAAAAAAAAAAA", nowMs: 1_700_000_000_500, jti: "j".repeat(22) });
    expect(Object.keys(s)).toEqual(["v", "aud", "iat", "jti", "scope", "sid"]);
    expect(s).toEqual({ v: 1, aud: "h", iat: 1_700_000_000, jti: "j".repeat(22), scope: "session", sid: "AAAAAAAAAAAAAAAAAAAAAA" });
    const u = buildAdminRequestBody({ aud: "h", scope: "user", sub: "auth0|x", reason: "left company" });
    expect(Object.keys(u)).toEqual(["v", "aud", "iat", "jti", "scope", "sub", "reason"]);
    expect(u.jti).toMatch(JTI_RE);
  });

  it.each([
    [{ aud: "", scope: "session", sid: "s" }],
    [{ aud: "h", scope: "all", sid: "s" }],
    [{ aud: "h", scope: "session" }],
    [{ aud: "h", scope: "session", sid: "s", sub: "u" }],
    [{ aud: "h", scope: "user", sid: "s", sub: "u" }],
    [{ aud: "h", scope: "user", sub: "u", reason: "naïve" }],
    [{ aud: "h", scope: "user", sub: "u", reason: "x".repeat(201) }],
    [{ aud: "h", scope: "user", sub: "u", jti: "short" }],
    [{ aud: "h", scope: "user", sub: "u", iat: 1.5 }],
  ])("buildAdminRequestBody rejects %j", (fields) => {
    expect(() => buildAdminRequestBody(fields)).toThrow(TypeError);
  });

  it("signAdminRequest: the header verifies over the returned body string", async () => {
    const { body, authorization, payload } = await signAdminRequest(KEY, { aud: "h", scope: "user", sub: "u" });
    expect(JSON.parse(body)).toEqual(payload);
    expect(await verifyAdminSignature(KEY, utf8(body), authorization)).toBe(true);
  });
});
