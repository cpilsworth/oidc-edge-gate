import { describe, it, expect } from "vitest";
import { createPkcePair, randomState, randomNonce } from "../src/pkce.js";
import { base64UrlEncode } from "../src/encoding.js";

describe("pkce", () => {
  it("creates an S256 verifier/challenge pair", async () => {
    const { verifier, challenge, method } = await createPkcePair();
    expect(method).toBe("S256");
    expect(verifier).not.toMatch(/[+/=]/);
    const dg = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    expect(challenge).toBe(base64UrlEncode(dg));
  });
  it("state and nonce are unique random strings", () => {
    expect(randomState()).not.toBe(randomState());
    expect(randomNonce()).not.toBe(randomNonce());
  });
});
