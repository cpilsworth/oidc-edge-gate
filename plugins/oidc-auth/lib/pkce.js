// PKCE (RFC 7636, S256) and random state/nonce generation with Web Crypto.

import { base64UrlEncode, utf8 } from "../../../src/sdk/encoding.js";

function randomString(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

/** 128-bit random `state` (base64url). */
export function randomState() {
  return randomString(16);
}

/** 128-bit random `nonce` (base64url). */
export function randomNonce() {
  return randomString(16);
}

/**
 * A PKCE verifier (256 random bits, 43 base64url chars) and its S256 challenge.
 * @returns {Promise<{verifier: string, challenge: string, method: "S256"}>}
 */
export async function createPkcePair() {
  const verifier = randomString(32);
  const digest = await crypto.subtle.digest("SHA-256", utf8(verifier));
  return { verifier, challenge: base64UrlEncode(digest), method: "S256" };
}
