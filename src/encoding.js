// Small base64url + text helpers shared by the JWT, PKCE and session modules.
// The Fastly Compute runtime exposes Web Crypto, TextEncoder/Decoder, atob/btoa.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8(str) {
  return encoder.encode(str);
}

export function fromUtf8(bytes) {
  return decoder.decode(bytes);
}

/** Encode bytes (Uint8Array | ArrayBuffer) as base64url, no padding. */
export function base64UrlEncode(bytes) {
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url into a Uint8Array. */
export function base64UrlDecode(str) {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Decode a base64url JSON segment into an object. */
export function decodeJsonSegment(seg) {
  return JSON.parse(fromUtf8(base64UrlDecode(seg)));
}

/** Constant-time comparison of two strings to avoid timing leaks. */
export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
