// Cookie parsing + Set-Cookie serialization, plus HMAC-signed cookie values.
// Signed cookies let us trust the gate's own session/state without a backend
// round-trip on every request — important under AEM's 32-fetch-per-exec cap.

import { base64UrlEncode, base64UrlDecode, fromUtf8, timingSafeEqual, utf8 } from "./encoding.js";

/** Parse a Cookie header into a {name: value} map. */
export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) out[name] = decodeURIComponent(value);
  }
  return out;
}

/** Build a Set-Cookie header string. */
export function serializeCookie(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  parts.push(`SameSite=${opts.sameSite || "Lax"}`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  if (opts.secure !== false) parts.push("Secure");
  return parts.join("; ");
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    utf8(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** Sign a payload string, returning `payload.signature` (both base64url). */
export async function sign(payload, secret) {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, utf8(payload));
  return `${base64UrlEncode(utf8(payload))}.${base64UrlEncode(sig)}`;
}

/**
 * Verify a `payload.signature` token and return the decoded payload string,
 * or null if the signature does not match.
 */
export async function unsign(token, secret) {
  const dot = token.lastIndexOf(".");
  if (dot === -1) return null;
  const payloadB64 = token.slice(0, dot);
  const sigB64 = token.slice(dot + 1);
  const payload = fromUtf8(base64UrlDecode(payloadB64));

  const key = await hmacKey(secret);
  const expected = base64UrlEncode(await crypto.subtle.sign("HMAC", key, utf8(payload)));
  return timingSafeEqual(expected, sigB64) ? payload : null;
}
