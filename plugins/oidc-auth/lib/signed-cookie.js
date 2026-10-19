// HMAC-signed JSON cookie values (`base64url(json).base64url(hmac)`, the format
// of src/sdk/cookies.js sign/unsign). Used for both the session and the
// transient login-state cookie; one read path keeps their checks from drifting.

import { sign, unsign } from "../../../src/sdk/cookies.js";

/**
 * Sign a JSON value into a cookie token.
 * @param {unknown} value
 * @param {string} key  HMAC key
 * @returns {Promise<string>}
 */
export function encodeSigned(value, key) {
  return sign(JSON.stringify(value), key);
}

/**
 * Verify and parse a token. Null when absent, tampered, not JSON, or rejected
 * by `validate`. Never throws.
 * @param {string|undefined|null} token
 * @param {string} key
 * @param {(value: any) => boolean} validate
 */
export async function decodeSigned(token, key, validate) {
  try {
    if (!token) return null;
    const payload = await unsign(token, key);
    if (!payload) return null;
    const value = JSON.parse(payload);
    return validate(value) ? value : null;
  } catch {
    return null;
  }
}

/** True for a non-null, non-array object. */
export function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
