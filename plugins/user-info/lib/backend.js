// Calls to the user-info backend: URL template expansion, HTTP Basic service
// credentials and a bounded JSON read. Every failure of the lookup itself is a
// LookupFailure carrying a FIXED reason code; callers log that code only,
// never the URL (it carries the sub/email), the response body or the
// credentials.

import { PluginError } from "../../../src/sdk/index.js";
import { isCanonicalPath, templateOrigin } from "./options.js";

/** Upper bound on a backend response body (bytes). */
export const MAX_RESPONSE_BYTES = 262144;

/**
 * A failed lookup (network, status, body, shape). `reason` is a fixed,
 * log-safe code; `status` is the HTTP status when there was one.
 */
export class LookupFailure extends Error {
  /**
   * @param {"missing_variable"|"bad_url"|"network_error"|"http_status"|"too_large"|"bad_json"|"groups_missing"|"groups_not_array"|"not_an_object"} reason
   * @param {number} [status]
   */
  constructor(reason, status) {
    super(`user-info lookup failed: ${reason}`);
    this.name = "LookupFailure";
    this.reason = reason;
    if (status !== undefined) this.status = status;
  }
}

/** Log fields for a LookupFailure (fixed codes and the numeric status only). */
export function failureFields(err, purpose) {
  return { reason: err.reason, ...(err.status !== undefined ? { status: err.status } : {}), purpose };
}

/**
 * Expand `{sub}` / `{email}` with encodeURIComponent of the given verified
 * values, then check the result is still on the template's origin.
 * A variable without a value is a LookupFailure("missing_variable").
 * @param {string} template
 * @param {{sub?: string, email?: string}} who  the verified draft or identity
 * @returns {string} absolute URL
 */
export function expandTemplate(template, who) {
  const origin = templateOrigin(template);
  if (!origin) throw new LookupFailure("bad_url");
  let built;
  try {
    built = template.replace(/\{(sub|email)\}/g, (_, v) => {
      const value = who ? who[v] : undefined;
      if (typeof value !== "string" || value.length === 0) throw new LookupFailure("missing_variable");
      return encodeURIComponent(value); // throws URIError on a lone surrogate
    });
  } catch (err) {
    if (err instanceof LookupFailure) throw err;
    throw new LookupFailure("bad_url");
  }
  let url;
  try { url = new URL(built); } catch { throw new LookupFailure("bad_url"); }
  // Still on the configured origin, and no "."/".." value collapsed a path segment.
  if (url.origin !== origin || !isCanonicalPath(built, url)) throw new LookupFailure("bad_url");
  return url.href;
}

/**
 * `Basic base64(username:password)`, UTF-8 safe (btoa only takes Latin-1, so
 * the UTF-8 bytes are passed through as a binary string).
 * @param {string} username
 * @param {string} password
 */
export function basicAuthorization(username, password) {
  const bytes = new TextEncoder().encode(`${username}:${password}`);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return `Basic ${btoa(bin)}`;
}

/**
 * The service credentials. Missing ones are a misconfiguration: logged
 * (without values) and a generic 500, whatever on_login_error says.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @returns {string} the Authorization header value
 */
export function requireAuthorization(ctx) {
  const username = ctx.secret("user_info_username");
  const password = ctx.secret("user_info_password");
  const missing = [];
  if (typeof username !== "string" || username.length === 0) missing.push("user_info_username");
  if (typeof password !== "string" || password.length === 0) missing.push("user_info_password");
  if (missing.length) {
    ctx.log.error("misconfiguration: user-info service credentials are not configured", { reason: "missing_credentials", missing });
    throw new PluginError(500, "internal_error", "user-info service credentials are not configured");
  }
  return basicAuthorization(username, password);
}

/**
 * GET a JSON document from the backend through ctx.fetch (budgeted,
 * egress-checked, cache "pass"). Kernel fetch-policy errors (budget/egress,
 * PluginErrors) propagate unchanged; everything else is a LookupFailure.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} url
 * @param {string} authorization
 * @param {string} purpose  fetch-log purpose
 * @returns {Promise<unknown>} the parsed JSON
 */
export async function getJson(ctx, url, authorization, purpose) {
  let res;
  try {
    res = await ctx.fetch(url, {
      method: "GET",
      headers: { authorization, accept: "application/json" },
    }, { purpose });
  } catch (err) {
    if (err instanceof PluginError) throw err; // budget_exceeded / egress_denied: never degraded
    throw new LookupFailure("network_error");
  }
  if (!res || typeof res.status !== "number") throw new LookupFailure("network_error");
  if (res.status < 200 || res.status > 299) {
    cancelBody(res);
    throw new LookupFailure("http_status", res.status);
  }
  let text;
  try {
    text = await readTextCapped(res, MAX_RESPONSE_BYTES);
  } catch (err) {
    if (err instanceof LookupFailure) throw err;
    throw new LookupFailure("network_error");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new LookupFailure("bad_json");
  }
}

function cancelBody(res) {
  try { if (res.body && typeof res.body.cancel === "function") res.body.cancel().catch(() => {}); } catch { /* ignore */ }
}

/** Read a response body as UTF-8 text, never buffering more than `max` bytes. */
async function readTextCapped(res, max) {
  const declared = res.headers && res.headers.get("content-length");
  if (declared && /^\d+$/.test(declared) && Number(declared) > max) {
    cancelBody(res);
    throw new LookupFailure("too_large");
  }
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
    total += chunk.byteLength;
    if (total > max) {
      try { await reader.cancel(); } catch { /* ignore */ }
      throw new LookupFailure("too_large");
    }
    chunks.push(chunk);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return new TextDecoder().decode(out);
}

/**
 * Read a dot path from parsed JSON, own properties of plain objects only.
 * @param {unknown} body
 * @param {string} path
 * @returns {unknown} undefined when any segment is missing
 */
export function readPath(body, path) {
  let cur = body;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object" || Array.isArray(cur) || !Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
    cur = cur[seg];
  }
  return cur;
}
