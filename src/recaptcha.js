// Google reCAPTCHA verification for policy rules flagged `recaptcha: true`
// (see policy.js / index.js). A matched rule requires the submitted form to
// carry a `g-recaptcha-response` token, which is verified against Google's
// siteverify endpoint before the request is forwarded to origin/upstream.

const SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
const FIELD_NAME = "g-recaptcha-response";

/**
 * Pull the g-recaptcha-response value out of a buffered request body.
 * Handles the two encodings an HTML <form> can submit: the default
 * application/x-www-form-urlencoded, and multipart/form-data (used when the
 * form also has a file input). Returns null if the field is absent.
 * @param {string} bodyText
 * @param {?string} contentType
 */
export function extractRecaptchaToken(bodyText, contentType) {
  if (!bodyText) return null;
  const ct = (contentType || "").toLowerCase();
  if (ct.includes("multipart/form-data")) {
    return extractMultipartField(bodyText, contentType, FIELD_NAME);
  }
  // application/x-www-form-urlencoded, and the default a browser falls back
  // to when a form has no explicit enctype.
  return new URLSearchParams(bodyText).get(FIELD_NAME);
}

/** Minimal multipart/form-data field extractor — just enough to pull one named text field. */
function extractMultipartField(bodyText, contentType, fieldName) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || "");
  const boundary = m ? (m[1] || m[2]).trim() : null;
  if (!boundary) return null;
  for (const part of bodyText.split(`--${boundary}`)) {
    if (!part.includes(`name="${fieldName}"`)) continue;
    const headerEnd = part.indexOf("\r\n\r\n");
    if (headerEnd === -1) continue;
    return part.slice(headerEnd + 4).replace(/\r\n--\s*$/, "").trim();
  }
  return null;
}

/**
 * Verify a reCAPTCHA token against Google's siteverify endpoint.
 * @param {?string} token   the g-recaptcha-response field value (may be null/missing)
 * @param {string} secret   the site's reCAPTCHA secret key
 * @returns {Promise<{success:boolean, score?:number, "error-codes"?:string[]}>}
 */
export async function verifyRecaptcha(token, secret) {
  if (!token) return { success: false, "error-codes": ["missing-input-response"] };
  const body = new URLSearchParams({ secret, response: token });
  let res;
  try {
    // No `backend` option — dynamic backend from the absolute URL (see src/oidc.js).
    res = await fetch(SITEVERIFY_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
  } catch {
    return { success: false, "error-codes": ["siteverify-unreachable"] };
  }
  if (!res.ok) return { success: false, "error-codes": [`siteverify-http-${res.status}`] };
  try {
    return await res.json();
  } catch {
    return { success: false, "error-codes": ["siteverify-bad-response"] };
  }
}

/**
 * True if `result` (Google's siteverify response) counts as a pass: `success`
 * must be true, and if a v3 `score` is present alongside a configured
 * `minScore`, the score must clear it. v2 (checkbox/invisible) responses carry
 * no `score`, so `minScore` is a no-op for them.
 * @param {{success:boolean, score?:number}} result
 * @param {?number} minScore
 */
export function passesRecaptcha(result, minScore) {
  if (!result || !result.success) return false;
  if (minScore != null && typeof result.score === "number") return result.score >= minScore;
  return true;
}

/**
 * Build the trusted `x-recaptcha-*` headers to forward to origin/upstream
 * once a submission has passed verification — the same idea as `x-auth-*` for
 * session identity: computed by the gate from a value the client can't
 * control, and stripped from any client-supplied copy before this is applied
 * (see origin.js). Useful even after a pass/fail decision, e.g. so the form
 * backend can log/flag borderline v3 scores. Only includes fields Google's
 * siteverify response actually carries (v2 has no `score`), so the caller
 * doesn't need to special-case which reCAPTCHA version was used.
 * @param {{score?:number, hostname?:string, challenge_ts?:string}} result
 * @returns {Object<string,string>}
 */
export function recaptchaResultHeaders(result) {
  const headers = {};
  if (!result) return headers;
  if (typeof result.score === "number") headers["x-recaptcha-score"] = String(result.score);
  if (typeof result.hostname === "string") headers["x-recaptcha-hostname"] = result.hostname;
  if (typeof result.challenge_ts === "string") headers["x-recaptcha-challenge-ts"] = result.challenge_ts;
  return headers;
}
