// Authorization-code exchange at the token endpoint (purpose "token", default
// cache mode pass: the response is per-user and must never be cached).
//
// Client authentication follows the provider profile's tokenEndpointAuthMethod:
//   client_secret_post   client_id + client_secret in the form body
//   client_secret_basic  Authorization: Basic base64(form-urlencode(id) ":" form-urlencode(secret))
//                        (RFC 6749 §2.3.1); client_id stays in the body, no secret in it.

/**
 * Build the token request for one exchange. Pure; exported for tests.
 * @param {{method: "client_secret_post"|"client_secret_basic", clientId: string, clientSecret: string,
 *          code: string, redirectUri: string, verifier: string}} p
 * @returns {{headers: Object<string, string>, body: string}}
 */
export function buildTokenRequest({ method, clientId, clientSecret, code, redirectUri, verifier }) {
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  // Parameter order matches the pre-plugin gate for client_secret_post.
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", redirectUri);
  body.set("client_id", clientId);
  if (method === "client_secret_post") {
    body.set("client_secret", clientSecret);
  } else if (method === "client_secret_basic") {
    headers.authorization = `Basic ${btoa(`${formEncode(clientId)}:${formEncode(clientSecret)}`)}`;
  } else {
    throw new TypeError(`unsupported token endpoint auth method ${JSON.stringify(method)}`);
  }
  body.set("code_verifier", verifier);
  return { headers, body: body.toString() };
}

/** application/x-www-form-urlencoded encoding of one value (ASCII-only output). */
function formEncode(value) {
  return new URLSearchParams([["v", value]]).toString().slice(2);
}

/**
 * POST the code exchange through ctx.fetch.
 * @param {import("../../../src/sdk/index.js").Context} ctx
 * @param {string} tokenEndpoint
 * @param {Parameters<typeof buildTokenRequest>[0]} p
 * @returns {Promise<Response>}
 */
export function exchangeCode(ctx, tokenEndpoint, p) {
  const { headers, body } = buildTokenRequest(p);
  return ctx.fetch(tokenEndpoint, { method: "POST", headers, body }, { purpose: "token" });
}
