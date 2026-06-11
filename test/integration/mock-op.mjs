// Minimal OpenID Provider for the Viceroy integration smoke. Dependency-free
// (node:http + Web Crypto). Implements discovery, JWKS, authorize and token so
// the gate can run a real authorization-code-with-PKCE round trip against it.

import { createServer } from "node:http";
import { ISSUER, CLIENT_ID, OP_PORT, SUB, EMAIL, NAME, GROUPS } from "./constants.mjs";

const enc = new TextEncoder();

function b64url(bytes) {
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return Buffer.from(bin, "binary").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj) {
  return b64url(enc.encode(JSON.stringify(obj)));
}

async function signJwt(claims, privateKey, kid) {
  const header = b64urlJson({ alg: "RS256", typ: "JWT", kid });
  const payload = b64urlJson(claims);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, enc.encode(`${header}.${payload}`));
  return `${header}.${payload}.${b64url(sig)}`;
}

export async function startMockOp() {
  const kid = "integration-key-1";
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";

  // code -> { nonce } captured at /authorize, consumed at /token.
  const codes = new Map();

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, ISSUER);
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    };

    if (url.pathname === "/.well-known/openid-configuration") {
      return send(200, {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
        end_session_endpoint: `${ISSUER}/logout`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
      });
    }

    if (url.pathname === "/jwks") {
      return send(200, { keys: [jwk] });
    }

    if (url.pathname === "/authorize") {
      const state = url.searchParams.get("state") || "";
      const nonce = url.searchParams.get("nonce") || "";
      const redirectUri = url.searchParams.get("redirect_uri");
      const code = `code-${Math.random().toString(36).slice(2)}`;
      codes.set(code, { nonce });
      const back = new URL(redirectUri);
      back.searchParams.set("code", code);
      back.searchParams.set("state", state);
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }

    if (url.pathname === "/token" && req.method === "POST") {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      const code = form.get("code");
      const saved = codes.get(code);
      if (!saved) return send(400, { error: "invalid_grant" });
      codes.delete(code); // single-use code
      const now = Math.floor(Date.now() / 1000);
      const accessToken = `at-${Math.random().toString(36).slice(2)}`;
      const idToken = await signJwt({
        iss: ISSUER, aud: CLIENT_ID, sub: SUB, email: EMAIL, name: NAME, groups: GROUPS,
        iat: now, exp: now + 600, nonce: saved.nonce,
      }, pair.privateKey, kid);
      return send(200, { token_type: "Bearer", access_token: accessToken, id_token: idToken, expires_in: 600 });
    }

    if (url.pathname === "/logout") {
      const back = url.searchParams.get("post_logout_redirect_uri") || "/";
      res.writeHead(302, { location: back });
      return res.end();
    }

    send(404, { error: "not_found", path: url.pathname });
  });

  await new Promise((resolve) => server.listen(OP_PORT, "127.0.0.1", resolve));
  return server;
}
