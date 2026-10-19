// The Auth0 configuration end to end (W2.3, docs/architecture/plugins.md
// §14.4): src/index.js → kernel pipeline → oidc-auth (provider "auth0"), with
// the default-mode mock OP and NO user-info plugin. Groups come from the
// namespaced ID-token claim the tenant's post-login Action sets (CLAUDE.md
// "Groups"). Runs under both platform profiles (provisioned: the in-memory
// store stubs; sandbox: stores throw and a mocked src/embedded-config.js with
// this file's fake values is used).
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

const env = vi.hoisted(() => ({ sandbox: false }));
const embedded = vi.hoisted(() => ({ configs: {}, secrets: {} }));

const unprovisioned = (kind, name) => new Error(`No ${kind} named '${name}' exists`);
vi.mock("fastly:config-store", async () => {
  const real = await vi.importActual("./stubs/config-store.js");
  return {
    ConfigStore: class extends real.ConfigStore {
      constructor(name) { if (env.sandbox) throw unprovisioned("ConfigStore", name); super(name); }
    },
  };
});
vi.mock("fastly:secret-store", async () => {
  const real = await vi.importActual("./stubs/secret-store.js");
  return {
    SecretStore: class extends real.SecretStore {
      constructor(name) { if (env.sandbox) throw unprovisioned("SecretStore", name); super(name); }
    },
  };
});
vi.mock("fastly:kv-store", async () => {
  const real = await vi.importActual("./stubs/kv-store.js");
  return {
    KVStore: class extends real.KVStore {
      constructor(name) { if (env.sandbox) throw unprovisioned("KVStore", name); super(name); }
    },
  };
});
vi.mock("../src/embedded-config.js", () => ({ EMBEDDED_CONFIGS: embedded.configs, EMBEDDED_SECRETS: embedded.secrets }));

import { handleRequest } from "../src/index.js";
import { createMockOp } from "./mock-op.js";
import { routeFetch } from "./mock-user-info.js";
import { reqFor } from "./helpers.js";
import { getKvMap, resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const ISSUER = "https://tenant.auth0.test";
const SITE = "https://www.example.com";
const ORIGIN = "main--auth0--gate.aem.live";
const CLIENT_ID = "auth0-gate-client";
const CLIENT_SECRET = "auth0-gate-FAKE-client-secret";
const HMAC_KEY = "auth0-gate-FAKE-hmac-key-at-least-32-bytes!!";
const GROUPS_CLAIM = "https://oidc.workers.dev/groups";
const SESSION = "__Host-edge_session";
const LOGIN = "__Host-edge_login";
const realFetch = globalThis.fetch;

let profile;
let op;
let tokenRequests;
let discoveryExtra;
let codeSeq = 0;

const run = (path, opts) => handleRequest({ request: reqFor(path, opts) });
const cookieLine = (res, name) => res.headers.getSetCookie().find((l) => l.startsWith(`${name}=`)) || null;
const cookiePair = (res, name) => { const l = cookieLine(res, name); return l ? l.split(";")[0] : null; };
const maxAge = (line) => { const m = /;\s*Max-Age=(\d+)/i.exec(line || ""); return m ? Number(m[1]) : null; };
const payloadOf = (pair) => JSON.parse(Buffer.from(decodeURIComponent(pair.split("=")[1]).split(".")[0], "base64url").toString("utf8"));

function configure() {
  const config = {
    issuer: ISSUER,
    client_id: CLIENT_ID,
    redirect_uri: `${SITE}/.auth/callback`,
    scopes: "openid profile email",
    session_ttl_seconds: "3600",
    groups_claim: GROUPS_CLAIM,
    routes: JSON.stringify({ callback: "/.auth/callback", logout: "/.auth/logout" }),
    origin_hostname: ORIGIN,
    forwarded_host: "www.example.com",
    platform_profile: profile,
    policy: JSON.stringify({
      version: 2,
      default_tier: "protected",
      authentication: { use: "oidc-auth", options: { provider: "auth0" } },
      rules: [
        { path: "/", tier: "public" },
        { path: "/errors/*", tier: "public" },
        { path: "/protected/medical/*", tier: "protected", audience: ["medical"] },
      ],
    }),
  };
  const secrets = { client_secret: CLIENT_SECRET, session_hmac_key: HMAC_KEY };
  if (profile === "sandbox") {
    for (const bag of [embedded.configs, embedded.secrets]) for (const k of Object.keys(bag)) delete bag[k];
    Object.assign(embedded.configs, config);
    Object.assign(embedded.secrets, secrets);
  } else {
    resetStubs();
    seedConfig(config);
    seedSecrets({ secrets: JSON.stringify(secrets) });
  }
}

/** Gate login → (the browser at Auth0, modelled by issueCode) → gate callback. */
async function login({ groups = ["medical"], path = "/protected/medical/" } = {}) {
  const start = await run(path);
  expect(start.status).toBe(302);
  const authorize = new URL(start.headers.get("location"));
  const code = `auth0-code-${++codeSeq}`;
  // The default mock always adds a plain `groups: ["site-readers"]` claim; only the namespaced one counts.
  op.issueCode(code, {
    claims: { nonce: authorize.searchParams.get("nonce"), [GROUPS_CLAIM]: groups },
    codeChallenge: authorize.searchParams.get("code_challenge"),
  });
  const callback = await run(`/.auth/callback?code=${code}&state=${encodeURIComponent(authorize.searchParams.get("state"))}`,
    { cookie: cookiePair(start, LOGIN) });
  return { authorize, callback, session: cookiePair(callback, SESSION) };
}

beforeEach(() => {
  resetStubs();
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => { globalThis.fetch = realFetch; env.sandbox = false; vi.restoreAllMocks(); });

for (const p of ["provisioned", "sandbox"]) {
  describe(`Auth0 end to end [${p}]`, () => {
    beforeEach(async () => {
      profile = p;
      env.sandbox = p === "sandbox";
      op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, originHostname: ORIGIN });
      tokenRequests = [];
      discoveryExtra = {};
      const opRoute = async (r) => {
        const u = new URL(r.url);
        if (u.pathname === "/.well-known/openid-configuration") return Response.json({ ...op.discovery, ...discoveryExtra });
        if (u.pathname === "/token") {
          tokenRequests.push({ authorization: r.headers.get("authorization"), form: new URLSearchParams(await r.clone().text()) });
        }
        return op.handle(r);
      };
      globalThis.fetch = routeFetch({ [ISSUER]: opRoute, [ORIGIN]: (r) => op.handle(r) });
      configure();
    });

    it(`runs on the ${p} profile (KV: state marker + caches on provisioned, nothing on sandbox)`, async () => {
      const { callback } = await login();
      expect(callback.status).toBe(302);
      const keys = [...getKvMap("kv_default").keys()];
      if (p === "provisioned") expect(keys.some((k) => k.startsWith("plugin:oidc-auth:oidc:state-used:"))).toBe(true);
      else expect(keys).toEqual([]);
    });

    it("the authorize redirect has S256 PKCE and none of the Janrain extras", async () => {
      const { authorize } = await login();
      expect(`${authorize.origin}${authorize.pathname}`).toBe(`${ISSUER}/authorize`);
      expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
      expect(authorize.searchParams.has("response_mode")).toBe(false);
      expect(authorize.searchParams.has("claims")).toBe(false);
    });

    it("groups come from the namespaced claim only", async () => {
      const { callback, session } = await login({ groups: ["medical", "market-access"] });
      expect(callback.status).toBe(302);
      expect(payloadOf(session).groups).toEqual(["medical", "market-access"]); // not the plain "groups" claim
    });

    it.each([
      ["discovery omits token_endpoint_auth_methods_supported", {}],
      ["discovery lists basic first", { token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"] }],
    ])("client_secret_post is used (%s)", async (_label, extra) => {
      discoveryExtra = extra;
      const { callback } = await login();
      expect(callback.status).toBe(302);
      expect(tokenRequests).toHaveLength(1);
      const [{ authorization, form }] = tokenRequests;
      expect(authorization).toBeNull();
      expect([...form.keys()]).toEqual(["grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"]);
      expect(form.get("client_secret")).toBe(CLIENT_SECRET);
    });

    it("audience: 200 with the medical group, 403 without", async () => {
      const medical = await login();
      expect((await run("/protected/medical/", { cookie: medical.session })).status).toBe(200);
      const other = await login({ groups: ["market-access"] });
      expect((await run("/protected/medical/", { cookie: other.session })).status).toBe(403);
      expect((await run("/protected/other", { cookie: other.session })).status).toBe(200);
    });

    it("the session cookie is v2", async () => {
      const { session } = await login();
      const payload = payloadOf(session);
      expect(payload).toMatchObject({ v: 2, typ: "session", sub: "user-123", email: "u@example.com", groups: ["medical"] });
      expect(payload.kid).toMatch(/^[A-Za-z0-9_-]{8}$/);
      expect(payload.sid).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(payload.exp - payload.iat).toBe(3600);
    });

    it("POST logout: 303 to end_session_endpoint with client_id + post_logout_redirect_uri and NO state; GET → 405", async () => {
      const { session } = await login();
      const res = await run("/.auth/logout", { method: "POST", cookie: session, headers: { origin: SITE } });
      expect(res.status).toBe(303);
      const to = new URL(res.headers.get("location"));
      expect(`${to.origin}${to.pathname}`).toBe(`${ISSUER}/logout`);
      expect(Object.fromEntries(to.searchParams)).toEqual({ client_id: CLIENT_ID, post_logout_redirect_uri: `${SITE}/` });
      for (const name of [SESSION, LOGIN]) expect(maxAge(cookieLine(res, name))).toBe(0);
      expect((await run("/.auth/logout", { cookie: session })).status).toBe(405);
    });
  });
}
