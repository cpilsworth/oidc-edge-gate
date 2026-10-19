// W3.2: server-side revocation end to end (docs/architecture/plugins.md §15.1,
// §15.3, §15.4): src/index.js → kernel pipeline → oidc-auth authenticate() →
// checkRevocation. Provisioned uses the in-memory store stubs (records seeded
// under the kernel's "plugin:oidc-auth:" KV namespace through the store API);
// sandbox makes every store constructor throw and uses a mocked
// src/embedded-config.js with this file's fake values.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

const env = vi.hoisted(() => ({ sandbox: false, kvUnbound: false, kvGetFails: false }));
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
      constructor(name) { if (env.sandbox || env.kvUnbound) throw unprovisioned("KVStore", name); super(name); }
      async get(key) {
        if (env.kvGetFails) throw new Error(`KV lookup failed for ${key}`);
        return super.get(key);
      }
    },
  };
});
vi.mock("../src/embedded-config.js", () => ({ EMBEDDED_CONFIGS: embedded.configs, EMBEDDED_SECRETS: embedded.secrets }));

import { handleRequest } from "../src/index.js";
import { revokeSession, revokeSubject } from "../plugins/oidc-auth/lib/revocation-store.js";
import { buildSession, encodeSession } from "../plugins/oidc-auth/lib/session.js";
import { createMockOp } from "./mock-op.js";
import { routeFetch } from "./mock-user-info.js";
import { reqFor } from "./helpers.js";
import { getKvMap, resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const ISSUER = "https://op.revocation.test";
const SITE = "https://www.example.com";
const ORIGIN = "main--revocation--gate.aem.live";
const CLIENT_ID = "revocation-gate-client";
const CLIENT_SECRET = "revocation-gate-FAKE-client-secret";
const HMAC_KEY = "revocation-gate-FAKE-hmac-key-at-least-32-bytes!!";
const TTL = 3600;
const SUB = "auth0|revocation-user-1";
const SESSION = "__Host-edge_session";
const LOGIN = "__Host-edge_login";
const KV_PREFIX = "plugin:oidc-auth:";
const realFetch = globalThis.fetch;
/** Any log line of the revocation check (the origin host also contains "revocation"). */
const REVOCATION_LOG = /session revoked|revocation check|revocation_unavailable/;

let profile;
let op;
let logLines;
let codeSeq = 0;

const run = (path, opts) => handleRequest({ request: reqFor(path, opts) });
const nowS = () => Math.floor(Date.now() / 1000);
const cookieLine = (res, name) => res.headers.getSetCookie().find((l) => l.startsWith(`${name}=`)) || null;
const cookiePair = (res, name) => { const l = cookieLine(res, name); return l ? l.split(";")[0] : null; };
const maxAge = (line) => { const m = /;\s*Max-Age=(\d+)/i.exec(line || ""); return m ? Number(m[1]) : null; };
const payloadOf = (pair) => JSON.parse(Buffer.from(decodeURIComponent(pair.split("=")[1]).split(".")[0], "base64url").toString("utf8"));

/** The oidc-auth KV view as the kernel namespaces it, over the provisioned stub's map. */
function pluginKv() {
  const map = getKvMap("kv_default");
  return {
    get: async (k) => (map.has(KV_PREFIX + k) ? map.get(KV_PREFIX + k) : null),
    put: async (k, v) => { map.set(KV_PREFIX + k, v); },
    delete: async (k) => { map.delete(KV_PREFIX + k); },
  };
}

function configure(extra = {}) {
  const config = {
    issuer: ISSUER,
    client_id: CLIENT_ID,
    redirect_uri: `${SITE}/.auth/callback`,
    scopes: "openid profile email",
    session_ttl_seconds: String(TTL),
    groups_claim: "groups",
    routes: JSON.stringify({ callback: "/.auth/callback", logout: "/.auth/logout" }),
    origin_hostname: ORIGIN,
    forwarded_host: "www.example.com",
    platform_profile: profile,
    policy: JSON.stringify({
      version: 2,
      default_tier: "protected",
      authentication: { use: "oidc-auth", options: {} },
      rules: [
        { path: "/", tier: "public" },
        { path: "/errors/*", tier: "public" },
        { path: "/maybe/*", tier: "public", auth: "optional" },
        { path: "/api/*", tier: "secured" },
      ],
    }),
    ...extra,
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

/** A session cookie as the callback mints it, with a chosen iat. */
async function mint({ iat = nowS(), sub = SUB } = {}) {
  const session = buildSession({ sub, groups: ["medical"] }, TTL, iat);
  return { session, cookie: `${SESSION}=${encodeURIComponent(await encodeSession(session, HMAC_KEY))}` };
}

/** The whole browser login through the gate and the mock OP. */
async function login({ sub } = {}) {
  const start = await run("/protected/page");
  expect(start.status).toBe(302);
  const authorize = new URL(start.headers.get("location"));
  const code = `rev-code-${++codeSeq}`;
  op.issueCode(code, {
    claims: { nonce: authorize.searchParams.get("nonce"), ...(sub ? { sub } : {}) },
    codeChallenge: authorize.searchParams.get("code_challenge"),
  });
  const callback = await run(`/.auth/callback?code=${code}&state=${encodeURIComponent(authorize.searchParams.get("state"))}`,
    { cookie: cookiePair(start, LOGIN) });
  expect(callback.status).toBe(302);
  const cookie = cookiePair(callback, SESSION);
  return { cookie, session: payloadOf(cookie) };
}

function expectLoginRedirect(res) {
  expect(res.status).toBe(302);
  const to = new URL(res.headers.get("location"));
  expect(`${to.origin}${to.pathname}`).toBe(op.discovery.authorization_endpoint);
}
const expectCleared = (res) => expect(maxAge(cookieLine(res, SESSION))).toBe(0);
const expectNoSessionCookie = (res) => expect(cookieLine(res, SESSION)).toBeNull();

beforeEach(() => {
  env.kvUnbound = false;
  env.kvGetFails = false;
  resetStubs();
  logLines = [];
  const capture = (...args) => { logLines.push(args.map(String).join(" ")); };
  vi.spyOn(console, "log").mockImplementation(capture);
  vi.spyOn(console, "warn").mockImplementation(capture);
  vi.spyOn(console, "error").mockImplementation(capture);
});
afterEach(() => { globalThis.fetch = realFetch; env.sandbox = false; vi.restoreAllMocks(); });

async function setupProfile(p) {
  profile = p;
  env.sandbox = p === "sandbox";
  op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, originHostname: ORIGIN });
  // The origin echoes the identity the gate forwarded.
  const origin = async (r) => new Response(`origin:${r.headers.get("x-auth-subject") ?? "-"}`, {
    status: 200, headers: { "content-type": "text/html" },
  });
  globalThis.fetch = routeFetch({ [ISSUER]: (r) => op.handle(r), [ORIGIN]: origin });
  configure();
}

describe("revocation end to end [provisioned]", () => {
  beforeEach(() => setupProfile("provisioned"));

  it("a fresh login's session passes on protected, secured and auth: optional paths", async () => {
    const { cookie, session } = await login();
    const page = await run("/protected/page", { cookie });
    expect(page.status).toBe(200);
    expect(await page.text()).toBe(`origin:${session.sub}`);
    expectNoSessionCookie(page);
    expect((await run("/api/data", { cookie })).status).toBe(200);
    expect(await (await run("/maybe/x", { cookie })).text()).toBe(`origin:${session.sub}`);
  });

  it("a revoked sid: protected → 302 to the IdP + cookie cleared; secured → 401 + cleared; optional → anonymous + cleared", async () => {
    const { cookie, session } = await login();
    await revokeSession(pluginKv(), session.sid, { sessionTtlSeconds: TTL });
    expect(getKvMap("kv_default").has(`${KV_PREFIX}rev:sid:${session.sid}`)).toBe(true);

    const page = await run("/protected/page", { cookie });
    expectLoginRedirect(page);
    expectCleared(page);

    const api = await run("/api/data", { cookie });
    expect(api.status).toBe(401);
    expect(api.headers.get("www-authenticate")).toBe("Bearer");
    expect(await api.json()).toEqual({ error: "unauthorized" });
    expectCleared(api);

    const maybe = await run("/maybe/x", { cookie });
    expect(maybe.status).toBe(200);
    expect(await maybe.text()).toBe("origin:-");
    expectCleared(maybe);

    // Public (auth: none) paths never read the cookie.
    const home = await run("/", { cookie });
    expect(home.status).toBe(200);
    expectNoSessionCookie(home);

    // Logged at info with the reason only.
    const revokedLines = logLines.filter((l) => l.includes("session revoked"));
    expect(revokedLines).toHaveLength(3); // protected, secured, optional
    for (const l of revokedLines) expect(JSON.parse(l)).toMatchObject({ event: "session revoked", reason: "sid", level: "info" });
    for (const l of logLines) {
      expect(l).not.toContain(session.sid);
      expect(l).not.toContain(SUB);
      expect(l).not.toContain("rev:sid:");
    }
  });

  it("revoking one session leaves the user's other session alone", async () => {
    const a = await login();
    const b = await login();
    await revokeSession(pluginKv(), a.session.sid, { sessionTtlSeconds: TTL });
    expectLoginRedirect(await run("/protected/page", { cookie: a.cookie }));
    expect((await run("/protected/page", { cookie: b.cookie })).status).toBe(200);
  });

  it("a per-user epoch revokes older sessions; a session minted after it passes", async () => {
    const old = await mint({ iat: nowS() - 100 });
    const atEpoch = await mint({ iat: nowS() - 50 });
    const newer = await mint({ iat: nowS() - 49 });
    const other = await mint({ iat: nowS() - 100, sub: "auth0|someone-else" });
    await revokeSubject(pluginKv(), SUB, { sessionTtlSeconds: TTL, nowMs: (nowS() - 50) * 1000 });

    for (const s of [old, atEpoch]) {
      const res = await run("/protected/page", { cookie: s.cookie });
      expectLoginRedirect(res);
      expectCleared(res);
    }
    expect((await run("/protected/page", { cookie: newer.cookie })).status).toBe(200);
    expect((await run("/protected/page", { cookie: other.cookie })).status).toBe(200);
    expect(logLines.some((l) => l.includes('"event":"session revoked","reason":"sub"'))).toBe(true);
    for (const l of logLines) expect(l).not.toContain(SUB);
  });

  it("a fresh login after a per-user revocation passes", async () => {
    await revokeSubject(pluginKv(), SUB, { sessionTtlSeconds: TTL, nowMs: (nowS() - 1) * 1000 });
    const { cookie, session } = await login({ sub: SUB });
    expect(session.sub).toBe(SUB);
    expect((await run("/protected/page", { cookie })).status).toBe(200);
  });

  it("revocation_mode required with the KV constructor throwing → 503 revocation_unavailable, not a redirect loop", async () => {
    configure({ revocation_mode: "required" });
    env.kvUnbound = true;
    const { cookie } = await mint();
    const res = await run("/protected/page", { cookie });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "revocation_unavailable" });
    expect(res.headers.get("location")).toBeNull();
    expectNoSessionCookie(res);
    expect(res.headers.get("x-auth-request-id")).toBeTruthy();
    // Secured: the same 503.
    expect((await run("/api/data", { cookie })).status).toBe(503);
    // auth: optional rules continue anonymously (§4).
    const maybe = await run("/maybe/x", { cookie });
    expect(maybe.status).toBe(200);
    expect(await maybe.text()).toBe("origin:-");
  });

  it("auto on provisioned is required: no KV → 503 for a session; no session still starts a login", async () => {
    env.kvUnbound = true;
    const { cookie } = await mint();
    const res = await run("/protected/page", { cookie });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "revocation_unavailable" });
    expectLoginRedirect(await run("/protected/page"));
  });

  it("required with a failing KV → 503", async () => {
    configure({ revocation_mode: "required" });
    const { cookie } = await mint();
    env.kvGetFails = true;
    const res = await run("/protected/page", { cookie });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "revocation_unavailable" });
  });

  it("optional with a failing KV → page served and a warning logged (error class only)", async () => {
    configure({ revocation_mode: "optional" });
    const { cookie, session } = await mint();
    env.kvGetFails = true;
    const res = await run("/protected/page", { cookie });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(`origin:${SUB}`);
    const warn = logLines.filter((l) => l.includes("revocation check failed"));
    expect(warn).toHaveLength(1);
    expect(JSON.parse(warn[0])).toMatchObject({ level: "warn", error: "Error", plugin: "oidc-auth" });
    for (const l of logLines) {
      expect(l).not.toContain("KV lookup failed");
      expect(l).not.toContain(session.sid);
    }
  });

  it("optional with no KV → page served silently", async () => {
    configure({ revocation_mode: "optional" });
    env.kvUnbound = true;
    const { cookie } = await mint();
    expect((await run("/protected/page", { cookie })).status).toBe(200);
    expect(logLines.some((l) => REVOCATION_LOG.test(l))).toBe(false);
  });

  it("disabled ignores a revoked sid", async () => {
    configure({ revocation_mode: "disabled" });
    const { cookie, session } = await mint();
    await revokeSession(pluginKv(), session.sid, { sessionTtlSeconds: TTL });
    expect((await run("/protected/page", { cookie })).status).toBe(200);
  });
});

for (const p of ["provisioned", "sandbox"]) {
  describe(`session_min_iat [${p}]`, () => {
    beforeEach(() => setupProfile(p));

    it("revokes sessions issued before the cutoff; iat == cutoff and later pass", async () => {
      const cutoff = nowS() - 50;
      configure({ session_min_iat: String(cutoff) });
      const before = await mint({ iat: cutoff - 1 });
      const at = await mint({ iat: cutoff });
      const res = await run("/protected/page", { cookie: before.cookie });
      expectLoginRedirect(res);
      expectCleared(res);
      const api = await run("/api/data", { cookie: before.cookie });
      expect(api.status).toBe(401);
      expectCleared(api);
      expect((await run("/protected/page", { cookie: at.cookie })).status).toBe(200);
      expect(logLines.some((l) => l.includes('"event":"session revoked","reason":"min_iat"'))).toBe(true);
    });

    it("applies even with revocation_mode disabled", async () => {
      configure({ session_min_iat: String(nowS()), revocation_mode: "disabled" });
      const { cookie } = await mint({ iat: nowS() - 10 });
      expectLoginRedirect(await run("/protected/page", { cookie }));
    });
  });
}

describe("revocation end to end [sandbox]", () => {
  beforeEach(() => setupProfile("sandbox"));

  it("auto = optional with no KV: a session is accepted, nothing is read or written", async () => {
    const { cookie, session } = await login();
    const page = await run("/protected/page", { cookie });
    expect(page.status).toBe(200);
    expect(await page.text()).toBe(`origin:${session.sub}`);
    expect((await run("/api/data", { cookie })).status).toBe(200);
    expect([...getKvMap("kv_default").keys()]).toEqual([]);
    expect(logLines.some((l) => REVOCATION_LOG.test(l))).toBe(false);
  });

  it("required on a sandbox without KV fails every authenticated request with 503 (required means required)", async () => {
    configure({ revocation_mode: "required" });
    const { cookie } = await mint();
    const res = await run("/protected/page", { cookie });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "revocation_unavailable" });
  });
});
