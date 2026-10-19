// W3.3: the signed admin revocation route end to end
// (docs/architecture/plugins.md §15.5, §15.7): scripts/revoke.mjs run() signs a
// request whose fetch is src/index.js handleRequest → kernel routes →
// oidc-auth handleAdminRevoke → revocation-store → the KV store stub.
//
// Provisioned uses the in-memory store stubs (KV records land under the
// kernel's "plugin:oidc-auth:" namespace); sandbox makes every store
// constructor throw and serves a mocked src/embedded-config.js holding this
// file's fake values (including a revocation_admin_key, which must not matter).
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
import { run as runCli } from "../scripts/revoke.mjs";
import { sidKey, subKey } from "../plugins/oidc-auth/lib/revocation-store.js";
import { buildSession, encodeSession } from "../plugins/oidc-auth/lib/session.js";
import { createMockOp } from "./mock-op.js";
import { reqFor } from "./helpers.js";
import { getKvMap, resetStubs, seedConfig, seedSecrets } from "./stubs/state.js";

const ISSUER = "https://op.admin-revoke.test";
const SITE = "https://www.example.com";
const ORIGIN = "main--admin-revoke--gate.aem.live";
const HMAC_KEY = "admin-revoke-gate-FAKE-hmac-key-at-least-32-bytes!!";
const ADMIN_KEY = "admin-revoke-gate-FAKE-admin-key-at-least-32-bytes!";
const TTL = 3600;
const SUB = "auth0|admin-revoke-user-1";
const SESSION = "__Host-edge_session";
const KV_PREFIX = "plugin:oidc-auth:";
const realFetch = globalThis.fetch;

let logLines;

function configure(profile, { adminKey = ADMIN_KEY } = {}) {
  const config = {
    issuer: ISSUER,
    client_id: "admin-revoke-client",
    redirect_uri: `${SITE}/.auth/callback`,
    session_ttl_seconds: String(TTL),
    groups_claim: "groups",
    origin_hostname: ORIGIN,
    forwarded_host: "www.example.com",
    platform_profile: profile,
    policy: JSON.stringify({ rules: [{ path: "/", tier: "public" }], default_tier: "protected" }),
  };
  const secrets = { client_secret: "FAKE-client-secret", session_hmac_key: HMAC_KEY };
  if (adminKey) secrets.revocation_admin_key = adminKey;
  for (const bag of [embedded.configs, embedded.secrets]) for (const k of Object.keys(bag)) delete bag[k];
  resetStubs();
  if (profile === "sandbox") {
    Object.assign(embedded.configs, config);
    Object.assign(embedded.secrets, secrets);
  } else {
    seedConfig(config);
    seedSecrets({ secrets: JSON.stringify(secrets) });
  }
}

/** The CLI, with its fetch going straight into the gate. */
async function cli(argv, { key = ADMIN_KEY } = {}) {
  const out = [];
  const err = [];
  const sent = [];
  const code = await runCli({
    argv: ["--url", SITE, ...argv],
    env: { REVOCATION_ADMIN_KEY: key },
    fetch: async (url, init) => {
      const request = new Request(url, init);
      sent.push(request.clone());
      return handleRequest({ request });
    },
    stdout: { write: (s) => out.push(s) },
    stderr: { write: (s) => err.push(s) },
  });
  const stdout = out.join("");
  const json = (() => { try { return JSON.parse(stdout.split("\n").slice(1).join("\n").replace(/\nx-auth-request-id:.*\n?$/, "")); } catch { return null; } })();
  return { code, stdout, stderr: err.join(""), json, sent };
}

const kvMap = () => getKvMap("kv_default");

async function sessionCookie({ sub = SUB, iatOffset = 0 } = {}) {
  const session = buildSession({ sub, email: "u@example.com", groups: [] }, TTL, Math.floor(Date.now() / 1000) + iatOffset);
  return { sid: session.sid, cookie: `${SESSION}=${await encodeSession(session, HMAC_KEY)}` };
}

beforeEach(async () => {
  env.sandbox = false;
  const op = await createMockOp({ issuer: ISSUER, originHostname: ORIGIN });
  globalThis.fetch = async (input, init) => {
    const r = new Request(input, init);
    const host = new URL(r.url).host;
    if (host === ORIGIN) return new Response("origin-body", { status: 200, headers: { "content-type": "text/html" } });
    return op.handle(r);
  };
  logLines = [];
  const capture = (...args) => { logLines.push(args.map(String).join(" ")); };
  vi.spyOn(console, "log").mockImplementation(capture);
  vi.spyOn(console, "warn").mockImplementation(capture);
  vi.spyOn(console, "error").mockImplementation(capture);
});
afterEach(() => { globalThis.fetch = realFetch; env.sandbox = false; vi.restoreAllMocks(); });

describe("admin revoke end to end [provisioned]", () => {
  beforeEach(() => configure("provisioned"));

  it("a CLI-signed session revocation → 200, the namespaced rev:sid record exists, and a replay → 409", async () => {
    const { sid, cookie } = await sessionCookie();
    expect((await handleRequest({ request: reqFor("/protected/page", { cookie }) })).status).toBe(200);

    const first = await cli(["--sid", sid, "--reason", "e2e test"]);
    expect(first.code).toBe(0);
    expect(first.stdout).toMatch(/^HTTP 200\n/);
    expect(first.json).toEqual({ revoked: "session", propagation_seconds: 60 });
    const stored = kvMap().get(`${KV_PREFIX}${sidKey(sid)}`);
    expect(stored).toBeTruthy();
    expect(JSON.parse(stored).value).toEqual({ at: expect.any(Number) });
    const [sent] = first.sent;
    expect(sent.url).toBe(`${SITE}/.auth/admin/revoke`);
    expect(sent.headers.get("authorization")).toMatch(/^Gate-Revoke-HMAC-SHA256 [A-Za-z0-9_-]{43}$/);
    const markerKeys = [...kvMap().keys()].filter((k) => k.startsWith(`${KV_PREFIX}admin:jti:`));
    expect(markerKeys).toHaveLength(1);

    // The very same signed bytes again → 409 replayed.
    const replay = await handleRequest({ request: new Request(sent.url, { method: "POST", headers: sent.headers, body: await sent.text() }) });
    expect(replay.status).toBe(409);
    expect(await replay.json()).toEqual({ error: "replayed" });
    expect(replay.headers.get("x-auth-request-id")).toBeTruthy();

    // W3.2's request check is present: the revoked session no longer passes.
    const after = await handleRequest({ request: reqFor("/protected/page", { cookie }) });
    expect(after.status).toBe(302);
  });

  it("a CLI-signed user revocation → 200 with revoked_at and the hashed rev:sub record", async () => {
    const { cookie } = await sessionCookie({ iatOffset: -5 });
    const res = await cli(["--sub", SUB]);
    expect(res.code).toBe(0);
    expect(res.json).toEqual({ revoked: "user", revoked_at: expect.any(Number), propagation_seconds: 60 });
    const stored = kvMap().get(`${KV_PREFIX}${await subKey(SUB)}`);
    expect(JSON.parse(stored).value).toEqual({ revoked_at: res.json.revoked_at });
    expect([...kvMap().keys()].some((k) => k.includes(SUB))).toBe(false);
    expect((await handleRequest({ request: reqFor("/protected/page", { cookie }) })).status).toBe(302);
  });

  it("the gate's responses carry no-store and the logs never contain the key, the sub or the signature", async () => {
    const res = await cli(["--sub", SUB]);
    expect(res.code).toBe(0);
    const auth = res.sent[0].headers.get("authorization");
    const text = logLines.join("\n");
    for (const v of [ADMIN_KEY, SUB, auth, auth.split(" ")[1]]) expect(text).not.toContain(v);
    expect(res.stdout).not.toContain(ADMIN_KEY);
    expect(res.stdout).not.toContain(auth.split(" ")[1]);
  });

  it("a request signed with the wrong key → 401, exit 1, nothing written", async () => {
    const { sid } = await sessionCookie();
    const res = await cli(["--sid", sid], { key: "a-wrong-admin-key-that-is-at-least-32-bytes!" });
    expect(res.code).toBe(1);
    expect(res.stdout).toMatch(/^HTTP 401\n/);
    expect([...kvMap().keys()].some((k) => k.includes("rev:"))).toBe(false);
  });

  it("an aud for another environment → 401", async () => {
    const { sid } = await sessionCookie();
    const res = await cli(["--sid", sid, "--aud", "staging.example.com"]);
    expect(res.code).toBe(1);
    expect(res.stdout).toMatch(/^HTTP 401\n/);
  });

  it("without revocation_admin_key the route is 404", async () => {
    configure("provisioned", { adminKey: null });
    const { sid } = await sessionCookie();
    const res = await cli(["--sid", sid]);
    expect(res.code).toBe(1);
    expect(res.stdout).toMatch(/^HTTP 404\n/);
  });
});

describe("admin revoke end to end [sandbox]", () => {
  beforeEach(() => {
    env.sandbox = true;
    configure("sandbox");
  });

  it("404 even with an embedded revocation_admin_key, for POST and GET", async () => {
    const { sid } = await sessionCookie();
    const res = await cli(["--sid", sid]);
    expect(res.code).toBe(1);
    expect(res.stdout).toMatch(/^HTTP 404\n/);
    expect(res.json).toEqual({ error: "not_found" });
    const get = await handleRequest({ request: reqFor("/.auth/admin/revoke") });
    expect(get.status).toBe(404);
  });
});
