// The IdP revocation webhook skeleton (docs/architecture/plugins.md §15.6):
// availability, method, adapter resolution, the janrain stub (501) and the
// apply path through a fake adapter.
import { describe, it, expect } from "vitest";
import { createTestContext } from "../../../src/sdk/testing.js";
import { sidKey, subKey } from "../lib/revocation-store.js";
import { settingsFor } from "../lib/settings.js";
import {
  ADAPTERS, MAX_WEBHOOK_EVENTS, WEBHOOK_ADAPTERS, WebhookNotImplementedError, handleWebhook, janrainAdapter,
  normalizeWebhookEvents,
} from "../lib/webhook.js";
import { CONFIG, ISSUER, SECRETS, SITE, oidcAuth, routeFor } from "./support.js";

const PATH = "/.auth/webhook/janrain";
const OPTIONS = oidcAuth.validate({ issuer: ISSUER, webhook_path: PATH, webhook_adapter: "janrain" });
const ADMIN_KEY = "webhook-test-admin-key-at-least-32-bytes!!";
const SID = "V2ViaG9va1NpZDEyMzQ1Ng";
const SID2 = "V2ViaG9va1NpZDEyMzQ1Nw";
const SUB = "janrain-uuid-secret-0001";
const PROVISIONED = { profile: "provisioned" };

function hookCtx({ method = "POST", body = "{}", platform = PROVISIONED, kv = true, secrets, config = CONFIG, options = OPTIONS } = {}) {
  return createTestContext({
    plugin: oidcAuth,
    request: new Request(`${SITE}${PATH}`, { method, headers: { "content-type": "application/json" }, ...(method === "GET" || method === "HEAD" ? {} : { body }) }),
    options,
    config,
    secrets: secrets ?? { ...SECRETS, revocation_admin_key: ADMIN_KEY },
    kv,
    platform,
  });
}

/** A fake adapter registry under the configured name ("janrain"). */
const fake = (verify) => ({ janrain: { name: "fake", verify } });

async function run(ctxOpts, adapters, deps = {}) {
  const ctx = hookCtx(ctxOpts);
  const res = await handleWebhook(ctx, settingsFor(ctx, ctxOpts?.options ?? OPTIONS), { adapters, ...deps });
  let json = null;
  try { json = await res.clone().json(); } catch { /* none */ }
  return { ctx, res, json };
}

function expectError(r, status, error) {
  expect(r.res.status).toBe(status);
  expect(r.json).toEqual({ error });
  expect(r.res.headers.get("x-auth-request-id")).toBe("test-request-id");
  expect(r.res.headers.get("cache-control")).toBe("private, no-store");
}

describe("wiring", () => {
  it("the janrain adapter is the only built-in one", () => {
    expect(WEBHOOK_ADAPTERS).toEqual(["janrain"]);
    expect(Object.keys(ADAPTERS)).toEqual(["janrain"]);
    expect(ADAPTERS.janrain).toBe(janrainAdapter);
  });

  it("the route is claimed only with webhook_path, and served by handleWebhook (janrain stub → 501)", async () => {
    expect(oidcAuth.routes(oidcAuth.validate({ issuer: ISSUER }))[PATH]).toBeUndefined();
    const ctx = hookCtx();
    const res = await routeFor(PATH, OPTIONS)(ctx, OPTIONS);
    expect(res.status).toBe(501);
    expect(await res.json()).toEqual({ error: "not_implemented" });
  });
});

describe("availability → 404 (the admin route's rule)", () => {
  it.each([
    ["sandbox", { platform: { profile: "sandbox" } }],
    ["revocation_mode disabled", { config: { ...CONFIG, revocationMode: "disabled" } }],
    ["no revocation_admin_key", { secrets: SECRETS }],
  ])("%s → 404 for every method; the adapter is never called", async (_label, opts) => {
    let called = 0;
    for (const method of ["POST", "GET", "PUT"]) {
      const r = await run({ method, ...opts }, fake(async () => { called += 1; return []; }));
      expectError(r, 404, "not_found");
    }
    expect(called).toBe(0);
  });
});

describe("method → 405", () => {
  it.each(["GET", "PUT", "DELETE"])("%s → 405 with Allow: POST; the adapter is never called", async (method) => {
    let called = 0;
    const r = await run({ method }, fake(async () => { called += 1; return []; }));
    expectError(r, 405, "method_not_allowed");
    expect(r.res.headers.get("allow")).toBe("POST");
    expect(called).toBe(0);
  });
});

describe("adapter verify", () => {
  it("the janrain stub throws WebhookNotImplementedError → 501 not_implemented, nothing written", async () => {
    await expect(janrainAdapter.verify(hookCtx(), new Request(SITE))).rejects.toBeInstanceOf(WebhookNotImplementedError);
    const r = await run({});
    expectError(r, 501, "not_implemented");
    expect(r.ctx.recorded.kv.size).toBe(0);
  });

  it("verify gets ctx and the request", async () => {
    const seen = [];
    await run({ body: '{"hello":1}' }, fake(async (ctx, request) => { seen.push([ctx.path, request.method, await request.text()]); return []; }));
    expect(seen).toEqual([[PATH, "POST", '{"hello":1}']]);
  });

  it("any other verify failure → 401 unauthorized, nothing written", async () => {
    for (const err of [new Error("bad signature"), new TypeError("x"), "a string"]) {
      const r = await run({}, fake(async () => { throw err; }));
      expectError(r, 401, "unauthorized");
      expect(r.ctx.recorded.kv.size).toBe(0);
    }
  });

  it("an unknown adapter name (validate() prevents it) → 500 internal_error", async () => {
    const r = await run({}, {});
    expectError(r, 500, "internal_error");
  });
});

describe("events → 400", () => {
  it.each([
    ["not an array", { scope: "session", sid: SID }],
    ["null", null],
    [`more than ${MAX_WEBHOOK_EVENTS} events`, Array.from({ length: MAX_WEBHOOK_EVENTS + 1 }, () => ({ scope: "session", sid: SID }))],
    ["an unknown scope", [{ scope: "all" }]],
    ["an extra key", [{ scope: "session", sid: SID, at: 1 }]],
    ["a session event with a sub", [{ scope: "session", sub: SUB }]],
    ["a session event with sid and sub", [{ scope: "session", sid: SID, sub: SUB }]],
    ["an invalid sid", [{ scope: "session", sid: "nope" }]],
    ["an empty sub", [{ scope: "user", sub: "" }]],
    ["a non-object event", ["session"]],
    ["one bad event among good ones", [{ scope: "session", sid: SID }, { scope: "user" }]],
  ])("%s → 400, nothing written", async (_label, events) => {
    const r = await run({}, fake(async () => events));
    expectError(r, 400, "bad_request");
    expect(r.ctx.recorded.kv.size).toBe(0);
  });

  it("normalizeWebhookEvents copies only the known fields", () => {
    expect(normalizeWebhookEvents([{ sid: SID, scope: "session" }])).toEqual([{ scope: "session", sid: SID }]);
    expect(normalizeWebhookEvents([])).toEqual([]);
  });
});

describe("apply", () => {
  it("applies session and user events through revocation-store.js → 200 {applied: n}", async () => {
    const now = 1_800_000_000;
    const events = [{ scope: "session", sid: SID }, { scope: "user", sub: SUB }, { scope: "session", sid: SID2 }];
    const r = await run({}, fake(async () => events), { nowMs: () => now * 1000 });
    expect(r.res.status).toBe(200);
    expect(r.json).toEqual({ applied: 3 });
    expect(r.res.headers.get("x-auth-request-id")).toBe("test-request-id");
    const kv = r.ctx.recorded.kv;
    expect(JSON.parse(kv.get(sidKey(SID))).value).toEqual({ at: now });
    expect(JSON.parse(kv.get(sidKey(SID2))).value).toEqual({ at: now });
    expect(JSON.parse(kv.get(await subKey(SUB))).value).toEqual({ revoked_at: now });
    expect(r.ctx.recorded.logs).toContainEqual({ level: "info", msg: "oidc webhook applied", fields: { outcome: "applied", adapter: "janrain", applied: 3 } });
  });

  it("exactly 10 events are accepted; an empty list applies 0", async () => {
    const ten = Array.from({ length: 10 }, () => ({ scope: "session", sid: SID }));
    expect((await run({}, fake(async () => ten))).json).toEqual({ applied: 10 });
    expect((await run({}, fake(async () => []))).json).toEqual({ applied: 0 });
  });

  it("available but no KV → 503 revocation_unavailable", async () => {
    expectError(await run({ kv: null }, fake(async () => [{ scope: "session", sid: SID }])), 503, "revocation_unavailable");
  });

  it("a KV write failure → 503 kv_write_failed, logged with the error class and the count applied", async () => {
    const ctx = hookCtx();
    let puts = 0;
    const base = ctx.kv;
    Object.defineProperty(ctx, "kv", {
      value: Object.freeze({
        get: (k) => base.get(k),
        delete: (k) => base.delete(k),
        put: async (k, v, o) => {
          puts += 1;
          if (puts === 2) { const e = new Error(`fail ${k}`); e.name = "KvWriteError"; throw e; }
          return base.put(k, v, o);
        },
      }),
    });
    const res = await handleWebhook(ctx, settingsFor(ctx, OPTIONS), { adapters: fake(async () => [{ scope: "session", sid: SID }, { scope: "user", sub: SUB }]) });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "kv_write_failed" });
    expect(ctx.recorded.logs).toContainEqual({
      level: "error", msg: "oidc webhook rejected",
      fields: { outcome: "rejected", status: 503, reason: "kv_write_failed", adapter: "janrain", applied: 1, error: "KvWriteError" },
    });
  });

  it("logs never carry a sid or sub", async () => {
    const logs = [];
    for (const verify of [
      async () => [{ scope: "session", sid: SID }, { scope: "user", sub: SUB }],
      async () => [{ scope: "user", sub: SUB, extra: SID }],
      async () => { throw new Error(`bad ${SUB}`); },
    ]) logs.push(...(await run({}, fake(verify))).ctx.recorded.logs);
    const text = JSON.stringify(logs);
    for (const v of [SID, SUB, ADMIN_KEY]) expect(text).not.toContain(v);
  });
});
