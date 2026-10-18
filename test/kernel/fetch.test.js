import { describe, it, expect, vi, afterEach } from "vitest";
import { definePlugin, PluginError } from "../../src/sdk/index.js";
import { CacheOverride } from "fastly:cache-override";
import {
  createFetchBudget, defaultCacheOverride, isFatalError, KernelFetchError, DEFAULT_FETCH_BUDGET,
} from "../../src/kernel/fetch.js";

const noop = async () => {};
const plugin = (extra = {}) => definePlugin({
  name: "demo", kind: "middleware", phases: ["beforeForward"], beforeForward: noop,
  egress: ["https://api.example.com"], maxFetches: 2, ...extra,
});

function harness(opts = {}) {
  const calls = [];
  const logs = [];
  const fetchImpl = vi.fn(async (input, init) => {
    calls.push({ input, init });
    return new Response("ok", { status: 201 });
  });
  const budget = createFetchBudget({
    fetchImpl, logSink: (event, fields) => logs.push({ event, ...fields }), requestId: "rid-1", ...opts,
  });
  return { budget, calls, logs, fetchImpl };
}

describe("defaultCacheOverride", () => {
  it("pass is positional", () => {
    const co = defaultCacheOverride("pass");
    expect(co).toBeInstanceOf(CacheOverride);
    expect(co.mode).toBe("pass");
  });
  it("{ttl} becomes override with the ttl (mode positional, not an init object)", () => {
    const co = defaultCacheOverride({ ttl: 3600 });
    expect(co.mode).toBe("override");
    expect(co.ttl).toBe(3600);
  });
  it("rejects anything else", () => {
    expect(() => defaultCacheOverride({ mode: "pass" })).toThrow(TypeError);
    expect(() => defaultCacheOverride("override")).toThrow(TypeError);
  });
});

describe("createFetchBudget — kernel fetch", () => {
  it("defaults to 16 and counts used/remaining", async () => {
    const { budget } = harness();
    expect(DEFAULT_FETCH_BUDGET).toBe(16);
    expect(budget.used()).toBe(0);
    expect(budget.remaining()).toBe(16);
    await budget.kernelFetch("https://origin.example/x");
    expect(budget.used()).toBe(1);
    expect(budget.remaining()).toBe(15);
  });

  it("has no egress check and defaults to cache pass", async () => {
    const { budget, calls } = harness();
    const res = await budget.kernelFetch("https://anywhere.example/a?b=c", { method: "POST" }, { purpose: "forward" });
    expect(res.status).toBe(201);
    expect(calls[0].init.method).toBe("POST");
    expect(calls[0].init.cacheOverride.mode).toBe("pass");
  });

  it("honours an explicit init.cacheOverride and opts.cache", async () => {
    const { budget, calls } = harness();
    const mine = new CacheOverride("override", { ttl: 5 });
    await budget.kernelFetch("https://o.example/", { cacheOverride: mine });
    await budget.kernelFetch("https://o.example/", {}, { cache: { ttl: 60 } });
    expect(calls[0].init.cacheOverride).toBe(mine);
    expect(calls[1].init.cacheOverride.mode).toBe("override");
    expect(calls[1].init.cacheOverride.ttl).toBe(60);
  });

  it("throws a fatal 503 budget_exceeded past the limit and records the violation", async () => {
    const { budget, fetchImpl } = harness({ limit: 2 });
    await budget.kernelFetch("https://o.example/1");
    await budget.kernelFetch("https://o.example/2");
    const err = await budget.kernelFetch("https://o.example/3").catch((e) => e);
    expect(err).toBeInstanceOf(KernelFetchError);
    expect(err).toBeInstanceOf(PluginError);
    expect(err.status).toBe(503);
    expect(err.code).toBe("budget_exceeded");
    expect(err.fatal).toBe(true);
    expect(isFatalError(err)).toBe(true);
    expect(budget.violation()).toBe(err);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(budget.remaining()).toBe(0);
  });

  it("uses globalThis.fetch lazily when no fetchImpl is given", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("g"));
    try {
      const budget = createFetchBudget({ logSink: () => {} });
      expect(await (await budget.kernelFetch("https://o.example/")).text()).toBe("g");
      expect(spy).toHaveBeenCalledOnce();
    } finally {
      spy.mockRestore();
    }
  });

  it("rejects an invalid limit", () => {
    expect(() => createFetchBudget({ limit: -1 })).toThrow(TypeError);
  });
});

describe("createFetchBudget — plugin fetch", () => {
  it("allows egress origins and passes init through with cache pass and no redirects", async () => {
    const { budget, calls } = harness();
    const f = budget.forPlugin(plugin(), {});
    await f("https://api.example.com/v1/thing?q=1", { method: "POST", backend: "named", cacheOverride: "x" });
    // F6: the plugin's input+init are canonicalized into ONE Request, which is what is fetched.
    expect(calls[0].input).toBeInstanceOf(Request);
    expect(calls[0].input.url).toBe("https://api.example.com/v1/thing?q=1");
    expect(calls[0].input.method).toBe("POST");
    expect(calls[0].init.backend).toBeUndefined();
    expect(calls[0].init.cacheOverride.mode).toBe("pass");
    expect(calls[0].init.redirect).toBe("manual");
  });

  it("F6: the egress check runs on the canonical Request URL, not a spoofable `url` property", async () => {
    const { budget, fetchImpl } = harness();
    const f = budget.forPlugin(plugin(), {});
    const evil = { url: "https://api.example.com/ok", toString: () => "https://evil.example/steal" };
    const err = await f(evil).catch((e) => e);
    expect(err).toBeInstanceOf(KernelFetchError);
    expect(err.code).toBe("egress_denied");
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(budget.used()).toBe(0);
  });

  it("F6: a Request input that already carries a backend is refused", async () => {
    const { budget, fetchImpl } = harness();
    const req = new Request("https://api.example.com/x");
    Object.defineProperty(req, "backend", { value: "named-backend" });
    const err = await budget.forPlugin(plugin(), {})(req).catch((e) => e);
    expect(err.code).toBe("egress_denied");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("cache {ttl} gives an override CacheOverride", async () => {
    const factory = vi.fn(defaultCacheOverride);
    const { budget, calls } = harness({ cacheOverride: factory });
    await budget.forPlugin(plugin(), {})("https://api.example.com/jwks", undefined, { cache: { ttl: 3600 } });
    expect(factory).toHaveBeenCalledWith({ ttl: 3600 });
    expect(calls[0].init.cacheOverride.mode).toBe("override");
    expect(calls[0].init.cacheOverride.ttl).toBe(3600);
  });

  it("an invalid cache option throws before spending budget", async () => {
    const { budget } = harness();
    await expect(budget.forPlugin(plugin(), {})("https://api.example.com/", {}, { cache: "override" })).rejects.toThrow(TypeError);
    expect(budget.used()).toBe(0);
  });

  it("accepts URL and Request inputs", async () => {
    const { budget, calls } = harness();
    const f = budget.forPlugin(plugin(), {});
    await f(new URL("https://api.example.com/a"));
    await f(new Request("https://api.example.com/b"));
    expect(calls).toHaveLength(2);
  });

  it("resolves egress from options (egress function)", async () => {
    const { budget } = harness();
    const p = plugin({ egress: (o) => [o.base] });
    await expect(budget.forPlugin(p, { base: "https://dyn.example" })("https://dyn.example/x")).resolves.toBeInstanceOf(Response);
  });

  it("egress violation is a fatal 500 egress_denied and spends no budget", async () => {
    const { budget, fetchImpl } = harness();
    const f = budget.forPlugin(plugin(), {});
    for (const target of ["https://evil.example/", "http://api.example.com/", "https://api.example.com:444/", "/relative"]) {
      const err = await f(target).catch((e) => e);
      expect(err).toBeInstanceOf(KernelFetchError);
      expect(err.status).toBe(500);
      expect(err.code).toBe("egress_denied");
      expect(err.fatal).toBe(true);
    }
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(budget.used()).toBe(0);
    expect(budget.violation().code).toBe("egress_denied");
  });

  it("enforces the plugin's maxFetches, shared by name across forPlugin calls", async () => {
    const { budget } = harness();
    const p = plugin({ maxFetches: 2 });
    const f1 = budget.forPlugin(p, {});
    const f2 = budget.forPlugin(p, { other: true });
    await f1("https://api.example.com/1");
    await f2("https://api.example.com/2");
    const err = await f1("https://api.example.com/3").catch((e) => e);
    expect(err.code).toBe("budget_exceeded");
    expect(err.status).toBe(503);
    expect(budget.used()).toBe(2);
  });

  it("maxFetches 0 (the default) means no fetches", async () => {
    const { budget } = harness();
    const err = await budget.forPlugin(plugin({ maxFetches: undefined }), {})("https://api.example.com/").catch((e) => e);
    expect(err.code).toBe("budget_exceeded");
  });

  it("plugin fetches count against the global budget too", async () => {
    const { budget } = harness({ limit: 1 });
    await budget.kernelFetch("https://o.example/");
    const err = await budget.forPlugin(plugin(), {})("https://api.example.com/").catch((e) => e);
    expect(err.code).toBe("budget_exceeded");
    expect(budget.used()).toBe(1);
  });

  it("the first violation is the one recorded", async () => {
    const { budget } = harness({ limit: 0 });
    const f = budget.forPlugin(plugin(), {});
    await f("https://evil.example/").catch(() => {});
    await f("https://api.example.com/").catch(() => {});
    expect(budget.violation().code).toBe("egress_denied");
  });
});

describe("createFetchBudget — logging", () => {
  it("logs purpose, host, status and duration only", async () => {
    const { budget, logs } = harness();
    await budget.forPlugin(plugin(), {})("https://api.example.com/secret/path?token=abc", {
      headers: { authorization: "Bearer zzz" }, body: "pw=hunter2", method: "POST",
    }, { purpose: "userinfo" });
    await budget.kernelFetch("https://origin.example/p?q=s");
    expect(logs).toHaveLength(2);
    expect(logs[0]).toMatchObject({ event: "fetch", purpose: "userinfo", host: "api.example.com", status: 201, plugin: "demo", requestId: "rid-1" });
    expect(typeof logs[0].ms).toBe("number");
    expect(logs[1]).toMatchObject({ purpose: "kernel", host: "origin.example", status: 201 });
    const text = JSON.stringify(logs);
    for (const leak of ["secret/path", "token=abc", "Bearer", "hunter2", "/p", "q=s"]) expect(text).not.toContain(leak);
  });

  it("purpose defaults to the plugin name", async () => {
    const { budget, logs } = harness();
    await budget.forPlugin(plugin(), {})("https://api.example.com/");
    expect(logs[0].purpose).toBe("demo");
  });

  it("a failing fetch logs status 0 and the error name only, then rethrows", async () => {
    const logs = [];
    const budget = createFetchBudget({
      fetchImpl: async () => { throw new TypeError("connect failed to https://api.example.com/secret?x=1"); },
      logSink: (event, fields) => logs.push({ event, ...fields }),
    });
    await expect(budget.kernelFetch("https://api.example.com/secret?x=1")).rejects.toThrow(TypeError);
    expect(logs[0]).toMatchObject({ status: 0, error: "TypeError", host: "api.example.com" });
    expect(JSON.stringify(logs)).not.toContain("secret");
  });

  it("a throwing log sink never breaks a fetch", async () => {
    const budget = createFetchBudget({ fetchImpl: async () => new Response("x"), logSink: () => { throw new Error("sink down"); } });
    await expect(budget.kernelFetch("https://o.example/")).resolves.toBeInstanceOf(Response);
  });
});

afterEach(() => vi.restoreAllMocks());
