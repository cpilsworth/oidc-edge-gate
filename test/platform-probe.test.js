// Unit tests for the platform probe's pure helpers (tools/platform-probe/src/lib.js).
// lib.js has no `fastly:*` imports, so nothing needs mocking; the probe's
// entry point (index.js) is exercised only on the real runtime.
import { describe, it, expect } from "vitest";
import {
  ALLOWED_HOSTS, PROBE_HEADERS, isTokenConfigured, tokenMatches, checkAllowedUrl, isProbeKey, clampInt,
  percentile, summarize, describeError, classifyProfile, pickHeaders, probeBody, jsonResponse, notFound,
  b64uToBytes, shortHash,
} from "../tools/platform-probe/src/lib.js";
import { PROBE_TOKEN } from "../tools/platform-probe/src/token.js";
import * as FX from "../tools/platform-probe/src/fixtures.js";

const TOKEN = "0123456789abcdef0123";

describe("probe token", () => {
  it("committed token.js holds the placeholder, which is never accepted", () => {
    expect(PROBE_TOKEN).toBe("REPLACE_WITH_PROBE_TOKEN");
    expect(isTokenConfigured(PROBE_TOKEN)).toBe(false);
    expect(tokenMatches("REPLACE_WITH_PROBE_TOKEN", PROBE_TOKEN)).toBe(false);
  });

  it("rejects short or non-string expected tokens", () => {
    expect(isTokenConfigured("short")).toBe(false);
    expect(isTokenConfigured(undefined)).toBe(false);
    expect(isTokenConfigured(TOKEN)).toBe(true);
  });

  it("matches only the exact token", () => {
    expect(tokenMatches(TOKEN, TOKEN)).toBe(true);
    expect(tokenMatches(TOKEN.slice(0, -1), TOKEN)).toBe(false);
    expect(tokenMatches(TOKEN + "x", TOKEN)).toBe(false);
    expect(tokenMatches(TOKEN.replace("0", "1"), TOKEN)).toBe(false);
    expect(tokenMatches("", TOKEN)).toBe(false);
    expect(tokenMatches(null, TOKEN)).toBe(false);
  });
});

describe("checkAllowedUrl", () => {
  it("accepts https URLs on allowlisted hosts", () => {
    for (const h of ALLOWED_HOSTS) {
      const r = checkAllowedUrl(`https://${h}/path?q=1`);
      expect(r.ok).toBe(true);
    }
  });

  it.each([
    [null, "missing"],
    ["not a url", "invalid"],
    ["http://www.aem.live/", "https"],
    ["https://evil.example/", "allowlisted"],
    ["https://www.aem.live.evil.example/", "allowlisted"],
    ["https://user:pw@www.aem.live/", "credentials"],
    ["https://www.aem.live:8443/", "port"],
  ])("rejects %s", (raw, msg) => {
    const r = checkAllowedUrl(raw);
    expect(r.ok).toBe(false);
    expect(r.error).toContain(msg);
  });
});

describe("isProbeKey", () => {
  it("requires the probe: prefix and a safe charset", () => {
    expect(isProbeKey("probe:a-1.b_c:d")).toBe(true);
    expect(isProbeKey("oidc:state")).toBe(false);
    expect(isProbeKey("probe:")).toBe(false);
    expect(isProbeKey("probe:a#b")).toBe(false);
    expect(isProbeKey("probe:a\nb")).toBe(false);
    expect(isProbeKey("probe:" + "a".repeat(201))).toBe(false);
    expect(isProbeKey(null)).toBe(false);
  });
});

describe("clampInt", () => {
  it("defaults, parses and clamps", () => {
    expect(clampInt(null, 5, 1, 10)).toBe(5);
    expect(clampInt("abc", 5, 1, 10)).toBe(5);
    expect(clampInt("7", 5, 1, 10)).toBe(7);
    expect(clampInt("0", 5, 1, 10)).toBe(1);
    expect(clampInt("999", 5, 1, 40)).toBe(40);
  });
});

describe("percentile / summarize", () => {
  it("uses nearest-rank percentiles", () => {
    const s = Array.from({ length: 100 }, (_, i) => i + 1);
    expect(percentile(s, 50)).toBe(50);
    expect(percentile(s, 95)).toBe(95);
    expect(percentile([], 50)).toBeNull();
    expect(percentile([3], 95)).toBe(3);
  });

  it("summarises unsorted samples", () => {
    expect(summarize([4, 1, 3, 2])).toEqual({ n: 4, min: 1, p50: 2, p95: 4, max: 4, mean: 2.5, total: 10 });
    expect(summarize([])).toMatchObject({ n: 0, p50: null, total: 0 });
  });
});

describe("describeError", () => {
  it("reports class, name and message only", () => {
    expect(describeError(new TypeError("nope"))).toEqual({ class: "TypeError", name: "TypeError", message: "nope" });
    expect(describeError("plain")).toEqual({ class: "string", name: "", message: "plain" });
  });
});

describe("classifyProfile", () => {
  const s = (c, se, k) => ({ config: { constructed: c }, secret: { constructed: se }, kv: { constructed: k } });
  it("maps store availability to a platform profile", () => {
    expect(classifyProfile(s(true, true, true))).toBe("provisioned");
    expect(classifyProfile(s(false, false, false))).toBe("sandbox");
    expect(classifyProfile(s(true, false, true))).toBe("partial");
    expect(classifyProfile({})).toBe("sandbox");
  });
});

describe("response shaping", () => {
  it("probeBody has the documented shape", () => {
    expect(probeBody("env", true, { a: 1 }, ["n"], 10, 12.3456, { pop: "LCY" }))
      .toEqual({ probe: "env", ok: true, results: { a: 1 }, notes: ["n"], elapsed_ms: 2.346, pop: "LCY" });
  });

  it("jsonResponse is never cacheable", async () => {
    const r = jsonResponse(200, { ok: true });
    expect(r.headers.get("cache-control")).toBe("private, no-store");
    expect(r.headers.get("surrogate-control")).toBe("private");
    expect(await r.json()).toEqual({ ok: true });
    expect(PROBE_HEADERS["cache-control"]).toBe("private, no-store");
  });

  it("notFound is an opaque, uncacheable 404", async () => {
    const r = notFound();
    expect(r.status).toBe(404);
    expect(r.headers.get("cache-control")).toBe("private, no-store");
    expect(r.headers.get("surrogate-control")).toBe("private");
    expect(await r.text()).toBe("Not Found");
  });

  it("pickHeaders returns only present headers", () => {
    const h = new Headers({ age: "3", "x-cache": "HIT", other: "x" });
    expect(pickHeaders(h, ["age", "x-cache", "x-served-by"])).toEqual({ age: "3", "x-cache": "HIT" });
  });
});

describe("crypto fixtures", () => {
  it("b64uToBytes decodes the 32-byte HMAC key", () => {
    expect(b64uToBytes(FX.HMAC_KEY_B64U)).toHaveLength(32);
  });

  it("embedded HMAC and RS256 signatures verify against the message", async () => {
    const msg = new TextEncoder().encode(FX.MESSAGE);
    const hk = await crypto.subtle.importKey("raw", b64uToBytes(FX.HMAC_KEY_B64U), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    expect(await crypto.subtle.verify("HMAC", hk, b64uToBytes(FX.HMAC_SIG_B64U), msg)).toBe(true);
    const rk = await crypto.subtle.importKey("jwk", FX.RSA_PUBLIC_JWK, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    expect(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", rk, b64uToBytes(FX.RSA_SIG_B64U), msg)).toBe(true);
  });

  it("shortHash is a stable 16-hex-char digest prefix", async () => {
    const a = await shortHash(new TextEncoder().encode("x").buffer);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(await shortHash(new TextEncoder().encode("x").buffer)).toBe(a);
  });
});
