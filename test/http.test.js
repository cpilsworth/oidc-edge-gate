import { describe, it, expect } from "vitest";
import { NO_STORE_HEADERS, errorResponse, requestId } from "../src/sdk/http.js";

describe("http helpers", () => {
  it("NO_STORE_HEADERS keeps responses out of CDN + browser caches", () => {
    expect(NO_STORE_HEADERS["surrogate-control"]).toBe("private");
    expect(NO_STORE_HEADERS["cache-control"]).toBe("private, no-store");
  });

  it("errorResponse serializes an object body as JSON with no-store headers", async () => {
    const res = errorResponse(403, { error: "forbidden" });
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(res.headers.get("surrogate-control")).toBe("private");
    expect(await res.json()).toEqual({ error: "forbidden" });
  });

  it("errorResponse sends a string body as text/plain", async () => {
    const res = errorResponse(400, "nope");
    expect(res.headers.get("content-type")).toContain("text/plain");
    expect(await res.text()).toBe("nope");
  });

  it("errorResponse merges extra headers last", () => {
    const res = errorResponse(401, { error: "unauthorized" }, {
      headers: { "www-authenticate": "Bearer", "x-auth-request-id": "abc" },
    });
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
    expect(res.headers.get("x-auth-request-id")).toBe("abc");
  });

  it("requestId prefers the Fastly trace id when present", () => {
    const req = new Request("https://x/", { headers: { "fastly-trace-id": "trace-123" } });
    expect(requestId(req)).toBe("trace-123");
  });

  // F12: an inbound trace id is only trusted in a safe, bounded shape.
  it("requestId ignores a malformed or oversized fastly-trace-id and generates its own", () => {
    for (const bad of ["short", "x".repeat(65), "has space 123", "a\u0007bcdefgh", "inject\"},{\"x\":1", "../../etc/passwd", "abc;def=ghi"]) {
      let req;
      try { req = new Request("https://x/", { headers: { "fastly-trace-id": bad } }); } catch { continue; } // control chars are rejected by Headers itself
      const id = requestId(req);
      expect(id, bad).not.toBe(bad);
      expect(id).toMatch(/^[0-9a-f-]{32,36}$/);
    }
    for (const ok of ["abcdefgh", "A1.b2_c3-d4", "x".repeat(64)]) {
      expect(requestId(new Request("https://x/", { headers: { "fastly-trace-id": ok } }))).toBe(ok);
    }
  });

  it("requestId generates an id when no trace header is present", () => {
    const id = requestId(new Request("https://x/"));
    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(0);
  });

  it("requestId falls back to a 32-hex random id when crypto.randomUUID is unavailable", () => {
    const saved = crypto.randomUUID;
    Object.defineProperty(crypto, "randomUUID", { value: undefined, configurable: true });
    try {
      const id = requestId(new Request("https://x/"));
      // 16 random bytes -> 32 hex chars; UUID-shaped (8-4-4-4-12) form must not
      // leak out of the fallback path.
      expect(id).toMatch(/^[0-9a-f]{32}$/);
    } finally {
      Object.defineProperty(crypto, "randomUUID", { value: saved, configurable: true });
    }
  });

  it("requestId generates a valid id when called with no request (no headers to read)", () => {
    // The `request && request.headers` guard must let requestId still mint an id
    // rather than throwing; it should be a real UUID or the 32-hex fallback.
    const id = requestId(undefined);
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|^[0-9a-f]{32}$/);
  });
});
