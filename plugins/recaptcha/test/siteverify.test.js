import { describe, it, expect } from "vitest";
import { PluginError } from "../../../src/sdk/index.js";
import { extractRecaptchaToken, verifyRecaptcha, passesRecaptcha, recaptchaResultHeaders, matchesExpectations } from "../lib/siteverify.js";

describe("extractRecaptchaToken", () => {
  it("reads the field from an application/x-www-form-urlencoded body", () => {
    const body = "name=Ada&g-recaptcha-response=tok123&email=ada%40example.com";
    expect(extractRecaptchaToken(body, "application/x-www-form-urlencoded")).toBe("tok123");
  });

  it("defaults to urlencoded parsing when content-type is absent", () => {
    expect(extractRecaptchaToken("g-recaptcha-response=tok123", null)).toBe("tok123");
  });

  it("returns null when the field is missing", () => {
    expect(extractRecaptchaToken("name=Ada", "application/x-www-form-urlencoded")).toBeNull();
  });

  it("returns null for an empty/absent body", () => {
    expect(extractRecaptchaToken("", "application/x-www-form-urlencoded")).toBeNull();
    expect(extractRecaptchaToken(null, "application/x-www-form-urlencoded")).toBeNull();
  });

  it("reads the field out of a multipart/form-data body", () => {
    const boundary = "----WebKitFormBoundaryABC";
    const body = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="name"',
      "",
      "Ada",
      `--${boundary}`,
      'Content-Disposition: form-data; name="g-recaptcha-response"',
      "",
      "tok-multipart",
      `--${boundary}--`,
      "",
    ].join("\r\n");
    expect(extractRecaptchaToken(body, `multipart/form-data; boundary=${boundary}`)).toBe("tok-multipart");
  });

  it("returns null for multipart with no matching field", () => {
    const boundary = "B1";
    const body = [`--${boundary}`, 'Content-Disposition: form-data; name="name"', "", "Ada", `--${boundary}--`, ""].join("\r\n");
    expect(extractRecaptchaToken(body, `multipart/form-data; boundary=${boundary}`)).toBeNull();
  });

  it("returns null for multipart with no boundary in content-type", () => {
    expect(extractRecaptchaToken("anything", "multipart/form-data")).toBeNull();
  });
});

describe("verifyRecaptcha", () => {
  // verifyRecaptcha takes the plugin's ctx.fetch; these stand-ins record it.
  it("posts the token+secret to Google's siteverify endpoint and returns its JSON", async () => {
    let seen;
    const fetchFn = async (input, init, opts) => {
      const r = input instanceof Request ? input : new Request(input, init);
      seen = { url: r.url, body: init.body, contentType: init.headers["content-type"], opts };
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    };
    const result = await verifyRecaptcha("the-token", "the-secret", fetchFn);
    expect(seen.url).toBe("https://www.google.com/recaptcha/api/siteverify");
    expect(seen.contentType).toBe("application/x-www-form-urlencoded");
    expect(new URLSearchParams(seen.body).get("secret")).toBe("the-secret");
    expect(new URLSearchParams(seen.body).get("response")).toBe("the-token");
    expect(seen.opts).toEqual({ purpose: "siteverify" });
    expect(result).toEqual({ success: true });
  });

  it("fails closed with missing-input-response when no token is given", async () => {
    let called = false;
    const fetchFn = async () => { called = true; return new Response("{}"); };
    const result = await verifyRecaptcha(null, "secret", fetchFn);
    expect(result.success).toBe(false);
    expect(result["error-codes"]).toContain("missing-input-response");
    expect(called).toBe(false); // no point calling Google with nothing to verify
  });

  it("fails closed on a non-2xx siteverify response", async () => {
    const result = await verifyRecaptcha("tok", "secret", async () => new Response("boom", { status: 503 }));
    expect(result.success).toBe(false);
    expect(result["error-codes"]).toEqual(["siteverify-http-503"]);
  });

  it("fails closed when the siteverify fetch throws", async () => {
    const result = await verifyRecaptcha("tok", "secret", async () => { throw new Error("network down"); });
    expect(result.success).toBe(false);
    expect(result["error-codes"]).toEqual(["siteverify-unreachable"]);
  });

  it("fails closed on a non-JSON siteverify response", async () => {
    const result = await verifyRecaptcha("tok", "secret", async () => new Response("not json", { status: 200 }));
    expect(result.success).toBe(false);
  });

  it("rethrows a kernel fetch-policy error (budget/egress) instead of folding it into a failed check", async () => {
    const err = new PluginError(503, "budget_exceeded", "over budget");
    await expect(verifyRecaptcha("tok", "secret", async () => { throw err; })).rejects.toBe(err);
  });
});

describe("passesRecaptcha", () => {
  it("fails on a falsy/missing result", () => {
    expect(passesRecaptcha(null, null)).toBe(false);
    expect(passesRecaptcha(undefined, null)).toBe(false);
    expect(passesRecaptcha({ success: false }, null)).toBe(false);
  });

  it("v2: success alone is enough, no score involved", () => {
    expect(passesRecaptcha({ success: true }, null)).toBe(true);
    expect(passesRecaptcha({ success: true }, 0.5)).toBe(true); // no score on the result -> minScore is a no-op
  });

  it("v3: score must clear minScore", () => {
    expect(passesRecaptcha({ success: true, score: 0.9 }, 0.5)).toBe(true);
    expect(passesRecaptcha({ success: true, score: 0.3 }, 0.5)).toBe(false);
    expect(passesRecaptcha({ success: true, score: 0.5 }, 0.5)).toBe(true); // boundary is inclusive
  });
});

describe("recaptchaResultHeaders", () => {
  it("returns nothing for a falsy result", () => {
    expect(recaptchaResultHeaders(null)).toEqual({});
    expect(recaptchaResultHeaders(undefined)).toEqual({});
  });

  it("v2: no score on the response -> no x-recaptcha-score header", () => {
    const headers = recaptchaResultHeaders({ success: true, hostname: "example.com", challenge_ts: "2026-07-13T10:00:00Z" });
    expect(headers).toEqual({ "x-recaptcha-hostname": "example.com", "x-recaptcha-challenge-ts": "2026-07-13T10:00:00Z" });
  });

  it("v3: includes score, stringified", () => {
    const headers = recaptchaResultHeaders({ success: true, score: 0.9, hostname: "example.com", challenge_ts: "2026-07-13T10:00:00Z" });
    expect(headers).toEqual({
      "x-recaptcha-score": "0.9",
      "x-recaptcha-hostname": "example.com",
      "x-recaptcha-challenge-ts": "2026-07-13T10:00:00Z",
    });
  });

  it("omits fields the response doesn't carry", () => {
    expect(recaptchaResultHeaders({ success: true })).toEqual({});
  });
});

describe("matchesExpectations (F8)", () => {
  it("no expectations -> null for any result, including v2 results without action/hostname", () => {
    expect(matchesExpectations({ success: true })).toBeNull();
    expect(matchesExpectations({ success: true }, {})).toBeNull();
  });
  it("hostname must be one of expectedHostnames (case-insensitive)", () => {
    const e = { expectedHostnames: ["www.example.com"] };
    expect(matchesExpectations({ hostname: "www.example.com" }, e)).toBeNull();
    expect(matchesExpectations({ hostname: "WWW.EXAMPLE.COM" }, e)).toBeNull();
    expect(matchesExpectations({ hostname: "evil.example" }, e)).toBe("hostname_mismatch");
    expect(matchesExpectations({}, e)).toBe("hostname_mismatch");
    expect(matchesExpectations({ hostname: 5 }, e)).toBe("hostname_mismatch");
  });
  it("action must equal expectedAction exactly", () => {
    const e = { expectedAction: "submit" };
    expect(matchesExpectations({ action: "submit" }, e)).toBeNull();
    expect(matchesExpectations({ action: "Submit" }, e)).toBe("action_mismatch");
    expect(matchesExpectations({}, e)).toBe("action_mismatch");
    expect(matchesExpectations(null, e)).toBe("action_mismatch");
  });
});
