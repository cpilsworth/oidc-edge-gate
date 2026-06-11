import { describe, it, expect } from "vitest";
import { KVStore } from "fastly:kv-store";

describe("harness", () => {
  it("runs under node with Web Crypto + the KV stub round-trip", async () => {
    expect(typeof crypto.subtle.digest).toBe("function");
    expect(typeof crypto.getRandomValues).toBe("function");
    const kv = new KVStore("smoke");
    await kv.put("k", "v");
    const entry = await kv.get("k");
    expect(await entry.text()).toBe("v");
    expect(await kv.get("missing")).toBeNull();
  });
});
