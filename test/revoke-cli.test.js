// scripts/revoke.mjs (docs/architecture/plugins.md §15.7): argument parsing,
// exit codes, the key-only-from-env rule, dry-run output and https enforcement.
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { DEFAULT_PATH, run } from "../scripts/revoke.mjs";
import { verifyAdminSignature } from "../plugins/oidc-auth/lib/admin-signature.js";

const KEY = "cli-test-admin-key-at-least-32-bytes-long!!";
const SID = "Q2xpVGVzdFNpZDEyMzQ1Ng";
const SUB = "auth0|cli-user-77";
const NOW = 1_800_000_000_000;

async function cli(argv, { env = { REVOCATION_ADMIN_KEY: KEY }, respond } = {}) {
  const out = [];
  const err = [];
  const requests = [];
  const fetch = async (url, init) => {
    requests.push({ url, init });
    if (respond) return respond(url, init);
    return Response.json({ revoked: "session", propagation_seconds: 60 }, { headers: { "x-auth-request-id": "rid-1" } });
  };
  const code = await run({ argv, env, fetch, stdout: { write: (s) => out.push(s) }, stderr: { write: (s) => err.push(s) }, now: () => NOW });
  return { code, stdout: out.join(""), stderr: err.join(""), requests };
}

describe("a successful request", () => {
  it("POSTs a signed JSON body to <url>/.auth/admin/revoke and exits 0", async () => {
    const r = await cli(["--url", "https://www.example.com", "--sid", SID, "--reason", "lost device"]);
    expect(r.code).toBe(0);
    expect(r.requests).toHaveLength(1);
    const { url, init } = r.requests[0];
    expect(url).toBe(`https://www.example.com${DEFAULT_PATH}`);
    expect(init.method).toBe("POST");
    expect(init.headers["content-type"]).toBe("application/json");
    expect(await verifyAdminSignature(KEY, init.body, init.headers.authorization)).toBe(true);
    const body = JSON.parse(init.body);
    expect(body).toEqual({ v: 1, aud: "www.example.com", iat: NOW / 1000, jti: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), scope: "session", sid: SID, reason: "lost device" });
    expect(r.stdout).toBe('HTTP 200\n{\n  "revoked": "session",\n  "propagation_seconds": 60\n}\nx-auth-request-id: rid-1\n');
    expect(r.stderr).toBe("");
  });

  it("--sub builds a user-scope body; --aud overrides the URL host; --path overrides the route", async () => {
    const r = await cli(["--url=https://edge.internal.example", "--sub", SUB, "--aud", "www.example.com", "--path", "/.auth/admin/revoke2"]);
    expect(r.code).toBe(0);
    expect(r.requests[0].url).toBe("https://edge.internal.example/.auth/admin/revoke2");
    const body = JSON.parse(r.requests[0].init.body);
    expect(body).toMatchObject({ scope: "user", sub: SUB, aud: "www.example.com" });
    expect(body).not.toHaveProperty("sid");
    expect(body).not.toHaveProperty("reason");
  });

  it("aud defaults to the URL host, including a non-default port", async () => {
    const r = await cli(["--url", "http://localhost:7676", "--sid", SID]);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.requests[0].init.body).aud).toBe("localhost:7676");
    expect(r.requests[0].url).toBe("http://localhost:7676/.auth/admin/revoke");
  });

  it("every run uses a fresh jti", async () => {
    const a = await cli(["--url", "https://h.example", "--sid", SID]);
    const b = await cli(["--url", "https://h.example", "--sid", SID]);
    expect(JSON.parse(a.requests[0].init.body).jti).not.toBe(JSON.parse(b.requests[0].init.body).jti);
  });

  it("never prints the key or the signature", async () => {
    const r = await cli(["--url", "https://h.example", "--sid", SID]);
    const tag = r.requests[0].init.headers.authorization.split(" ")[1];
    for (const s of [r.stdout, r.stderr]) {
      expect(s).not.toContain(KEY);
      expect(s).not.toContain(tag);
      expect(s).not.toContain("Gate-Revoke-HMAC-SHA256");
    }
  });
});

describe("HTTP and network errors → exit 1", () => {
  it.each([401, 404, 409, 413, 503])("HTTP %i → exit 1 with the status and body printed", async (status) => {
    const r = await cli(["--url", "https://h.example", "--sid", SID], { respond: () => Response.json({ error: "x" }, { status }) });
    expect(r.code).toBe(1);
    expect(r.stdout).toBe(`HTTP ${status}\n{\n  "error": "x"\n}\n`);
  });

  it("a non-JSON body is printed as-is", async () => {
    const r = await cli(["--url", "https://h.example", "--sid", SID], { respond: () => new Response("upstream down", { status: 502 }) });
    expect(r.code).toBe(1);
    expect(r.stdout).toBe("HTTP 502\nupstream down\n");
  });

  it("a network error → exit 1 with the error class only", async () => {
    const r = await cli(["--url", "https://h.example", "--sid", SID], { respond: () => { throw new TypeError(`fetch failed ${KEY}`); } });
    expect(r.code).toBe(1);
    expect(r.stderr).toBe("error: request to https://h.example/.auth/admin/revoke failed (TypeError)\n");
    expect(r.stderr).not.toContain(KEY);
  });

  it("a redirect is not followed (redirect: manual) and is an error", async () => {
    const r = await cli(["--url", "https://h.example", "--sid", SID], { respond: () => new Response(null, { status: 302, headers: { location: "https://evil.example/" } }) });
    expect(r.requests[0].init.redirect).toBe("manual");
    expect(r.code).toBe(1);
  });
});

describe("dry run", () => {
  it("prints the body only; nothing signed or sent; works without the key", async () => {
    for (const env of [{ REVOCATION_ADMIN_KEY: KEY }, {}]) {
      const r = await cli(["--url", "https://www.example.com", "--sub", SUB, "--dry-run"], { env });
      expect(r.code).toBe(0);
      expect(r.requests).toEqual([]);
      const lines = r.stdout.trimEnd().split("\n");
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0])).toEqual({ v: 1, aud: "www.example.com", iat: NOW / 1000, jti: expect.any(String), scope: "user", sub: SUB });
      expect(r.stdout).not.toContain(KEY);
      expect(r.stdout).not.toContain("Gate-Revoke");
      expect(r.stderr).toBe("");
    }
  });
});

describe("usage errors → exit 2, nothing sent", () => {
  it.each([
    ["no arguments", []],
    ["no --url", ["--sid", SID]],
    ["neither --sid nor --sub", ["--url", "https://h.example"]],
    ["both --sid and --sub", ["--url", "https://h.example", "--sid", SID, "--sub", SUB]],
    ["an invalid sid", ["--url", "https://h.example", "--sid", "abc"]],
    ["an empty sub", ["--url", "https://h.example", "--sub", ""]],
    ["a non-ASCII reason", ["--url", "https://h.example", "--sid", SID, "--reason", "über"]],
    ["a 201-char reason", ["--url", "https://h.example", "--sid", SID, "--reason", "x".repeat(201)]],
    ["an unknown option", ["--url", "https://h.example", "--sid", SID, "--force"]],
    ["a positional argument", ["https://h.example", "--sid", SID]],
    ["a missing value", ["--url", "https://h.example", "--sid"]],
    ["a repeated option", ["--url", "https://h.example", "--sid", SID, "--sid", SID]],
    ["a value on a flag", ["--url", "https://h.example", "--sid", SID, "--dry-run=yes"]],
    ["http to a public host", ["--url", "http://www.example.com", "--sid", SID]],
    ["ftp", ["--url", "ftp://www.example.com", "--sid", SID]],
    ["not a URL", ["--url", "www.example.com", "--sid", SID]],
    ["credentials in the URL", ["--url", "https://u:p@www.example.com", "--sid", SID]],
    ["a URL with a path", ["--url", "https://www.example.com/.auth/admin/revoke", "--sid", SID]],
    ["a URL with a query", ["--url", "https://www.example.com/?x=1", "--sid", SID]],
    ["a path outside /.auth/", ["--url", "https://h.example", "--sid", SID, "--path", "/admin"]],
  ])("%s", async (_label, argv) => {
    const r = await cli(argv);
    expect(r.code).toBe(2);
    expect(r.requests).toEqual([]);
    expect(r.stderr).toMatch(/^error: /);
    expect(r.stderr).toContain("usage:");
    expect(r.stderr).not.toContain(KEY);
  });

  it("http is allowed for localhost, 127.0.0.1 and [::1]", async () => {
    for (const url of ["http://localhost:7676", "http://127.0.0.1:7676", "http://[::1]:7676"]) {
      expect((await cli(["--url", url, "--sid", SID])).code).toBe(0);
    }
  });

  it("REVOCATION_ADMIN_KEY missing or empty → exit 2", async () => {
    for (const env of [{}, { REVOCATION_ADMIN_KEY: "" }]) {
      const r = await cli(["--url", "https://h.example", "--sid", SID], { env });
      expect(r.code).toBe(2);
      expect(r.stderr).toContain("REVOCATION_ADMIN_KEY is not set");
      expect(r.requests).toEqual([]);
    }
  });

  it("a key shorter than 32 bytes → exit 2 (without printing it)", async () => {
    const r = await cli(["--url", "https://h.example", "--sid", SID], { env: { REVOCATION_ADMIN_KEY: "short-key-xyz" } });
    expect(r.code).toBe(2);
    expect(r.stderr).not.toContain("short-key-xyz");
  });

  it("--help prints the usage and exits 0", async () => {
    const r = await cli(["--help"]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("usage:");
    expect(r.requests).toEqual([]);
  });
});

describe("the key is never accepted on the command line", () => {
  it.each([
    [["--key", "abc"]],
    [["--key=abc"]],
    [["--admin-key", "abc"]],
    [["--revocation-admin-key=abc"]],
    [["--secret", "abc"]],
    [["-k", "abc"]],
    [["--KEY", "abc"]],
  ])("%j → exit 2", async (extra) => {
    const r = await cli(["--url", "https://h.example", "--sid", SID, ...extra]);
    expect(r.code).toBe(2);
    expect(r.requests).toEqual([]);
    expect(r.stderr).toContain("must not be given on the command line");
    expect(r.stderr).not.toContain("abc");
  });

  it("the env key's value pasted anywhere in argv → exit 2, and it is not echoed", async () => {
    for (const argv of [
      ["--url", "https://h.example", "--sid", SID, "--reason", KEY],
      ["--url", "https://h.example", "--sid", SID, `--reason=${KEY}`],
      ["--url", "https://h.example", "--sid", SID, KEY],
    ]) {
      const r = await cli(argv);
      expect(r.code).toBe(2);
      expect(r.requests).toEqual([]);
      expect(r.stderr).not.toContain(KEY);
      expect(r.stdout).not.toContain(KEY);
    }
  });
});

describe("as a script", () => {
  const script = fileURLToPath(new URL("../scripts/revoke.mjs", import.meta.url));

  it("runs run() when executed directly: --dry-run prints the body, a usage error exits 2", () => {
    const dry = spawnSync(process.execPath, [script, "--url", "https://www.example.com", "--sid", SID, "--dry-run"], { encoding: "utf8", env: { PATH: process.env.PATH } });
    expect(dry.status).toBe(0);
    expect(JSON.parse(dry.stdout)).toMatchObject({ v: 1, scope: "session", sid: SID, aud: "www.example.com" });
    const bad = spawnSync(process.execPath, [script, "--key", "x"], { encoding: "utf8", env: { PATH: process.env.PATH } });
    expect(bad.status).toBe(2);
  });
});
