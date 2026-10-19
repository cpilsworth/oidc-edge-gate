#!/usr/bin/env node
// Sign and send one revocation to the gate's admin route
// (docs/architecture/plugins.md §15.5, §15.7).
//
//   REVOCATION_ADMIN_KEY=… node scripts/revoke.mjs --url https://<public host> \
//     (--sid <sid> | --sub <subject>) [--reason <text>] [--aud <host>] [--path </.auth/...>] [--dry-run]
//
// - The key comes ONLY from the REVOCATION_ADMIN_KEY environment variable. A
//   key-like option on the command line (or the key's value anywhere in argv) is
//   a usage error: argv leaks into shell history and the process list. The key
//   and the signature are never printed.
// - --url must be https (http only for localhost / 127.0.0.1 / [::1]) and a bare
//   origin; the request goes to <url><path>, path default /.auth/admin/revoke.
// - --aud defaults to the URL's host; it must equal the gate's forwarded_host.
// - --dry-run prints the JSON body only (no signature, nothing sent; the key is
//   not needed).
// - Output: "HTTP <status>" and the response body. Exit codes: 0 success
//   (2xx), 1 HTTP or network error, 2 usage error.
// - Each run uses a fresh random jti. On 503 kv_write_failed, run it again
//   after at least 1 s.
//
// The signing code is the gate's own (plugins/oidc-auth/lib/admin-signature.js),
// so the CLI and the route can't drift.

import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { MAX_REASON_LENGTH, REASON_RE, buildAdminRequestBody, signAdminBody } from "../plugins/oidc-auth/lib/admin-signature.js";
import { isSessionId, isSubject } from "../plugins/oidc-auth/lib/revocation-store.js";

export const DEFAULT_PATH = "/.auth/admin/revoke";
export const KEY_ENV = "REVOCATION_ADMIN_KEY";
const MIN_KEY_BYTES = 32;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const VALUE_OPTIONS = new Set(["url", "sid", "sub", "reason", "aud", "path"]);
const FLAG_OPTIONS = new Set(["dry-run", "help"]);
// Options that would carry the key on the command line.
const KEY_OPTIONS = new Set(["key", "admin-key", "revocation-admin-key", "secret", "hmac-key", "k"]);

export const USAGE = `usage: ${KEY_ENV}=… node scripts/revoke.mjs --url https://<public host> (--sid <sid> | --sub <subject>)
         [--reason <text>] [--aud <host>] [--path ${DEFAULT_PATH}] [--dry-run]

  --url      the gate's public origin (https; http only for localhost)
  --sid      revoke one session (its sid, 22 base64url characters)
  --sub      revoke every current session of a user (the OIDC subject)
  --reason   optional note for the gate's log (printable ASCII, at most ${MAX_REASON_LENGTH} characters)
  --aud      the gate's forwarded_host (default: the URL's host)
  --path     the admin route (default ${DEFAULT_PATH})
  --dry-run  print the request body and exit; nothing is signed or sent

The key is read from ${KEY_ENV} only, never from the command line.
Exit codes: 0 success, 1 HTTP or network error, 2 usage error.
`;

class UsageError extends Error {}

/**
 * Parse argv (without node and the script path).
 * @param {string[]} argv
 * @param {string|undefined} key  the env key, to detect it pasted into argv
 */
export function parseArgs(argv, key) {
  const out = { dryRun: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (typeof key === "string" && key.length > 0 && arg.includes(key)) {
      throw new UsageError(`the admin key must not be given on the command line; set ${KEY_ENV}`);
    }
    const m = /^--?([A-Za-z][A-Za-z-]*)(?:=(.*))?$/s.exec(arg);
    if (!m) throw new UsageError(`unexpected argument at position ${i + 1}`);
    const name = m[1];
    if (KEY_OPTIONS.has(name.toLowerCase())) {
      throw new UsageError(`the admin key must not be given on the command line; set ${KEY_ENV}`);
    }
    if (FLAG_OPTIONS.has(name)) {
      if (m[2] !== undefined) throw new UsageError(`--${name} takes no value`);
      if (name === "dry-run") out.dryRun = true; else out.help = true;
      continue;
    }
    if (!VALUE_OPTIONS.has(name) || !arg.startsWith("--")) throw new UsageError(`unknown option ${arg.startsWith("--") ? "--" : "-"}${name}`);
    let value = m[2];
    if (value === undefined) {
      i += 1;
      if (i >= argv.length) throw new UsageError(`--${name} needs a value`);
      value = argv[i];
      if (typeof key === "string" && key.length > 0 && value.includes(key)) {
        throw new UsageError(`the admin key must not be given on the command line; set ${KEY_ENV}`);
      }
    }
    if (Object.prototype.hasOwnProperty.call(out, name)) throw new UsageError(`--${name} given twice`);
    out[name] = value;
  }
  return out;
}

/**
 * Validate parsed options into a request plan.
 * @returns {{target: string, fields: Object, dryRun: boolean}}
 */
export function planRequest(opts, nowMs) {
  if (!opts.url) throw new UsageError("--url is required");
  let url;
  try {
    url = new URL(opts.url);
  } catch {
    throw new UsageError("--url is not a valid URL");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname))) {
    throw new UsageError("--url must be https (http is allowed only for localhost)");
  }
  if (url.username || url.password) throw new UsageError("--url must not contain credentials");
  if ((url.pathname !== "/" && url.pathname !== "") || url.search || url.hash) {
    throw new UsageError("--url must be a bare origin (use --path for the route)");
  }
  const path = opts.path ?? DEFAULT_PATH;
  if (!/^\/\.auth\/[A-Za-z0-9._~\/-]+$/.test(path)) throw new UsageError("--path must be a path under /.auth/");

  if ((opts.sid === undefined) === (opts.sub === undefined)) throw new UsageError("give exactly one of --sid or --sub");
  if (opts.sid !== undefined && !isSessionId(opts.sid)) throw new UsageError("--sid must be a session id (22 base64url characters)");
  if (opts.sub !== undefined && !isSubject(opts.sub)) throw new UsageError("--sub must be a non-empty subject of at most 1024 bytes");
  if (opts.reason !== undefined && !REASON_RE.test(opts.reason)) {
    throw new UsageError(`--reason must be printable ASCII of at most ${MAX_REASON_LENGTH} characters`);
  }
  const aud = opts.aud ?? url.host;
  if (!aud) throw new UsageError("--aud must not be empty");

  const fields = { aud, nowMs, ...(opts.sid !== undefined ? { scope: "session", sid: opts.sid } : { scope: "user", sub: opts.sub }) };
  if (opts.reason !== undefined) fields.reason = opts.reason;
  return { target: `${url.origin}${path}`, fields, dryRun: opts.dryRun };
}

/**
 * Run the CLI. Never throws; returns the exit code.
 * @param {Object} io
 * @param {string[]} io.argv     arguments after the script path
 * @param {Object<string,string|undefined>} io.env
 * @param {typeof fetch} io.fetch
 * @param {{write: (s: string) => unknown}} io.stdout
 * @param {{write: (s: string) => unknown}} io.stderr
 * @param {() => number} [io.now]  epoch ms
 * @returns {Promise<0|1|2>}
 */
export async function run({ argv, env, fetch: fetchFn, stdout, stderr, now = Date.now }) {
  const key = env[KEY_ENV];
  let plan;
  try {
    const opts = parseArgs(argv, key);
    if (opts.help) {
      stdout.write(USAGE);
      return 0;
    }
    plan = planRequest(opts, now());
    if (!plan.dryRun) {
      if (typeof key !== "string" || key.length === 0) throw new UsageError(`${KEY_ENV} is not set`);
      if (new TextEncoder().encode(key).length < MIN_KEY_BYTES) throw new UsageError(`${KEY_ENV} must be at least ${MIN_KEY_BYTES} bytes`);
    }
  } catch (e) {
    if (!(e instanceof UsageError)) {
      stderr.write("error: unexpected failure while preparing the request\n");
      return 2;
    }
    stderr.write(`error: ${e.message}\n\n${USAGE}`);
    return 2;
  }

  let body;
  try {
    body = JSON.stringify(buildAdminRequestBody(plan.fields));
  } catch (e) {
    stderr.write(`error: ${e.message}\n`);
    return 2;
  }
  if (plan.dryRun) {
    stdout.write(`${body}\n`);
    return 0;
  }

  let res;
  try {
    const authorization = await signAdminBody(key, body);
    res = await fetchFn(plan.target, {
      method: "POST",
      headers: { "content-type": "application/json", authorization },
      body,
      redirect: "manual",
    });
  } catch (e) {
    stderr.write(`error: request to ${plan.target} failed (${(e && e.name) || "Error"})\n`);
    return 1;
  }
  let text = "";
  try {
    text = await res.text();
  } catch {
    /* no body */
  }
  let shown = text;
  try {
    shown = JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    /* not JSON: print as-is */
  }
  stdout.write(`HTTP ${res.status}\n${shown}${shown.endsWith("\n") || shown === "" ? "" : "\n"}`);
  const requestId = res.headers.get("x-auth-request-id");
  if (requestId) stdout.write(`x-auth-request-id: ${requestId}\n`);
  return res.status >= 200 && res.status < 300 ? 0 : 1;
}

function isMain() {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href
      || fileURLToPath(import.meta.url) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}

if (isMain()) {
  const code = await run({
    argv: process.argv.slice(2),
    env: process.env,
    fetch: globalThis.fetch,
    stdout: process.stdout,
    stderr: process.stderr,
  });
  process.exitCode = code;
}
