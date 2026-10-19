#!/usr/bin/env node
// Inject the probe token from $PROBE_TOKEN into src/token.js (build-time only).
// Mirrors how CI injects OIDC_CLIENT_SECRET into src/embedded-config.js.
//
//   PROBE_TOKEN="$(openssl rand -hex 24)" node scripts/inject-token.mjs
//
// Afterwards build, then RESTORE the placeholder before any commit:
//   git checkout -- src/token.js        (from tools/platform-probe)
// The token value is never printed.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const f = fileURLToPath(new URL("../src/token.js", import.meta.url));
const t = process.env.PROBE_TOKEN;
if (!t || t.length < 16 || !/^[A-Za-z0-9._~-]+$/.test(t)) {
  console.error("PROBE_TOKEN must be set: >=16 chars of [A-Za-z0-9._~-] (e.g. openssl rand -hex 24)");
  process.exit(1);
}
const src = readFileSync(f, "utf8");
if (!src.includes('"REPLACE_WITH_PROBE_TOKEN"')) {
  console.error("placeholder not found in src/token.js (already injected?) — run: git checkout -- src/token.js");
  process.exit(1);
}
writeFileSync(f, src.replace('"REPLACE_WITH_PROBE_TOKEN"', () => JSON.stringify(t)));
console.log("Injected probe token into src/token.js (remember to restore the placeholder).");
