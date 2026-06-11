// Integration smoke (plan §5 Layer 2): runs the real Wasm under Viceroy
// (`fastly compute serve`) with a local mock OP + stub origin, and drives the
// full three-tier + auth-code-with-PKCE round trip over HTTP. Exits non-zero on
// any failed assertion. Run via `npm run test:integration`.

import { spawn } from "node:child_process";
import { startMockOp } from "./mock-op.mjs";
import { startOrigin } from "./origin.mjs";
import { GATE_BASE, OP_BASE, SUB, EMAIL } from "./constants.mjs";

const results = [];
function check(name, cond, detail = "") {
  results.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "  ✓" : "  ✗"} ${name}${cond ? "" : `  — ${detail}`}`);
}

// --- tiny manual cookie jar (node fetch does not manage cookies) -------------
function parseSetCookie(res) {
  const lines = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  return lines.map((l) => {
    const nv = l.split(";")[0];
    const i = nv.indexOf("=");
    return { raw: l, name: nv.slice(0, i).trim(), value: nv.slice(i + 1).trim() };
  });
}
function cookieHeader(jar) {
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");
}

async function waitForGate(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${GATE_BASE}/scripts/__ready`, { redirect: "manual" });
      if (r.status === 200) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  return false;
}

let op, origin, viceroy;
async function cleanup() {
  try { if (viceroy && viceroy.pid) process.kill(-viceroy.pid, "SIGTERM"); } catch { /* */ }
  await new Promise((r) => { if (op) op.close(r); else r(); });
  await new Promise((r) => { if (origin) origin.close(r); else r(); });
}

async function main() {
  op = await startMockOp();
  origin = await startOrigin();

  viceroy = spawn(
    "fastly",
    ["compute", "serve", "--env", "integration", "--file", "bin/main.wasm", "--addr", "127.0.0.1:7676"],
    { cwd: process.cwd(), detached: true, stdio: ["ignore", "pipe", "pipe"] },
  );
  let vlog = "";
  viceroy.stdout.on("data", (d) => { vlog += d; });
  viceroy.stderr.on("data", (d) => { vlog += d; });

  if (!(await waitForGate())) {
    console.error("Viceroy did not become ready. Server log:\n" + vlog);
    throw new Error("gate-not-ready");
  }

  // 1. public tier — forwarded, no auth headers, origin caching intact
  {
    const r = await fetch(`${GATE_BASE}/scripts/app.js`, { redirect: "manual" });
    const body = await r.json();
    check("public: 200 forwarded to origin", r.status === 200, `status ${r.status}`);
    check("public: origin sees gate Host rewrite", body.seen.host === "origin.local", body.seen.host);
    check("public: X-Forwarded-Host set", body.seen["x-forwarded-host"] === "www.example.com", body.seen["x-forwarded-host"]);
    check("public: no x-auth-* injected (no session)", body.seen["x-auth-subject"] === null, String(body.seen["x-auth-subject"]));
    check("public: origin cache-control preserved", /max-age=60/.test(r.headers.get("cache-control") || ""), r.headers.get("cache-control"));
    check("public: no Surrogate-Control (outer CDN may cache)", r.headers.get("surrogate-control") === null, String(r.headers.get("surrogate-control")));
    const sc = parseSetCookie(r);
    check("public: gate Set-Cookie stripped from origin response", !sc.some((c) => c.name === "__edge_session"), JSON.stringify(sc.map((c) => c.name)));
    check("public: app Set-Cookie passed through", sc.some((c) => c.name === "app_pref"), JSON.stringify(sc.map((c) => c.name)));
  }

  // 2. spoof strip — client-supplied x-auth-* must never reach origin
  {
    const r = await fetch(`${GATE_BASE}/scripts/app.js`, { redirect: "manual", headers: { "x-auth-subject": "attacker" } });
    const body = await r.json();
    check("spoof: client x-auth-subject stripped", body.seen["x-auth-subject"] === null, String(body.seen["x-auth-subject"]));
  }

  // 3. secured tier, unauthenticated — 401 JSON (no redirect)
  {
    const r = await fetch(`${GATE_BASE}/api/data`, { redirect: "manual" });
    const body = await r.json().catch(() => ({}));
    check("secured: 401 for unauthenticated", r.status === 401, `status ${r.status}`);
    check("secured: JSON error body", body.error === "unauthorized", JSON.stringify(body));
    check("secured: no-store", /no-store/.test(r.headers.get("cache-control") || ""), r.headers.get("cache-control"));
    check("secured: Surrogate-Control private", r.headers.get("surrogate-control") === "private", String(r.headers.get("surrogate-control")));
  }

  // 4. protected tier, unauthenticated — 302 to IdP + login cookie, no-store
  let loginCookie, authorizeUrl;
  {
    const r = await fetch(`${GATE_BASE}/protected/secret`, { redirect: "manual" });
    authorizeUrl = r.headers.get("location") || "";
    const sc = parseSetCookie(r);
    const login = sc.find((c) => c.name === "__edge_login");
    loginCookie = login ? `${login.name}=${login.value}` : null;
    check("protected: 302 to IdP", r.status === 302 && authorizeUrl.startsWith(`${OP_BASE}/authorize`), authorizeUrl);
    check("protected: __edge_login cookie set", !!loginCookie, "missing");
    check("protected: auth 302 is no-store", /no-store/.test(r.headers.get("cache-control") || ""), r.headers.get("cache-control"));
    check("protected: auth 302 Surrogate-Control private", r.headers.get("surrogate-control") === "private", String(r.headers.get("surrogate-control")));
  }

  // 5. full round trip — follow authorize -> callback -> session -> forward
  let sessionCookie, callbackUrl;
  {
    const a = await fetch(authorizeUrl, { redirect: "manual" });
    callbackUrl = a.headers.get("location") || "";
    check("authorize: 302 back to redirect_uri with code", a.status === 302 && callbackUrl.includes("/.auth/callback?") && callbackUrl.includes("code="), callbackUrl);

    const cb = await fetch(callbackUrl, { redirect: "manual", headers: { cookie: loginCookie } });
    const loc = cb.headers.get("location");
    const sc = parseSetCookie(cb);
    const sess = sc.find((c) => c.name === "__edge_session");
    sessionCookie = sess ? `${sess.name}=${sess.value}` : null;
    const cleared = sc.find((c) => c.name === "__edge_login");
    check("callback: 302 back to original path", cb.status === 302 && loc === "/protected/secret", `${cb.status} ${loc}`);
    check("callback: __edge_session minted", !!sessionCookie, "missing");
    check("callback: __edge_login cleared", !!cleared && /Max-Age=0/.test(cleared.raw), cleared ? cleared.raw : "missing");
    check("callback: no-store", /no-store/.test(cb.headers.get("cache-control") || ""), cb.headers.get("cache-control"));
  }

  // 6. authenticated protected request — forwarded with trusted identity headers
  {
    const r = await fetch(`${GATE_BASE}/protected/secret`, { redirect: "manual", headers: { cookie: sessionCookie } });
    const body = await r.json();
    check("authed: 200 forwarded", r.status === 200, `status ${r.status}`);
    check("authed: x-auth-subject injected", body.seen["x-auth-subject"] === SUB, String(body.seen["x-auth-subject"]));
    check("authed: x-auth-email injected", body.seen["x-auth-email"] === EMAIL, String(body.seen["x-auth-email"]));
    check("authed: x-auth-groups injected", body.seen["x-auth-groups"] === "medical", String(body.seen["x-auth-groups"]));
    check("authed: X-Push-Invalidation enabled", body.seen["x-push-invalidation"] === "enabled", String(body.seen["x-push-invalidation"]));
    check("authed: correlation id sent", !!body.seen["x-auth-request-id"], "missing");
    check("authed: gate cookie not leaked to origin", body.seen["cookie"] === null, String(body.seen["cookie"]));
    check("authed: response is private no-store", /no-store/.test(r.headers.get("cache-control") || ""), r.headers.get("cache-control"));
    check("authed: Surrogate-Control private (outer CDN won't cache per-user)", r.headers.get("surrogate-control") === "private", String(r.headers.get("surrogate-control")));
  }

  // 7. audience gating — user has [medical], not [finance]
  {
    const ok = await fetch(`${GATE_BASE}/protected/medical/report`, { redirect: "manual", headers: { cookie: sessionCookie } });
    check("audience: matching audience allowed (200)", ok.status === 200, `status ${ok.status}`);
    const no = await fetch(`${GATE_BASE}/protected/finance/report`, { redirect: "manual", headers: { cookie: sessionCookie } });
    check("audience: wrong audience forbidden (403)", no.status === 403, `status ${no.status}`);
  }

  // 8. replay — re-using the same callback (code + state + login cookie) is rejected
  {
    const r = await fetch(callbackUrl, { redirect: "manual", headers: { cookie: loginCookie } });
    check("replay: reused callback rejected (>=400)", r.status >= 400 && r.status < 500, `status ${r.status}`);
  }

  // 9. logout — clears session, 302 to end_session_endpoint
  {
    const r = await fetch(`${GATE_BASE}/.auth/logout`, { redirect: "manual", headers: { cookie: sessionCookie } });
    const sc = parseSetCookie(r);
    const cleared = sc.find((c) => c.name === "__edge_session");
    check("logout: 302", r.status === 302, `status ${r.status}`);
    check("logout: session cookie cleared", !!cleared && /Max-Age=0/.test(cleared.raw), cleared ? cleared.raw : "missing");
  }
}

main()
  .then(async () => {
    await cleanup();
    const failed = results.filter((r) => !r.ok);
    console.log(`\nIntegration smoke: ${results.length - failed.length}/${results.length} passed.`);
    process.exit(failed.length === 0 ? 0 : 1);
  })
  .catch(async (e) => {
    await cleanup();
    console.error("\nIntegration smoke aborted:", e.message);
    process.exit(1);
  });
