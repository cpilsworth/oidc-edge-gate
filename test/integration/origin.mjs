// Stub EDS origin for the integration smoke. Echoes the headers it received
// (so the test can assert the gate's BYO-CDN contract + x-auth-* injection and
// the client-spoof strip) and sets two Set-Cookie lines (one gate-named, one
// not) so the test can assert gate-cookie stripping from origin responses.

import { createServer } from "node:http";
import { ORIGIN_PORT } from "./constants.mjs";

export async function startOrigin() {
  const server = createServer((req, res) => {
    const seen = {
      host: req.headers["host"] || null,
      "x-forwarded-host": req.headers["x-forwarded-host"] || null,
      "x-push-invalidation": req.headers["x-push-invalidation"] || null,
      "x-auth-subject": req.headers["x-auth-subject"] || null,
      "x-auth-email": req.headers["x-auth-email"] || null,
      "x-auth-groups": req.headers["x-auth-groups"] || null,
      "x-auth-request-id": req.headers["x-auth-request-id"] || null,
      cookie: req.headers["cookie"] || null,
    };
    res.writeHead(200, {
      "content-type": "application/json",
      "cache-control": "public, max-age=60",
      // The gate must strip the gate-named Set-Cookie but pass the app one through.
      "set-cookie": ["__edge_session=should-be-stripped; Path=/", "app_pref=keep; Path=/"],
    });
    res.end(JSON.stringify({ ok: true, path: req.url, seen }));
  });

  await new Promise((resolve) => server.listen(ORIGIN_PORT, "127.0.0.1", resolve));
  return server;
}
