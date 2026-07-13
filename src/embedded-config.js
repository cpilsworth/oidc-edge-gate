// Build-time embedded configuration — FALLBACK for SANDBOX programs only.
//
// Cloud Manager *sandbox* programs do not provision the edge-function service
// stores (config_default / secret_default / kv_default), so constructing a
// ConfigStore / SecretStore throws at runtime and every request 500s. loadConfig
// (src/config.js) falls back to these values when the stores are absent, letting
// the gate run store-free for a POC on a sandbox environment.
//
// On a NON-sandbox environment the platform provisions the stores and their
// values take precedence — these embedded values are only a fallback. Keep them
// in sync with config/edgeFunctions.yaml, which is the source of truth for
// provisioned environments.
//
// SECURITY: embedding secrets in source is POC-ONLY and must never ship to a
// real environment. `session_hmac_key` below is a throwaway session-signing key.
// `client_secret` is a placeholder — the OIDC login flow (token exchange) will
// fail until it is replaced with the real Auth0 client secret; public-tier paths
// work without it.

export const EMBEDDED_CONFIGS = {
  issuer: "https://dev-37naouno.us.auth0.com",
  client_id: "IgIFZftc6r4IkUBxGhgfwCBgTQaaMpeO",
  redirect_uri: "https://edgefunction-p31359-e2079124-oidc-edge-gate.adobeaemcloud.com/.auth/callback",
  scopes: "openid profile email groups",
  session_ttl_seconds: "3600",
  groups_claim: "https://oidc.workers.dev/groups",
  routes: '{"callback":"/.auth/callback","logout":"/.auth/logout"}',
  backends: '{"origin":"origin","idp":"idp"}',
  origin_hostname: "main--az-poc-ch--hmehta-adobe.aem.live",
  forwarded_host: "edgefunction-p31359-e2079124-oidc-edge-gate.adobeaemcloud.com",
  push_invalidation: "enabled",
  policy: JSON.stringify({
    rules: [
      { path: "/", tier: "public" },
      { path: "/scripts/*", tier: "public" },
      { path: "/styles/*", tier: "public" },
      { path: "/blocks/*", tier: "public" },
      { path: "/icons/*", tier: "public" },
      { path: "/fonts/*", tier: "public" },
      { path: "/media_*", tier: "public" },
      { path: "/.well-known/*", tier: "public" },
      { path: "/sitemap.xml", tier: "public" },
      { path: "/robots.txt", tier: "public" },
      // EDS loads the header/footer as fragments via scripts.js. These must be
      // public or every page's chrome 302s to login and fails to render.
      { path: "/nav", tier: "public" },
      { path: "/footer", tier: "public" },
      { path: "/nav.plain.html", tier: "public" },
      { path: "/footer.plain.html", tier: "public" },
      { path: "/content/nav.plain.html", tier: "public" },
      { path: "/content/footer.plain.html", tier: "public" },
      // Branded error pages served on 403 etc. (see originErrorPage) — public so
      // they render without themselves requiring auth.
      { path: "/errors/*", tier: "public" },
      { path: "/protected/*", tier: "protected" },
      { path: "/protected/medical/*", tier: "protected", audience: ["medical"] },
      { path: "/protected/market-access/*", tier: "protected", audience: ["market-access"] },
      // Proxy the API tier to the SWAPI demo API instead of the EDS origin.
      // Path is preserved: /api/people -> https://swapi.dev/api/people.
      { path: "/api/*", tier: "public", upstream: "https://swapi.dev" },
      // Demonstrates policy-configured headers (see src/policy.js): form
      // submissions are proxied to a Pipedream debug endpoint that echoes the
      // request (including headers) back in its response, so the injected
      // header is visible for testing. A real form origin behind this route
      // could require this header and reject any request that arrives
      // without it — i.e. one that didn't come through the gate. Swap the
      // upstream + header value before using this pattern in a live deployment.
      {
        path: "/form/*",
        tier: "public",
        upstream: "https://eou3xkiimz5rjmr.m.pipedream.net",
        headers: { "x-edge-gate-secret": "demo-shared-secret-change-me" },
      },
    ],
    default_tier: "protected",
  }),
};

export const EMBEDDED_SECRETS = {
  // POC-only. Replace with the real Auth0 client secret for login to work.
  client_secret: "REPLACE_WITH_REAL_AUTH0_CLIENT_SECRET",
  // Throwaway 48-byte session-signing key (stable across instances so cookies validate).
  session_hmac_key: "poTj8U1cdiskB57pwSrjU_HMK383NnCIHgosH7MP2bEc",
};
