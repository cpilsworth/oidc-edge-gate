# oidc-edge-gate

An [AEM Edge Function](https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/developing/edge-functions) that sits in front of a site and enforces authentication on **every request**. It acts as an OpenID Connect **relying party** (OAuth client) protecting a resource: unauthenticated visitors are sent through the authorization-code-with-PKCE flow against your OpenID Provider, and only requests carrying a valid, in-policy session are forwarded to origin.

AEM Edge Functions run on the [Fastly Compute](https://www.fastly.com/documentation/guides/compute/) JavaScript runtime and execute at the CDN layer, between the CDN cache and the origin — exactly where an access gate belongs.

## Background

Putting auth *inside* the site means every page, asset and API has to remember to check it, and unauthenticated requests still reach (and can be cached by) the origin. Pushing it to the edge means **nothing reaches origin without a valid session**, the check happens before the cache, and the site itself stays oblivious to OIDC.

The tricky constraint is AEM's **hard limit of 32 `fetch()` (backend) calls per execution**. A naive design that re-validates the IdP's JWT against the JWKS endpoint on every request would be both slow and quota-hungry. So this gate splits the work:

- **Once per login** (the auth-code flow): talk to the IdP — discovery, token exchange, and full RS256 JWT validation against the JWKS.
- **Every request after that**: validate the gate's *own* HMAC-signed session cookie locally, with **zero backend calls**, then pass through to origin.

## Architecture

```
                         ┌───────────────────────────────────────────┐
   Browser ──▶ CDN ──▶   │            oidc-edge-gate (Edge Fn)         │
              cache      │                                             │
                         │   1. /.auth/callback  ─┐                    │
                         │   2. /.auth/logout    ─┤  gate-owned routes │
                         │                        │                    │
                         │   3. valid session? ───┼─ yes ─▶ forward ───┼──▶ Origin (AEM site)
                         │      (HMAC, no fetch)   │                    │
                         │                        └─ no ──▶ start login │
                         └───────────────┬─────────────────────────────┘
                                         │  (login + callback only)
                                         ▼
                              OpenID Provider (idp backend)
                         authorize · token · jwks · end_session
```

### Request lifecycle

1. **Every request** enters the edge function first.
2. If the path is `/.auth/callback` or `/.auth/logout`, the gate handles it.
3. Otherwise the gate reads the `__edge_session` cookie and verifies its HMAC signature + `exp` **locally** — no backend round-trip.
4. **Valid + in policy** → identity is attached as `x-auth-*` headers and the request is forwarded to the `origin` backend.
5. **No/expired session** → a `state`, `nonce` and PKCE verifier are minted, stashed in a short-lived signed cookie, and the browser is 302'd to the IdP's `authorization_endpoint`.
6. The IdP redirects back to `/.auth/callback`; the gate checks `state`, exchanges the `code` for tokens, validates the `id_token` (RS256 against JWKS, `iss`/`aud`/`exp`/`nonce`), mints the session cookie, and bounces the user back to where they started.

## Project structure

```
oidc-edge-gate/
├── src/
│   ├── index.js        # Edge Function entry point — routing, policy, forward-to-origin
│   ├── oidc.js         # Relying party: auth-code+PKCE flow, callback, logout
│   ├── jwt.js          # RS256 ID-token validation against JWKS (+ KV-cached discovery/JWKS)
│   ├── session.js      # Mint/verify the HMAC-signed session + transient login-state cookies
│   ├── pkce.js         # PKCE verifier/challenge + random state/nonce
│   ├── cookies.js      # Cookie parse/serialize + HMAC sign/unsign
│   ├── config.js       # Loads config from ConfigStore + secrets from SecretStore
│   └── encoding.js     # base64url, UTF-8, constant-time compare helpers
├── edgeFunctions.yaml  # AEM service declaration (configs + secrets + origins)
├── cdn.yaml            # CDN routing snippet (route host -> function, define origin)
├── fastly.toml         # Fastly CLI manifest for local build/serve
├── local.config.json   # Local ConfigStore values (dev only)
└── package.json
```

## Security model

- **Session cookie** (`__edge_session`): `HttpOnly`, `Secure`, `SameSite=Lax`, HMAC-SHA256 signed with `session_hmac_key`. Carries `sub`, `email`, `groups`, `iat`, `exp`. Tampering breaks the signature; expiry is enforced on read.
- **CSRF / replay**: `state` is compared in constant time; `nonce` is bound into the ID token and checked at the callback; PKCE (S256) protects the code exchange.
- **Open redirect**: the post-login `returnTo` is restricted to same-origin relative paths.
- **Origin trust**: the gate strips the inbound `Cookie` header and injects `x-auth-subject` / `x-auth-email` / `x-auth-groups`. The origin should only trust these when reached *through* the edge (e.g. via a shared secret header or network controls).
- **Authorization**: optional coarse policy (`require_claim` + `allow_values`) gates access by group/role claim; authenticated-but-unauthorized users get `403`.

## Configuration

Set non-secret values in `edgeFunctions.yaml` under `configs:` (exposed via `ConfigStore("oidc_config")`) and secrets under `secrets:` (Cloud Manager → `SecretStore("oidc_secrets")`):

| Key | Where | Example |
| --- | --- | --- |
| `issuer` | config | `https://your-tenant.okta.com` |
| `client_id` | config | `0oaEXAMPLEclientid` |
| `redirect_uri` | config | `https://www.example.com/.auth/callback` |
| `scopes` | config | `openid profile email groups` |
| `session_ttl_seconds` | config | `3600` |
| `routes` | config (JSON) | `{"callback":"/.auth/callback","logout":"/.auth/logout"}` |
| `policy` | config (JSON) | `{"require_claim":"groups","allow_values":["site-readers"]}` |
| `backends` | config (JSON) | `{"origin":"origin","idp":"idp"}` |
| `client_secret` | secret | `${{OIDC_CLIENT_SECRET}}` |
| `session_hmac_key` | secret | `${{OIDC_SESSION_HMAC_KEY}}` (≥ 32 bytes) |

At the IdP, register `redirect_uri` as an allowed callback and (if used) `https://www.example.com/` as a post-logout redirect.

## Prerequisites

- [Node.js](https://nodejs.org/) ≥ 18
- [Fastly CLI](https://www.fastly.com/documentation/reference/cli/) (local build/serve)
- [`aio` CLI](https://developer.adobe.com/app-builder/docs/get_started/app_builder_get_started/set-up/) with the AEM plugin (AEM deploy)
- An OIDC client registered at your provider (Okta, Entra ID, Ping, Auth0, …)

## Local development

```bash
cd oidc-edge-gate
npm install

# Edit local.config.json and the secret/backend stubs in fastly.toml,
# then run the function locally:
npm run dev          # fastly compute serve  -> http://127.0.0.1:7676
```

Hitting any path without a session redirects you to the IdP; after login you land back on the original path with `__edge_session` set. `/.auth/logout` clears it.

## Deploying to AEM

```bash
# 1. Add edgeFunctions.yaml + the cdn.yaml routing rule to your AEM project repo.
# 2. Create the Cloud Manager secrets OIDC_CLIENT_SECRET and OIDC_SESSION_HMAC_KEY.
# 3. Build + deploy the function:
npm run aem:build    # aio aem edge-functions build
npm run aem:deploy   # aio aem edge-functions deploy oidc-edge-gate
```

Traffic for the configured hostname then routes through the gate before reaching origin.

## Notes & limitations

- This is a research / reference implementation, not a hardened product.
- Session revocation is time-based only (cookie `exp`); there's no server-side session store, so shortening `session_ttl_seconds` is the main revocation lever. A KV-backed denylist keyed on `sub`/`jti` would be a natural extension.
- Only the `id_token` is validated; access/refresh tokens aren't persisted. Add refresh handling if you need long-lived sessions without re-login.
- Watch the **32 backend requests per execution** ceiling — the design keeps authenticated requests at a single origin fetch and caches discovery/JWKS in KV.
